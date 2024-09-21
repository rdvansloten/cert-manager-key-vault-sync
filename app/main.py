import os
import base64
import re
import time
import logging
import subprocess

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.core.exceptions import ResourceNotFoundError, ServiceRequestError
from kubernetes import client, config

# Configure logging
logging.basicConfig(level=getattr(logging, os.getenv("DEFAULT_LOGGING_LEVEL", "INFO")), format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('azure').setLevel(getattr(logging, os.getenv("AZURE_LOGGING_LEVEL", "WARNING")))

# Set variables
key_vault_name = os.getenv("AZURE_KEY_VAULT_NAME")
key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
use_namespaces = os.getenv("USE_NAMESPACES") in ("true", "1", "yes", "enabled")
check_interval = int(os.getenv("CHECK_INTERVAL", 300))
filter_annotation = os.getenv("ANNOTATION", "cert-manager.io/certificate-name")

# Logging credentials initialization
logging.info(f"Using Key Vault: {key_vault_name}")
logging.info(f"Using Key Vault URI: {key_vault_uri}")
logging.info(f"Using Namespace separation: {use_namespaces}")

# Initialize Key Vault client
try:
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False, additionally_allowed_tenants="*")
    certificate_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

    # Test connection by making a small request
    logging.info("Detected Key Vault Certificates:")
    certificate_client.list_properties_of_certificates(max_page_size=1)
    for cert in certificate_client.list_properties_of_certificates():
        logging.info(f"- {cert.name}")

    logging.info(f"Initialized Azure Key Vault client using Key Vault '{key_vault_name}'.")

except ResourceNotFoundError as e:
    logging.error(f"Failed to connect to Key Vault '{key_vault_name}': {str(e)}")
    raise

except ServiceRequestError as e:
    logging.error(f"Failed to connect to Key Vault '{key_vault_name}': {str(e)}")
    raise

except Exception as e:
    logging.error(f"Failed to connect to Key Vault '{key_vault_name}': {str(e)}")
    raise

# Initialize Kubernetes client
config.load_incluster_config()
k8s_client = client.CoreV1Api()

def compare_thumbprint(kubernetes_cert, key_vault_thumbprint):
    # Write Kubernetes Cert to file
    with open("cert.pem", "wb") as cert_file:
        cert_file.write(kubernetes_cert)

    kubernetes_raw_thumbprint = subprocess.run([
        "openssl", "x509", "-in", "cert.pem", "-noout", "-fingerprint"
    ], capture_output=True, text=True)
    kubernetes_thumbprint = re.search(r'Fingerprint=([\dA-F:]+)', kubernetes_raw_thumbprint.stdout).group(1).replace(':', '')
    
    # Remove certificate after use
    logging.debug(f"Deleting temporary file 'cert.pem'.")
    os.remove("cert.pem")

    logging.debug(f"Kubernetes Thumbprint: {kubernetes_thumbprint}")
    logging.debug(f"Key Vault Thumbprint: {key_vault_thumbprint}")
    
    if kubernetes_thumbprint != key_vault_thumbprint:
        return True
    else:
        return False

def create_pfx(cert_data, key_data, cert_name):
    with open("cert.pem", "wb") as cert_file, open("key.pem", "wb") as key_file:
        cert_file.write(cert_data)
        key_file.write(key_data)

    # Generate the PFX file
    subprocess.check_output([
        "openssl", "pkcs12", "-export",
        "-in", "cert.pem",
        "-inkey", "key.pem",
        "-out", f"{cert_name}.pfx",
        "-passout", "pass:"
    ])

    return f"{cert_name}.pfx"

def load_initial_state():
    try:
        k8s_client.list_secret_for_all_namespaces()
        logging.info("Connection to Kubernetes successful.")
        logging.info("Detected Secrets:")
        secrets = k8s_client.list_secret_for_all_namespaces()
        for secret in secrets.items:
            annotations = secret.metadata.annotations
            if annotations and filter_annotation in annotations:
                logging.info(f"- '{secret.metadata.name}' in namespace '{secret.metadata.namespace}'")

    except Exception as e:
        logging.error(f"Failed to load Secrets from Kubernetes: {str(e)}")

    try:
        certificate_client.list_properties_of_certificates()
    except Exception as e:
        logging.error(f"Failed to load Certificates from Key Vault: {str(e)}")

def create_key_vault_certificate(cert_name, namespace, cert_data, key_data):
    pfx_file = create_pfx(cert_data, key_data, cert_name)

    try:
        with open(pfx_file, "rb") as f:
            pfx_cert_bytes = f.read()
        
        logging.info(f"Writing Secret {cert_name} from namespace '{namespace}' to Key Vault '{key_vault_name}'.")
        imported_pfx_cert = certificate_client.import_certificate(certificate_name=cert_name, certificate_bytes=pfx_cert_bytes, tags={"SyncFrom": "cert-manager-key-vault-sync", "namespace": namespace})
        logging.info(f"PFX certificate '{imported_pfx_cert.name}' imported successfully.")

    except Exception as e:
        error = f"Failed to sync Secret {cert_name} from namespace '{namespace}' to Key Vault '{key_vault_name}': {str(e)}"
        logging.error(error)
    
    finally:
        logging.debug(f"Deleting temporary certificate files.")
        os.remove(pfx_file)
        os.remove("key.pem")
        os.remove("cert.pem")

def sync_k8s_secrets_to_key_vault():
    secrets = k8s_client.list_secret_for_all_namespaces()
    for secret in secrets.items:
        annotations = secret.metadata.annotations
        if annotations and filter_annotation in annotations:
            cert_name = annotations[filter_annotation]
            namespace = secret.metadata.namespace

            # Extract certificate data
            cert_data = base64.b64decode(secret.data['tls.crt'])
            key_data = base64.b64decode(secret.data['tls.key'])

            # Check if the certificate exists in Key Vault
            certificate_exists = True
            
            try:
                if use_namespaces is True:
                    certificate_client.get_certificate(f"{namespace}-{cert_name}")
                else:
                    certificate_client.get_certificate(cert_name)
            except ResourceNotFoundError as e:
                certificate_exists = False
            
            if certificate_exists is False:
                if use_namespaces is True:
                    logging.info(f"Key Vault Certificate '{namespace}-{cert_name}' does not exist. Creating it.")
                    create_key_vault_certificate(f"{namespace}-{cert_name}", namespace, cert_data, key_data)
                else:
                    logging.info(f"Key Vault Certificate '{cert_name}' does not exist. Creating it.")
                    create_key_vault_certificate(cert_name, namespace, cert_data, key_data)
            elif use_namespaces is True and compare_thumbprint(cert_data, certificate_client.get_certificate(f"{namespace}-{cert_name}").properties.x509_thumbprint.hex().upper().replace('X', 'x')):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{namespace}-{cert_name}'. Updating it.")
                create_key_vault_certificate(f"{namespace}-{cert_name}", namespace, cert_data, key_data)
            elif use_namespaces is False and compare_thumbprint(cert_data, certificate_client.get_certificate(cert_name).properties.x509_thumbprint.hex().upper().replace('X', 'x')):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{cert_name}'. Updating it.")
                create_key_vault_certificate(cert_name, namespace, cert_data, key_data)
            else:
                if use_namespaces is True:
                    logging.debug(f"Key Vault Certificate '{namespace}-{cert_name}' is up-to-date.")
                else:
                    logging.debug(f"Key Vault Certificate '{cert_name}' is up-to-date.")

def main():
    logging.info("Starting cert-manager-key-vault-sync process.")
    load_initial_state()
    
    # Loop to synchronize Kubernetes secrets to Key Vault
    while True:
        sync_k8s_secrets_to_key_vault()
        logging.debug(f"Waiting for {check_interval} seconds.")
        time.sleep(check_interval)

if __name__ == "__main__":
    main()
