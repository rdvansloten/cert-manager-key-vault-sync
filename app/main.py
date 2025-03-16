import os
import base64
import re
import time
import logging
import subprocess
import json
import requests
import threading
import fnmatch

from packaging import version
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.core.exceptions import ResourceNotFoundError, ServiceRequestError
from kubernetes import client, config

# Prometheus metrics
from prometheus_client import start_http_server, Counter, Histogram

# Configure logging
logging.basicConfig(level=getattr(logging, os.getenv("DEFAULT_LOGGING_LEVEL", "INFO")), format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('azure').setLevel(getattr(logging, os.getenv("AZURE_LOGGING_LEVEL", "WARNING")))

# Prometheus Metrics Definitions
sync_total = Counter('sync_total', 'Total number of sync cycles attempted')
sync_success_total = Counter('sync_success_total', 'Total number of successful sync cycles')
sync_error_total = Counter('sync_error_total', 'Total number of sync cycles with errors')
sync_duration_seconds = Histogram('sync_duration_seconds', 'Time spent in sync cycles (seconds)')

# New metric: track certificate sync operations with certificate name and namespace as labels
certificate_sync_total = Counter(
    'certificate_sync_total',
    'Total number of certificate sync operations attempted',
    ['certificate', 'namespace']
)

# Set variables
key_vault_name = os.getenv("AZURE_KEY_VAULT_NAME")
key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
use_namespaces = os.getenv("USE_NAMESPACES") in ("true", "1", "yes", "enabled")
check_interval = int(os.getenv("CHECK_INTERVAL", 300))
filter_annotation = os.getenv("ANNOTATION", "cert-manager.io/certificate-name")
certificate_name_filter = os.getenv("CERT_NAME_FILTER", "*")

# Set version check information
github_repository_owner = os.getenv("GITHUB_REPO_OWNER", "rdvansloten")
github_repository_name = os.getenv("GITHUB_REPO_NAME", "cert-manager-key-vault-sync")
version_check_interval = os.getenv("VERSION_CHECK_INTERVAL", "86400")
current_version = "v1.2.0"
check_version = os.getenv("CHECK_VERSION", "true").lower()

# Logging credentials initialization
logging.info(f"Using Key Vault: {key_vault_name}")
logging.info(f"Using Key Vault URI: {key_vault_uri}")
logging.info(f"Using Namespace separation: {use_namespaces}")

# Initialize Key Vault client
try:
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False, additionally_allowed_tenants="*")
    certificate_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

    # List installed certificates
    logging.debug("Detected Key Vault Certificates:")
    certificate_client.list_properties_of_certificates(max_page_size=1)
    for cert in certificate_client.list_properties_of_certificates():
        logging.debug(f"- {cert.name}")

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
    logging.debug("Deleting temporary file 'cert.pem'.")
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
        logging.debug("Detected Secrets:")
        secrets = k8s_client.list_secret_for_all_namespaces()
        for secret in secrets.items:
            annotations = secret.metadata.annotations
            if annotations and filter_annotation in annotations:
                logging.debug(f"- '{secret.metadata.name}' in namespace '{secret.metadata.namespace}'")

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
        imported_pfx_cert = certificate_client.import_certificate(
            certificate_name=cert_name,
            certificate_bytes=pfx_cert_bytes,
            tags={"SyncFrom": "cert-manager-key-vault-sync", "namespace": namespace}
        )
        logging.info(f"PFX certificate '{imported_pfx_cert.name}' imported successfully.")

    except Exception as e:
        error = f"Failed to sync Secret {cert_name} from namespace '{namespace}' to Key Vault '{key_vault_name}': {str(e)}"
        logging.error(error)
    
    finally:
        logging.debug("Deleting temporary certificate files.")
        os.remove(pfx_file)
        os.remove("key.pem")
        os.remove("cert.pem")

def sync_k8s_secrets_to_key_vault():
    response = k8s_client.list_secret_for_all_namespaces(_preload_content=False)

    # Parse JSON response
    secrets_data = json.loads(response.data.decode('utf-8'))

    if not secrets_data.get('items'):
        logging.warning("No Kubernetes secrets found with the required annotations.")

    for secret in secrets_data.get('items', []):
        metadata = secret.get('metadata', {})
        annotations = metadata.get('annotations', {})

        if annotations and filter_annotation in annotations:
            cert_name = annotations[filter_annotation]
            namespace = metadata.get('namespace')

            # Apply certificate name filter using wildcard pattern
            if not fnmatch.fnmatch(cert_name, certificate_name_filter):
                logging.debug(f"Skipping certificate '{cert_name}' as it does not match filter '{certificate_name_filter}'")
                continue

            # Extract certificate data
            secret_data = secret.get('data', {})
            cert_data = base64.b64decode(secret_data.get('tls.crt', ''))
            key_data = base64.b64decode(secret_data.get('tls.key', ''))

            # Check if the certificate exists in Key Vault
            certificate_exists = True

            try:
                if use_namespaces:
                    certificate_client.get_certificate(f"{namespace}-{cert_name}")
                else:
                    certificate_client.get_certificate(cert_name)
            except ResourceNotFoundError:
                certificate_exists = False

            if not certificate_exists:
                if use_namespaces:
                    logging.info(f"Key Vault Certificate '{namespace}-{cert_name}' does not exist. Creating it.")
                    certificate_sync_total.labels(certificate=f"{namespace}-{cert_name}", namespace=namespace).inc()
                    create_key_vault_certificate(f"{namespace}-{cert_name}", namespace, cert_data, key_data)
                else:
                    logging.info(f"Key Vault Certificate '{cert_name}' does not exist. Creating it.")
                    certificate_sync_total.labels(certificate=cert_name, namespace=namespace).inc()
                    create_key_vault_certificate(cert_name, namespace, cert_data, key_data)
            elif use_namespaces and compare_thumbprint(cert_data, certificate_client.get_certificate(f"{namespace}-{cert_name}").properties.x509_thumbprint.hex().upper().replace('X', 'x')):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{namespace}-{cert_name}'. Updating it.")
                certificate_sync_total.labels(certificate=f"{namespace}-{cert_name}", namespace=namespace).inc()
                create_key_vault_certificate(f"{namespace}-{cert_name}", namespace, cert_data, key_data)
            elif not use_namespaces and compare_thumbprint(cert_data, certificate_client.get_certificate(cert_name).properties.x509_thumbprint.hex().upper().replace('X', 'x')):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{cert_name}'. Updating it.")
                certificate_sync_total.labels(certificate=cert_name, namespace=namespace).inc()
                create_key_vault_certificate(cert_name, namespace, cert_data, key_data)
            else:
                if use_namespaces:
                    logging.debug(f"Key Vault Certificate '{namespace}-{cert_name}' is up-to-date.")
                else:
                    logging.debug(f"Key Vault Certificate '{cert_name}' is up-to-date.")

def check_for_new_version():
    """Checks GitHub for a new release version and logs a warning if a newer version is available."""
    if check_version in ("false", "0", "no", "disabled"):
        logging.info("Version check is disabled.")
        return

    try:
        url = f"https://api.github.com/repos/{github_repository_owner}/{github_repository_name}/releases/latest"
        response = requests.get(url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=10)

        if response.status_code == 200:
            latest_version = response.json().get("tag_name", "").strip()

            # Remove the 'v' prefix if present
            latest_version_clean = latest_version.lstrip("v")
            current_version_clean = current_version.lstrip("v")

            # Compare versions correctly
            if latest_version_clean and version.parse(latest_version_clean) > version.parse(current_version_clean):
                logging.warning(f"A new version {latest_version} is available! (Current: {current_version})")
            else:
                logging.info(f"Running the latest version: {current_version}")
        else:
            logging.error(f"Failed to check latest version: {response.status_code} for {url} - {response.text}")

    except Exception as e:
        logging.error(f"Error checking for updates: {e}")

def schedule_version_check():
    """Runs the version check once at startup and every 24 hours in the background."""
    check_for_new_version()

    def periodic_check():
        while True:
            time.sleep(int(version_check_interval))
            check_for_new_version()

    # Start background thread for daily version check
    version_check_thread = threading.Thread(target=periodic_check, daemon=True)
    version_check_thread.start()

def main():
    logging.info("Starting cert-manager-key-vault-sync process.")
    schedule_version_check()
    load_initial_state()

    # Start Prometheus metrics server on port 8000
    start_http_server(8000)
    logging.info("Prometheus metrics server started on port 8000")

    # Loop to synchronize Kubernetes secrets to Key Vault with metrics instrumentation
    while True:
        sync_total.inc()
        sync_start = time.time()
        try:
            sync_k8s_secrets_to_key_vault()
            sync_success_total.inc()
        except Exception as e:
            sync_error_total.inc()
            logging.error(f"Error during sync: {str(e)}")
        finally:
            duration = time.time() - sync_start
            sync_duration_seconds.observe(duration)
            logging.debug(f"Sync cycle duration: {duration} seconds.")
        logging.debug(f"Waiting for {check_interval} seconds.")
        time.sleep(check_interval)

if __name__ == "__main__":
    main()
