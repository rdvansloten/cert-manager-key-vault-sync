#!/usr/bin/env python3
import os
import base64
import re
import time
import json
import fnmatch
import logging
import subprocess
import threading
import datetime
import requests
from packaging import version
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.core.exceptions import ResourceNotFoundError, ServiceRequestError
from kubernetes import client, config
from prometheus_client import start_http_server, Counter, Histogram

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("DEFAULT_LOGGING_LEVEL", "INFO")),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.getLogger("azure").setLevel(getattr(logging, os.getenv("AZURE_LOGGING_LEVEL", "WARNING")))

# Prometheus metrics definitions
sync_total = Counter("sync_total", "Total number of sync cycles attempted")
sync_success_total = Counter("sync_success_total", "Total number of successful sync cycles")
sync_error_total = Counter("sync_error_total", "Total number of sync cycles with errors")
sync_duration_seconds = Histogram("sync_duration_seconds", "Time spent in sync cycles (seconds)")
certificate_sync_total = Counter("certificate_sync_total", "Total number of certificate sync operations attempted", ["certificate", "namespace"])

# Set application variables
key_vault_name = os.getenv("AZURE_KEY_VAULT_NAME")
key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
use_namespaces = os.getenv("USE_NAMESPACES", "false").lower() in ("true", "1", "yes", "enabled")
check_interval = int(os.getenv("CHECK_INTERVAL", 300))
filter_annotation = os.getenv("ANNOTATION", "cert-manager.io/certificate-name")
certificate_name_filter = os.getenv("CERT_NAME_FILTER", "*")

# GitHub version check variables
github_repository_owner = os.getenv("GITHUB_REPO_OWNER", "rdvansloten")
github_repository_name = os.getenv("GITHUB_REPO_NAME", "cert-manager-key-vault-sync")
version_check_interval = os.getenv("VERSION_CHECK_INTERVAL", "86400")
current_version = "v1.2.0"
check_version = os.getenv("CHECK_VERSION", "true").lower()

# Leader election variables
lease_name = os.getenv("LEADER_ELECTION_LEASE_NAME", "cert-manager-key-vault-sync-leader")
lease_namespace = os.getenv("POD_NAMESPACE", "cert-manager-key-vault-sync")
lease_duration_seconds = int(os.getenv("LEASE_DURATION_SECONDS", 60))
renew_interval_seconds = int(os.getenv("RENEW_INTERVAL_SECONDS", 60))
pod_name = os.getenv("POD_NAME", "unknown")
leader_active = True

logging.info("Starting cert-manager-key-vault-sync operator.")
logging.info(f"Current version: {current_version}")
logging.info(f"Using Key Vault: {key_vault_uri}")
logging.info(f"Using Namespace separation: {str(use_namespaces).lower()}")
logging.info(f"Using certificate name filter: {certificate_name_filter}")
logging.info(f"Using annotation filter: {filter_annotation}")
logging.info(f"Using version check interval: {version_check_interval}")
logging.info(f"Using GitHub version check: {check_version}")

# Initialize Key Vault client
try:
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False, additionally_allowed_tenants="*")
    certificate_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

    logging.info("Detected Key Vault Certificates:")
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

# Initialize Kubernetes client (in-cluster config)
config.load_incluster_config()
k8s_client = client.CoreV1Api()


# Leader election functions
def get_lease(api):
    try:
        lease = api.read_namespaced_lease(lease_name, lease_namespace)
        return lease
    except client.exceptions.ApiException as e:
        if e.status == 404:
            return None
        else:
            raise


def create_lease(api):
    now = datetime.datetime.now(datetime.timezone.utc)
    lease = client.V1Lease(
        metadata=client.V1ObjectMeta(
            name=lease_name,
            namespace=lease_namespace,
        ),
        spec=client.V1LeaseSpec(holder_identity=pod_name, acquire_time=now, renew_time=now, lease_duration_seconds=lease_duration_seconds),
    )
    try:
        created = api.create_namespaced_lease(lease_namespace, lease)
        logging.info(f"[{pod_name}] Created lease; acquired leadership.")
        return created
    except client.exceptions.ApiException as e:
        logging.error(f"[{pod_name}] Error creating lease: {e}")
        return None


def try_acquire_leadership(api):
    now = datetime.datetime.now(datetime.timezone.utc)
    lease = get_lease(api)
    if lease is None:
        lease = create_lease(api)
        if lease is not None:
            return True
        else:
            return False

    spec = lease.spec
    if spec.renew_time is None:
        expired = True
    else:
        last_renew = spec.renew_time
        if isinstance(last_renew, str):
            last_renew = datetime.datetime.fromisoformat(last_renew.replace("Z", "+00:00"))
        expired = (now - last_renew).total_seconds() > spec.lease_duration_seconds

    if spec.holder_identity == pod_name or expired:
        lease.spec.holder_identity = pod_name
        lease.spec.acquire_time = now
        lease.spec.renew_time = now
        lease.spec.lease_duration_seconds = lease_duration_seconds
        try:
            api.replace_namespaced_lease(lease_name, lease_namespace, lease)
            logging.info(f"[{pod_name}] Acquired/renewed leadership.")
            return True
        except client.exceptions.ApiException as e:
            logging.error(f"[{pod_name}] Failed to update lease: {e}")
            return False
    else:
        logging.debug(f"[{pod_name}] Leadership held by {spec.holder_identity}.")
        return False


def renew_leadership(api):
    global leader_active
    while leader_active:
        time.sleep(renew_interval_seconds)
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            lease = get_lease(api)
            if lease is None:
                logging.error(f"[{pod_name}] Lease not found.")
                leader_active = False
                break
            if lease.spec.holder_identity != pod_name:
                logging.error(f"[{pod_name}] Leadership lost (current leader: {lease.spec.holder_identity}).")
                leader_active = False
                break
            lease.spec.renew_time = now
            api.replace_namespaced_lease(lease_name, lease_namespace, lease)
            logging.info(f"[{pod_name}] Renewed leadership at {now.isoformat()}.")
        except client.exceptions.ApiException as e:
            logging.error(f"[{pod_name}] Error renewing lease: {e}")
            leader_active = False
            break


# Compares the thumbprint from a Kubernetes certificate with the one from Key Vault.
def compare_thumbprint(kubernetes_cert, key_vault_thumbprint):
    with open("cert.pem", "wb") as cert_file:
        cert_file.write(kubernetes_cert)

    kubernetes_raw_thumbprint = subprocess.run(
        ["openssl", "x509", "-in", "cert.pem", "-noout", "-fingerprint"],
        capture_output=True,
        text=True,
    )
    kubernetes_thumbprint = re.search(r"Fingerprint=([\dA-F:]+)", kubernetes_raw_thumbprint.stdout).group(1).replace(":", "")

    logging.debug("Deleting temporary file 'cert.pem'.")
    os.remove("cert.pem")

    logging.debug(f"Kubernetes Thumbprint: {kubernetes_thumbprint}")
    logging.debug(f"Key Vault Thumbprint: {key_vault_thumbprint}")

    return kubernetes_thumbprint != key_vault_thumbprint


# Creates a PFX file using the provided certificate and key data.
def create_pfx(cert_data, key_data, cert_name):
    with open("cert.pem", "wb") as cert_file, open("key.pem", "wb") as key_file:
        cert_file.write(cert_data)
        key_file.write(key_data)

    subprocess.check_output(
        [
            "openssl",
            "pkcs12",
            "-export",
            "-in",
            "cert.pem",
            "-inkey",
            "key.pem",
            "-out",
            f"{cert_name}.pfx",
            "-passout",
            "pass:",
        ]
    )
    return f"{cert_name}.pfx"


# Loads the initial state from Kubernetes and Key Vault, just a quick check.
def load_initial_state():
    try:
        secrets = k8s_client.list_secret_for_all_namespaces()
        logging.info("Connection to Kubernetes successful.")
        logging.info("Detected Secrets:")
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


# Creates or updates a certificate in Key Vault from the given secret data.
def create_key_vault_certificate(cert_name, namespace, cert_data, key_data):
    pfx_file = create_pfx(cert_data, key_data, cert_name)
    try:
        with open(pfx_file, "rb") as f:
            pfx_cert_bytes = f.read()

        logging.info(f"Writing Secret {cert_name} from namespace '{namespace}' to Key Vault '{key_vault_name}'.")
        imported_pfx_cert = certificate_client.import_certificate(
            certificate_name=cert_name,
            certificate_bytes=pfx_cert_bytes,
            tags={"SyncFrom": "cert-manager-key-vault-sync", "namespace": namespace},
        )
        logging.info(f"PFX certificate '{imported_pfx_cert.name}' imported successfully.")
    except Exception as e:
        logging.error(f"Failed to sync Secret {cert_name} from namespace '{namespace}' to Key Vault '{key_vault_name}': {str(e)}")
    finally:
        logging.debug("Deleting temporary certificate files.")
        os.remove(pfx_file)
        os.remove("key.pem")
        os.remove("cert.pem")


# Syncs Kubernetes secrets to Key Vault by checking for new or updated certificates.
def sync_k8s_secrets_to_key_vault():
    response = k8s_client.list_secret_for_all_namespaces(_preload_content=False)
    secrets_data = json.loads(response.data.decode("utf-8"))

    if not secrets_data.get("items"):
        logging.warning("No Kubernetes secrets found with the required annotations.")

    for secret in secrets_data.get("items", []):
        metadata = secret.get("metadata", {})
        annotations = metadata.get("annotations", {})

        if annotations and filter_annotation in annotations:
            cert_name = annotations[filter_annotation]
            namespace = metadata.get("namespace")

            if not fnmatch.fnmatch(cert_name, certificate_name_filter):
                logging.debug(f"Skipping certificate '{cert_name}' as it does not match filter '{certificate_name_filter}'")
                continue

            secret_data = secret.get("data", {})
            cert_data = base64.b64decode(secret_data.get("tls.crt", ""))
            key_data = base64.b64decode(secret_data.get("tls.key", ""))

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
            elif use_namespaces and compare_thumbprint(
                cert_data,
                certificate_client.get_certificate(f"{namespace}-{cert_name}").properties.x509_thumbprint.hex().upper().replace("X", "x"),
            ):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{namespace}-{cert_name}'. Updating it.")
                certificate_sync_total.labels(certificate=f"{namespace}-{cert_name}", namespace=namespace).inc()
                create_key_vault_certificate(f"{namespace}-{cert_name}", namespace, cert_data, key_data)
            elif not use_namespaces and compare_thumbprint(
                cert_data,
                certificate_client.get_certificate(cert_name).properties.x509_thumbprint.hex().upper().replace("X", "x"),
            ):
                logging.info(f"Thumbprint mismatch for Key Vault Certificate '{cert_name}'. Updating it.")
                certificate_sync_total.labels(certificate=cert_name, namespace=namespace).inc()
                create_key_vault_certificate(cert_name, namespace, cert_data, key_data)
            else:
                if use_namespaces:
                    logging.debug(f"Key Vault Certificate '{namespace}-{cert_name}' is up-to-date.")
                else:
                    logging.debug(f"Key Vault Certificate '{cert_name}' is up-to-date.")


# Checks GitHub for a newer version of the operator and logs a warning if one is found.
def check_for_new_version():
    if check_version in ("false", "0", "no", "disabled"):
        logging.info("Version check is disabled.")
        return

    try:
        url = f"https://api.github.com/repos/{github_repository_owner}/{github_repository_name}/releases/latest"
        response = requests.get(url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=10)

        if response.status_code == 200:
            latest_version = response.json().get("tag_name", "").strip()
            latest_version_clean = latest_version.lstrip("v")
            current_version_clean = current_version.lstrip("v")

            if latest_version_clean and version.parse(latest_version_clean) > version.parse(current_version_clean):
                logging.warning(f"A new version {latest_version} is available! (Current: {current_version})")
            else:
                logging.info(f"Running the latest version: {current_version}")
        else:
            logging.error(f"Failed to check latest version: {response.status_code} for {url} - {response.text}")

    except Exception as e:
        logging.error(f"Error checking for updates: {e}")


def schedule_version_check():
    check_for_new_version()

    def periodic_check():
        while True:
            time.sleep(int(version_check_interval))
            check_for_new_version()

    version_check_thread = threading.Thread(target=periodic_check, daemon=True)
    version_check_thread.start()


def main():
    global leader_active
    logging.info("Starting cert-manager-key-vault-sync process.")
    schedule_version_check()
    load_initial_state()

    # Start Prometheus metrics server on port 8000
    start_http_server(8000)
    logging.info("Prometheus metrics server started on port 8000")

    coordination_api = client.CoordinationV1Api()
    while True:
        if try_acquire_leadership(coordination_api):
            threading.Thread(target=renew_leadership, args=(coordination_api,), daemon=True).start()
            logging.info(f"Acquired leadership as {pod_name}. Starting sync loop.")
            break
        else:
            logging.debug(f"Not the leader, retrying in {renew_interval_seconds} seconds.")
            time.sleep(renew_interval_seconds)

    # Only run the following if this replica is the leader.
    while leader_active:
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

    logging.error("Leadership lost, exiting process.")
    exit(1)


if __name__ == "__main__":
    main()
