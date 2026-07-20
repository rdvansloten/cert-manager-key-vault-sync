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
check_interval = int(os.getenv("CHECK_INTERVAL", "300"))
filter_annotation = os.getenv("ANNOTATION", "cert-manager.io/certificate-name")
certificate_name_filter = os.getenv("CERT_NAME_FILTER", "*")

_regex_prefix = "regex:"
_certificate_name_regex = None
_certificate_filter_broken = False
if certificate_name_filter.startswith(_regex_prefix):
    _regex_pattern = certificate_name_filter[len(_regex_prefix):]
    try:
        _certificate_name_regex = re.compile(_regex_pattern)
    except re.error as e:
        _certificate_filter_broken = True
        logging.error(
            f"Invalid regex in CERT_NAME_FILTER '{_regex_pattern}': {e}. "
            "No certificates will be synced until this is corrected."
        )


def matches_certificate_filter(name):
    '''Return True if a certificate name passes CERT_NAME_FILTER.'''
    if _certificate_filter_broken:
        return False
    if _certificate_name_regex is not None:
        return bool(_certificate_name_regex.search(name))
    return fnmatch.fnmatch(name, certificate_name_filter)

# GitHub version check variables
github_repository_owner = os.getenv("GITHUB_REPO_OWNER", "rdvansloten")
github_repository_name = os.getenv("GITHUB_REPO_NAME", "cert-manager-key-vault-sync")
version_check_interval = os.getenv("VERSION_CHECK_INTERVAL", "86400")
current_version = "v1.3.0"
check_version = os.getenv("CHECK_VERSION", "true").lower()

# Leader election variables
lease_name = os.getenv("LEADER_ELECTION_LEASE_NAME", "cert-manager-key-vault-sync-leader")
lease_namespace = os.getenv("POD_NAMESPACE", "cert-manager-key-vault-sync")
lease_duration_seconds = int(os.getenv("LEASE_DURATION_SECONDS", "60"))
renew_interval_seconds = int(os.getenv("RENEW_INTERVAL_SECONDS", str(max(1, lease_duration_seconds // 3))))
acquire_retry_seconds = int(os.getenv("ACQUIRE_RETRY_SECONDS", str(renew_interval_seconds)))
pod_name = os.getenv("POD_NAME", "unknown")
leader_active = True

logging.info("Starting cert-manager-key-vault-sync operator.")
logging.info(f"Current version: {current_version}")
logging.info(f"Using Key Vault: {key_vault_uri}")
logging.info(f"Using Namespace separation: {str(use_namespaces).lower()}")
logging.info(f"Using certificate name filter: {certificate_name_filter}")
logging.info("Using annotation filter: %s", filter_annotation)
logging.info(f"Using version check interval: {version_check_interval}")
logging.info(f"Using GitHub version check: {check_version}")

# Initialize Kubernetes client (in-cluster config)
config.load_incluster_config()
k8s_client = client.CoreV1Api()

# Azure credential and Key Vault client will be initialized after leadership is acquired
credential = None
certificate_client = None

def init_key_vault_client():
    '''Initialize the Azure Key Vault client using DefaultAzureCredential.''' 
    global credential, certificate_client
    # Lazy initialization if not already done
    if certificate_client is not None:
        return

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False, additionally_allowed_tenants="*")
    certificate_client = CertificateClient(vault_url=key_vault_uri, credential=credential)

    try:
        logging.info("Detected Key Vault Certificates:")
        for cert in certificate_client.list_properties_of_certificates():
            logging.info(cert.name)

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
        logging.info(f"Pod {pod_name} created lease; acquired leadership.")
        return created
    except client.exceptions.ApiException as e:
        logging.error(f"Pod {pod_name} could not create a lease: {e}")
        return None

def try_acquire_leadership(api):
    now = datetime.datetime.now(datetime.timezone.utc)
    # Fetch current Lease (or None if it doesn’t exist)
    lease = get_lease(api)
    if lease is None:
        # Try to create it (first comers win)
        lease = create_lease(api)
        return True if lease is not None else False

    spec = lease.spec
    # Determine if the existing lease has expired
    if spec.renew_time is None:
        expired = True
    else:
        last_renew = spec.renew_time
        if isinstance(last_renew, str):
            last_renew = datetime.datetime.fromisoformat(last_renew.replace("Z", "+00:00"))
        expired = (now - last_renew).total_seconds() > spec.lease_duration_seconds

    # If we already hold it or it’s expired, try to take it
    if spec.holder_identity == pod_name or expired:
        lease.spec.holder_identity = pod_name
        lease.spec.acquire_time = now
        lease.spec.renew_time = now
        lease.spec.lease_duration_seconds = lease_duration_seconds

        try:
            api.replace_namespaced_lease(lease_name, lease_namespace, lease)
            logging.info(f"Pod {pod_name} acquired/renewed leadership.")
            return True

        except client.exceptions.ApiException as e:
            if e.status == 409:
                # Another pod updated the lease first—just back off
                logging.debug(f"Pod {pod_name} had a lease update conflict; leadership held elsewhere.")
                return False
            else:
                logging.error(f"Pod {pod_name} has failed to update lease: {e}")
                return False

    else:
        # Someone else still holds a valid lease
        logging.debug(f"Leadership held by {spec.holder_identity}.")
        return False

def renew_leadership(api):
    global leader_active
    # Wall-clock time of our last confirmed renewal. If we cannot renew for
    # longer than the lease duration we can no longer assume we are the leader
    # and must step down; a single transient error must not abdicate.
    last_success = time.monotonic()
    while leader_active:
        time.sleep(renew_interval_seconds)
        if not leader_active:
            break
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            lease = get_lease(api)
            if lease is None:
                logging.warning(f"Lease disappeared; Pod {pod_name} is stepping down.")
                leader_active = False
                break
            if lease.spec.holder_identity != pod_name:
                logging.warning(f"Pod {pod_name} no longer holds the lease (current leader: {lease.spec.holder_identity}); stepping down.")
                leader_active = False
                break
            lease.spec.renew_time = now
            lease.spec.lease_duration_seconds = lease_duration_seconds
            api.replace_namespaced_lease(lease_name, lease_namespace, lease)
            last_success = time.monotonic()
            logging.debug(f"Pod {pod_name} renewed leadership at {now.isoformat()}.")
        except client.exceptions.ApiException as e:
            # A 409 means the lease was modified between our read and write.
            if e.status == 409:
                logging.debug(f"Pod {pod_name} hit a lease update conflict; will retry next tick.")
            else:
                logging.warning(f"Pod {pod_name} could not renew lease (will retry): {e.reason}")
            if time.monotonic() - last_success > lease_duration_seconds:
                logging.error(f"Pod {pod_name} failed to renew lease within {lease_duration_seconds}s; stepping down.")
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
        secrets = k8s_client.list_secret_for_all_namespaces(field_selector="type=kubernetes.io/tls")
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
    # Only pull TLS secrets
    response = k8s_client.list_secret_for_all_namespaces(
        field_selector="type=kubernetes.io/tls", _preload_content=False
    )
    secrets_data = json.loads(response.data.decode("utf-8"))

    if not secrets_data.get("items"):
        logging.warning("No Kubernetes secrets found with the required annotations.")

    for secret in secrets_data.get("items", []):
        metadata = secret.get("metadata", {})
        annotations = metadata.get("annotations", {})

        if annotations and filter_annotation in annotations:
            cert_name = annotations[filter_annotation]
            namespace = metadata.get("namespace")

            if not matches_certificate_filter(cert_name):
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


def run_leader_workload(api):
    '''Run the sync loop for as long as this pod holds leadership.

    Returns (rather than exiting the process) when leadership is lost, so the
    caller can drop back to standby and try to re-acquire.
    '''
    init_key_vault_client()
    threading.Thread(target=renew_leadership, args=(api,), daemon=True).start()
    load_initial_state()

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

        # Sleep in small slices so we react promptly when leadership is lost
        # instead of blocking for a full check_interval.
        logging.debug(f"Waiting up to {check_interval} seconds.")
        slept = 0
        while slept < check_interval and leader_active:
            nap = min(5, check_interval - slept)
            time.sleep(nap)
            slept += nap


def main():
    global leader_active
    logging.info("Starting cert-manager-key-vault-sync process.")

    coordination_api = client.CoordinationV1Api()

    start_http_server(8000)
    logging.info("Prometheus metrics server started on port 8000")
    schedule_version_check()

    while True:
        leader_active = False
        while not try_acquire_leadership(coordination_api):
            logging.debug(f"This Pod ({pod_name}) is not the leader, retrying in {acquire_retry_seconds} seconds.")
            time.sleep(acquire_retry_seconds)

        leader_active = True
        logging.info(f"Pod {pod_name} acquired leadership. Starting sync loop.")
        run_leader_workload(coordination_api)
        logging.warning(f"Pod {pod_name} stepped down from leadership; returning to standby.")

if __name__ == "__main__":
    main()
