#!/bin/bash

NUM_CERTS=10
CERT_DIR="./.certs"
OUTPUT_DIR="./.secrets"
DAYS_VALID=365

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --count) NUM_CERTS="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Ensures directories exist
mkdir -p "$CERT_DIR"
mkdir -p "$OUTPUT_DIR"

# Detects Mac or Linux for base64 compatibility
if base64 --help 2>&1 | grep -q "wrap"; then
    BASE64_CMD="base64 --wrap=0"
else
    BASE64_CMD="base64 | tr -d '\n'"
fi

# Generates a random lowercase alphanumeric string (8 characters)
generate_random_name() {
    cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | head -c 8
}

# Generate self-signed certificates and create Kubernetes Secrets
for i in $(seq 1 $NUM_CERTS); do
    CERT_NAME="cert-$(generate_random_name)"
    KEY_FILE="$CERT_DIR/$CERT_NAME.key"
    CRT_FILE="$CERT_DIR/$CERT_NAME.crt"
    SECRET_FILE="$OUTPUT_DIR/$CERT_NAME-secret.yaml"

    echo "Generating self-signed certificate: $CERT_NAME"

    # Generates a private key
    openssl genrsa -out "$KEY_FILE" 2048

    # Generates a self-signed certificate
    openssl req -new -x509 -key "$KEY_FILE" -out "$CRT_FILE" -days "$DAYS_VALID" -subj "/CN=$CERT_NAME"

    # Encodes certificate and key in base64
    TLS_KEY_B64=$(cat "$KEY_FILE" | eval $BASE64_CMD)
    TLS_CRT_B64=$(cat "$CRT_FILE" | eval $BASE64_CMD)

    # Creates Kubernetes Secret
    cat <<EOF > "$SECRET_FILE"
apiVersion: v1
kind: Secret
metadata:
  name: $CERT_NAME
  annotations:
    cert-manager.io/alt-names: ""
    cert-manager.io/certificate-name: "$CERT_NAME"
    cert-manager.io/common-name: "$CERT_NAME"
    cert-manager.io/ip-sans: ""
    cert-manager.io/issuer-kind: "Issuer"
    cert-manager.io/issuer-name: "selfsigned-issuer"
    cert-manager.io/uri-sans: ""
type: kubernetes.io/tls
data:
  tls.crt: $TLS_CRT_B64
  tls.key: $TLS_KEY_B64
EOF

    echo "Created Kubernetes Secret: $SECRET_FILE"
done

echo "All certificates and Secrets have been successfully generated!"
