#!/usr/bin/env bash
# Generate a self-signed TLS certificate and private key for the TAPP gRPC server.
# Usage: ./scripts/gen-tls-cert.sh [output_dir]
#
# Default output directory: /etc/tapp/tls
# The script creates:
#   server.crt  — PEM-encoded X.509 certificate (valid 365 days)
#   server.key  — PEM-encoded RSA private key (4096-bit)

set -euo pipefail

OUTPUT_DIR="${1:-/etc/tapp/tls}"

mkdir -p "$OUTPUT_DIR"

CERT_FILE="$OUTPUT_DIR/server.crt"
KEY_FILE="$OUTPUT_DIR/server.key"

echo "Generating self-signed TLS certificate..."
echo "  Output directory: $OUTPUT_DIR"

openssl req -x509 -newkey rsa:4096 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -nodes \
    -subj "/CN=tapp-server/O=0G-TAPP/OU=TEE" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo "Done."
echo "  Certificate: $CERT_FILE"
echo "  Private key: $KEY_FILE"
echo ""
echo "Add these to your config.toml:"
echo "  tls_enabled = true"
echo "  tls_cert_path = \"$CERT_FILE\""
echo "  tls_key_path  = \"$KEY_FILE\""
