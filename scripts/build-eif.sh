#!/usr/bin/env bash
# Build a Nitro Enclave Image Format (EIF) from the AWS Docker image
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_TAG="${1:-tapp:aws}"
OUTPUT="${2:-tapp.eif}"

echo "=== Building AWS Docker image ==="
docker build \
    --build-arg TARGET=aws \
    -f "${PROJECT_DIR}/Dockerfile.multi" \
    -t "${IMAGE_TAG}" \
    "${PROJECT_DIR}"

echo "=== Building EIF ==="
nitro-cli build-enclave \
    --docker-uri "${IMAGE_TAG}" \
    --output-file "${OUTPUT}"

echo "=== EIF built successfully ==="
echo "Output: ${OUTPUT}"
echo ""
echo "PCR values:"
nitro-cli describe-eif --eif-path "${OUTPUT}" 2>/dev/null || echo "(install nitro-cli to view PCR values)"
