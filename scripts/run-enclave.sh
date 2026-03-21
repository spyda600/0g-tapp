#!/usr/bin/env bash
# Run TAPP in a Nitro Enclave
set -euo pipefail

EIF_PATH="${1:-tapp.eif}"
CPU_COUNT="${2:-2}"
MEMORY_MIB="${3:-4096}"
ENCLAVE_CID="${4:-5}"

echo "=== Starting Nitro Enclave ==="
echo "EIF: ${EIF_PATH}"
echo "CPUs: ${CPU_COUNT}"
echo "Memory: ${MEMORY_MIB} MiB"
echo "CID: ${ENCLAVE_CID}"

nitro-cli run-enclave \
    --eif-path "${EIF_PATH}" \
    --cpu-count "${CPU_COUNT}" \
    --memory "${MEMORY_MIB}" \
    --enclave-cid "${ENCLAVE_CID}"

echo ""
echo "=== Enclave started ==="
nitro-cli describe-enclaves

echo ""
echo "To start vsock proxy:"
echo "  vsock-proxy 50051 ${ENCLAVE_CID} 50051 &"
echo ""
echo "To view console (debug mode only):"
echo "  nitro-cli console --enclave-id \$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
