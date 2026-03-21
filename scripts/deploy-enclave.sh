#!/usr/bin/env bash
# deploy-enclave.sh — Production deployment of TAPP Nitro Enclave
#
# Builds the Docker image, creates the EIF, manages allocator memory,
# terminates any running enclave, launches a new one, starts the socat
# proxy, and runs a health check. Idempotent and safe to re-run.
#
# Usage:
#   ./scripts/deploy-enclave.sh              # deploy from local machine via SSH
#   ./scripts/deploy-enclave.sh --local      # run directly on the EC2 instance
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE_IP="3.81.185.0"
SSH_KEY="$HOME/.ssh/tapp-enclave-key.pem"
AWS_PROFILE="0g-labs"

ENCLAVE_CID=5
ENCLAVE_MEMORY_MIB=1024
ENCLAVE_CPUS=2
GRPC_PORT=50051

IMAGE_TAG="tapp:aws"
EIF_FILE="/tmp/tapp.eif"
PCR_FILE="/tmp/tapp-pcr-values.json"

# Allocator memory: low during docker build (needs host RAM), high for enclave
ALLOCATOR_MEM_BUILD_MIB=512
ALLOCATOR_MEM_RUN_MIB=1536  # must be >= ENCLAVE_MEMORY_MIB + overhead

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()    { echo -e "${GREEN}[$(date '+%H:%M:%S')] OK:${NC} $*"; }
warn()  { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*" >&2; }
fail()  { echo -e "${RED}[$(date '+%H:%M:%S')] FAIL:${NC} $*" >&2; exit 1; }

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        warn "Deployment failed (exit code $exit_code). Check output above."
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Remote wrapper — if not --local, SSH into the instance and run there
# ---------------------------------------------------------------------------
if [[ "${1:-}" != "--local" ]]; then
    log "Syncing project to ${INSTANCE_IP}..."
    rsync -az --delete \
        --exclude target/ \
        --exclude .git/ \
        --exclude '.claude/' \
        -e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no" \
        "${PROJECT_DIR}/" \
        "ec2-user@${INSTANCE_IP}:~/0g-tapp/"

    log "Running deployment on remote instance..."
    ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no \
        "ec2-user@${INSTANCE_IP}" \
        "cd ~/0g-tapp && bash scripts/deploy-enclave.sh --local"
    exit $?
fi

# ---------------------------------------------------------------------------
# From here on, we are running on the EC2 instance
# ---------------------------------------------------------------------------

log "=========================================="
log " TAPP Nitro Enclave — Production Deploy"
log "=========================================="

# ---------------------------------------------------------------------------
# Step 0: Preflight checks
# ---------------------------------------------------------------------------
log "Step 0: Preflight checks"

for cmd in docker nitro-cli socat jq; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: ${cmd}"
done

if ! systemctl is-active --quiet nitro-enclaves-allocator 2>/dev/null; then
    fail "nitro-enclaves-allocator service is not running"
fi

if ! systemctl is-active --quiet docker 2>/dev/null; then
    fail "docker service is not running"
fi

ok "All preflight checks passed"

# ---------------------------------------------------------------------------
# Step 1: Reduce allocator memory for Docker build (needs host RAM)
# ---------------------------------------------------------------------------
log "Step 1: Reducing allocator memory for build phase (${ALLOCATOR_MEM_BUILD_MIB} MiB)"

# Terminate any running enclave first so we can change allocator
RUNNING_ENCLAVES=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[].EnclaveID // empty' 2>/dev/null || true)
if [ -n "$RUNNING_ENCLAVES" ]; then
    log "Terminating existing enclave(s) before adjusting allocator..."
    for eid in $RUNNING_ENCLAVES; do
        nitro-cli terminate-enclave --enclave-id "$eid" 2>/dev/null || true
    done
    sleep 2
fi

# Update allocator config for build phase
sudo sed -i "s/^memory_mib:.*/memory_mib: ${ALLOCATOR_MEM_BUILD_MIB}/" \
    /etc/nitro_enclaves/allocator.yaml
sudo systemctl restart nitro-enclaves-allocator
sleep 2

ok "Allocator set to ${ALLOCATOR_MEM_BUILD_MIB} MiB for build phase"

# ---------------------------------------------------------------------------
# Step 2: Build Docker image
# ---------------------------------------------------------------------------
log "Step 2: Building Docker image (${IMAGE_TAG})"

docker build \
    --build-arg TARGET=aws \
    -f "${PROJECT_DIR}/Dockerfile.multi" \
    -t "${IMAGE_TAG}" \
    "${PROJECT_DIR}"

ok "Docker image built: ${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Step 3: Build EIF and capture PCR measurements
# ---------------------------------------------------------------------------
log "Step 3: Building Enclave Image Format (EIF)"

BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri "${IMAGE_TAG}" \
    --output-file "${EIF_FILE}" 2>&1)

echo "$BUILD_OUTPUT"

# Extract PCR values from build output
echo "$BUILD_OUTPUT" | grep -A1 "PCR" > "${PCR_FILE}" 2>/dev/null || true

# Also get structured PCR info
PCR_JSON=$(nitro-cli describe-eif --eif-path "${EIF_FILE}" 2>/dev/null || echo "{}")
echo "$PCR_JSON" > "${PCR_FILE}"

ok "EIF built: ${EIF_FILE}"

# ---------------------------------------------------------------------------
# Step 4: Increase allocator memory for enclave launch
# ---------------------------------------------------------------------------
log "Step 4: Increasing allocator memory for enclave (${ALLOCATOR_MEM_RUN_MIB} MiB)"

sudo sed -i "s/^memory_mib:.*/memory_mib: ${ALLOCATOR_MEM_RUN_MIB}/" \
    /etc/nitro_enclaves/allocator.yaml
sudo systemctl restart nitro-enclaves-allocator
sleep 3

ok "Allocator set to ${ALLOCATOR_MEM_RUN_MIB} MiB for enclave launch"

# ---------------------------------------------------------------------------
# Step 5: Terminate any lingering enclave (idempotent)
# ---------------------------------------------------------------------------
log "Step 5: Cleaning up any existing enclave"

RUNNING_ENCLAVES=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[].EnclaveID // empty' 2>/dev/null || true)
if [ -n "$RUNNING_ENCLAVES" ]; then
    for eid in $RUNNING_ENCLAVES; do
        log "Terminating enclave: ${eid}"
        nitro-cli terminate-enclave --enclave-id "$eid"
    done
    sleep 2
    ok "Existing enclave(s) terminated"
else
    ok "No existing enclaves to terminate"
fi

# ---------------------------------------------------------------------------
# Step 6: Launch enclave (production — no debug-mode)
# ---------------------------------------------------------------------------
log "Step 6: Launching enclave (CID=${ENCLAVE_CID}, ${ENCLAVE_CPUS} CPUs, ${ENCLAVE_MEMORY_MIB} MiB)"

LAUNCH_OUTPUT=$(nitro-cli run-enclave \
    --eif-path "${EIF_FILE}" \
    --cpu-count "${ENCLAVE_CPUS}" \
    --memory "${ENCLAVE_MEMORY_MIB}" \
    --enclave-cid "${ENCLAVE_CID}" 2>&1)

echo "$LAUNCH_OUTPUT"

ENCLAVE_ID=$(echo "$LAUNCH_OUTPUT" | jq -r '.EnclaveID // empty' 2>/dev/null || true)
if [ -z "$ENCLAVE_ID" ]; then
    fail "Enclave failed to start. Output: ${LAUNCH_OUTPUT}"
fi

# Verify enclave is in RUNNING state
sleep 3
ENCLAVE_STATE=$(nitro-cli describe-enclaves | jq -r '.[0].State // empty' 2>/dev/null || true)
if [ "$ENCLAVE_STATE" != "RUNNING" ]; then
    fail "Enclave is not in RUNNING state (got: ${ENCLAVE_STATE})"
fi

ok "Enclave running: ${ENCLAVE_ID}"

# ---------------------------------------------------------------------------
# Step 7: Start socat proxy (kill any existing, then launch)
# ---------------------------------------------------------------------------
log "Step 7: Starting socat proxy (TCP:${GRPC_PORT} <-> vsock:${ENCLAVE_CID}:${GRPC_PORT})"

# Kill any existing socat processes bridging this port
pkill -f "socat.*TCP-LISTEN:${GRPC_PORT}.*vsock-connect:${ENCLAVE_CID}" 2>/dev/null || true
pkill -f "socat.*vsock.*${GRPC_PORT}" 2>/dev/null || true
sleep 1

# Start socat in the background
nohup socat TCP-LISTEN:${GRPC_PORT},reuseaddr,fork \
    VSOCK-CONNECT:${ENCLAVE_CID}:${GRPC_PORT} \
    > /var/log/tapp/socat.log 2>&1 &

SOCAT_PID=$!
sleep 2

# Verify socat is running
if kill -0 "$SOCAT_PID" 2>/dev/null; then
    ok "socat proxy running (PID: ${SOCAT_PID})"
else
    fail "socat proxy failed to start — check /var/log/tapp/socat.log"
fi

# ---------------------------------------------------------------------------
# Step 8: Health check
# ---------------------------------------------------------------------------
log "Step 8: Running health check"

HEALTH_OK=false
for attempt in 1 2 3 4 5; do
    log "Health check attempt ${attempt}/5..."
    sleep 3

    if tapp-cli get-tapp-info --addr "http://127.0.0.1:${GRPC_PORT}" 2>/dev/null; then
        HEALTH_OK=true
        break
    fi

    # Fallback: try without --addr flag in case CLI uses default
    if tapp-cli get-tapp-info 2>/dev/null; then
        HEALTH_OK=true
        break
    fi
done

if [ "$HEALTH_OK" = true ]; then
    ok "Health check passed"
else
    warn "Health check failed after 5 attempts — enclave may still be initializing"
    warn "Try manually: tapp-cli get-tapp-info --addr http://127.0.0.1:${GRPC_PORT}"
fi

# ---------------------------------------------------------------------------
# Step 9: Output summary and PCR values
# ---------------------------------------------------------------------------
echo ""
log "=========================================="
log " Deployment Summary"
log "=========================================="
echo ""
echo "  Enclave ID:  ${ENCLAVE_ID}"
echo "  Enclave CID: ${ENCLAVE_CID}"
echo "  CPUs:        ${ENCLAVE_CPUS}"
echo "  Memory:      ${ENCLAVE_MEMORY_MIB} MiB"
echo "  gRPC:        127.0.0.1:${GRPC_PORT} -> vsock:${ENCLAVE_CID}:${GRPC_PORT}"
echo "  EIF:         ${EIF_FILE}"
echo "  Mode:        PRODUCTION (no debug-mode)"
echo ""

log "PCR Measurements (for attestation verification):"
echo "---"
if [ -f "$PCR_FILE" ]; then
    cat "$PCR_FILE"
else
    nitro-cli describe-eif --eif-path "${EIF_FILE}" 2>/dev/null || echo "  (PCR values unavailable)"
fi
echo "---"
echo ""

log "Useful commands:"
echo "  nitro-cli describe-enclaves"
echo "  tapp-cli get-tapp-info --addr http://127.0.0.1:${GRPC_PORT}"
echo "  tail -f /var/log/tapp/socat.log"
echo ""

ok "Deployment complete"
