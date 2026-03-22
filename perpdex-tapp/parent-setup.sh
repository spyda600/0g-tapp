#!/usr/bin/env bash
# parent-setup.sh - Parent EC2 setup for PerpDex TAPP deployment
# Run this on the parent EC2 instance to expose port 3000 and verify proxy.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

API_PORT="${API_PORT:-3000}"

# ---------------------------------------------------------------------------
# 1. Open port 3000 in iptables
# ---------------------------------------------------------------------------
setup_iptables() {
    log "Checking iptables rules for port ${API_PORT} ..."

    if sudo iptables -C INPUT -p tcp --dport "${API_PORT}" -j ACCEPT 2>/dev/null; then
        log "iptables rule for port ${API_PORT} already exists."
    else
        log "Adding iptables rule to allow TCP port ${API_PORT} ..."
        sudo iptables -A INPUT -p tcp --dport "${API_PORT}" -j ACCEPT
        log "iptables rule added."
    fi

    # Also ensure FORWARD chain allows traffic to Docker containers
    if sudo iptables -C FORWARD -p tcp --dport "${API_PORT}" -j ACCEPT 2>/dev/null; then
        log "FORWARD rule for port ${API_PORT} already exists."
    else
        sudo iptables -A FORWARD -p tcp --dport "${API_PORT}" -j ACCEPT
        log "FORWARD rule for port ${API_PORT} added."
    fi
}

# ---------------------------------------------------------------------------
# 2. Start socat bridge (if Docker port mapping is not directly reachable)
# ---------------------------------------------------------------------------
setup_socat_bridge() {
    # Docker compose with port mapping "3000:3000" should expose the port
    # directly on the host. socat is only needed if there is NAT or routing
    # complexity between the host NIC and Docker bridge.

    if command -v socat &>/dev/null; then
        # Check if socat is already bridging this port
        if pgrep -f "socat.*TCP-LISTEN:${API_PORT}" >/dev/null 2>&1; then
            log "socat bridge for port ${API_PORT} is already running."
        else
            warn "Starting socat bridge: external :${API_PORT} -> 127.0.0.1:${API_PORT}"
            nohup socat TCP-LISTEN:${API_PORT},fork,reuseaddr TCP:127.0.0.1:${API_PORT} \
                >/var/log/perpdex-socat.log 2>&1 &
            log "socat bridge started (PID: $!)."
        fi
    else
        warn "socat not installed. If Docker port mapping works directly, this is fine."
        warn "Install with: sudo yum install -y socat  (or apt-get install socat)"
    fi
}

# ---------------------------------------------------------------------------
# 3. Verify docker-proxy-parent.py is running (for Nitro enclave deployments)
# ---------------------------------------------------------------------------
verify_docker_proxy() {
    log "Checking for docker-proxy-parent.py ..."

    if pgrep -f "docker-proxy-parent" >/dev/null 2>&1; then
        log "docker-proxy-parent.py is running."
        pgrep -af "docker-proxy-parent"
    else
        warn "docker-proxy-parent.py is NOT running."
        warn "If this is a Nitro Enclave deployment, start it with:"
        warn "  python3 /opt/tapp/docker-proxy-parent.py &"
    fi
}

# ---------------------------------------------------------------------------
# 4. Verify Docker is accessible and containers are running
# ---------------------------------------------------------------------------
verify_docker() {
    log "Checking Docker status ..."

    if ! command -v docker &>/dev/null; then
        error "Docker not found on PATH."
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running or not accessible."
        exit 1
    fi

    log "Docker is running. Current PerpDex containers:"
    docker ps --filter "label=com.docker.compose.project" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 5. Quick connectivity test
# ---------------------------------------------------------------------------
test_connectivity() {
    log "Testing API endpoint connectivity on port ${API_PORT} ..."

    if command -v curl &>/dev/null; then
        if curl -sf --max-time 5 "http://127.0.0.1:${API_PORT}/" >/dev/null 2>&1; then
            log "API service is responding on port ${API_PORT}."
        else
            warn "API service is not yet responding on port ${API_PORT}."
            warn "It may still be starting up. Check with: docker logs <api-service-container>"
        fi
    else
        warn "curl not available; skipping connectivity test."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "=== PerpDex Parent EC2 Setup ==="
setup_iptables
setup_socat_bridge
verify_docker_proxy
verify_docker
test_connectivity
log "=== Setup complete ==="
