#!/usr/bin/env bash
# deploy.sh - Build, push, and deploy PerpDex to 0G TAPP
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERPDEX_REPO="${PERPDEX_REPO:-$HOME/Desktop/perpdex-rust-backend}"
REGISTRY="ghcr.io/spyda600"
TAG="${TAG:-testnet}"
TAPP_CLI="${TAPP_CLI:-tapp-cli}"
APP_ID="${APP_ID:-perpdex}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Step 1: Build Docker images
# ---------------------------------------------------------------------------
build_images() {
    log "Building Docker images from ${PERPDEX_REPO} ..."

    local services=("api-service" "settlement-service" "price-oracle")
    for svc in "${services[@]}"; do
        log "  Building ${svc} ..."
        docker build \
            -t "${REGISTRY}/perpdex-${svc}:${TAG}" \
            -f "${PERPDEX_REPO}/${svc}/Dockerfile" \
            "${PERPDEX_REPO}"
    done

    log "All images built successfully."
}

# ---------------------------------------------------------------------------
# Step 2: Push to GHCR
# ---------------------------------------------------------------------------
push_images() {
    log "Pushing images to ${REGISTRY} ..."

    local services=("api-service" "settlement-service" "price-oracle")
    for svc in "${services[@]}"; do
        log "  Pushing perpdex-${svc}:${TAG} ..."
        docker push "${REGISTRY}/perpdex-${svc}:${TAG}"
    done

    log "All images pushed."
}

# ---------------------------------------------------------------------------
# Step 3: Deploy via TAPP CLI
# ---------------------------------------------------------------------------
deploy_tapp() {
    log "Authenticating Docker registry with TAPP ..."
    ${TAPP_CLI} docker-login \
        --registry ghcr.io \
        --username "${GHCR_USERNAME:-spyda600}" \
        --password "${GHCR_TOKEN:?Set GHCR_TOKEN env var with a GitHub PAT}"

    log "Deploying PerpDex app via TAPP StartApp RPC ..."
    ${TAPP_CLI} start-app \
        --app-id "${APP_ID}" \
        --compose-file "${SCRIPT_DIR}/docker-compose.yml" \
        --mount-file "${SCRIPT_DIR}/configs/api-config.toml:./api-config.toml" \
        --mount-file "${SCRIPT_DIR}/configs/settlement-galileo.toml:./settlement-galileo.toml" \
        --mount-file "${SCRIPT_DIR}/configs/price-oracle-default.toml:./price-oracle-default.toml" \
        --mount-file "${SCRIPT_DIR}/configs/init-db.sql:./init-db.sql" \
        --env "JANE_PERPS__CHAIN_CONFIG__PRIVATE_KEY=${JANE_PERPS__CHAIN_CONFIG__PRIVATE_KEY:?Set JANE_PERPS__CHAIN_CONFIG__PRIVATE_KEY env var}"

    log "PerpDex deployment submitted to TAPP."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
usage() {
    echo "Usage: $0 [build|push|deploy|all]"
    echo ""
    echo "Commands:"
    echo "  build   - Build Docker images from perpdex-rust-backend"
    echo "  push    - Push images to GHCR"
    echo "  deploy  - Deploy to TAPP (requires GHCR_TOKEN and JANE_PERPS__CHAIN_CONFIG__PRIVATE_KEY)"
    echo "  all     - Build, push, and deploy (default)"
    echo ""
    echo "Environment variables:"
    echo "  PERPDEX_REPO     - Path to perpdex-rust-backend (default: ~/Desktop/perpdex-rust-backend)"
    echo "  TAG              - Docker image tag (default: testnet)"
    echo "  TAPP_CLI         - Path to tapp-cli binary (default: tapp-cli)"
    echo "  APP_ID           - TAPP application ID (default: perpdex)"
    echo "  GHCR_TOKEN       - GitHub Container Registry PAT (required for push/deploy)"
    echo "  GHCR_USERNAME    - GitHub username (default: spyda600)"
    echo "  JANE_PERPS__CHAIN_CONFIG__PRIVATE_KEY - Settlement service private key (required for deploy)"
}

case "${1:-all}" in
    build)  build_images ;;
    push)   push_images ;;
    deploy) deploy_tapp ;;
    all)
        build_images
        push_images
        deploy_tapp
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
