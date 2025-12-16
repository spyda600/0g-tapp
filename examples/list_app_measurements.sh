#!/bin/bash

# List application measurements from TAPP service
# Usage:
#   ./list_app_measurements.sh [OPTIONS]
#
# Examples:
#   ./list_app_measurements.sh --host 39.97.63.199
#   ./list_app_measurements.sh --host 39.97.63.199 --deployer 0x1234...

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_DEPLOYER_FILTER=""

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
DEPLOYER_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        --deployer)
            DEPLOYER_FILTER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --deployer ADDRESS      Filter by deployer address (optional)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199"
            echo "  $0 --host 39.97.63.199 --deployer 0x1234..."
            echo ""
            echo "Legacy positional format also supported:"
            echo "  $0 HOST PORT DEPLOYER_FILTER"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            # Original order: HOST PORT DEPLOYER_FILTER
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            elif [ -z "$DEPLOYER_FILTER" ]; then
                DEPLOYER_FILTER="$1"
            else
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
            fi
            shift
            ;;
    esac
done

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Quick dependency check
missing_deps=()

if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
fi

if ! command -v jq &> /dev/null; then
    missing_deps+=("jq")
fi

# Check proto file
proto_file="$SCRIPT_DIR/../proto/tapp_service.proto"
if [ ! -f "$proto_file" ]; then
    missing_deps+=("tapp_service.proto")
fi

if [ ${#missing_deps[@]} -gt 0 ]; then
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    echo ""
    for dep in "${missing_deps[@]}"; do
        case "$dep" in
            "grpcurl")
                echo "• grpcurl: https://github.com/fullstorydev/grpcurl/releases"
                ;;
            "jq")
                echo "• jq: https://stedolan.github.io/jq/download/"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
        esac
    done
    exit 1
fi

# Display configuration
echo "======================================"
echo "ListAppMeasurements Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
if [ -n "$DEPLOYER_FILTER" ]; then
    echo "Filter:        Deployer = $DEPLOYER_FILTER"
else
    echo "Filter:        None (list all)"
fi
echo "======================================"
echo ""

# Build request JSON
request_json=$(jq -n \
    --arg deployer_filter "$DEPLOYER_FILTER" \
    '{
        deployer_filter: $deployer_filter
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

echo "Querying app measurements..."
echo ""

# Call gRPC service
response=$(printf "%s" "$request_json" | tr -d '\n' | grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d @ \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/ListAppMeasurements 2>&1)

# Check if request was successful
if echo "$response" | grep -q "Code:"; then
    echo "❌ Request failed:"
    echo "--------------------------------------"
    echo "$response"
    echo "--------------------------------------"
    exit 1
fi

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"