#!/bin/bash

# Get attestation evidence from TAPP service
# Usage:
#   ./get_evidence.sh [OPTIONS]
#
# Examples:
#   ./get_evidence.sh --host 39.97.63.199 --port 50051
#   ./get_evidence.sh --host 39.97.63.199 --report-data bae5046287f1b3fe...
#   REPORT_DATA_HEX=bae5046287f1b3fe... ./get_evidence.sh --host 39.97.63.199

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_REPORT_DATA_HEX="bae5046287f1b3fe2540d13160778c459d0f4038f1dcda0651679f5cb8a21f0ef1550b51ab5e6ae5a8e531512b1a06a97dfbb992c5e6f3aa36b04e1dd928d269"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
REPORT_DATA_HEX=""

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
        --report-data)
            REPORT_DATA_HEX="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --report-data HEX       Custom report data in hex (max 64 bytes/128 hex chars)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --port 50051"
            echo "  $0 --host 39.97.63.199 --report-data bae5046287f1b3fe..."
            echo ""
            echo "Environment variable:"
            echo "  REPORT_DATA_HEX=bae5046287f1b3fe... $0 --host 39.97.63.199"
            echo ""
            echo "Legacy positional format also supported:"
            echo "  $0 39.97.63.199 50051 bae5046287f1b3fe..."
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            if [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
            elif [ -z "$REPORT_DATA_HEX" ]; then
                REPORT_DATA_HEX="$1"
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

# Report data priority: command line arg > environment variable > default
if [ -z "$REPORT_DATA_HEX" ] && [ -n "$REPORT_DATA_HEX_ENV" ]; then
    REPORT_DATA_HEX="$REPORT_DATA_HEX_ENV"
elif [ -z "$REPORT_DATA_HEX" ]; then
    REPORT_DATA_HEX="$DEFAULT_REPORT_DATA_HEX"
fi

# Remove 0x prefix if present
REPORT_DATA_HEX=${REPORT_DATA_HEX#0x}
REPORT_DATA_HEX=${REPORT_DATA_HEX#0X}

# Validate report data length (should be at most 128 hex characters = 64 bytes)
if [ ${#REPORT_DATA_HEX} -gt 128 ]; then
    echo "Error: Report data must be at most 64 bytes (128 hex characters)"
    echo "Got: ${#REPORT_DATA_HEX} hex characters"
    echo ""
    echo "Usage: $0 --host HOST --port PORT [--report-data HEX]"
    echo "Use --help for more information"
    exit 1
fi

# Quick dependency check
missing_deps=()

if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
fi

if ! command -v xxd &> /dev/null; then
    missing_deps+=("xxd")
fi

if ! command -v base64 &> /dev/null; then
    missing_deps+=("base64")
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
            "xxd"|"base64")
                echo "• $dep: Usually included in vim-common or coreutils package"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
        esac
    done
    exit 1
fi

# Convert hex to base64 (if not empty)
if [ -n "$REPORT_DATA_HEX" ]; then
    REPORT_DATA_BASE64=$(echo -n "$REPORT_DATA_HEX" | xxd -r -p | base64 | tr -d '\n')
else
    REPORT_DATA_BASE64=""
fi

# Display configuration
echo "======================================"
echo "GetEvidence Request"
echo "======================================"
echo "Target:             $TARGET_ADDRESS"
echo "Report Data (hex):  ${REPORT_DATA_HEX:0:32}...${REPORT_DATA_HEX: -32}"
echo "======================================"
echo ""

echo "Requesting attestation evidence..."
echo ""

# Call gRPC service
response=$(grpcurl -plaintext \
  -import-path "$SCRIPT_DIR/../proto" \
  -proto tapp_service.proto \
  -d "{
    \"report_data\": \"$REPORT_DATA_BASE64\"
  }" \
  "$TARGET_ADDRESS" \
  tapp_service.TappService/GetEvidence 2>&1)

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
echo "$response" | jq . 2>/dev/null || echo "$response"
echo "--------------------------------------"
echo ""

# Check if evidence was returned
if echo "$response" | jq -e '.evidence' &>/dev/null; then
    echo "✅ Evidence retrieved successfully!"
    echo ""
    
    # Extract evidence size
    evidence=$(echo "$response" | jq -r '.evidence // empty' 2>/dev/null)
    if [ -n "$evidence" ]; then
        evidence_size=${#evidence}
        echo "Evidence size: $evidence_size bytes (base64)"
        
        # Optionally save to file
        echo "$evidence" | base64 -d > /tmp/evidence.bin 2>/dev/null && \
            echo "Binary evidence saved to: /tmp/evidence.bin"
    fi
else
    echo "⚠️  No evidence found in response"
fi