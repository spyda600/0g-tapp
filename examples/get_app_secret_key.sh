#!/bin/bash

# Get application secret key with Ethereum signature authentication
# Usage:
#   ./get_app_secret_key.sh [OPTIONS]
#
# Examples:
#   ./get_app_secret_key.sh --host 39.97.63.199 --app-id test-nginx-app --use-owner
#   ./get_app_secret_key.sh --host 39.97.63.199 --app-id test-nginx-app --use-whitelist
#
# Security Warning:
#   This command retrieves the PRIVATE KEY of the application.
#   Only run this from a secure, trusted environment.
#   The private key should be handled with extreme care.

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"
DEFAULT_APP_ID=""

# Pre-configured addresses (for reference only)
OWNER_ADDRESS="0xea695C312CE119dE347425B29AFf85371c9d1837"
WHITELIST_ADDRESS="0x0E552ac14124F6f336a4504Aa72c921b4D7F8032"

# Private keys from environment variables (recommended for security)
# Set these in your environment:
#   export TAPP_OWNER_PRIVATE_KEY="0x..."
#   export TAPP_WHITELIST_PRIVATE_KEY="0x..."
OWNER_PRIVATE_KEY="${TAPP_OWNER_PRIVATE_KEY:-}"
WHITELIST_PRIVATE_KEY="${TAPP_WHITELIST_PRIVATE_KEY:-}"

# Parse command line arguments
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
APP_ID=""
PRIVATE_KEY=""
USE_OWNER=false
USE_WHITELIST=false

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
        --app-id)
            APP_ID="$2"
            shift 2
            ;;
        --private-key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        --use-owner)
            USE_OWNER=true
            shift
            ;;
        --use-whitelist)
            USE_WHITELIST=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --app-id APP_ID         Application ID (required)"
            echo "  --private-key KEY       Private key for signing (required unless using presets)"
            echo "  --use-owner             Use pre-configured owner credentials (requires TAPP_OWNER_PRIVATE_KEY env var)"
            echo "  --use-whitelist         Use pre-configured whitelist user credentials (requires TAPP_WHITELIST_PRIVATE_KEY env var)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  TAPP_OWNER_PRIVATE_KEY       Private key for owner account"
            echo "  TAPP_WHITELIST_PRIVATE_KEY   Private key for whitelist account"
            echo ""
            echo "Examples:"
            echo "  $0 --host 39.97.63.199 --app-id test-nginx-app --use-owner"
            echo "  $0 --host 39.97.63.199 --app-id test-nginx-app --use-whitelist"
            echo ""
            echo "⚠️  SECURITY WARNING:"
            echo "  This command retrieves the APPLICATION'S PRIVATE KEY."
            echo "  Only the app deployer (owner) can retrieve the secret key."
            echo "  Handle the returned private key with extreme care!"
            echo ""
            echo "Pre-configured users:"
            echo "  Owner: $OWNER_ADDRESS"
            echo "  Whitelist: $WHITELIST_ADDRESS"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Determine which credentials to use
if [ "$USE_OWNER" = true ]; then
    if [ -z "$OWNER_PRIVATE_KEY" ]; then
        echo "Error: Owner private key not found"
        echo "Please set the TAPP_OWNER_PRIVATE_KEY environment variable:"
        echo "  export TAPP_OWNER_PRIVATE_KEY=\"0x...\""
        exit 1
    fi
    PRIVATE_KEY="$OWNER_PRIVATE_KEY"
    echo "Using owner credentials: $OWNER_ADDRESS"
elif [ "$USE_WHITELIST" = true ]; then
    if [ -z "$WHITELIST_PRIVATE_KEY" ]; then
        echo "Error: Whitelist private key not found"
        echo "Please set the TAPP_WHITELIST_PRIVATE_KEY environment variable:"
        echo "  export TAPP_WHITELIST_PRIVATE_KEY=\"0x...\""
        exit 1
    fi
    PRIVATE_KEY="$WHITELIST_PRIVATE_KEY"
    echo "Using whitelist user credentials: $WHITELIST_ADDRESS"
elif [ -z "$PRIVATE_KEY" ]; then
    echo "Error: Private key is required"
    echo ""
    echo "Options:"
    echo "  1. Use --private-key KEY"
    echo "  2. Use --use-owner with TAPP_OWNER_PRIVATE_KEY env var"
    echo "  3. Use --use-whitelist with TAPP_WHITELIST_PRIVATE_KEY env var"
    exit 1
fi

TARGET_ADDRESS="$TARGET_HOST:$TARGET_PORT"

# Validate app ID
if [ -z "$APP_ID" ]; then
    echo "Error: Application ID is required"
    echo ""
    echo "Usage: $0 --host HOST --port PORT --app-id APP_ID"
    echo "Use --help for more information"
    exit 1
fi

echo "Checking dependencies..."
echo "========================================"

# Track if all dependencies are met
deps_ok=true
missing_deps=()

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "✗ python3: Not found"
    deps_ok=false
    missing_deps+=("python3")
else
    py_version=$(python3 --version 2>&1 | awk '{print $2}')
    py_major=$(echo "$py_version" | cut -d. -f1)
    py_minor=$(echo "$py_version" | cut -d. -f2)
    if [ "$py_major" -lt 3 ] || ([ "$py_major" -eq 3 ] && [ "$py_minor" -lt 6 ]); then
        echo "✗ python3: Version $py_version (requires >= 3.6)"
        deps_ok=false
        missing_deps+=("python3 (>= 3.6)")
    else
        echo "✓ python3: $py_version"
    fi
fi

# Check eth-account Python package
if command -v python3 &> /dev/null; then
    if python3 -c "import eth_account" 2>/dev/null; then
        eth_version=$(python3 -c "import eth_account; print(eth_account.__version__)" 2>/dev/null || echo "unknown")
        echo "✓ eth-account: $eth_version"
    else
        echo "✗ eth-account: Not installed"
        deps_ok=false
        missing_deps+=("eth-account")
    fi
fi

# Check jq
if ! command -v jq &> /dev/null; then
    echo "✗ jq: Not found"
    deps_ok=false
    missing_deps+=("jq")
else
    jq_version=$(jq --version 2>&1 | sed 's/jq-//')
    echo "✓ jq: $jq_version"
fi

# Check grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo "✗ grpcurl: Not found"
    deps_ok=false
    missing_deps+=("grpcurl")
else
    grpcurl_version=$(grpcurl --version 2>&1 | head -1 | awk '{print $2}')
    echo "✓ grpcurl: $grpcurl_version"
fi

# Check proto file
proto_file="$SCRIPT_DIR/../proto/tapp_service.proto"
if [ ! -f "$proto_file" ]; then
    echo "✗ proto file: Not found at $proto_file"
    deps_ok=false
    missing_deps+=("tapp_service.proto")
else
    echo "✓ proto file: found"
fi

# Check if sign_message.py exists
sign_script="$SCRIPT_DIR/sign_message.py"
if [ ! -f "$sign_script" ]; then
    echo "✗ sign_message.py: Not found at $sign_script"
    deps_ok=false
    missing_deps+=("sign_message.py")
else
    echo "✓ sign_message.py: found"
fi

echo "========================================"

# Exit if dependencies are missing
if [ "$deps_ok" = false ]; then
    echo ""
    echo "❌ Missing dependencies: ${missing_deps[*]}"
    echo ""
    echo "Installation guide:"
    echo ""
    for dep in "${missing_deps[@]}"; do
        case "$dep" in
            "python3"*)
                echo "• Python 3.6+:"
                echo "  CentOS/RHEL: yum install python3"
                echo "  Ubuntu/Debian: apt-get install python3"
                echo "  macOS: brew install python3"
                ;;
            "eth-account")
                echo "• eth-account:"
                echo "  pip3 install eth-account"
                ;;
            "jq")
                echo "• jq:"
                echo "  https://stedolan.github.io/jq/download/"
                ;;
            "grpcurl")
                echo "• grpcurl:"
                echo "  https://github.com/fullstorydev/grpcurl/releases"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
            "sign_message.py")
                echo "• sign_message.py:"
                echo "  The signature utility script is missing"
                echo "  Expected location: $sign_script"
                ;;
        esac
        echo ""
    done
    exit 1
fi

echo "✅ All dependencies satisfied"
echo ""

echo "======================================"
echo "⚠️  GetAppSecretKey Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "App ID:        $APP_ID"
echo ""
echo "WARNING: This will retrieve the application's PRIVATE KEY!"
echo "Only the app deployer should have access to this key."
echo "======================================"
echo ""

# Generate signature
echo "Generating signature..."
SIGN_OUTPUT=$(python3 "$sign_script" "GetAppSecretKey" "$PRIVATE_KEY" 2>&1)
if [ $? -ne 0 ]; then
    echo "Error generating signature: $SIGN_OUTPUT"
    exit 1
fi

SIGNATURE=$(echo "$SIGN_OUTPUT" | cut -d',' -f1)
TIMESTAMP=$(echo "$SIGN_OUTPUT" | cut -d',' -f2)
SIGNER_ADDRESS=$(echo "$SIGN_OUTPUT" | cut -d',' -f3)

echo "Signer: $SIGNER_ADDRESS"
echo "Signature: ${SIGNATURE:0:20}...${SIGNATURE: -20}"
echo "Timestamp: $TIMESTAMP"
echo "======================================"
echo ""

# Create request JSON
request_json=$(jq -n \
    --arg app_id "$APP_ID" \
    '{
        app_id: $app_id
    }')

echo "Request:"
echo "--------------------------------------"
echo "$request_json"
echo "--------------------------------------"
echo ""

echo "Sending GetAppSecretKey request..."
echo ""

# Send request with signature headers and capture both stdout and stderr
set +e  # Don't exit on error
response=$(printf "%s" "$request_json" | tr -d '\n' | \
    grpcurl -plaintext \
        -H "x-signature: $SIGNATURE" \
        -H "x-timestamp: $TIMESTAMP" \
        -import-path "$SCRIPT_DIR/../proto" \
        -proto tapp_service.proto \
        -d @ \
        "$TARGET_ADDRESS" \
        tapp_service.TappService/GetAppSecretKey 2>&1)
exit_code=$?
set -e

echo "Response:"
echo "--------------------------------------"
echo "$response"
echo "--------------------------------------"
echo ""