#!/bin/bash

# Get task status from TAPP service
# Usage:
#   ./get_task_status.sh TASK_ID [HOST] [PORT]
#
# Examples:
#   ./get_task_status.sh task-abc123-def456-789
#   ./get_task_status.sh task-abc123-def456-789 39.97.63.199 50051

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_HOST="localhost"
DEFAULT_PORT="50051"

# Parse command line arguments
TASK_ID=""
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"

while [[ $# -gt 0 ]]; do
    case $1 in
        --task-id)
            TASK_ID="$2"
            shift 2
            ;;
        --host)
            TARGET_HOST="$2"
            shift 2
            ;;
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 --task-id TASK_ID [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --task-id TASK_ID       Task ID returned from StartApp (required)"
            echo "  --host HOST             gRPC server host (default: $DEFAULT_HOST)"
            echo "  --port PORT             gRPC server port (default: $DEFAULT_PORT)"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --task-id task-abc123-def456-789"
            echo "  $0 --task-id task-abc123-def456-789 --host 39.97.63.199 --port 50051"
            echo ""
            echo "Legacy positional format also supported:"
            echo "  $0 task-abc123-def456-789 39.97.63.199 50051"
            exit 0
            ;;
        *)
            # Support legacy positional arguments for backward compatibility
            if [ -z "$TASK_ID" ]; then
                TASK_ID="$1"
            elif [ "$TARGET_HOST" = "$DEFAULT_HOST" ]; then
                TARGET_HOST="$1"
            elif [ "$TARGET_PORT" = "$DEFAULT_PORT" ]; then
                TARGET_PORT="$1"
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

# Check if task ID is provided
if [ -z "$TASK_ID" ]; then
    echo "Error: Task ID is required"
    echo ""
    echo "Usage: $0 --task-id TASK_ID [OPTIONS]"
    echo "Use --help for more information"
    exit 1
fi

# Quick dependency check (only critical ones for this script)
missing_deps=()

if ! command -v jq &> /dev/null; then
    missing_deps+=("jq")
fi

if ! command -v grpcurl &> /dev/null; then
    missing_deps+=("grpcurl")
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
            "jq")
                echo "• jq: yum install jq (CentOS) or apt-get install jq (Ubuntu) or brew install jq (macOS)"
                ;;
            "grpcurl")
                echo "• grpcurl: https://github.com/fullstorydev/grpcurl/releases"
                ;;
            "tapp_service.proto")
                echo "• proto file not found at: $proto_file"
                ;;
        esac
    done
    exit 1
fi

echo "======================================"
echo "GetTaskStatus Request"
echo "======================================"
echo "Target:        $TARGET_ADDRESS"
echo "Task ID:       $TASK_ID"
echo "======================================"
echo ""

# Build request JSON
request_json=$(jq -n \
  --arg task_id "$TASK_ID" \
  '{
    task_id: $task_id
  }')

echo "Querying task status..."
echo ""

# Send request
response=$(printf "%s" "$request_json" | tr -d '\n' | \
  grpcurl -plaintext \
    -import-path "$SCRIPT_DIR/../proto" \
    -proto tapp_service.proto \
    -d @ \
    "$TARGET_ADDRESS" \
    tapp_service.TappService/GetTaskStatus 2>&1)

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

# Parse and display status
status=$(echo "$response" | jq -r '.status // empty' 2>/dev/null)
message=$(echo "$response" | jq -r '.message // empty' 2>/dev/null)

if [ -n "$status" ]; then
    echo "======================================"
    echo "Task Status Summary"
    echo "======================================"
    echo "Status: $status"
    
    if [ -n "$message" ]; then
        echo "Message: $message"
    fi
    
    case "$status" in
        "COMPLETED"|"SUCCESS")
            echo ""
            echo "✅ Task completed successfully!"
            echo ""
            echo "You can now get evidence:"
            echo "  sh ./get_evidence.sh --host $TARGET_HOST --port $TARGET_PORT"
            exit 0
            ;;
        "RUNNING"|"PENDING")
            echo ""
            echo "⏳ Task is still in progress..."
            echo ""
            echo "Check again in a few seconds:"
            echo "  sh ./get_task_status.sh --task-id $TASK_ID --host $TARGET_HOST --port $TARGET_PORT"
            exit 2
            ;;
        "FAILED"|"ERROR")
            echo ""
            echo "❌ Task failed!"
            exit 1
            ;;
        *)
            echo ""
            echo "⚠️  Unknown status: $status"
            exit 2
            ;;
    esac
else
    echo "⚠️  Could not parse task status from response"
    exit 2
fi