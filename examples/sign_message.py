#!/usr/bin/env python3
"""
Ethereum signature utility for TAPP service authentication.

Usage:
    python3 sign_message.py <method_name> <private_key>

Example:
    python3 sign_message.py GetAppLogs 0xdb56d646e7de8081b9e4242fd41fec80976cbed8e495ed8598b9a3a8542fb8a3

Output format:
    signature,timestamp,address
"""

import sys
import time
from eth_account import Account
from eth_account.messages import encode_defunct


def main():
    if len(sys.argv) != 3:
        print("Usage: sign_message.py <method_name> <private_key>", file=sys.stderr)
        print("", file=sys.stderr)
        print("Example:", file=sys.stderr)
        print("  python3 sign_message.py GetAppLogs 0xabc123...", file=sys.stderr)
        sys.exit(1)

    method_name = sys.argv[1]
    private_key = sys.argv[2]

    # Remove 0x prefix if present
    if private_key.startswith('0x') or private_key.startswith('0X'):
        private_key = private_key[2:]

    try:
        # Create account from private key
        account = Account.from_key('0x' + private_key)
    except Exception as e:
        print(f"Error: Invalid private key - {e}", file=sys.stderr)
        sys.exit(1)

    # Get current timestamp
    timestamp = int(time.time())

    # Build message: "MethodName:timestamp"
    message = f"{method_name}:{timestamp}"

    try:
        # Sign message using EIP-191 standard
        encoded_message = encode_defunct(text=message)
        signed = account.sign_message(encoded_message)
    except Exception as e:
        print(f"Error: Failed to sign message - {e}", file=sys.stderr)
        sys.exit(1)

    # Output: signature,timestamp,address
    print(f"{signed.signature.hex()},{timestamp},{account.address}")


if __name__ == "__main__":
    main()