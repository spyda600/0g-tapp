#!/bin/sh
# Enclave init script — runs before tapp-server
# Provides basic diagnostics on console if something goes wrong

echo "=== TAPP Enclave Init ==="
echo "Date: $(date -u)"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"

# Check for NSM device
if [ -e /dev/nsm ]; then
    echo "NSM device: available"
else
    echo "NSM device: NOT FOUND"
fi

# Check network
echo "Network interfaces:"
ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "  (no network tools)"

echo "=== Starting tapp-server ==="
exec /usr/local/bin/tapp-server --config /etc/tapp/config.toml "$@"
