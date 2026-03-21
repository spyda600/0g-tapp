#!/bin/sh
# Enclave init script — runs before tapp-server
# Provides basic diagnostics on console if something goes wrong

echo "=== TAPP Enclave Init ==="
echo "Date: $(date -u)"
echo "Kernel: $(uname -r)"

# Bring up loopback — Nitro Enclaves don't auto-configure networking
ip link set lo up 2>/dev/null && \
  ip addr add 127.0.0.1/8 dev lo 2>/dev/null && \
  echo "Loopback: UP" || \
  echo "WARNING: could not bring up loopback"

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
