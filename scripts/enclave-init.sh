#!/bin/sh
# Enclave init script — runs as PID 1 inside Nitro Enclave.
# Performs privileged setup then exec's tapp-server.
set -eu

# Restrictive PATH — defense against supply chain PATH injection
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

echo "=== TAPP Enclave Init ==="
echo "Date: $(date -u)"
echo "Kernel: $(uname -r)"

# Bring up loopback — REQUIRED for the vsock-to-TCP bridge.
# Nitro Enclaves don't auto-configure any networking.
ip link set lo up || { echo "FATAL: cannot bring up loopback"; exit 1; }
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true  # may already exist
echo "Loopback: UP"

# Verify NSM device exists (required for Nitro attestation)
if [ ! -e /dev/nsm ]; then
    echo "FATAL: NSM device /dev/nsm not found — not running in a Nitro Enclave?"
    exit 1
fi
echo "NSM device: available"

# Drop privileges: run tapp-server as non-root user if available
if id tapp >/dev/null 2>&1; then
    echo "Dropping privileges to user 'tapp'"
    # chown directories the server needs to write to
    chown -R tapp /var/lib/tapp /var/log/tapp 2>/dev/null || true
    exec runuser -u tapp -- /usr/local/bin/tapp-server --config /etc/tapp/config.toml "$@"
else
    echo "WARNING: Running as root (no 'tapp' user found)"
    exec /usr/local/bin/tapp-server --config /etc/tapp/config.toml "$@"
fi
