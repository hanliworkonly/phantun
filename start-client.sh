#!/bin/bash
#
# Phantun Client Startup Script
# This script helps configure and start the Phantun client correctly
#

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Configuration
LOCAL_ADDR="${LOCAL_ADDR:-127.0.0.1:55555}"
REMOTE_ADDR="${REMOTE_ADDR:-47.238.151.42:18888}"
TUN_LOCAL="${TUN_LOCAL:-192.168.221.1}"
TUN_PEER="${TUN_PEER:-192.168.221.2}"
STREAMS="${STREAMS:-4}"
INTERFACE="${INTERFACE:-eth0}"  # Change to your actual interface

echo "=== Phantun Client Startup ==="
echo "Local address: $LOCAL_ADDR"
echo "Remote server: $REMOTE_ADDR"
echo "TUN local: $TUN_LOCAL"
echo "TUN peer: $TUN_PEER"
echo "Streams: $STREAMS"
echo "Interface: $INTERFACE"
echo

# Step 1: Enable IP forwarding
echo "[1/4] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IP forwarding enabled"

# Step 2: Check if iptables rules exist
echo "[2/4] Checking firewall rules..."
if ! iptables -t nat -C POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null; then
    echo "Adding MASQUERADE rule..."
    iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
    echo "✓ MASQUERADE rule added"
else
    echo "✓ MASQUERADE rule already exists"
fi

# Step 3: Test connectivity to server
echo "[3/4] Testing connectivity to server..."
if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${REMOTE_ADDR%:*}/${REMOTE_ADDR##*:}" 2>/dev/null; then
    echo "✓ Server is reachable"
else
    echo "⚠ WARNING: Cannot connect to $REMOTE_ADDR"
    echo "  Make sure the server is running and accessible"
    echo "  Press Ctrl+C to abort, or Enter to continue anyway..."
    read
fi

# Step 4: Start Phantun client
echo "[4/4] Starting Phantun client..."
echo

CLIENT_BIN="./target/release/client"
if [ ! -f "$CLIENT_BIN" ]; then
    echo "ERROR: Client binary not found at $CLIENT_BIN"
    echo "Please run 'cargo build --release' first"
    exit 1
fi

export RUST_LOG="${RUST_LOG:-info}"

exec $CLIENT_BIN \
    --local "$LOCAL_ADDR" \
    --remote "$REMOTE_ADDR" \
    --tun-local "$TUN_LOCAL" \
    --tun-peer "$TUN_PEER" \
    --streams "$STREAMS"
