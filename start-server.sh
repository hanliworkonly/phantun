#!/bin/bash
#
# Phantun Server Startup Script
# This script helps configure and start the Phantun server correctly
#

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Configuration
LOCAL_PORT="${LOCAL_PORT:-18888}"
REMOTE_ADDR="${REMOTE_ADDR:-127.0.0.1:51820}"  # Your UDP server (e.g., WireGuard)
TUN_LOCAL="${TUN_LOCAL:-192.168.201.1}"
TUN_PEER="${TUN_PEER:-192.168.201.2}"
INTERFACE="${INTERFACE:-eth0}"  # Change to your actual interface

echo "=== Phantun Server Startup ==="
echo "Listen port: $LOCAL_PORT"
echo "UDP target: $REMOTE_ADDR"
echo "TUN local: $TUN_LOCAL"
echo "TUN peer: $TUN_PEER"
echo "Interface: $INTERFACE"
echo

# Step 1: Enable IP forwarding
echo "[1/3] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IP forwarding enabled"

# Step 2: Configure DNAT rule (CRITICAL for Phantun to work!)
echo "[2/3] Configuring DNAT rule..."
if ! iptables -t nat -C PREROUTING -p tcp -i $INTERFACE --dport $LOCAL_PORT -j DNAT --to-destination $TUN_PEER 2>/dev/null; then
    echo "Adding DNAT rule..."
    iptables -t nat -A PREROUTING -p tcp -i $INTERFACE --dport $LOCAL_PORT -j DNAT --to-destination $TUN_PEER
    echo "✓ DNAT rule added"
else
    echo "✓ DNAT rule already exists"
fi

# Step 3: Start Phantun server
echo "[3/3] Starting Phantun server..."
echo

SERVER_BIN="./target/release/server"
if [ ! -f "$SERVER_BIN" ]; then
    echo "ERROR: Server binary not found at $SERVER_BIN"
    echo "Please run 'cargo build --release' first"
    exit 1
fi

export RUST_LOG="${RUST_LOG:-info}"

exec $SERVER_BIN \
    --local "$LOCAL_PORT" \
    --remote "$REMOTE_ADDR" \
    --tun-local "$TUN_LOCAL" \
    --tun-peer "$TUN_PEER"
