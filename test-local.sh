#!/bin/bash
#
# Local Testing Script
# Tests Phantun client and server on localhost
#

set -e

echo "=== Phantun Local Test ==="
echo

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

# Kill any existing phantun processes
pkill -9 client 2>/dev/null || true
pkill -9 server 2>/dev/null || true
sleep 1

# Configuration
SERVER_PORT=18888
UDP_TEST_PORT=9999

echo "[1] Setting up test UDP server on port $UDP_TEST_PORT..."
nc -lu 127.0.0.1 $UDP_TEST_PORT > /tmp/udp-received.txt &
UDP_SERVER_PID=$!
echo "✓ UDP server started (PID: $UDP_SERVER_PID)"

echo
echo "[2] Configuring system..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "✓ IP forwarding enabled"

echo
echo "[3] Starting Phantun server..."
RUST_LOG=debug ./target/release/server \
    --local $SERVER_PORT \
    --remote 127.0.0.1:$UDP_TEST_PORT \
    --tun-local 192.168.201.1 \
    --tun-peer 192.168.201.2 \
    > /tmp/phantun-server.log 2>&1 &
SERVER_PID=$!
sleep 2

if ! ps -p $SERVER_PID > /dev/null; then
    echo "❌ Server failed to start!"
    cat /tmp/phantun-server.log
    kill $UDP_SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "✓ Server started (PID: $SERVER_PID)"

# Check server log for errors
if grep -q "ERROR\|FATAL\|panic" /tmp/phantun-server.log; then
    echo "❌ Server has errors:"
    grep "ERROR\|FATAL\|panic" /tmp/phantun-server.log
    kill $SERVER_PID $UDP_SERVER_PID 2>/dev/null || true
    exit 1
fi

echo
echo "[4] Configuring iptables DNAT rule..."
# Clean up old rules
iptables -t nat -D PREROUTING -p tcp --dport $SERVER_PORT -j DNAT --to-destination 192.168.201.2 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport $SERVER_PORT -j DNAT --to-destination 192.168.201.2
echo "✓ DNAT rule added"

echo
echo "[5] Starting Phantun client..."
RUST_LOG=debug ./target/release/client \
    --local 127.0.0.1:55555 \
    --remote 127.0.0.1:$SERVER_PORT \
    --tun-local 192.168.200.1 \
    --tun-peer 192.168.200.2 \
    --streams 4 \
    > /tmp/phantun-client.log 2>&1 &
CLIENT_PID=$!
sleep 3

if ! ps -p $CLIENT_PID > /dev/null; then
    echo "❌ Client failed to start!"
    cat /tmp/phantun-client.log
    kill $SERVER_PID $UDP_SERVER_PID 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport $SERVER_PORT -j DNAT --to-destination 192.168.201.2 2>/dev/null || true
    exit 1
fi

echo "✓ Client started (PID: $CLIENT_PID)"

# Check client log for connection errors
if grep -q "Unable to connect\|Failed to create all" /tmp/phantun-client.log; then
    echo "❌ Client failed to connect:"
    grep "ERROR" /tmp/phantun-client.log
    echo
    echo "Server log:"
    tail -20 /tmp/phantun-server.log
    echo
    echo "Full logs available at:"
    echo "  Client: /tmp/phantun-client.log"
    echo "  Server: /tmp/phantun-server.log"
    kill $CLIENT_PID $SERVER_PID $UDP_SERVER_PID 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport $SERVER_PORT -j DNAT --to-destination 192.168.201.2 2>/dev/null || true
    exit 1
fi

echo
echo "[6] Sending test packet..."
echo "HELLO PHANTUN" | nc -u 127.0.0.1 55555 -w 1
sleep 2

echo
echo "[7] Checking results..."
if [ -s /tmp/udp-received.txt ]; then
    echo "✓ SUCCESS! Received:"
    cat /tmp/udp-received.txt
else
    echo "❌ No data received"
    echo
    echo "Client log:"
    tail -30 /tmp/phantun-client.log
    echo
    echo "Server log:"
    tail -30 /tmp/phantun-server.log
fi

echo
echo "[8] Cleanup..."
kill $CLIENT_PID $SERVER_PID $UDP_SERVER_PID 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport $SERVER_PORT -j DNAT --to-destination 192.168.201.2 2>/dev/null || true
echo "✓ Cleaned up"

echo
echo "=== Test Complete ==="
echo "Logs available at:"
echo "  Client: /tmp/phantun-client.log"
echo "  Server: /tmp/phantun-server.log"
