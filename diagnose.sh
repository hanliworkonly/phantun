#!/bin/bash
#
# Phantun Diagnostic Tool
# This script helps diagnose connection issues
#

echo "=== Phantun Connection Diagnostic ==="
echo

# Configuration
CLIENT_IP="47.238.151.42"
CLIENT_PORT="18888"

echo "[1] Checking if running as root..."
if [ "$EUID" -ne 0 ]; then
    echo "❌ NOT running as root - This is likely the problem!"
    echo "   Solution: Run with sudo"
    exit 1
else
    echo "✓ Running as root"
fi

echo
echo "[2] Checking IP forwarding..."
if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
    echo "✓ IP forwarding is enabled"
else
    echo "❌ IP forwarding is DISABLED - This will cause connection failures!"
    echo "   Solution: sudo sysctl -w net.ipv4.ip_forward=1"
fi

echo
echo "[3] Checking TUN module..."
if lsmod | grep -q tun; then
    echo "✓ TUN module is loaded"
else
    echo "⚠ TUN module not loaded"
    echo "   Trying to load..."
    modprobe tun 2>/dev/null && echo "✓ TUN module loaded" || echo "❌ Failed to load TUN module"
fi

echo
echo "[4] Checking existing TUN interfaces..."
TUN_COUNT=$(ip tuntap list | wc -l)
if [ "$TUN_COUNT" -gt 0 ]; then
    echo "✓ Found $TUN_COUNT TUN/TAP interfaces:"
    ip tuntap list | sed 's/^/   /'
else
    echo "⚠ No TUN interfaces found (will be created when phantun starts)"
fi

echo
echo "[5] Checking firewall rules (iptables)..."
echo "NAT POSTROUTING rules:"
iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -E "MASQUERADE|SNAT" | sed 's/^/   /' || echo "   (none)"

echo
echo "[6] Testing connectivity to server $CLIENT_IP:$CLIENT_PORT..."
if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$CLIENT_IP/$CLIENT_PORT" 2>/dev/null; then
    echo "✓ Server is reachable!"
else
    echo "❌ CANNOT connect to server - This is the main problem!"
    echo "   Possible causes:"
    echo "   1. Server is not running"
    echo "   2. Server firewall is blocking port $CLIENT_PORT"
    echo "   3. Server DNAT rules are not configured"
    echo "   4. Network connectivity issue"
fi

echo
echo "[7] Checking route to server..."
if ip route get $CLIENT_IP >/dev/null 2>&1; then
    echo "✓ Route exists:"
    ip route get $CLIENT_IP | sed 's/^/   /'
else
    echo "❌ No route to server!"
fi

echo
echo "[8] Testing raw connectivity (ping)..."
if timeout 3 ping -c 1 $CLIENT_IP >/dev/null 2>&1; then
    echo "✓ Server responds to ping"
else
    echo "⚠ Server does not respond to ping (might be normal if ICMP is blocked)"
fi

echo
echo "=== Summary ==="
echo
echo "If you see ❌ marks above, those need to be fixed."
echo
echo "Common issues:"
echo "1. Not running as root (sudo) - Most common!"
echo "2. IP forwarding disabled"
echo "3. No iptables MASQUERADE rule"
echo "4. Server not running or not accessible"
echo "5. Server DNAT rules not configured"
echo
echo "Next steps:"
echo "- Fix any ❌ issues above"
echo "- Use ./start-client.sh to automatically configure everything"
echo "- Check server is running: ssh $CLIENT_IP 'ps aux | grep phantun'"
echo
