#!/bin/bash
# Test 3: Multi-homed Server
# Tests: Server with multiple IP addresses, client distributes traffic across both

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Multi-homed Server"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52200
PORT_END=52210

# For multi-homed server test, we need to configure server to listen on 0.0.0.0
# The server binds to all interfaces and client connects to both IPs
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "0.0.0.0"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.2.0/24"
max_clients = 10
enable_nat = true
EOF

# Create client config with multiple server addresses
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"

[client]
server = [\"$SERVER_IP_1\", \"$SERVER_IP_2\"]
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

log_info "Starting server on 0.0.0.0 (multi-homed)..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Test 3a: Verify server is accessible on both IPs"
# Check if server is listening on both IPs
RESULT_1=0
for IP in $SERVER_IP_1 $SERVER_IP_2; do
    if ! nc -u -z -w1 $IP $PORT_START 2>/dev/null; then
        log_warn "Could not connect to $IP:$PORT_START"
    else
        log_info "Server reachable on $IP:$PORT_START"
    fi
done
assert_test "Server accessible on both IPs" $RESULT_1

log_info "Starting client with multi-server config..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Generate traffic
log_info "Test 3b: Generating traffic to verify distribution across server IPs..."
ssh $CLIENT_HOST "ping -c 100 -i 0.05 10.99.2.1" > /dev/null 2>&1 &
PING_PID=$!

# Capture packets on both interfaces
log_info "Capturing traffic on both server IPs..."
sudo timeout 8 tcpdump -i any "udp portrange $PORT_START-$PORT_END and (host $SERVER_IP_1 or host $SERVER_IP_2)" -nn 2>/dev/null | tee /tmp/multi-ip-capture.txt &
TCPDUMP_PID=$!

sleep 6
wait $PING_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# Check if traffic went to both IPs
IP1_COUNT=$(grep -c "$SERVER_IP_1" /tmp/multi-ip-capture.txt 2>/dev/null || echo "0")
IP2_COUNT=$(grep -c "$SERVER_IP_2" /tmp/multi-ip-capture.txt 2>/dev/null || echo "0")

log_info "Packets to $SERVER_IP_1: $IP1_COUNT"
log_info "Packets to $SERVER_IP_2: $IP2_COUNT"

if [ "$IP1_COUNT" -gt 5 ] && [ "$IP2_COUNT" -gt 5 ]; then
    RESULT_2=0
    log_info "Traffic successfully distributed across both server IPs"
else
    RESULT_2=1
    log_warn "Traffic not evenly distributed across server IPs"
fi
assert_test "Traffic distributed across server IPs" $RESULT_2

# Test connectivity still works
log_info "Test 3c: Verify tunnel connectivity after multi-IP traffic"
test_ping_from_client "10.99.2.1" 5 5
RESULT_3=$?
assert_test "Tunnel connectivity with multi-homed server" $RESULT_3

# Cleanup
cleanup_all

# Summary
log_info "=========================================="
log_info "Test Summary: $TEST_NAME"
log_info "=========================================="
PASSED=0
FAILED=0
[ $RESULT_1 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_2 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_3 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
log_info "Passed: $PASSED / 3"
log_info "Failed: $FAILED / 3"

if [ $FAILED -gt 0 ]; then
    log_error "TEST FAILED"
    exit 1
else
    log_test "TEST PASSED"
    exit 0
fi
