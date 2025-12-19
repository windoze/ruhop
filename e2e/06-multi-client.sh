#!/bin/bash
# Test 6: Multiple Concurrent Clients
# Tests: Server handles multiple clients simultaneously

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Multiple Concurrent Clients"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52500
PORT_END=52510

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.5.0/24"
dns = ["8.8.8.8"]
max_clients = 10
enable_nat = true
EOF

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

# For multi-client test, we'll run 2 clients on client host with different TUN devices
# Client 1
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client1.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
tun_device = \"ruhop-e2e1\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

# Client 2
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client2.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
tun_device = \"ruhop-e2e2\"
control_socket = \"/tmp/ruhop-client2.sock\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

log_info "Starting client 1..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client1.toml > /tmp/client1.log 2>&1 &"
sleep 3

log_info "Starting client 2..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client2.toml > /tmp/client2.log 2>&1 &"
sleep 5

# Wait for both clients
log_info "Waiting for both clients to connect..."
sleep 10

# Test 6a: Check server shows 2 connected sessions
log_info "Test 6a: Verify server shows 2 connected sessions"
SERVER_STATUS=$(sudo $SERVER_RUHOP_BIN status 2>/dev/null)
echo "$SERVER_STATUS"
SESSION_COUNT=$(echo "$SERVER_STATUS" | grep -oP '(Active Sessions:|sessions:)\s*\K\d+' || echo "0")
log_info "Connected sessions: $SESSION_COUNT"

if [ "$SESSION_COUNT" -eq 2 ]; then
    RESULT_1=0
else
    RESULT_1=1
fi
assert_test "Server shows 2 connected clients" $RESULT_1

# Test 6b: Ping from client 1
log_info "Test 6b: Ping server from client 1"
CLIENT1_IP=$(ssh $CLIENT_HOST "ip addr show ruhop-e2e1 2>/dev/null | grep -oP '10\.99\.5\.\d+' | head -1" || echo "")
log_info "Client 1 tunnel IP: $CLIENT1_IP"
if [ -n "$CLIENT1_IP" ] && ssh $CLIENT_HOST "ping -I ruhop-e2e1 -c 3 -W 5 10.99.5.1" > /dev/null 2>&1; then
    RESULT_2=0
else
    RESULT_2=1
fi
assert_test "Ping from client 1" $RESULT_2

# Test 6c: Ping from client 2
log_info "Test 6c: Ping server from client 2"
CLIENT2_IP=$(ssh $CLIENT_HOST "ip addr show ruhop-e2e2 2>/dev/null | grep -oP '10\.99\.5\.\d+' | head -1" || echo "")
log_info "Client 2 tunnel IP: $CLIENT2_IP"
if [ -n "$CLIENT2_IP" ] && ssh $CLIENT_HOST "ping -I ruhop-e2e2 -c 3 -W 5 10.99.5.1" > /dev/null 2>&1; then
    RESULT_3=0
else
    RESULT_3=1
fi
assert_test "Ping from client 2" $RESULT_3

# Test 6d: Verify clients have different IPs
log_info "Test 6d: Verify clients have unique tunnel IPs"
if [ -n "$CLIENT1_IP" ] && [ -n "$CLIENT2_IP" ] && [ "$CLIENT1_IP" != "$CLIENT2_IP" ]; then
    RESULT_4=0
    log_info "Clients have unique IPs: $CLIENT1_IP vs $CLIENT2_IP"
else
    RESULT_4=1
    log_error "Clients do not have unique IPs"
fi
assert_test "Clients have unique tunnel IPs" $RESULT_4

# Test 6e: Simultaneous traffic from both clients
log_info "Test 6e: Simultaneous traffic from both clients"
ssh $CLIENT_HOST "ping -I ruhop-e2e1 -c 10 -i 0.1 10.99.5.1" > /dev/null 2>&1 &
PID1=$!
ssh $CLIENT_HOST "ping -I ruhop-e2e2 -c 10 -i 0.1 10.99.5.1" > /dev/null 2>&1 &
PID2=$!
wait $PID1
R1=$?
wait $PID2
R2=$?
if [ $R1 -eq 0 ] && [ $R2 -eq 0 ]; then
    RESULT_5=0
else
    RESULT_5=1
fi
assert_test "Simultaneous traffic from both clients" $RESULT_5

# Cleanup
ssh $CLIENT_HOST "sudo pkill -f 'ruhop client'" 2>/dev/null || true
cleanup_server

# Summary
log_info "=========================================="
log_info "Test Summary: $TEST_NAME"
log_info "=========================================="
PASSED=0
FAILED=0
[ $RESULT_1 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_2 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_3 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_4 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
[ $RESULT_5 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))
log_info "Passed: $PASSED / 5"
log_info "Failed: $FAILED / 5"

if [ $FAILED -gt 0 ]; then
    log_error "TEST FAILED"
    exit 1
else
    log_test "TEST PASSED"
    exit 0
fi
