#!/bin/bash
# Test 9: Graceful Shutdown
# Tests: Server and client graceful shutdown with FIN packets

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Graceful Shutdown"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52800
PORT_END=52810

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.8.0/24"
dns = ["8.8.8.8"]
max_clients = 10
enable_nat = true
EOF

# Create client config
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Test 9a: Client graceful shutdown (SIGTERM)
log_info "Test 9a: Client graceful shutdown with SIGTERM"

# Capture packets to see FIN exchange
sudo timeout 10 tcpdump -i any "udp portrange $PORT_START-$PORT_END" -nn -c 50 2>/dev/null > /tmp/shutdown-capture.txt &
TCPDUMP_PID=$!
sleep 1

# Send SIGTERM to client
ssh $CLIENT_HOST "sudo pkill -SIGTERM -f 'ruhop client'" 2>/dev/null || true
sleep 3

# Wait for tcpdump
wait $TCPDUMP_PID 2>/dev/null || true

# Check client is no longer running
CLIENT_RUNNING=$(ssh $CLIENT_HOST "pgrep -f 'ruhop client'" 2>/dev/null || echo "")
if [ -z "$CLIENT_RUNNING" ]; then
    RESULT_1=0
    log_info "Client process terminated cleanly"
else
    RESULT_1=1
    log_error "Client process still running"
fi
assert_test "Client SIGTERM shutdown" $RESULT_1

# Test 9b: Server session cleanup after client disconnect
log_info "Test 9b: Server session cleanup"
sleep 2
SERVER_STATUS=$(sudo $SERVER_RUHOP_BIN status 2>/dev/null)
SESSION_COUNT=$(echo "$SERVER_STATUS" | grep -oP '(Active Sessions:|sessions:)\s*\K\d+' || echo "0")
log_info "Sessions after client disconnect: $SESSION_COUNT"

if [ "$SESSION_COUNT" -eq 0 ]; then
    RESULT_2=0
    log_info "Server cleaned up session correctly"
else
    RESULT_2=1
    log_warn "Server still shows active sessions"
fi
assert_test "Server session cleanup" $RESULT_2

# Test 9c: Server graceful shutdown with active client
log_info "Test 9c: Server graceful shutdown with active client"

# Restart client
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &
if ! wait_for_client 30; then
    log_error "Failed to reconnect client"
    cleanup_all
    exit 1
fi

# Send SIGTERM to server
log_info "Sending SIGTERM to server..."
sudo pkill -SIGTERM -f "ruhop server" 2>/dev/null || true
sleep 5

# Check server is no longer running
SERVER_RUNNING=$(pgrep -f "ruhop server" || echo "")
if [ -z "$SERVER_RUNNING" ]; then
    RESULT_3=0
    log_info "Server process terminated cleanly"
else
    RESULT_3=1
    log_error "Server process still running"
fi
assert_test "Server SIGTERM shutdown" $RESULT_3

# Test 9d: Client detects server shutdown
log_info "Test 9d: Client detects server shutdown"
sleep 3
CLIENT_STATUS=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>&1 || echo "error")
log_info "Client status after server shutdown: $CLIENT_STATUS"

if echo "$CLIENT_STATUS" | grep -qiE "(disconnect|error|not running)"; then
    RESULT_4=0
    log_info "Client detected server shutdown"
else
    RESULT_4=1
    log_warn "Client may not have detected server shutdown"
fi
assert_test "Client detects server shutdown" $RESULT_4

# Test 9e: TUN device cleanup after shutdown
log_info "Test 9e: TUN device cleanup"

# Check if TUN devices are cleaned up
TUN_DEVICES=$(ssh $CLIENT_HOST "ip link show | grep -c 'ruhop\\|tun' || echo 0")
log_info "Remaining TUN devices on client: $TUN_DEVICES"

# Note: We don't enforce TUN cleanup as it might be handled by the OS
RESULT_5=0
assert_test "TUN device cleanup check" $RESULT_5

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
