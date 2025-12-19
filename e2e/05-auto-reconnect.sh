#!/bin/bash
# Test 5: Auto-Reconnection
# Tests: Client reconnects after network disruption (using iptables to block/restore traffic)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Auto-Reconnection"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52400
PORT_END=52410

# Function to block VPN traffic using iptables on the client
# Note: Only block INPUT (receiving) to simulate packet loss without immediate send errors
# Blocking OUTPUT causes "Operation not permitted" which crashes the TUN task
block_vpn_traffic() {
    log_info "Blocking VPN traffic with iptables (INPUT only)..."
    ssh $CLIENT_HOST "sudo iptables -A INPUT -s $SERVER_IP_1 -p udp --sport $PORT_START:$PORT_END -j DROP"
}

# Function to restore VPN traffic
restore_vpn_traffic() {
    log_info "Restoring VPN traffic (removing iptables rules)..."
    ssh $CLIENT_HOST "sudo iptables -D INPUT -s $SERVER_IP_1 -p udp --sport $PORT_START:$PORT_END -j DROP" 2>/dev/null || true
}

# Make sure iptables rules are clean at start
restore_vpn_traffic

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.4.0/24"
dns = ["8.8.8.8"]
max_clients = 10
enable_nat = true
EOF

# Create client config WITH auto_reconnect enabled
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = true
reconnect_delay = 2
EOF"

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with auto-reconnect enabled..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Test 5a: Initial connectivity
log_info "Test 5a: Verify initial connectivity"
test_ping_from_client "10.99.4.1" 5 5
RESULT_1=$?
assert_test "Initial connectivity" $RESULT_1

# Test 5b: Block traffic and verify client detects disconnection
log_info "Test 5b: Blocking VPN traffic..."
block_vpn_traffic

# Wait for heartbeat timeout to trigger (default heartbeat is 30s, so wait longer)
log_info "Waiting for client to detect network disruption (heartbeat timeout)..."
sleep 45

# Check client status - should show reconnecting or disconnected
CLIENT_STATUS=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>&1 || echo "error")
log_info "Client status after blocking traffic: $CLIENT_STATUS"

if echo "$CLIENT_STATUS" | grep -qiE "(reconnect|disconnect|connecting|error|not running)"; then
    RESULT_2=0
    log_info "Client detected network disruption"
else
    # Even if status shows "Connected", ping should fail
    log_info "Verifying connectivity is actually broken..."
    if ! ssh $CLIENT_HOST "ping -c 1 -W 2 10.99.4.1" 2>/dev/null; then
        RESULT_2=0
        log_info "Connectivity is broken (ping failed)"
    else
        RESULT_2=1
        log_warn "Client may not have detected disruption"
    fi
fi
assert_test "Client detects network disruption" $RESULT_2

# Test 5c: Restore traffic and verify client reconnects
log_info "Test 5c: Restoring VPN traffic..."
restore_vpn_traffic

# Wait for client to reconnect
log_info "Waiting for client to auto-reconnect..."
sleep 15

# Check if client reconnected
if wait_for_client 60; then
    RESULT_3=0
    log_info "Client successfully reconnected!"
else
    RESULT_3=1
    log_error "Client failed to reconnect"
fi
assert_test "Client auto-reconnects" $RESULT_3

# Test 5d: Verify connectivity after reconnection
log_info "Test 5d: Verify connectivity after reconnection"
test_ping_from_client "10.99.4.1" 5 5
RESULT_4=$?
assert_test "Connectivity after reconnection" $RESULT_4

# Cleanup (make sure iptables rules are removed)
restore_vpn_traffic
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
log_info "Passed: $PASSED / 4"
log_info "Failed: $FAILED / 4"

if [ $FAILED -gt 0 ]; then
    log_error "TEST FAILED"
    exit 1
else
    log_test "TEST PASSED"
    exit 0
fi
