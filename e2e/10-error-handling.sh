#!/bin/bash
# Test 10: Error Handling
# Tests: Invalid config, max clients, wrong key, etc.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Error Handling"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52900
PORT_END=52910

# Test 10a: Invalid server config (missing key)
log_info "Test 10a: Invalid server config (missing key)"

cat > /tmp/e2e-invalid-server.toml << EOF
[common]
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.9.0/24"
EOF

if sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-invalid-server.toml 2>&1 | grep -qiE "(error|invalid|missing|required)"; then
    RESULT_1=0
    log_info "Server correctly rejected invalid config"
else
    RESULT_1=1
    log_error "Server should have rejected config without key"
fi
assert_test "Invalid config rejected" $RESULT_1

# Test 10b: Invalid port range
log_info "Test 10b: Invalid port range"

cat > /tmp/e2e-invalid-ports.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [60000, 50000]
tunnel_network = "10.99.9.0/24"
EOF

if sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-invalid-ports.toml 2>&1 | grep -qiE "(error|invalid|port)"; then
    RESULT_2=0
    log_info "Server correctly rejected invalid port range"
else
    RESULT_2=1
    log_warn "Server may not have rejected invalid port range"
fi
assert_test "Invalid port range rejected" $RESULT_2

# Test 10c: Client with wrong key
log_info "Test 10c: Client with wrong key"

# Start valid server
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.9.0/24"
dns = ["8.8.8.8"]
max_clients = 2
enable_nat = true
EOF

sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

# Create client with WRONG key
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-wrongkey.toml << EOF
[common]
key = \"wrong-key-12345\"
mtu = 1400
log_level = \"debug\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

# Try to connect with wrong key
log_info "Attempting connection with wrong key..."
ssh $CLIENT_HOST "timeout 15 sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-wrongkey.toml" 2>&1 &
sleep 10

# Check if client connected (it shouldn't)
CLIENT_STATUS=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>&1 || echo "not running")
if echo "$CLIENT_STATUS" | grep -qiE "(connected|10\.99\.9)"; then
    RESULT_3=1
    log_error "Client connected with wrong key - security issue!"
else
    RESULT_3=0
    log_info "Client correctly failed to connect with wrong key"
fi
cleanup_client
assert_test "Wrong key rejected" $RESULT_3

# Test 10d: Max clients limit
log_info "Test 10d: Max clients limit (max=2)"

# Create valid client config
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

# Connect first client
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client1.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
tun_device = \"ruhop-max1\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client2.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
tun_device = \"ruhop-max2\"
control_socket = \"/tmp/ruhop-max2.sock\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client3.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
tun_device = \"ruhop-max3\"
control_socket = \"/tmp/ruhop-max3.sock\"

[client]
server = \"$SERVER_IP_1\"
port_range = [$PORT_START, $PORT_END]
route_all_traffic = false
auto_reconnect = false
EOF"

log_info "Connecting client 1..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client1.toml &" &
sleep 5

log_info "Connecting client 2..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client2.toml &" &
sleep 5

# Check we have 2 connected
SERVER_STATUS=$(sudo $SERVER_RUHOP_BIN status 2>/dev/null)
SESSIONS=$(echo "$SERVER_STATUS" | grep -oP '(Active Sessions:|sessions:)\s*\K\d+' || echo "0")
log_info "Connected sessions: $SESSIONS"

if [ "$SESSIONS" -eq 2 ]; then
    log_info "2 clients connected, now trying 3rd..."

    # Try to connect 3rd client (should fail due to max_clients=2)
    ssh $CLIENT_HOST "timeout 10 sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client3.toml" 2>&1 &
    sleep 8

    # Check server still shows only 2 sessions
    SERVER_STATUS=$(sudo $SERVER_RUHOP_BIN status 2>/dev/null)
    SESSIONS=$(echo "$SERVER_STATUS" | grep -oP '(Active Sessions:|sessions:)\s*\K\d+' || echo "0")
    log_info "Sessions after 3rd client attempt: $SESSIONS"

    if [ "$SESSIONS" -le 2 ]; then
        RESULT_4=0
        log_info "Max clients limit enforced correctly"
    else
        RESULT_4=1
        log_error "Max clients limit not enforced"
    fi
else
    RESULT_4=1
    log_error "Could not establish baseline with 2 clients"
fi
assert_test "Max clients limit enforced" $RESULT_4

# Cleanup
ssh $CLIENT_HOST "sudo pkill -f 'ruhop client'" 2>/dev/null || true
cleanup_server

# Test 10e: Invalid tunnel network
log_info "Test 10e: Invalid tunnel network CIDR"

cat > /tmp/e2e-invalid-network.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "invalid-network"
EOF

if sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-invalid-network.toml 2>&1 | grep -qiE "(error|invalid|parse)"; then
    RESULT_5=0
    log_info "Server correctly rejected invalid tunnel network"
else
    RESULT_5=1
    log_warn "Server may not have rejected invalid tunnel network"
fi
assert_test "Invalid tunnel network rejected" $RESULT_5

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
