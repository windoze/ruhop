#!/bin/bash
# Test 7: Lifecycle Scripts
# Tests: on_connect and on_disconnect script execution

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Lifecycle Scripts"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52600
PORT_END=52610

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.6.0/24"
dns = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
EOF

# Create lifecycle scripts on client host
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/on_connect.sh << 'SCRIPT'
#!/bin/bash
# Arguments: <local_ip> <prefix_len> <tun_device> <dns_servers>
echo \"CONNECT: local_ip=\$1 prefix_len=\$2 tun_device=\$3 dns_servers=\$4\" > /tmp/ruhop-connect.log
echo \"timestamp=\$(date +%s)\" >> /tmp/ruhop-connect.log
echo \"all_args=\$@\" >> /tmp/ruhop-connect.log
SCRIPT
chmod +x $CLIENT_TMP_DIR/on_connect.sh"

ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/on_disconnect.sh << 'SCRIPT'
#!/bin/bash
# Arguments: <local_ip> <prefix_len> <tun_device> <dns_servers>
echo \"DISCONNECT: local_ip=\$1 prefix_len=\$2 tun_device=\$3 dns_servers=\$4\" > /tmp/ruhop-disconnect.log
echo \"timestamp=\$(date +%s)\" >> /tmp/ruhop-disconnect.log
echo \"all_args=\$@\" >> /tmp/ruhop-disconnect.log
SCRIPT
chmod +x $CLIENT_TMP_DIR/on_disconnect.sh"

# Clean up any previous log files
ssh $CLIENT_HOST "rm -f /tmp/ruhop-connect.log /tmp/ruhop-disconnect.log"

# Create client config with lifecycle scripts
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
on_connect = \"$CLIENT_TMP_DIR/on_connect.sh\"
on_disconnect = \"$CLIENT_TMP_DIR/on_disconnect.sh\"
EOF"

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with lifecycle scripts..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Wait a bit for scripts to execute
sleep 3

# Test 7a: Verify on_connect script was executed
log_info "Test 7a: Verify on_connect script executed"
CONNECT_LOG=$(ssh $CLIENT_HOST "cat /tmp/ruhop-connect.log 2>/dev/null" || echo "")
log_info "Connect log: $CONNECT_LOG"

if echo "$CONNECT_LOG" | grep -q "CONNECT:"; then
    RESULT_1=0
    log_info "on_connect script was executed"
else
    RESULT_1=1
    log_error "on_connect script was NOT executed"
fi
assert_test "on_connect script executed" $RESULT_1

# Test 7b: Verify correct arguments passed to on_connect
log_info "Test 7b: Verify on_connect received correct arguments"
RESULT_2=1
if echo "$CONNECT_LOG" | grep -q "local_ip=10.99.6"; then
    log_info "local_ip argument correct"
    if echo "$CONNECT_LOG" | grep -q "prefix_len=24"; then
        log_info "prefix_len argument correct"
        if echo "$CONNECT_LOG" | grep -q "tun_device="; then
            log_info "tun_device argument present"
            RESULT_2=0
        fi
    fi
fi
assert_test "on_connect arguments correct" $RESULT_2

# Test 7c: Verify DNS servers passed to script
log_info "Test 7c: Verify DNS servers passed to on_connect"
if echo "$CONNECT_LOG" | grep -q "dns_servers=.*8.8.8.8"; then
    RESULT_3=0
    log_info "DNS servers passed correctly"
else
    RESULT_3=1
    log_warn "DNS servers may not be passed correctly"
fi
assert_test "DNS servers in on_connect" $RESULT_3

# Stop client to trigger on_disconnect
log_info "Stopping client to trigger on_disconnect..."
ssh $CLIENT_HOST "sudo pkill -SIGTERM -f 'ruhop client'" 2>/dev/null || true
sleep 5

# Test 7d: Verify on_disconnect script was executed
log_info "Test 7d: Verify on_disconnect script executed"
DISCONNECT_LOG=$(ssh $CLIENT_HOST "cat /tmp/ruhop-disconnect.log 2>/dev/null" || echo "")
log_info "Disconnect log: $DISCONNECT_LOG"

if echo "$DISCONNECT_LOG" | grep -q "DISCONNECT:"; then
    RESULT_4=0
    log_info "on_disconnect script was executed"
else
    RESULT_4=1
    log_error "on_disconnect script was NOT executed"
fi
assert_test "on_disconnect script executed" $RESULT_4

# Test 7e: Verify on_disconnect received same arguments
log_info "Test 7e: Verify on_disconnect received correct arguments"
if echo "$DISCONNECT_LOG" | grep -q "local_ip=10.99.6"; then
    RESULT_5=0
else
    RESULT_5=1
fi
assert_test "on_disconnect arguments correct" $RESULT_5

# Cleanup
cleanup_all
ssh $CLIENT_HOST "rm -f /tmp/ruhop-connect.log /tmp/ruhop-disconnect.log"

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
