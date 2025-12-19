#!/bin/bash
# Test 2: Port Hopping
# Tests: Verify traffic is distributed across multiple ports

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Port Hopping"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

# Use a wider port range for this test
PORT_START=52100
PORT_END=52120

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.1.0/24"
dns = ["8.8.8.8"]
max_clients = 10
enable_nat = true
EOF

# Create client config on client host
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

log_info "Starting server on ports $PORT_START-$PORT_END..."
sudo $SERVER_RUHOP_BIN server -c /tmp/e2e-server.toml &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

# Verify server is listening on multiple ports
log_info "Test 2a: Verify server listens on multiple ports"
LISTENING_PORTS=$(sudo ss -ulnp | grep -c ":521" || echo "0")
log_info "Found $LISTENING_PORTS listening UDP ports in range"
if [ "$LISTENING_PORTS" -ge 10 ]; then
    RESULT_1=0
else
    RESULT_1=1
fi
assert_test "Server listens on multiple ports" $RESULT_1

log_info "Starting client on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Generate traffic by doing multiple pings
log_info "Generating traffic with continuous pings..."
ssh $CLIENT_HOST "ping -c 50 -i 0.1 10.99.1.1" > /dev/null 2>&1 &
PING_PID=$!

# Capture packets on server to verify port distribution
log_info "Test 2b: Capturing traffic to verify port distribution..."
sudo timeout 10 tcpdump -i any -c 100 "udp portrange $PORT_START-$PORT_END" -nn 2>/dev/null | tee /tmp/port-capture.txt &
TCPDUMP_PID=$!
sleep 8
wait $PING_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

# Analyze captured packets for port distribution
UNIQUE_PORTS=$(grep -oP "\.521[0-9]{2}" /tmp/port-capture.txt 2>/dev/null | sort -u | wc -l || echo "0")
log_info "Traffic observed on $UNIQUE_PORTS unique ports"
if [ "$UNIQUE_PORTS" -ge 3 ]; then
    RESULT_2=0
    log_info "Port hopping is working - traffic distributed across multiple ports"
else
    RESULT_2=1
    log_warn "Port hopping may not be working - limited port distribution"
fi
assert_test "Traffic distributed across ports" $RESULT_2

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
log_info "Passed: $PASSED / 2"
log_info "Failed: $FAILED / 2"

if [ $FAILED -gt 0 ]; then
    log_error "TEST FAILED"
    exit 1
else
    log_test "TEST PASSED"
    exit 0
fi
