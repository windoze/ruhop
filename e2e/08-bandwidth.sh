#!/bin/bash
# Test 8: Bandwidth/Throughput Test
# Tests: VPN throughput using iperf3

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Bandwidth/Throughput"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52700
PORT_END=52710

# Generate server config
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "info"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.7.0/24"
dns = ["8.8.8.8"]
max_clients = 10
enable_nat = true
EOF

# Create client config
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"info\"

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

# Verify connectivity first
log_info "Verifying tunnel connectivity..."
test_ping_from_client "10.99.7.1" 3 5
if [ $? -ne 0 ]; then
    log_error "Tunnel connectivity failed, cannot proceed with bandwidth test"
    cleanup_all
    exit 1
fi

# Test 8a: TCP bandwidth test (server -> client)
log_info "Test 8a: TCP bandwidth (server -> client)"

# Start iperf3 server on tunnel IP
iperf3 -s --bind 10.99.7.1 -D -1
sleep 2

# Run iperf3 client from client host
IPERF_RESULT=$(ssh $CLIENT_HOST "iperf3 -c 10.99.7.1 -t 10 -J" 2>/dev/null || echo "{}")
sleep 1

# Parse results
TCP_BANDWIDTH=$(echo "$IPERF_RESULT" | grep -oP '"bits_per_second"\s*:\s*\K[0-9.e+]+' | head -1 || echo "0")
if [ -n "$TCP_BANDWIDTH" ] && [ "$TCP_BANDWIDTH" != "0" ]; then
    TCP_MBPS=$(echo "scale=2; $TCP_BANDWIDTH / 1000000" | bc 2>/dev/null || echo "N/A")
    log_info "TCP Bandwidth: ${TCP_MBPS} Mbps"
    # Consider pass if we get > 10 Mbps (reasonable for VPN over 1Gbps link)
    if [ $(echo "$TCP_BANDWIDTH > 10000000" | bc 2>/dev/null || echo "0") -eq 1 ]; then
        RESULT_1=0
    else
        RESULT_1=1
        log_warn "TCP bandwidth seems low"
    fi
else
    TCP_MBPS="N/A"
    RESULT_1=1
    log_error "Failed to measure TCP bandwidth"
fi
assert_test "TCP bandwidth measurement" $RESULT_1

# Test 8b: TCP bandwidth (client -> server, reverse)
log_info "Test 8b: TCP bandwidth (client -> server)"

# Start iperf3 server again
pkill iperf3 2>/dev/null || true
sleep 1
iperf3 -s --bind 10.99.7.1 -D -1
sleep 2

# Run reverse test
IPERF_REV_RESULT=$(ssh $CLIENT_HOST "iperf3 -c 10.99.7.1 -t 10 -R -J" 2>/dev/null || echo "{}")

TCP_REV_BANDWIDTH=$(echo "$IPERF_REV_RESULT" | grep -oP '"bits_per_second"\s*:\s*\K[0-9.e+]+' | head -1 || echo "0")
if [ -n "$TCP_REV_BANDWIDTH" ] && [ "$TCP_REV_BANDWIDTH" != "0" ]; then
    TCP_REV_MBPS=$(echo "scale=2; $TCP_REV_BANDWIDTH / 1000000" | bc 2>/dev/null || echo "N/A")
    log_info "TCP Reverse Bandwidth: ${TCP_REV_MBPS} Mbps"
    if [ $(echo "$TCP_REV_BANDWIDTH > 10000000" | bc 2>/dev/null || echo "0") -eq 1 ]; then
        RESULT_2=0
    else
        RESULT_2=1
    fi
else
    TCP_REV_MBPS="N/A"
    RESULT_2=1
fi
assert_test "TCP reverse bandwidth measurement" $RESULT_2

pkill iperf3 2>/dev/null || true

# Test 8c: UDP bandwidth test
log_info "Test 8c: UDP bandwidth test"

iperf3 -s --bind 10.99.7.1 -D -1
sleep 2

IPERF_UDP_RESULT=$(ssh $CLIENT_HOST "iperf3 -c 10.99.7.1 -u -b 500M -t 10 -J" 2>/dev/null || echo "{}")

UDP_BANDWIDTH=$(echo "$IPERF_UDP_RESULT" | grep -oP '"bits_per_second"\s*:\s*\K[0-9.e+]+' | tail -1 || echo "0")
UDP_LOSS=$(echo "$IPERF_UDP_RESULT" | grep -oP '"lost_percent"\s*:\s*\K[0-9.]+' || echo "N/A")

if [ -n "$UDP_BANDWIDTH" ] && [ "$UDP_BANDWIDTH" != "0" ]; then
    UDP_MBPS=$(echo "scale=2; $UDP_BANDWIDTH / 1000000" | bc 2>/dev/null || echo "N/A")
    log_info "UDP Bandwidth: ${UDP_MBPS} Mbps"
    log_info "UDP Packet Loss: ${UDP_LOSS}%"
    RESULT_3=0
else
    UDP_MBPS="N/A"
    RESULT_3=1
fi
assert_test "UDP bandwidth measurement" $RESULT_3

pkill iperf3 2>/dev/null || true

# Test 8d: Check VPN stats
log_info "Test 8d: Check VPN traffic statistics"
SERVER_STATS=$(sudo $SERVER_RUHOP_BIN status 2>/dev/null)
log_info "Server stats after bandwidth test:"
echo "$SERVER_STATS"

if echo "$SERVER_STATS" | grep -qE "(Bytes RX|Bytes TX|Packets RX|Packets TX)"; then
    RESULT_4=0
else
    RESULT_4=1
fi
assert_test "VPN statistics available" $RESULT_4

# Cleanup
cleanup_all

# Summary
log_info "=========================================="
log_info "Test Summary: $TEST_NAME"
log_info "=========================================="
log_info "TCP Bandwidth (S->C): $TCP_MBPS Mbps"
log_info "TCP Bandwidth (C->S): $TCP_REV_MBPS Mbps"
log_info "UDP Bandwidth: $UDP_MBPS Mbps"
log_info "UDP Packet Loss: $UDP_LOSS%"
log_info ""
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
