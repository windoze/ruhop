#!/bin/bash
# Test 4: Data Transfer and Fragmentation
# Tests: Large payload transfer, packet fragmentation, data integrity

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Data Transfer and Fragmentation"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

PORT_START=52300
PORT_END=52310

# Generate server config with specific MTU
cat > /tmp/e2e-server.toml << EOF
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [$PORT_START, $PORT_END]
tunnel_network = "10.99.3.0/24"
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

# Test 4a: Small payload (ping with default size)
log_info "Test 4a: Small payload transfer (default ping)"
test_ping_from_client "10.99.3.1" 10 5
RESULT_1=$?
assert_test "Small payload transfer" $RESULT_1

# Test 4b: Large payload that requires fragmentation
log_info "Test 4b: Large payload requiring fragmentation (ping -s 4000)"
if ssh $CLIENT_HOST "ping -c 5 -s 4000 -W 10 10.99.3.1" > /dev/null 2>&1; then
    RESULT_2=0
    log_info "Large payload (4000 bytes) transfer successful"
else
    RESULT_2=1
    log_error "Large payload transfer failed"
fi
assert_test "Large payload (fragmented) transfer" $RESULT_2

# Test 4c: Maximum safe payload
log_info "Test 4c: Maximum safe payload (ping -s 8000)"
if ssh $CLIENT_HOST "ping -c 5 -s 8000 -W 10 10.99.3.1" > /dev/null 2>&1; then
    RESULT_3=0
    log_info "Maximum payload (8000 bytes) transfer successful"
else
    RESULT_3=1
    log_error "Maximum payload transfer failed"
fi
assert_test "Maximum payload transfer" $RESULT_3

# Test 4d: Data integrity with netcat file transfer
log_info "Test 4d: File transfer integrity test"

# Generate a test file on client
ssh $CLIENT_HOST "dd if=/dev/urandom of=$CLIENT_TMP_DIR/testfile.bin bs=1M count=5 2>/dev/null"
ssh $CLIENT_HOST "md5sum $CLIENT_TMP_DIR/testfile.bin | cut -d' ' -f1" > /tmp/client_md5.txt
CLIENT_MD5=$(cat /tmp/client_md5.txt)
log_info "Client file MD5: $CLIENT_MD5"

# Start netcat listener on server
nc -l -p 9999 > /tmp/received.bin &
NC_PID=$!
sleep 1

# Send file from client through tunnel
log_info "Sending 5MB file through tunnel..."
ssh $CLIENT_HOST "nc -w 10 10.99.3.1 9999 < $CLIENT_TMP_DIR/testfile.bin"
sleep 2

# Verify received file
if [ -f /tmp/received.bin ]; then
    SERVER_MD5=$(md5sum /tmp/received.bin | cut -d' ' -f1)
    log_info "Server received file MD5: $SERVER_MD5"
    if [ "$CLIENT_MD5" == "$SERVER_MD5" ]; then
        RESULT_4=0
        log_info "File transfer integrity verified!"
    else
        RESULT_4=1
        log_error "MD5 mismatch! Data corruption detected."
    fi
else
    RESULT_4=1
    log_error "File not received on server"
fi
kill $NC_PID 2>/dev/null || true
assert_test "File transfer integrity" $RESULT_4

# Test 4e: Bidirectional transfer
log_info "Test 4e: Bidirectional data transfer"

# Generate file on server
dd if=/dev/urandom of=/tmp/server_testfile.bin bs=1M count=2 2>/dev/null
SERVER_ORIG_MD5=$(md5sum /tmp/server_testfile.bin | cut -d' ' -f1)
log_info "Server file MD5: $SERVER_ORIG_MD5"

# Start netcat listener on client
ssh $CLIENT_HOST "nc -l -p 9998 > $CLIENT_TMP_DIR/received_from_server.bin &"
sleep 1

# Send file from server to client through tunnel
nc -w 10 $(ssh $CLIENT_HOST "ip addr show | grep -oP '10\.99\.3\.\d+' | head -1") 9998 < /tmp/server_testfile.bin
sleep 2

# Verify on client
CLIENT_RECV_MD5=$(ssh $CLIENT_HOST "md5sum $CLIENT_TMP_DIR/received_from_server.bin 2>/dev/null | cut -d' ' -f1" || echo "error")
log_info "Client received file MD5: $CLIENT_RECV_MD5"

if [ "$SERVER_ORIG_MD5" == "$CLIENT_RECV_MD5" ]; then
    RESULT_5=0
    log_info "Bidirectional transfer verified!"
else
    RESULT_5=1
    log_error "Bidirectional transfer failed"
fi
assert_test "Bidirectional data transfer" $RESULT_5

# Cleanup
cleanup_all
rm -f /tmp/received.bin /tmp/server_testfile.bin /tmp/client_md5.txt

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
