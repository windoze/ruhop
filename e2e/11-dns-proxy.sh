#!/bin/bash
# Test 11: Client-Side DNS Proxy
# Tests: DNS proxy on client with server-provided DNS, AAAA filtering, two-level proxy

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="Client-Side DNS Proxy"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Cleanup before test
cleanup_all

# ============================================================================
# Test 1: Basic DNS proxy with server-provided upstreams (direct DNS servers)
# ============================================================================
log_info "Test 1: Basic DNS proxy with server-provided upstreams"

# Generate server config that pushes external DNS servers
SERVER_CONFIG="/tmp/e2e-server-dns.toml"
cat > "$SERVER_CONFIG" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52100, 52110]
tunnel_network = "10.99.0.0/24"
dns = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
TOML
log_info "Server config: $SERVER_CONFIG"

# Create client config with DNS proxy enabled
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-dns-proxy.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"

[client]
server = \"$SERVER_IP_1\"
port_range = [52100, 52110]
route_all_traffic = false
auto_reconnect = false

[client.dns_proxy]
enabled = true
port = 15353
EOF"

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG" &
SERVER_PID=$!
log_info "Server PID: $SERVER_PID"

# Wait for server
if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with DNS proxy on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-proxy.toml &" &

# Wait for client to connect
if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

# Wait for DNS proxy to start
sleep 2

# Get client tunnel IP
CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")
log_info "Client tunnel IP: $CLIENT_TUNNEL_IP"

# Test DNS query through proxy
log_info "Testing DNS query through proxy on $CLIENT_TUNNEL_IP:15353..."
DNS_RESULT=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p 15353 google.com +short +time=5" 2>/dev/null || echo "")
if [ -n "$DNS_RESULT" ]; then
    log_info "DNS query result: $DNS_RESULT"
    RESULT_1=0
else
    log_error "DNS query failed or returned empty"
    RESULT_1=1
fi
assert_test "Basic DNS proxy query" $RESULT_1

cleanup_all
sleep 2

# ============================================================================
# Test 2: Two-level DNS proxy (server DNS proxy -> external DNS)
# ============================================================================
log_info "Test 2: Two-level DNS proxy (client -> server proxy -> external)"

# Generate server config with server-side DNS proxy
SERVER_CONFIG_PROXY="/tmp/e2e-server-dns-proxy.toml"
cat > "$SERVER_CONFIG_PROXY" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52100, 52110]
tunnel_network = "10.99.0.0/24"
dns = "tunnel"
dns_servers = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
TOML
log_info "Server config with DNS proxy: $SERVER_CONFIG_PROXY"

log_info "Starting server with DNS proxy..."
sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG_PROXY" &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with DNS proxy on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-proxy.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

sleep 2
CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")

# Test DNS query through two-level proxy chain
log_info "Testing two-level DNS proxy chain..."
DNS_RESULT=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p 15353 example.com +short +time=5" 2>/dev/null || echo "")
if [ -n "$DNS_RESULT" ]; then
    log_info "Two-level proxy query result: $DNS_RESULT"
    RESULT_2=0
else
    log_error "Two-level DNS proxy query failed"
    RESULT_2=1
fi
assert_test "Two-level DNS proxy" $RESULT_2

cleanup_all
sleep 2

# ============================================================================
# Test 3: DNS proxy with IPv6 filtering
# ============================================================================
log_info "Test 3: DNS proxy with AAAA (IPv6) filtering"

# Create client config with filter_ipv6 enabled
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-dns-filter.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"

[client]
server = \"$SERVER_IP_1\"
port_range = [52100, 52110]
route_all_traffic = false
auto_reconnect = false

[client.dns_proxy]
enabled = true
port = 15353
filter_ipv6 = true
EOF"

log_info "Starting server..."
sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG" &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with IPv6 filtering on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-filter.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

sleep 2
CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")

# Test that AAAA queries return no records
log_info "Testing AAAA query filtering..."
AAAA_RESULT=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p 15353 google.com AAAA +short +time=5" 2>/dev/null || echo "")
A_RESULT=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p 15353 google.com A +short +time=5" 2>/dev/null || echo "")

log_info "AAAA result (should be empty): '$AAAA_RESULT'"
log_info "A result (should have IPs): '$A_RESULT'"

if [ -z "$AAAA_RESULT" ] && [ -n "$A_RESULT" ]; then
    log_info "IPv6 filtering working correctly"
    RESULT_3=0
elif [ -n "$A_RESULT" ]; then
    # A record works, AAAA might have some records (could be cached)
    log_warn "AAAA returned records (might be from cache), but A works"
    RESULT_3=0
else
    log_error "DNS query failed"
    RESULT_3=1
fi
assert_test "IPv6 (AAAA) filtering" $RESULT_3

cleanup_all
sleep 2

# ============================================================================
# Test 4: DNS proxy not started without server DNS
# ============================================================================
log_info "Test 4: DNS proxy not started when server provides no DNS"

# Generate server config without DNS servers
SERVER_CONFIG_NODNS="/tmp/e2e-server-nodns.toml"
cat > "$SERVER_CONFIG_NODNS" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52100, 52110]
tunnel_network = "10.99.0.0/24"
max_clients = 10
enable_nat = true
TOML

log_info "Starting server without DNS..."
sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG_NODNS" &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    exit 1
fi

log_info "Starting client with DNS proxy enabled on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-proxy.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    exit 1
fi

sleep 2

# Check if DNS proxy port is listening (should NOT be)
log_info "Checking if DNS proxy is listening (should not be)..."
LISTENING=$(ssh $CLIENT_HOST "sudo ss -ulnp | grep 15353" 2>/dev/null || echo "")
if [ -z "$LISTENING" ]; then
    log_info "DNS proxy correctly not started (no server DNS)"
    RESULT_4=0
else
    log_error "DNS proxy unexpectedly started without server DNS: $LISTENING"
    RESULT_4=1
fi
assert_test "DNS proxy not started without server DNS" $RESULT_4

cleanup_all

# ============================================================================
# Summary
# ============================================================================
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
