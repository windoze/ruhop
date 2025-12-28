#!/bin/bash
# Test 12: DNS Proxy with ipset/nftset Integration
# Tests: DNS proxy on client adds resolved IPs to ipset/nftset
#
# This test requires:
# - Linux server and client (ipset/nftset are Linux-only)
# - Root privileges on both machines
# - The nft or ipset command available on client

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TEST_NAME="DNS Proxy with ipset/nftset"
log_info "=========================================="
log_info "Starting Test: $TEST_NAME"
log_info "=========================================="

# Test-specific variables
IPSET_NAME="ruhop_e2e_test"
NFT_TABLE="ruhop_e2e"
NFT_SET="dns_resolved"
DNS_PORT=15353

# ============================================================================
# Helper Functions
# ============================================================================

# Check if nftables is available on client
check_nftables_available() {
    if ssh $CLIENT_HOST "command -v nft" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Check if ipset is available on client
check_ipset_available() {
    if ssh $CLIENT_HOST "command -v ipset" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Cleanup nftables set on client
cleanup_nftset() {
    log_info "Cleaning up nftables set..."
    ssh $CLIENT_HOST "sudo nft delete table ip $NFT_TABLE" 2>/dev/null || true
}

# Cleanup ipset on client
cleanup_ipset() {
    log_info "Cleaning up ipset..."
    ssh $CLIENT_HOST "sudo ipset destroy $IPSET_NAME" 2>/dev/null || true
}

# Check if IP is in nftables set
check_ip_in_nftset() {
    local ip=$1
    # Use nft list set and grep for the IP address
    if ssh $CLIENT_HOST "sudo nft list set ip $NFT_TABLE $NFT_SET 2>/dev/null | grep -q '$ip'"; then
        return 0
    else
        return 1
    fi
}

# Check if IP is in ipset
check_ip_in_ipset() {
    local ip=$1
    if ssh $CLIENT_HOST "sudo ipset test $IPSET_NAME $ip" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# List IPs in nftables set
list_nftset_ips() {
    ssh $CLIENT_HOST "sudo nft list set ip $NFT_TABLE $NFT_SET" 2>/dev/null || echo "Set not found"
}

# List IPs in ipset
list_ipset_ips() {
    ssh $CLIENT_HOST "sudo ipset list $IPSET_NAME" 2>/dev/null || echo "Set not found"
}

# Cleanup before test
cleanup_all
cleanup_nftset
cleanup_ipset

# ============================================================================
# Test 1: DNS proxy with nftset (preferred backend)
# ============================================================================
log_info "Test 1: DNS proxy with nftset integration"

# Check if nftables is available
if ! check_nftables_available; then
    log_warn "nftables not available on client, skipping nftset test"
    RESULT_1=0  # Skip test
    SKIPPED_1=1
else
    SKIPPED_1=0

    # Generate server config with DNS proxy enabled
    SERVER_CONFIG="/tmp/e2e-server-dns-ipset.toml"
    cat > "$SERVER_CONFIG" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52200, 52210]
tunnel_network = "10.99.0.0/24"
dns_proxy = true
dns_servers = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
TOML
    log_info "Server config: $SERVER_CONFIG"

    # Create client config with DNS proxy and ipset enabled (nftables backend)
    ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-dns-ipset.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
use_nftables = true

[client]
server = \"$SERVER_IP_1\"
port_range = [52200, 52210]
route_all_traffic = false
auto_reconnect = false

[client.dns_proxy]
enabled = true
port = $DNS_PORT
ipset = \"$NFT_TABLE/$NFT_SET\"
EOF"

    log_info "Starting server with DNS proxy..."
    sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG" &
    SERVER_PID=$!
    log_info "Server PID: $SERVER_PID"

    # Wait for server
    if ! wait_for_server 30; then
        cleanup_all
        cleanup_nftset
        exit 1
    fi

    log_info "Starting client with DNS proxy and nftset on $CLIENT_HOST..."
    ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-ipset.toml &" &

    # Wait for client to connect
    if ! wait_for_client 30; then
        cleanup_all
        cleanup_nftset
        exit 1
    fi

    # Wait for DNS proxy to start
    sleep 3

    # Get client tunnel IP
    CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")
    log_info "Client tunnel IP: $CLIENT_TUNNEL_IP"

    # Query some domains to populate the ipset
    log_info "Making DNS queries to populate nftset..."
    DOMAINS=("google.com" "cloudflare.com" "github.com")
    declare -a RESOLVED_IPS

    for domain in "${DOMAINS[@]}"; do
        log_info "Resolving $domain..."
        IP=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p $DNS_PORT $domain A +short +time=5 | head -1" 2>/dev/null || echo "")
        if [ -n "$IP" ]; then
            log_info "  $domain -> $IP"
            RESOLVED_IPS+=("$IP")
        else
            log_warn "  Failed to resolve $domain"
        fi
        sleep 1
    done

    # Wait for ipset queue to flush (default 100ms interval)
    sleep 2

    # Verify IPs were added to nftset
    log_info "Verifying IPs in nftset..."
    log_info "Current nftset contents:"
    list_nftset_ips

    FOUND_COUNT=0
    for ip in "${RESOLVED_IPS[@]}"; do
        if check_ip_in_nftset "$ip"; then
            log_info "  IP $ip found in nftset"
            FOUND_COUNT=$((FOUND_COUNT + 1))
        else
            log_warn "  IP $ip NOT found in nftset"
        fi
    done

    if [ ${#RESOLVED_IPS[@]} -eq 0 ]; then
        log_error "No IPs were resolved"
        RESULT_1=1
    elif [ $FOUND_COUNT -ge 1 ]; then
        log_info "Found $FOUND_COUNT/${#RESOLVED_IPS[@]} resolved IPs in nftset"
        RESULT_1=0
    else
        log_error "No resolved IPs found in nftset"
        RESULT_1=1
    fi

    cleanup_all
    cleanup_nftset
    sleep 2
fi

assert_test "DNS proxy with nftset" $RESULT_1

# ============================================================================
# Test 2: DNS proxy with ipset (legacy backend)
# ============================================================================
log_info "Test 2: DNS proxy with ipset integration (legacy backend)"

# Check if ipset is available
if ! check_ipset_available; then
    log_warn "ipset command not available on client, skipping ipset test"
    RESULT_2=0  # Skip test
    SKIPPED_2=1
else
    SKIPPED_2=0

    # Generate server config with DNS proxy enabled
    SERVER_CONFIG="/tmp/e2e-server-dns-ipset.toml"
    cat > "$SERVER_CONFIG" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52200, 52210]
tunnel_network = "10.99.0.0/24"
dns_proxy = true
dns_servers = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
TOML

    # Create client config with DNS proxy and ipset enabled (ipset backend)
    ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-dns-ipset-legacy.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
use_nftables = false

[client]
server = \"$SERVER_IP_1\"
port_range = [52200, 52210]
route_all_traffic = false
auto_reconnect = false

[client.dns_proxy]
enabled = true
port = $DNS_PORT
ipset = \"$IPSET_NAME\"
EOF"

    log_info "Starting server with DNS proxy..."
    sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG" &
    SERVER_PID=$!
    log_info "Server PID: $SERVER_PID"

    # Wait for server
    if ! wait_for_server 30; then
        cleanup_all
        cleanup_ipset
        exit 1
    fi

    log_info "Starting client with DNS proxy and ipset on $CLIENT_HOST..."
    ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-ipset-legacy.toml &" &

    # Wait for client to connect
    if ! wait_for_client 30; then
        cleanup_all
        cleanup_ipset
        exit 1
    fi

    # Wait for DNS proxy to start
    sleep 3

    # Get client tunnel IP
    CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")
    log_info "Client tunnel IP: $CLIENT_TUNNEL_IP"

    # Query some domains to populate the ipset
    log_info "Making DNS queries to populate ipset..."
    DOMAINS=("amazon.com" "microsoft.com" "apple.com")
    declare -a RESOLVED_IPS

    for domain in "${DOMAINS[@]}"; do
        log_info "Resolving $domain..."
        IP=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p $DNS_PORT $domain A +short +time=5 | head -1" 2>/dev/null || echo "")
        if [ -n "$IP" ]; then
            log_info "  $domain -> $IP"
            RESOLVED_IPS+=("$IP")
        else
            log_warn "  Failed to resolve $domain"
        fi
        sleep 1
    done

    # Wait for ipset queue to flush
    sleep 2

    # Verify IPs were added to ipset
    log_info "Verifying IPs in ipset..."
    log_info "Current ipset contents:"
    list_ipset_ips

    FOUND_COUNT=0
    for ip in "${RESOLVED_IPS[@]}"; do
        if check_ip_in_ipset "$ip"; then
            log_info "  IP $ip found in ipset"
            FOUND_COUNT=$((FOUND_COUNT + 1))
        else
            log_warn "  IP $ip NOT found in ipset"
        fi
    done

    if [ ${#RESOLVED_IPS[@]} -eq 0 ]; then
        log_error "No IPs were resolved"
        RESULT_2=1
    elif [ $FOUND_COUNT -ge 1 ]; then
        log_info "Found $FOUND_COUNT/${#RESOLVED_IPS[@]} resolved IPs in ipset"
        RESULT_2=0
    else
        log_error "No resolved IPs found in ipset"
        RESULT_2=1
    fi

    cleanup_all
    cleanup_ipset
    sleep 2
fi

assert_test "DNS proxy with ipset (legacy)" $RESULT_2

# ============================================================================
# Test 3: Multiple DNS queries accumulate in ipset
# ============================================================================
log_info "Test 3: Multiple DNS queries accumulate IPs in set"

# Use nftables for this test if available, otherwise ipset
if check_nftables_available; then
    USE_NFT=1
    IPSET_CONFIG="$NFT_TABLE/$NFT_SET"
    NFT_FLAG="true"
else
    USE_NFT=0
    IPSET_CONFIG="$IPSET_NAME"
    NFT_FLAG="false"
fi

# Generate server config
SERVER_CONFIG="/tmp/e2e-server-dns-ipset.toml"
cat > "$SERVER_CONFIG" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$SERVER_IP_1"
port_range = [52200, 52210]
tunnel_network = "10.99.0.0/24"
dns_proxy = true
dns_servers = ["8.8.8.8", "1.1.1.1"]
max_clients = 10
enable_nat = true
TOML

# Create client config
ssh $CLIENT_HOST "cat > $CLIENT_TMP_DIR/client-dns-multi.toml << EOF
[common]
key = \"$TEST_KEY\"
mtu = 1400
log_level = \"debug\"
use_nftables = $NFT_FLAG

[client]
server = \"$SERVER_IP_1\"
port_range = [52200, 52210]
route_all_traffic = false
auto_reconnect = false

[client.dns_proxy]
enabled = true
port = $DNS_PORT
ipset = \"$IPSET_CONFIG\"
EOF"

log_info "Starting server with DNS proxy..."
sudo $SERVER_RUHOP_BIN server -c "$SERVER_CONFIG" &
SERVER_PID=$!

if ! wait_for_server 30; then
    cleanup_all
    [ $USE_NFT -eq 1 ] && cleanup_nftset || cleanup_ipset
    exit 1
fi

log_info "Starting client with DNS proxy on $CLIENT_HOST..."
ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN client -c $CLIENT_TMP_DIR/client-dns-multi.toml &" &

if ! wait_for_client 30; then
    cleanup_all
    [ $USE_NFT -eq 1 ] && cleanup_nftset || cleanup_ipset
    exit 1
fi

sleep 3

CLIENT_TUNNEL_IP=$(ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -oP 'tunnel_ip:\s*\K[0-9.]+' || echo "10.99.0.2")
log_info "Client tunnel IP: $CLIENT_TUNNEL_IP"

# Query multiple domains in batches
log_info "Making multiple DNS queries in batches..."
BATCH1_DOMAINS=("google.com" "cloudflare.com")
BATCH2_DOMAINS=("github.com" "amazon.com")
declare -a ALL_IPS

# First batch
log_info "Batch 1:"
for domain in "${BATCH1_DOMAINS[@]}"; do
    IP=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p $DNS_PORT $domain A +short +time=5 | head -1" 2>/dev/null || echo "")
    if [ -n "$IP" ]; then
        log_info "  $domain -> $IP"
        ALL_IPS+=("$IP")
    fi
done

sleep 2

# Check first batch
if [ $USE_NFT -eq 1 ]; then
    BATCH1_COUNT=$(list_nftset_ips | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
else
    BATCH1_COUNT=$(list_ipset_ips | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
fi
log_info "IPs in set after batch 1: $BATCH1_COUNT"

# Second batch
log_info "Batch 2:"
for domain in "${BATCH2_DOMAINS[@]}"; do
    IP=$(ssh $CLIENT_HOST "dig @$CLIENT_TUNNEL_IP -p $DNS_PORT $domain A +short +time=5 | head -1" 2>/dev/null || echo "")
    if [ -n "$IP" ]; then
        log_info "  $domain -> $IP"
        ALL_IPS+=("$IP")
    fi
done

sleep 2

# Check second batch
if [ $USE_NFT -eq 1 ]; then
    BATCH2_COUNT=$(list_nftset_ips | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
else
    BATCH2_COUNT=$(list_ipset_ips | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
fi
log_info "IPs in set after batch 2: $BATCH2_COUNT"

# Verify accumulation
if [ $BATCH2_COUNT -gt $BATCH1_COUNT ] || [ $BATCH2_COUNT -ge 2 ]; then
    log_info "IPs accumulated correctly: $BATCH1_COUNT -> $BATCH2_COUNT"
    RESULT_3=0
else
    log_error "IPs did not accumulate as expected"
    RESULT_3=1
fi

cleanup_all
[ $USE_NFT -eq 1 ] && cleanup_nftset || cleanup_ipset

assert_test "Multiple DNS queries accumulate IPs" $RESULT_3

# ============================================================================
# Summary
# ============================================================================
log_info "=========================================="
log_info "Test Summary: $TEST_NAME"
log_info "=========================================="
PASSED=0
FAILED=0
SKIPPED=0

if [ "${SKIPPED_1:-0}" -eq 1 ]; then
    log_warn "Test 1 (nftset): SKIPPED (nftables not available)"
    SKIPPED=$((SKIPPED+1))
elif [ $RESULT_1 -eq 0 ]; then
    PASSED=$((PASSED+1))
else
    FAILED=$((FAILED+1))
fi

if [ "${SKIPPED_2:-0}" -eq 1 ]; then
    log_warn "Test 2 (ipset): SKIPPED (ipset not available)"
    SKIPPED=$((SKIPPED+1))
elif [ $RESULT_2 -eq 0 ]; then
    PASSED=$((PASSED+1))
else
    FAILED=$((FAILED+1))
fi

[ $RESULT_3 -eq 0 ] && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))

log_info "Passed: $PASSED / 3"
log_info "Failed: $FAILED / 3"
log_info "Skipped: $SKIPPED / 3"

if [ $FAILED -gt 0 ]; then
    log_error "TEST FAILED"
    exit 1
else
    log_test "TEST PASSED"
    exit 0
fi
