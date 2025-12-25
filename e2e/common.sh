#!/bin/bash
# Common utilities for E2E tests
#
# This file contains configuration variables and helper functions for running
# E2E tests. All host-specific settings can be overridden via environment
# variables or by creating a local config file at e2e/config.local.sh

# Load local config if exists (for site-specific overrides)
# config.local.sh looks like this:
###########################################################
# #!/bin/bash
# # Local configuration for E2E tests
# # This file should NOT be committed to version control

# # Server Configuration
# SERVER_RUHOP_BIN="/path/to/ruhop/target/x86_64-unknown-linux-musl/release/ruhop"
# SERVER_IP_1="192.168.1.100"
# SERVER_IP_2="192.168.1.101"

# # Client Configuration
# CLIENT_HOST="client-hostname-or-ip"
# CLIENT_RUHOP_BIN="/path/to/tmp/ruhop-e2e/ruhop"
# CLIENT_TMP_DIR="/path/to/tmp/ruhop-e2e"
###########################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/config.local.sh" ]; then
    source "$SCRIPT_DIR/config.local.sh"
fi

# ============================================================================
# Server Configuration (the machine running the VPN server)
# ============================================================================
# Path to ruhop binary on the server machine
# REQUIRED: Set this in config.local.sh or via environment variable
SERVER_RUHOP_BIN="${SERVER_RUHOP_BIN:-./target/release/ruhop}"

# Primary IP address for the server
# REQUIRED: Set this in config.local.sh or via environment variable
SERVER_IP_1="${SERVER_IP_1:-127.0.0.1}"

# Secondary IP address for multi-homed server tests (optional)
# Set this in config.local.sh for multi-homed server tests
SERVER_IP_2="${SERVER_IP_2:-}"

# ============================================================================
# Client Configuration (the machine running the VPN client)
# ============================================================================
# SSH host for the client machine
# REQUIRED: Set this in config.local.sh or via environment variable
CLIENT_HOST="${CLIENT_HOST:-client-host}"

# Path to ruhop binary on the client machine
# REQUIRED: Set this in config.local.sh or via environment variable
CLIENT_RUHOP_BIN="${CLIENT_RUHOP_BIN:-/tmp/ruhop-e2e/ruhop}"

# Temporary directory on the client machine for configs
CLIENT_TMP_DIR="${CLIENT_TMP_DIR:-/tmp/ruhop-e2e}"

# ============================================================================
# Test Configuration
# ============================================================================
# Pre-shared key for tests
TEST_KEY="${TEST_KEY:-e2e-test-key-2024}"

# Default port range
DEFAULT_PORT_RANGE_START="${DEFAULT_PORT_RANGE_START:-52000}"
DEFAULT_PORT_RANGE_END="${DEFAULT_PORT_RANGE_END:-52010}"

# ============================================================================
# Output Colors
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================================================
# Logging Functions
# ============================================================================
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

# ============================================================================
# Cleanup Functions
# ============================================================================

# Cleanup server processes
cleanup_server() {
    log_info "Cleaning up server..."
    sudo pkill -f "ruhop server" 2>/dev/null || true
    sleep 1
}

# Cleanup client processes
cleanup_client() {
    log_info "Cleaning up client on $CLIENT_HOST..."
    ssh $CLIENT_HOST "sudo pkill -f 'ruhop client'" 2>/dev/null || true
    sleep 1
}

# Cleanup all processes
cleanup_all() {
    cleanup_server
    cleanup_client
}

# ============================================================================
# Wait Functions
# ============================================================================

# Wait for server to be ready
wait_for_server() {
    local max_wait=${1:-30}
    local count=0
    log_info "Waiting for server to be ready (max ${max_wait}s)..."
    while [ $count -lt $max_wait ]; do
        if sudo $SERVER_RUHOP_BIN status 2>/dev/null | grep -q "Listening"; then
            log_info "Server is ready!"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    log_error "Server did not become ready within ${max_wait}s"
    return 1
}

# Wait for client to connect
wait_for_client() {
    local max_wait=${1:-30}
    local count=0
    log_info "Waiting for client to connect (max ${max_wait}s)..."
    while [ $count -lt $max_wait ]; do
        if ssh $CLIENT_HOST "sudo $CLIENT_RUHOP_BIN status" 2>/dev/null | grep -q "Connected"; then
            log_info "Client is connected!"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    log_error "Client did not connect within ${max_wait}s"
    return 1
}

# ============================================================================
# Config Generation Functions
# ============================================================================

# Generate server config
gen_server_config() {
    local listen_ip=${1:-$SERVER_IP_1}
    local port_start=${2:-$DEFAULT_PORT_RANGE_START}
    local port_end=${3:-$DEFAULT_PORT_RANGE_END}
    local tunnel_network=${4:-"10.99.0.0/24"}
    local output_file=${5:-"/tmp/ruhop-server.toml"}

    cat > "$output_file" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[server]
listen = "$listen_ip"
port_range = [$port_start, $port_end]
tunnel_network = "$tunnel_network"
max_clients = 10
enable_nat = true
TOML
    echo "$output_file"
}

# Generate client config
gen_client_config() {
    local server_addr=${1:-$SERVER_IP_1}
    local port_start=${2:-$DEFAULT_PORT_RANGE_START}
    local port_end=${3:-$DEFAULT_PORT_RANGE_END}
    local output_file=${4:-"/tmp/ruhop-client.toml"}
    local route_all=${5:-"false"}
    local auto_reconnect=${6:-"false"}

    cat > "$output_file" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[client]
server = "$server_addr"
port_range = [$port_start, $port_end]
route_all_traffic = $route_all
auto_reconnect = $auto_reconnect
TOML
    echo "$output_file"
}

# Generate multi-server client config (array of servers)
gen_multi_server_client_config() {
    local servers="$1"  # e.g., '"192.168.2.60", "192.168.2.61"'
    local port_start=${2:-$DEFAULT_PORT_RANGE_START}
    local port_end=${3:-$DEFAULT_PORT_RANGE_END}
    local output_file=${4:-"/tmp/ruhop-client.toml"}

    cat > "$output_file" << TOML
[common]
key = "$TEST_KEY"
mtu = 1400
log_level = "debug"

[client]
server = [$servers]
port_range = [$port_start, $port_end]
route_all_traffic = false
auto_reconnect = false
TOML
    echo "$output_file"
}

# ============================================================================
# Test Helper Functions
# ============================================================================

# Test ping from server
test_ping() {
    local target_ip=$1
    local count=${2:-3}
    local timeout=${3:-5}

    log_info "Testing ping to $target_ip..."
    if ping -c $count -W $timeout "$target_ip" > /dev/null 2>&1; then
        log_info "Ping to $target_ip successful"
        return 0
    else
        log_error "Ping to $target_ip failed"
        return 1
    fi
}

# Test ping from client
test_ping_from_client() {
    local target_ip=$1
    local count=${2:-3}
    local timeout=${3:-5}

    log_info "Testing ping from client to $target_ip..."
    if ssh $CLIENT_HOST "ping -c $count -W $timeout $target_ip" > /dev/null 2>&1; then
        log_info "Ping from client to $target_ip successful"
        return 0
    else
        log_error "Ping from client to $target_ip failed"
        return 1
    fi
}

# Run iperf3 bandwidth test
run_bandwidth_test() {
    local duration=${1:-10}
    log_info "Running bandwidth test for ${duration}s..."

    # Start iperf3 server on tunnel IP
    iperf3 -s -D -1 --bind 10.99.0.1 2>/dev/null
    sleep 1

    # Run iperf3 client from client host
    ssh $CLIENT_HOST "iperf3 -c 10.99.0.1 -t $duration -J" 2>/dev/null
}

# Assert test result
assert_test() {
    local test_name=$1
    local result=$2

    if [ $result -eq 0 ]; then
        log_test "PASS: $test_name"
        return 0
    else
        log_test "FAIL: $test_name"
        return 1
    fi
}
