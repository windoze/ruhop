# Ruhop E2E Tests

End-to-end tests for the Ruhop VPN.

## Test Environment

These tests require **two Linux hosts**:

- **Server host**: Runs the test scripts and the VPN server
- **Client host**: Runs the VPN client (accessed via SSH from the server host)

The test scripts are executed on the server host and use SSH to control the client host.

## Prerequisites

1. Both hosts must have the `ruhop` binary compiled and available
2. SSH access from server host to client host (passwordless recommended)
3. `sudo` access on both hosts (for TUN device creation and network configuration)
4. `iperf3` installed on both hosts (for bandwidth tests)

## Configuration

Create a `config.local.sh` file in the `e2e/` directory with your environment-specific settings:

```bash
#!/bin/bash
# Local configuration for E2E tests
# This file should NOT be committed to version control

# Server Configuration
SERVER_RUHOP_BIN="/path/to/ruhop/target/release/ruhop"
SERVER_IP_1="192.168.1.100"
SERVER_IP_2="192.168.1.101"  # Optional: for multi-homed server tests

# Client Configuration
CLIENT_HOST="client-hostname"  # SSH hostname or IP
CLIENT_RUHOP_BIN="/path/to/ruhop"
CLIENT_TMP_DIR="/tmp/ruhop-e2e"
```

The `config.local.sh` file is gitignored and will not be committed.

## Running Tests

Run all tests:

```bash
./run-all-tests.sh
```

Run specific tests by number:

```bash
./run-all-tests.sh 1 3 5    # Run tests 01, 03, 05
./run-all-tests.sh 8        # Run only bandwidth test
```

Run a single test directly:

```bash
./01-basic-connectivity.sh
```

## Test Descriptions

| Test | Name | Description |
|------|------|-------------|
| 01 | Basic Connectivity | Basic tunnel setup and ping tests |
| 02 | Port Hopping | Verifies client uses multiple ports |
| 03 | Multi-homed Server | Server with multiple IP addresses |
| 04 | Data Transfer | TCP/UDP data transfer through tunnel |
| 05 | Auto Reconnect | Client reconnection after network disruption |
| 06 | Multi Client | Multiple concurrent client connections |
| 07 | Lifecycle Scripts | on_connect/on_disconnect script execution |
| 08 | Bandwidth | Throughput testing with iperf3 |
| 09 | Graceful Shutdown | Clean shutdown with SIGTERM |
| 10 | Error Handling | Invalid configs, wrong keys, max clients |

## Notes

- Tests use port ranges starting at 52000 to avoid conflicts
- Each test uses a different tunnel network (10.99.X.0/24)
- Tests clean up processes before and after execution
- Test 03 (multi-homed) requires `SERVER_IP_2` to be configured
- Test 05 (auto-reconnect) uses nftables (preferred) or iptables (fallback) rules to simulate network disruption
