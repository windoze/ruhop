#!/bin/bash
# Run all E2E tests
# Usage: ./run-all-tests.sh [test_number...]
# Example: ./run-all-tests.sh          # Run all tests
# Example: ./run-all-tests.sh 1 3 5    # Run tests 01, 03, 05

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

log_info "=========================================="
log_info "Ruhop VPN E2E Test Suite"
log_info "=========================================="
log_info "Server IPs: $SERVER_IP_1, $SERVER_IP_2"
log_info "Client host: $CLIENT_HOST"
log_info "Server binary: $SERVER_RUHOP_BIN"
log_info "Client binary: $CLIENT_RUHOP_BIN"
log_info "=========================================="

# Test list
TESTS=(
    "01-basic-connectivity.sh"
    "02-port-hopping.sh"
    "03-multi-homed-server.sh"
    "04-data-transfer.sh"
    "05-auto-reconnect.sh"
    "06-multi-client.sh"
    "07-lifecycle-scripts.sh"
    "08-bandwidth.sh"
    "09-graceful-shutdown.sh"
    "10-error-handling.sh"
)

# Track results
declare -A RESULTS
TOTAL_PASSED=0
TOTAL_FAILED=0

# Determine which tests to run
if [ $# -gt 0 ]; then
    SELECTED_TESTS=()
    for num in "$@"; do
        # Pad single digit with leading zero
        padded=$(printf "%02d" $num)
        for test in "${TESTS[@]}"; do
            if [[ $test == ${padded}* ]]; then
                SELECTED_TESTS+=("$test")
                break
            fi
        done
    done
else
    SELECTED_TESTS=("${TESTS[@]}")
fi

log_info "Running ${#SELECTED_TESTS[@]} tests..."
echo ""

# Make sure all test scripts are executable
for test in "${SELECTED_TESTS[@]}"; do
    chmod +x "$SCRIPT_DIR/$test"
done

# Run each test
for test in "${SELECTED_TESTS[@]}"; do
    log_info "=========================================="
    log_info "Running: $test"
    log_info "=========================================="

    # Cleanup before each test
    cleanup_all 2>/dev/null || true
    sleep 2

    # Run the test
    if "$SCRIPT_DIR/$test"; then
        RESULTS[$test]="PASS"
        ((TOTAL_PASSED++))
    else
        RESULTS[$test]="FAIL"
        ((TOTAL_FAILED++))
    fi

    # Cleanup after each test
    cleanup_all 2>/dev/null || true
    sleep 2
    echo ""
done

# Print summary
log_info "=========================================="
log_info "E2E TEST SUITE SUMMARY"
log_info "=========================================="

for test in "${SELECTED_TESTS[@]}"; do
    if [ "${RESULTS[$test]}" == "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $test"
    else
        echo -e "${RED}[FAIL]${NC} $test"
    fi
done

echo ""
log_info "Total: $((TOTAL_PASSED + TOTAL_FAILED)) tests"
log_info "Passed: $TOTAL_PASSED"
log_info "Failed: $TOTAL_FAILED"

if [ $TOTAL_FAILED -gt 0 ]; then
    log_error "Some tests failed!"
    exit 1
else
    log_test "All tests passed!"
    exit 0
fi
