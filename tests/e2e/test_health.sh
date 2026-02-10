#!/bin/bash
# E2E Tests: Health Check Endpoint
# Tests shallow, deep, and readiness health check levels

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Health Check Tests"
echo "========================================"
echo ""

# Test 1: Default health check
run_test_status "GET /health returns 200" \
    "$BASE_URL/health" \
    "200" \
    '"status":"healthy"'

# Test 2: Shallow health check
run_test_status "Shallow health check" \
    "'$BASE_URL/health?level=shallow'" \
    "200" \
    '"status":"healthy"'

# Test 3: Deep health check — includes component checks
run_test "Deep health check includes circuit_breaker" \
    "curl -s '$BASE_URL/health?level=deep'" \
    "circuit_breaker"

# Test 4: Readiness check
run_test_status "Readiness health check" \
    "'$BASE_URL/health?level=readiness'" \
    "200" \
    '"status"'

print_summary "Health Check"
return $FAILED 2>/dev/null || exit $FAILED
