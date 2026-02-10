#!/bin/bash
# E2E Tests: Circuit Breaker
# Tests circuit breaker events API and metrics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Circuit Breaker Tests"
echo "========================================"
echo ""

# Test 1: Circuit breaker events API returns 200
run_test_status "Circuit breaker events API returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/circuit-breakers" \
    "200"

# Test 2: Metrics contain circuit breaker transitions
run_test "Circuit breaker metrics present" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_circuit_breaker_transitions_total"

print_summary "Circuit Breaker"
return $FAILED 2>/dev/null || exit $FAILED
