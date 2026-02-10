#!/bin/bash
# E2E Tests: Prometheus Metrics
# Tests that /metrics returns all expected metric families

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

# Generate some traffic first so metrics are populated
query_as_user 'analyst' 'testdb' 'SELECT 1' > /dev/null 2>&1
query_as_user 'admin' 'testdb' 'SELECT 1' > /dev/null 2>&1

echo "========================================"
echo "  Prometheus Metrics Tests"
echo "========================================"
echo ""

# Test 1: Metrics endpoint returns 200
run_test_status "Metrics endpoint returns 200" \
    "$BASE_URL/metrics" \
    "200"

# Test 2: Request counter
run_test "Contains sql_proxy_requests_total" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_requests_total"

# Test 3: Rate limit metrics
run_test "Contains rate limit metrics" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_rate_limit_total\|sql_proxy_rate_limit_checks_total"

# Test 4: Audit metrics
run_test "Contains audit emitted metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_audit_emitted_total"

# Test 5: Pool recycled metric
run_test "Contains pool connections recycled metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_pool_connections_recycled_total"

# Test 6: Pool acquire histogram
run_test "Contains pool acquire histogram" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_pool_acquire_duration_seconds_bucket"

# Test 7: IP blocked metric
run_test "Contains IP blocked metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_ip_blocked_total"

# Test 8: Circuit breaker transitions
run_test "Contains circuit breaker transition metrics" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_circuit_breaker_transitions_total"

# Test 9: Build info
run_test "Contains build info metric" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_info{version='

# Test 10: Auth failures metric
run_test "Contains auth failures metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_auth_failures_total\|sql_proxy_auth_blocks_total"

# Test 11: Slow query metric
run_test "Contains slow query metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_slow_queries_total"

# Test 12: Cache metrics
run_test "Contains cache hit metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_cache_hits_total"

# Test 13: Query cost metrics
run_test "Contains query cost estimated metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_query_cost_estimated_total"

# Test 14: Schema drift metrics
run_test "Contains schema drift checks metric" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_schema_drift_checks_total"

print_summary "Prometheus Metrics"
return $FAILED 2>/dev/null || exit $FAILED
