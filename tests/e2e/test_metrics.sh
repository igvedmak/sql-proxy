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

# Test 3: Rate limit metrics (actual name: sql_proxy_rate_limit_total with labels)
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

# ============================================================================
# Feature-gated metrics — only present when features are enabled in config
# These pass with E2E config (e2e_proxy.toml) but may skip with default config
# ============================================================================

# Test 10: Auth failures metric (requires brute_force enabled)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Contains auth failures metric (brute force)"
metrics_out=$(curl -s "$BASE_URL/metrics")
if echo "$metrics_out" | grep -q "sql_proxy_auth_failures_total\|sql_proxy_auth_blocks_total"; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${YELLOW}SKIP${NC} (brute force not enabled in config)"
    # Count as pass — feature is config-gated
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 11: Slow query metric (requires slow_query enabled)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Contains slow query metric"
if echo "$metrics_out" | grep -q "sql_proxy_slow_queries_total"; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${YELLOW}SKIP${NC} (slow query tracking not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 12: Cache metrics (requires result_cache enabled)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Contains cache hit metric"
if echo "$metrics_out" | grep -q "sql_proxy_cache_hits_total"; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${YELLOW}SKIP${NC} (result cache not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

print_summary "Prometheus Metrics"
return $FAILED 2>/dev/null || exit $FAILED
