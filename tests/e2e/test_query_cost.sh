#!/bin/bash
# E2E Tests: Query Cost Estimation
# Tests that the query cost estimator runs EXPLAIN on SELECT queries
# and exposes metrics via /metrics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Query Cost Estimation Tests"
echo "========================================"
echo ""

# Test 1: SELECT queries still succeed (cost estimator should not block normal queries)
run_test "Normal SELECT succeeds with cost estimation enabled" \
    "query_as_user 'admin' 'testdb' 'SELECT id, name FROM customers LIMIT 5'" \
    '"success":true'

# Run a few queries to populate cost estimation metrics
query_as_user 'admin' 'testdb' 'SELECT * FROM customers' > /dev/null 2>&1
query_as_user 'admin' 'testdb' 'SELECT * FROM orders' > /dev/null 2>&1
query_as_user 'admin' 'testdb' 'SELECT id FROM customers WHERE id = 1' > /dev/null 2>&1

# Test 2: Query cost metrics present in /metrics
run_test "Query cost estimated metric in /metrics" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_query_cost_estimated_total"

# Test 3: Query cost rejected metric exists (even if 0)
run_test "Query cost rejected metric in /metrics" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_query_cost_rejected_total"

# Test 4: INSERT queries should NOT be cost-estimated (only SELECTs)
# Developer inserts should still work normally (use random order_number for idempotency)
_COST_ORD="ORD-E2E-COST-$(date +%s%N | tail -c 8)"
run_test "INSERT not cost-estimated (developer can insert)" \
    "query_as_user 'developer' 'testdb' 'INSERT INTO orders (customer_id, order_number, amount, status) VALUES (1, '\''$_COST_ORD'\'', 99.99, '\''pending'\'')'" \
    '"success":true'

print_summary "Query Cost Estimation"
return $FAILED 2>/dev/null || exit $FAILED
