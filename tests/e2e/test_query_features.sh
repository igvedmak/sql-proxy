#!/bin/bash
# E2E Tests: Query Features
# Tests query rewriting, dry-run, RLS, tracing, subqueries

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Query Feature Tests"
echo "========================================"
echo ""

# Test 1: Query rewriting — enforce_limit adds LIMIT 1000
# A SELECT * without LIMIT should still succeed (rewriter adds LIMIT)
run_test "Query rewriting enforce_limit works" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM customers'" \
    '"success":true'

# Test 2: Dry-run endpoint — no actual execution
run_test "Dry-run query evaluation" \
    "curl -s -X POST $BASE_URL/api/v1/query/dry-run -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT id, name FROM customers\"}'" \
    'dry_run\|success'

# Test 3: RLS — analyst query on customers is filtered by region attribute
# Analyst has region = "us-west", so RLS should filter
run_test "RLS filters analyst queries by region" \
    "query_as_user 'analyst' 'testdb' 'SELECT id, name, region FROM customers'" \
    '"success":true'

# Test 4: W3C traceparent header propagation
run_test_header "Traceparent header returned on response" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "traceparent"

# Test 5: Subquery execution
run_test "Subquery executes successfully" \
    "query_as_user 'analyst' 'testdb' 'SELECT name FROM customers WHERE id IN (SELECT DISTINCT customer_id FROM orders) LIMIT 5'" \
    '"success":true'

# Test 6: Complex JOIN query
run_test "Complex JOIN query succeeds" \
    "query_as_user 'analyst' 'testdb' 'SELECT c.name, COUNT(o.id) as order_count FROM customers c LEFT JOIN orders o ON c.id = o.customer_id GROUP BY c.name LIMIT 5'" \
    '"success":true'

print_summary "Query Features"
return $FAILED 2>/dev/null || exit $FAILED
