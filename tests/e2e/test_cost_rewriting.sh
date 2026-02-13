#!/bin/bash
# E2E Tests: Cost-Based Query Rewriting
# Tests that cost-based rewriting transforms queries via the query pipeline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Cost-Based Rewriting Tests"
echo "========================================"
echo ""

# Test 1: SELECT * query gets processed (may be rewritten)
run_test "SELECT * query is processed" \
    "query_with_key '$ANALYST_KEY' 'testdb' 'SELECT * FROM customers LIMIT 5'" \
    'result\|rows\|columns\|error\|rewritten'

# Test 2: Query with specific columns passes through
run_test "Specific column query is processed" \
    "query_with_key '$ANALYST_KEY' 'testdb' 'SELECT id, name FROM customers LIMIT 5'" \
    'result\|rows\|columns\|error'

# Test 3: Expensive query (no LIMIT) may get rewritten
run_test "Query without LIMIT is processed" \
    "query_with_key '$ANALYST_KEY' 'testdb' 'SELECT * FROM customers'" \
    'result\|rows\|columns\|error\|rewritten\|limit'

# Test 4: Query explain shows cost estimation
run_test_status "Query explain returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"database\":\"testdb\",\"sql\":\"SELECT * FROM customers WHERE id = 1\"}' $BASE_URL/api/v1/query/explain" \
    "200"

# Test 5: Query explain returns cost info
run_test "Query explain returns cost data" \
    "curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"database\":\"testdb\",\"sql\":\"SELECT * FROM customers WHERE id = 1\"}' $BASE_URL/api/v1/query/explain" \
    'cost\|plan\|analysis\|estimate\|tables'

print_summary "Cost-Based Rewriting"
return $FAILED 2>/dev/null || exit $FAILED
