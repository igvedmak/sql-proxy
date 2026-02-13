#!/bin/bash
# E2E Tests: Index Recommender
# Tests index recommendation endpoint

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Index Recommender Tests"
echo "========================================"
echo ""

# Test 1: Index recommendations endpoint returns 200
run_test_status "Index recommendations endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/index-recommendations" \
    "200"

# Test 2: Response is valid JSON
run_test "Index recommendations returns JSON" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/index-recommendations" \
    'recommendations\|indexes\|tables\|\[\|\{'

# Test 3: Execute some filtered queries to populate patterns
query_with_key "$ANALYST_KEY" "testdb" "SELECT * FROM customers WHERE email = 'test@example.com'" > /dev/null 2>&1
query_with_key "$ANALYST_KEY" "testdb" "SELECT * FROM customers WHERE email = 'foo@bar.com'" > /dev/null 2>&1
query_with_key "$ANALYST_KEY" "testdb" "SELECT * FROM orders WHERE customer_id = 42" > /dev/null 2>&1
query_with_key "$ANALYST_KEY" "testdb" "SELECT * FROM orders WHERE customer_id = 99" > /dev/null 2>&1
sleep 1

# Test 4: Recommendations may update after queries
run_test_status "Index recommendations after queries" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/index-recommendations" \
    "200"

# Test 5: Index recommendations requires auth
run_test_status "Index recommendations rejects no-auth" \
    "$BASE_URL/api/v1/index-recommendations" \
    "401"

print_summary "Index Recommender"
return $FAILED 2>/dev/null || exit $FAILED
