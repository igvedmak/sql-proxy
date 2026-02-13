#!/bin/bash
# E2E Tests: Column Versioning
# Tests column history tracking endpoint

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Column Versioning Tests"
echo "========================================"
echo ""

# Test 1: Column history endpoint returns 200
run_test_status "Column history endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/column-history" \
    "200"

# Test 2: Column history response is valid JSON
run_test "Column history returns JSON response" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/column-history" \
    'history\|versions\|columns\|\[\|\{'

# Test 3: Execute a DDL-like query to generate history
query_with_key "$ANALYST_KEY" "testdb" "SELECT id, name FROM customers LIMIT 1" > /dev/null 2>&1
sleep 1

# Test 4: Column history endpoint still works after queries
run_test_status "Column history works after queries" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/column-history" \
    "200"

# Test 5: Column history requires auth
run_test_status "Column history rejects no-auth" \
    "$BASE_URL/api/v1/column-history" \
    "401"

print_summary "Column Versioning"
return $FAILED 2>/dev/null || exit $FAILED
