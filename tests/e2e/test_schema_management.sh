#!/bin/bash
# E2E Tests: Schema Management
# Tests schema history, pending changes, approve/reject, and drift detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1
require_feature "Schema Management" "/api/v1/schema/history" || return 0 2>/dev/null || exit 0

echo "========================================"
echo "  Schema Management Tests"
echo "========================================"
echo ""

# Test 1: Schema history endpoint returns 200
run_test_status "Schema history endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/history" \
    "200"

# Test 2: Schema history returns valid response
run_test "Schema history returns data" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/history" \
    'history\|changes\|migrations\|\[\|\{'

# Test 3: Schema pending changes endpoint returns 200
run_test_status "Schema pending endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/pending" \
    "200"

# Test 4: Schema approve endpoint responds
run_test_status "Schema approve endpoint responds" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"id\":\"test-change\"}' $BASE_URL/api/v1/schema/approve" \
    "200"

# Test 5: Schema reject endpoint responds
run_test_status "Schema reject endpoint responds" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"id\":\"test-change\"}' $BASE_URL/api/v1/schema/reject" \
    "200"

# Test 6: Schema endpoints require auth
run_test_status "Schema history rejects no-auth" \
    "$BASE_URL/api/v1/schema/history" \
    "401"

print_summary "Schema Management"
return $FAILED 2>/dev/null || exit $FAILED
