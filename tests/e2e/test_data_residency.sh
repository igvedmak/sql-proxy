#!/bin/bash
# E2E Tests: Data Residency
# Tests residency rules and region enforcement

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1
require_feature "Data Residency" "/admin/residency" || return 0 2>/dev/null || exit 0

echo "========================================"
echo "  Data Residency Tests"
echo "========================================"
echo ""

# Test 1: Residency endpoint returns 200
run_test_status "Residency endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/residency" \
    "200"

# Test 2: Residency response contains rules
run_test "Residency response contains rules or regions" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/residency" \
    'rules\|regions\|default_region'

# Test 3: Residency response contains enabled status
run_test "Residency shows enabled status" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/residency" \
    '"enabled":true'

# Test 4: Residency endpoint requires admin auth
run_test_status "Residency rejects no-auth" \
    "$BASE_URL/admin/residency" \
    "401"

print_summary "Data Residency"
return $FAILED 2>/dev/null || exit $FAILED
