#!/bin/bash
# E2E Tests: Admin Dashboard API
# Tests stats, policies, users, alerts endpoints with auth

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Dashboard API Tests"
echo "========================================"
echo ""

# Test 1: Dashboard stats with admin token
run_test_status "Dashboard stats endpoint" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/dashboard/api/stats" \
    "200"

# Test 2: Dashboard policies lists policy names
run_test "Dashboard policies lists policy names" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/dashboard/api/policies" \
    'block_all_ddl\|allow_admin_all\|policies'

# Test 3: Dashboard users lists user names
run_test "Dashboard users lists user names" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/dashboard/api/users" \
    'analyst\|admin\|users'

# Test 4: Dashboard alerts endpoint
run_test_status "Dashboard alerts endpoint" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/dashboard/api/alerts" \
    "200"

# Test 5: Dashboard without token returns 401
run_test_status "Dashboard without token returns 401" \
    "$BASE_URL/dashboard/api/stats" \
    "401"

print_summary "Dashboard API"
return $FAILED 2>/dev/null || exit $FAILED
