#!/bin/bash
# E2E Tests: Tenant Management
# Tests tenant CRUD operations at /admin/tenants

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Tenant Management Tests"
echo "========================================"
echo ""

# Test 1: List tenants (admin)
run_test_status "List tenants returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/tenants" \
    "200"

# Test 2: Create a tenant
run_test_status "Create tenant returns 201" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"tenant_id\":\"e2e_tenant\"}' $BASE_URL/admin/tenants" \
    "201" \
    'e2e_tenant'

# Test 3: Get tenant by ID
run_test_status "Get tenant by ID" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/tenants/e2e_tenant" \
    "200" \
    'e2e_tenant'

# Test 4: List tenants now includes new tenant
run_test "Created tenant appears in list" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/tenants" \
    'e2e_tenant'

# Test 5: Delete tenant
run_test_status "Delete tenant returns 200" \
    "-X DELETE -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/admin/tenants/e2e_tenant" \
    "200"

# Test 6: Tenant endpoints require admin auth
run_test_status "Tenants rejects no-auth" \
    "$BASE_URL/admin/tenants" \
    "401"

print_summary "Tenant Management"
return $FAILED 2>/dev/null || exit $FAILED
