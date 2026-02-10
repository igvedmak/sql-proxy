#!/bin/bash
# E2E Tests: Compliance Endpoints
# Tests PII report, security summary, and data lineage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

# Generate some traffic to populate lineage/PII data
query_as_user 'analyst' 'testdb' 'SELECT id, name, email FROM customers LIMIT 1' > /dev/null 2>&1
query_as_user 'developer' 'testdb' 'SELECT id, name, email FROM customers LIMIT 1' > /dev/null 2>&1

echo "========================================"
echo "  Compliance Endpoint Tests"
echo "========================================"
echo ""

# Test 1: PII report endpoint
run_test_status "PII report endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/compliance/pii-report" \
    "200"

# Test 2: Security summary endpoint
run_test_status "Security summary endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/compliance/security-summary" \
    "200"

# Test 3: Data lineage endpoint
run_test_status "Data lineage endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/compliance/lineage" \
    "200"

print_summary "Compliance Endpoints"
return $FAILED 2>/dev/null || exit $FAILED
