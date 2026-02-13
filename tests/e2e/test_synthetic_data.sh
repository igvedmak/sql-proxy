#!/bin/bash
# E2E Tests: Synthetic Data Generation
# Tests synthetic data generation endpoint

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1
require_feature "Synthetic Data" "/api/v1/synthetic-data" "POST" || return 0 2>/dev/null || exit 0

echo "========================================"
echo "  Synthetic Data Tests"
echo "========================================"
echo ""

# Test 1: Synthetic data endpoint returns 200
run_test_status "Synthetic data endpoint returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"table\":\"customers\",\"count\":5}' $BASE_URL/api/v1/synthetic-data" \
    "200"

# Test 2: Synthetic data response contains rows
run_test "Synthetic data returns rows" \
    "curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"table\":\"customers\",\"count\":3}' $BASE_URL/api/v1/synthetic-data" \
    'rows\|data\|records\|\['

# Test 3: Synthetic data with different table
run_test_status "Synthetic data for orders table" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"table\":\"orders\",\"count\":2}' $BASE_URL/api/v1/synthetic-data" \
    "200"

# Test 4: Synthetic data requires auth
run_test_status "Synthetic data rejects no-auth" \
    "-X POST -H 'Content-Type: application/json' -d '{\"table\":\"customers\",\"count\":1}' $BASE_URL/api/v1/synthetic-data" \
    "401"

print_summary "Synthetic Data"
return $FAILED 2>/dev/null || exit $FAILED
