#!/bin/bash
# E2E Tests: Schema Drift Detection
# Tests the /api/v1/schema/drift endpoint and related metrics

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Schema Drift Detection Tests"
echo "========================================"
echo ""

# Test 1: Schema drift endpoint returns 200 with admin token
run_test_status "Schema drift endpoint returns 200 (admin)" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/drift" \
    "200" \
    '"drift_events"'

# Test 2: Schema drift endpoint returns drift_events array
run_test "Schema drift response contains drift_events array" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/drift" \
    '"drift_events":\['

# Test 3: Schema drift response contains total_drifts counter
run_test "Schema drift response contains total_drifts" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/drift" \
    '"total_drifts"'

# Test 4: Schema drift response contains checks_performed counter
run_test "Schema drift response contains checks_performed" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/schema/drift" \
    '"checks_performed"'

# Test 5: Schema drift endpoint requires admin auth
run_test_status "Schema drift endpoint rejects no-auth" \
    "$BASE_URL/api/v1/schema/drift" \
    "401"

# Test 6: Schema drift metrics present in /metrics
run_test "Schema drift metrics in /metrics" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_schema_drift_checks_total"

print_summary "Schema Drift Detection"
return $FAILED 2>/dev/null || exit $FAILED
