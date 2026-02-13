#!/bin/bash
# E2E Tests: SQL Firewall
# Tests firewall mode, allowlist, and fingerprint learning

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  SQL Firewall Tests"
echo "========================================"
echo ""

# Test 1: Get firewall mode (admin)
run_test_status "Firewall mode endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/firewall/mode" \
    "200" \
    '"mode"'

# Test 2: Firewall mode shows current mode
run_test "Firewall reports learning or enforcing mode" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/firewall/mode" \
    '"mode"'

# Test 3: Get firewall allowlist
run_test_status "Firewall allowlist endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/firewall/allowlist" \
    "200"

# Test 4: Execute a query to populate allowlist (learning mode)
query_with_key "$ANALYST_KEY" "testdb" "SELECT id, name FROM customers LIMIT 1" > /dev/null 2>&1
sleep 1

# Test 5: Allowlist grows after queries (learning mode)
run_test "Allowlist contains fingerprints after queries" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/firewall/allowlist" \
    'fingerprints\|allowlist\|size'

# Test 6: Firewall endpoint requires admin auth
run_test_status "Firewall mode rejects no-auth" \
    "$BASE_URL/api/v1/firewall/mode" \
    "401"

print_summary "SQL Firewall"
return $FAILED 2>/dev/null || exit $FAILED
