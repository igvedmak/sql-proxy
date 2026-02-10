#!/bin/bash
# E2E Tests: Config Validation & Hot-Reload
# Tests config validation endpoint and policy reload

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Config & Hot-Reload Tests"
echo "========================================"
echo ""

# Test 1: Config validation with valid TOML
run_test "Config validation with valid TOML" \
    "curl -s -X POST $BASE_URL/api/v1/config/validate -H 'Authorization: Bearer $ADMIN_TOKEN' --data-binary '[server]
host = \"0.0.0.0\"
port = 8080
threads = 4

[[databases]]
name = \"testdb\"
type = \"postgresql\"
connection_string = \"postgresql://user:pass@localhost:5432/testdb\"
'" \
    'success\|valid'

# Test 2: Config validation with invalid TOML
run_test "Config validation with invalid TOML" \
    "curl -s -X POST $BASE_URL/api/v1/config/validate -H 'Authorization: Bearer $ADMIN_TOKEN' --data-binary 'this is not valid toml [[['" \
    'error\|invalid\|fail'

# Test 3: Policy hot-reload with admin token
run_test_status "Policy hot-reload succeeds" \
    "-X POST $BASE_URL/policies/reload -H 'Authorization: Bearer $ADMIN_TOKEN'" \
    "200" \
    'success\|reload'

# Test 4: Policy reload without token — 401
run_test_status "Policy reload without token returns 401" \
    "-X POST $BASE_URL/policies/reload" \
    "401"

print_summary "Config & Hot-Reload"
return $FAILED 2>/dev/null || exit $FAILED
