#!/bin/bash
# E2E Tests: Authentication
# Tests API key auth (Bearer), JSON body user, and error cases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Authentication Tests"
echo "========================================"
echo ""

# Test 1: Valid API key via Bearer header
run_test_status "Valid API key via Bearer header" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'Authorization: Bearer $ANALYST_KEY' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1 as test\"}'" \
    "200" \
    '"success":true'

# Test 2: Valid user via JSON body
run_test_status "Valid user via JSON body" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1 as test\"}'" \
    "200" \
    '"success":true'

# Test 3: Invalid API key returns 401
run_test_status "Invalid API key returns 401" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'Authorization: Bearer invalid-key-xxx' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "401" \
    'Invalid API key'

# Test 4: Unknown user returns 401
run_test_status "Unknown user returns 401" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"nonexistent_user\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "401" \
    'Unknown user'

# Test 5: Missing user and auth header returns 400
run_test_status "Missing user and auth header returns 400" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "400" \
    'Missing required field'

# Test 6: Valid query returns data
run_test "Valid query returns data columns" \
    "query_with_key '$ANALYST_KEY' 'testdb' 'SELECT id, name FROM customers LIMIT 1'" \
    '"columns"'

print_summary "Authentication"
return $FAILED 2>/dev/null || exit $FAILED
