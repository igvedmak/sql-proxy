#!/bin/bash
# E2E Tests: GDPR Data Subject Access
# Tests the /api/v1/compliance/data-subject-access endpoint

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

# Generate some lineage data by running queries as different users
query_as_user 'analyst' 'testdb' 'SELECT id, name, email FROM customers LIMIT 1' > /dev/null 2>&1
query_as_user 'developer' 'testdb' 'SELECT id, name, phone FROM customers LIMIT 1' > /dev/null 2>&1
query_as_user 'admin' 'testdb' 'SELECT * FROM customers LIMIT 1' > /dev/null 2>&1

echo "========================================"
echo "  GDPR Data Subject Access Tests"
echo "========================================"
echo ""

# Test 1: Data subject access endpoint with valid user
run_test_status "Data subject access for analyst returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' '$BASE_URL/api/v1/compliance/data-subject-access?user=analyst'" \
    "200" \
    '"subject":"analyst"'

# Test 2: Response contains events array
run_test "Response contains events array" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' '$BASE_URL/api/v1/compliance/data-subject-access?user=analyst'" \
    '"events":\['

# Test 3: Response contains total_events
run_test "Response contains total_events" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' '$BASE_URL/api/v1/compliance/data-subject-access?user=analyst'" \
    '"total_events"'

# Test 4: Missing user parameter returns 400
run_test_status "Missing user parameter returns 400" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/compliance/data-subject-access" \
    "400" \
    '"Missing required parameter: user"'

# Test 5: Requires admin auth
run_test_status "Data subject access rejects no-auth" \
    "'$BASE_URL/api/v1/compliance/data-subject-access?user=analyst'" \
    "401"

# Test 6: Query for user with no data returns empty events
run_test "Unknown user returns empty events" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' '$BASE_URL/api/v1/compliance/data-subject-access?user=nonexistent'" \
    '"total_events":0'

print_summary "GDPR Data Subject Access"
return $FAILED 2>/dev/null || exit $FAILED
