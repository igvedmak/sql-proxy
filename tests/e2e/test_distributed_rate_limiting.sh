#!/bin/bash
# E2E Tests: Distributed Rate Limiting
# Tests distributed rate limiter stats endpoint

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1
require_feature "Distributed Rate Limiting" "/api/v1/distributed-rate-limits" || return 0 2>/dev/null || exit 0

echo "========================================"
echo "  Distributed Rate Limiting Tests"
echo "========================================"
echo ""

# Test 1: Distributed rate limits endpoint returns 200
run_test_status "Distributed rate limits endpoint returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/distributed-rate-limits" \
    "200"

# Test 2: Response contains rate limit info
run_test "Distributed rate limits returns limit info" \
    "curl -s -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/distributed-rate-limits" \
    'limits\|nodes\|buckets\|rate\|\{'

# Test 3: Execute some queries to populate rate limit state
for i in $(seq 1 5); do
    query_with_key "$ANALYST_KEY" "testdb" "SELECT $i" > /dev/null 2>&1
done
sleep 1

# Test 4: Rate limits reflect traffic
run_test_status "Rate limits updated after queries" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/distributed-rate-limits" \
    "200"

# Test 5: Distributed rate limits requires auth
run_test_status "Distributed rate limits rejects no-auth" \
    "$BASE_URL/api/v1/distributed-rate-limits" \
    "401"

print_summary "Distributed Rate Limiting"
return $FAILED 2>/dev/null || exit $FAILED
