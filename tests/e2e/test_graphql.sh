#!/bin/bash
# E2E Tests: GraphQL Endpoint
# Tests GraphQL query execution

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  GraphQL Tests"
echo "========================================"
echo ""

# Test 1: GraphQL endpoint returns 200
run_test_status "GraphQL endpoint returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"query\":\"{ __typename }\"}' $BASE_URL/api/v1/graphql" \
    "200"

# Test 2: GraphQL response contains structured JSON
run_test "GraphQL returns structured response" \
    "curl -s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"query\":\"{ customers { id } }\"}' $BASE_URL/api/v1/graphql" \
    'data\|errors'

# Test 3: GraphQL query with table operation
run_test_status "GraphQL table query returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"query\":\"{ customers { id name } }\"}' $BASE_URL/api/v1/graphql" \
    "200"

# Test 4: GraphQL mutation
run_test_status "GraphQL mutation returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"query\":\"mutation { updateCustomer(id: 1, name: \\\"test\\\") { id } }\"}' $BASE_URL/api/v1/graphql" \
    "200"

# Test 5: GraphQL accepts anonymous requests (no admin auth required)
run_test_status "GraphQL allows anonymous access" \
    "-X POST -H 'Content-Type: application/json' -d '{\"query\":\"{ customers { id } }\"}' $BASE_URL/api/v1/graphql" \
    "200"

print_summary "GraphQL"
return $FAILED 2>/dev/null || exit $FAILED
