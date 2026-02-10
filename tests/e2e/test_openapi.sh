#!/bin/bash
# E2E Tests — OpenAPI / Swagger Endpoint (#40)

# --- Test 1: GET /openapi.json returns OpenAPI 3.0 spec ---
run_test_status "OpenAPI spec returns 200" \
    "$BASE_URL/openapi.json" \
    "200" \
    '"openapi"'

# --- Test 2: OpenAPI spec contains query endpoint ---
run_test "OpenAPI spec contains /api/v1/query" \
    "curl -s $BASE_URL/openapi.json" \
    '/api/v1/query'

# --- Test 3: OpenAPI spec contains components/schemas ---
run_test "OpenAPI spec contains schemas" \
    "curl -s $BASE_URL/openapi.json" \
    'QueryRequest'

# --- Test 4: GET /api/docs returns Swagger UI HTML ---
run_test_status "Swagger UI returns 200" \
    "$BASE_URL/api/docs" \
    "200" \
    'swagger-ui'

print_summary "OpenAPI / Swagger"
