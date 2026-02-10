#!/bin/bash
# E2E Tests — Request Prioritization (#3)

# --- Test 1: Request with priority=high succeeds ---
run_test "High priority request succeeds" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"database\":\"testdb\",\"sql\":\"SELECT 1\",\"priority\":\"high\"}'" \
    '"success":true'

# --- Test 2: Request with priority=low succeeds ---
run_test "Low priority request succeeds" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\",\"priority\":\"low\"}'" \
    '"success":true'

# --- Test 3: Request with priority=background succeeds ---
run_test "Background priority request succeeds" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\",\"priority\":\"background\"}'" \
    '"success":true'

# --- Test 4: Request without priority (default normal) succeeds ---
run_test "Default priority (normal) request succeeds" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    '"success":true'

print_summary "Request Prioritization"
