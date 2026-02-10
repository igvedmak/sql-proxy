#!/bin/bash
# E2E Tests — Per-Layer Distributed Tracing Spans (#18)

# --- Test 1: Execute query and check traceparent header ---
run_test_header "Response includes traceparent header" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "traceparent"

# --- Test 2: Pass traceparent header and verify propagation ---
run_test_header "Traceparent propagated in response" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736"

# --- Test 3: Execute query with spans enabled, verify audit metrics increment ---
run_test "Spans generate audit records" \
    "query_as_user analyst testdb 'SELECT id FROM customers LIMIT 1' && sleep 1 && curl -s $BASE_URL/metrics" \
    'sql_proxy_audit_emitted_total'

print_summary "Tracing Spans"
