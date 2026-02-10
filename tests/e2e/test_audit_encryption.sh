#!/bin/bash
# E2E Tests — Audit Record Encryption (#25)
# Note: Audit encryption is disabled by default in E2E config.
# These tests verify the configuration is parsed and metrics exist.

# --- Test 1: Audit emitter stats available in metrics ---
run_test "Audit emitter metrics present" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_audit_emitted_total'

# --- Test 2: Audit written total metric present ---
run_test "Audit written metrics present" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_audit_written_total'

# --- Test 3: Execute a query and verify audit records are being written ---
run_test "Query triggers audit emission" \
    "query_as_user analyst testdb 'SELECT 1' && sleep 1 && curl -s $BASE_URL/metrics" \
    'sql_proxy_audit_emitted_total [1-9]'

print_summary "Audit Encryption"
