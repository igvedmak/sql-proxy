#!/bin/bash
# E2E Tests — Adaptive Rate Limiting (#4)
# Note: Adaptive rate limiting is disabled by default in E2E config.
# These tests verify that metrics are available (populated when enabled).

# --- Test 1: Rate limiter checks metric present ---
run_test "Rate limit checks metric present" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_rate_limit_checks_total'

# --- Test 2: Rate limiter global rejects metric present ---
run_test "Rate limit rejects metric present" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_rate_limit_total'

# --- Test 3: Active buckets metric present ---
run_test "Rate limiter buckets metric present" \
    "curl -s $BASE_URL/metrics" \
    'sql_proxy_rate_limiter_buckets_active'

print_summary "Adaptive Rate Limiting"
