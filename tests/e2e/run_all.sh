#!/bin/bash
# E2E Test Suite — Master Runner
# Runs all feature test scripts and aggregates results

set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  SQL PROXY — FULL E2E TEST SUITE"
echo "========================================"
echo ""

TOTAL_PASSED=0
TOTAL_FAILED=0
TOTAL_TESTS=0
SUITE_RESULTS=""

run_suite() {
    local script="$1"
    local suite_name="$2"

    # Brief pause between suites to let rate limit tokens refill
    # (analyst/testdb: 50 tokens/sec, burst 10 — 1s adds 50 tokens)
    sleep 1

    echo ""
    echo "================================================================"
    echo "  Running: $suite_name"
    echo "================================================================"
    echo ""

    # Reset counters for each suite
    PASSED=0
    FAILED=0
    TOTAL=0

    # Source and run the suite (don't execute as subprocess — share helpers)
    source "$SCRIPT_DIR/$script"

    # Don't exit on FAILED — accumulate
    TOTAL_PASSED=$((TOTAL_PASSED + PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + FAILED))
    TOTAL_TESTS=$((TOTAL_TESTS + TOTAL))

    local status_icon="PASS"
    local status_color="$GREEN"
    if [ $FAILED -gt 0 ]; then
        status_icon="FAIL"
        status_color="$RED"
    fi

    SUITE_RESULTS="${SUITE_RESULTS}$(printf "  ${status_color}%-5s${NC} %-35s %d/%d\n" "$status_icon" "$suite_name" "$PASSED" "$TOTAL")"
}

# ============================================================================
# Run all test suites in order
# Core requirements run first to validate exercise deliverables
# ============================================================================

# --- Core suites (work with any config) ---
run_suite "test_core_requirements.sh" "Core Requirements (Exercise)"
run_suite "test_health.sh" "Health Checks"
run_suite "test_auth.sh" "Authentication"
run_suite "test_policies.sh" "Policy Engine"
run_suite "test_masking.sh" "Data Masking"
run_suite "test_query_features.sh" "Query Features"
run_suite "test_sql_injection.sh" "SQL Injection Detection"
run_suite "test_metrics.sh" "Prometheus Metrics"
run_suite "test_dashboard.sh" "Dashboard API"
run_suite "test_compliance.sh" "Compliance Endpoints"
run_suite "test_circuit_breaker.sh" "Circuit Breaker"
run_suite "test_config.sh" "Config & Hot-Reload"
run_suite "test_rate_limiting.sh" "Rate Limiting"

# --- Feature-gated suites (require E2E config with features enabled) ---
echo ""
echo -e "${CYAN}--- Feature-gated tests (require E2E config) ---${NC}"
run_suite "test_slow_query.sh" "Slow Query Tracking"
run_suite "test_ip_allowlist.sh" "IP Allowlisting"
run_suite "test_brute_force.sh" "Brute Force Protection"
run_suite "test_schema_drift.sh" "Schema Drift Detection"
run_suite "test_query_cost.sh" "Query Cost Estimation"
run_suite "test_gdpr.sh" "GDPR Data Subject Access"

# Final summary
echo ""
echo "================================================================"
echo "  FULL E2E TEST SUITE — FINAL SUMMARY"
echo "================================================================"
echo ""
echo "$SUITE_RESULTS"
echo ""
echo "================================================================"
echo -e "  Total Tests:  $TOTAL_TESTS"
echo -e "  ${GREEN}Passed:       $TOTAL_PASSED${NC}"
echo -e "  ${RED}Failed:       $TOTAL_FAILED${NC}"
echo "================================================================"

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL E2E TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}SOME E2E TESTS FAILED${NC}"
    exit 1
fi
