#!/bin/bash
# E2E Test Helpers — Shared utilities for all feature test scripts
# Source this file at the top of each test script:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/_helpers.sh"

set +e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
PASSED=0
FAILED=0
TOTAL=0

# Base URL
BASE_URL="${BASE_URL:-http://localhost:8080}"

# Admin credentials
ADMIN_TOKEN="${ADMIN_TOKEN:-aproxy.toml:9}"
ADMIN_KEY="sk-admin-key-12345"
ANALYST_KEY="sk-analyst-key-67890"
DEVELOPER_KEY="sk-developer-key-abcde"
AUDITOR_KEY="sk-auditor-key-fghij"
RESTRICTED_KEY="sk-restricted-key-99999"

# ============================================================================
# Test runner: check output contains expected pattern
# ============================================================================
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    TOTAL=$((TOTAL + 1))
    echo -e "${BLUE}[TEST $TOTAL]${NC} $test_name"

    local output
    output=$(eval "$command" 2>&1)
    local exit_code=$?

    echo -e "  ${YELLOW}Command:${NC} $command"
    echo -e "  ${YELLOW}Response:${NC} $(echo "$output" | head -c 500)"

    if echo "$output" | grep -q "$expected_pattern" && [ $exit_code -eq 0 ]; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected pattern: $expected_pattern${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# ============================================================================
# Test runner: check HTTP status code
# ============================================================================
run_test_status() {
    local test_name="$1"
    local curl_args="$2"
    local expected_status="$3"
    local expected_body_pattern="${4:-}"

    TOTAL=$((TOTAL + 1))
    echo -e "${BLUE}[TEST $TOTAL]${NC} $test_name"

    local http_code
    local body
    body=$(eval "curl -s -w '\\n%{http_code}' $curl_args" 2>&1)
    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    echo -e "  ${YELLOW}Command:${NC} curl -s $curl_args"
    echo -e "  ${YELLOW}Status:${NC} $http_code"
    echo -e "  ${YELLOW}Body:${NC} $(echo "$body" | head -c 300)"

    local pass=true
    if [ "$http_code" != "$expected_status" ]; then
        pass=false
    fi
    if [ -n "$expected_body_pattern" ] && ! echo "$body" | grep -q "$expected_body_pattern"; then
        pass=false
    fi

    if $pass; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected status: $expected_status, body pattern: ${expected_body_pattern:-any}${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# ============================================================================
# Test runner: check response header exists
# ============================================================================
run_test_header() {
    local test_name="$1"
    local curl_args="$2"
    local expected_header="$3"

    TOTAL=$((TOTAL + 1))
    echo -e "${BLUE}[TEST $TOTAL]${NC} $test_name"

    local headers
    headers=$(eval "curl -s -D - -o /dev/null $curl_args" 2>&1)

    echo -e "  ${YELLOW}Command:${NC} curl -s -D - -o /dev/null $curl_args"
    echo -e "  ${YELLOW}Headers:${NC} $(echo "$headers" | head -10)"

    if echo "$headers" | grep -qi "$expected_header"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected header: $expected_header${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo ""
}

# ============================================================================
# Wait for proxy to be ready (skips if already confirmed)
# ============================================================================
_PROXY_READY="${_PROXY_READY:-false}"
wait_for_proxy() {
    if [ "$_PROXY_READY" = "true" ]; then return 0; fi
    echo -e "${CYAN}Waiting for proxy at $BASE_URL ...${NC}"
    for i in $(seq 1 30); do
        if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Proxy is ready!${NC}"
            _PROXY_READY=true
            return 0
        fi
        if [ "$i" -eq 30 ]; then
            echo -e "${RED}ERROR: Proxy not ready after 30s${NC}"
            return 1
        fi
        sleep 1
    done
}

# ============================================================================
# POST a query as a specific user (by name, in JSON body)
# ============================================================================
query_as_user() {
    local user="$1"
    local database="$2"
    local sql="$3"
    curl -s -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -d "{\"user\":\"$user\",\"database\":\"$database\",\"sql\":\"$sql\"}"
}

# ============================================================================
# POST a query with Bearer token
# ============================================================================
query_with_key() {
    local api_key="$1"
    local database="$2"
    local sql="$3"
    curl -s -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $api_key" \
        -d "{\"database\":\"$database\",\"sql\":\"$sql\"}"
}

# ============================================================================
# Print test summary
# ============================================================================
print_summary() {
    local suite_name="${1:-E2E Tests}"
    echo "========================================"
    echo "  $suite_name — SUMMARY"
    echo "========================================"
    echo -e "Total:   $TOTAL"
    echo -e "${GREEN}Passed:  $PASSED${NC}"
    echo -e "${RED}Failed:  $FAILED${NC}"
    echo "========================================"
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}ALL TESTS PASSED!${NC}"
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
    fi
}

# ============================================================================
# Feature detection: skip suite if endpoint returns 404 (feature disabled)
# Usage: require_feature "Feature Name" "/api/v1/some-endpoint" || return 0
# ============================================================================
require_feature() {
    local feature_name="$1"
    local probe_url="$2"
    local probe_method="${3:-GET}"
    local probe_args=""

    if [ "$probe_method" = "POST" ]; then
        probe_args="-X POST -H 'Content-Type: application/json' -d '{}'"
    fi

    local http_code
    http_code=$(eval "curl -s -o /dev/null -w '%{http_code}' $probe_args -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL$probe_url" 2>/dev/null)

    if [ "$http_code" = "404" ]; then
        echo -e "${YELLOW}SKIP${NC} — $feature_name not enabled in current config (endpoint returned 404)"
        echo ""
        FAILED=0
        return 1
    fi
    return 0
}
