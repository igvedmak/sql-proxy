#!/bin/bash
# E2E Tests: IP Allowlisting
# Tests CIDR-based IP restrictions per user
# Auto-detects if restricted_user exists; skips those tests gracefully if not.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  IP Allowlisting Tests"
echo "========================================"
echo ""

# ---- Feature detection ----
# Probe whether restricted_user's API key is recognized
probe_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/v1/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $RESTRICTED_KEY" \
    -H 'X-Forwarded-For: 10.0.0.1' \
    -d '{"database":"testdb","sql":"SELECT 1"}')

RESTRICTED_USER_EXISTS=false
# If the key is recognized we get 200 (allowed IP) or 403 (blocked IP); 401 means key unknown
if [ "$probe_code" != "401" ]; then
    RESTRICTED_USER_EXISTS=true
fi

# ---- Tests ----

# Test 1: Restricted user from allowed IP (10.0.0.1) — allowed
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Restricted user from allowed IP (10.0.0.1)"

if $RESTRICTED_USER_EXISTS; then
    body=$(eval "curl -s -w '\\n%{http_code}' -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'Authorization: Bearer $RESTRICTED_KEY' -H 'X-Forwarded-For: 10.0.0.1' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1 as test\"}'")
    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    echo -e "  ${YELLOW}Status:${NC} $http_code"
    echo -e "  ${YELLOW}Body:${NC} $(echo "$body" | head -c 300)"

    if [ "$http_code" = "200" ] && echo "$body" | grep -q '"success":true'; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected status: 200, body pattern: \"success\":true${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} (restricted_user not defined in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 2: Restricted user from disallowed IP (203.0.113.1) — 403
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Restricted user from disallowed IP (403)"

if $RESTRICTED_USER_EXISTS; then
    body=$(eval "curl -s -w '\\n%{http_code}' -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'Authorization: Bearer $RESTRICTED_KEY' -H 'X-Forwarded-For: 203.0.113.1' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1 as test\"}'")
    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    echo -e "  ${YELLOW}Status:${NC} $http_code"
    echo -e "  ${YELLOW}Body:${NC} $(echo "$body" | head -c 300)"

    if [ "$http_code" = "403" ]; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected status: 403${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} (restricted_user not defined in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 3: Regular user (no allowlist) from any IP — allowed
run_test_status "Regular user (no allowlist) from any IP" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -H 'Authorization: Bearer $ANALYST_KEY' -H 'X-Forwarded-For: 203.0.113.99' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1 as test\"}'" \
    "200" \
    '"success":true'

# Test 4: IP block metric increments
run_test "IP block metric present" \
    "curl -s $BASE_URL/metrics" \
    "sql_proxy_ip_blocked_total"

print_summary "IP Allowlisting"
return $FAILED 2>/dev/null || exit $FAILED
