#!/bin/bash
# E2E Tests: IP Allowlisting
# Tests CIDR-based IP restrictions per user

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  IP Allowlisting Tests"
echo "========================================"
echo ""

# Test 1: Restricted user from allowed IP (10.0.0.1)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Restricted user from allowed IP (10.0.0.1)"

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
echo ""

# Test 2: Restricted user from disallowed IP (203.0.113.1)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Restricted user from disallowed IP (403)"

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
echo ""

# Test 3: Regular user (no allowlist) from any IP
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
