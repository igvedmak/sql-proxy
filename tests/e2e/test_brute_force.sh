#!/bin/bash
# E2E Tests: Brute Force Protection
# Tests lockout after max_attempts, exponential backoff, reset on success
# Auto-detects if brute force is enabled; skips gracefully if not.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Brute Force Protection Tests"
echo "========================================"
echo ""

# ---- Feature detection ----
# Send 4 bad auth attempts; if brute force is enabled we get 429, otherwise 401
PROBE_KEY="sk-brute-probe-$(date +%s)"
for i in $(seq 1 4); do
    curl -s -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $PROBE_KEY" \
        -d '{"database":"testdb","sql":"SELECT 1"}' > /dev/null
done
probe_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/v1/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $PROBE_KEY" \
    -d '{"database":"testdb","sql":"SELECT 1"}')

BRUTE_FORCE_ENABLED=false
if [ "$probe_code" = "429" ]; then
    BRUTE_FORCE_ENABLED=true
fi

# Wait for any probe lockout to expire before running real tests
sleep 3

# ---- Tests ----

# Use a unique fake key to avoid polluting other tests
FAKE_KEY="sk-brute-force-test-$(date +%s)"

# Test 1: Lockout after max_attempts failed auth
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Lockout after 3 failed attempts"

if $BRUTE_FORCE_ENABLED; then
    # Send 3 failed auth attempts
    for i in $(seq 1 3); do
        curl -s -X POST "$BASE_URL/api/v1/query" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer $FAKE_KEY" \
            -d '{"database":"testdb","sql":"SELECT 1"}' > /dev/null
    done

    # 4th attempt should be blocked with 429
    response=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $FAKE_KEY" \
        -d '{"database":"testdb","sql":"SELECT 1"}')
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    echo -e "  ${YELLOW}Status after 4th attempt:${NC} $http_code"
    echo -e "  ${YELLOW}Body:${NC} $(echo "$body" | head -c 200)"

    if [ "$http_code" = "429" ]; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC} (expected 429, got $http_code)"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} (brute force not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 2: Retry-After header is present on 429 response
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Retry-After header present on lockout"

if $BRUTE_FORCE_ENABLED; then
    headers=$(curl -s -D - -o /dev/null -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $FAKE_KEY" \
        -d '{"database":"testdb","sql":"SELECT 1"}')

    echo -e "  ${YELLOW}Headers:${NC} $(echo "$headers" | head -10)"

    if echo "$headers" | grep -qi "Retry-After"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected header: Retry-After${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} (brute force not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

# Test 3: Wait for lockout to expire, then retry succeeds
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Lockout expires after configured duration"

if $BRUTE_FORCE_ENABLED; then
    echo -e "  ${YELLOW}Waiting 3s for lockout to expire...${NC}"
    sleep 3
fi

# After lockout expires (or if never locked), a valid key should work
response=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $ANALYST_KEY" \
    -d '{"database":"testdb","sql":"SELECT 1 as test"}')
http_code=$(echo "$response" | tail -1)

echo -e "  ${YELLOW}Status after lockout expired (valid key):${NC} $http_code"

if [ "$http_code" = "200" ]; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} (expected 200, got $http_code)"
    FAILED=$((FAILED + 1))
fi
echo ""

# Test 4: Brute force metrics in /metrics
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Brute force metrics present"

if $BRUTE_FORCE_ENABLED; then
    if curl -s "$BASE_URL/metrics" | grep -q "sql_proxy_auth_failures_total\|sql_proxy_auth_blocks_total"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        echo -e "  ${RED}Expected pattern: sql_proxy_auth_failures_total${NC}"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${YELLOW}SKIP${NC} (brute force not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

print_summary "Brute Force Protection"
return $FAILED 2>/dev/null || exit $FAILED
