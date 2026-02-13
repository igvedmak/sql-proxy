#!/bin/bash
# E2E Tests: Rate Limiting
# Tests rate limit headers, burst rejection, and per-user independence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Rate Limiting Tests"
echo "========================================"
echo ""

# Test 1: Single request returns X-RateLimit-Remaining header
run_test_header "Rate limit header present on response" \
    "-X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    "X-RateLimit-Remaining"

# Test 2: Burst of requests — analyst has low per-user-per-db limit (30 TPS, burst 10)
# Send 20 requests in parallel to exhaust the burst capacity before refill
echo -e "${BLUE}[TEST $((TOTAL+1))]${NC} Burst requests trigger rate limiting"
TOTAL=$((TOTAL + 1))
RATE_LIMITED=0
TMPDIR_RL=$(mktemp -d)
for i in $(seq 1 20); do
    curl -s -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -d '{"user":"analyst","database":"testdb","sql":"SELECT 1 as test"}' \
        > "$TMPDIR_RL/resp_$i" 2>/dev/null &
done
wait
for i in $(seq 1 20); do
    http_code=$(tail -1 "$TMPDIR_RL/resp_$i" 2>/dev/null)
    if [ "$http_code" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
done
rm -rf "$TMPDIR_RL"
echo -e "  ${YELLOW}Rate limited requests:${NC} $RATE_LIMITED / 20"
if [ $RATE_LIMITED -gt 0 ]; then
    echo -e "  ${GREEN}PASS${NC} (at least 1 request was rate limited)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} (expected some requests to be rate limited)"
    FAILED=$((FAILED + 1))
fi
echo ""

# Test 3: Admin has higher rate limit — should not get limited with same burst
echo -e "${BLUE}[TEST $((TOTAL+1))]${NC} Admin has higher rate limit (no rejection on small burst)"
TOTAL=$((TOTAL + 1))
ADMIN_LIMITED=0
for i in $(seq 1 10); do
    response=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -d '{"user":"admin","database":"testdb","sql":"SELECT 1 as test"}')
    http_code=$(echo "$response" | tail -1)
    if [ "$http_code" = "429" ]; then
        ADMIN_LIMITED=$((ADMIN_LIMITED + 1))
    fi
done
echo -e "  ${YELLOW}Admin rate limited requests:${NC} $ADMIN_LIMITED / 10"
if [ $ADMIN_LIMITED -eq 0 ]; then
    echo -e "  ${GREEN}PASS${NC} (admin not rate limited on small burst)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} (admin should not be rate limited on small burst)"
    FAILED=$((FAILED + 1))
fi
echo ""

print_summary "Rate Limiting"
return $FAILED 2>/dev/null || exit $FAILED
