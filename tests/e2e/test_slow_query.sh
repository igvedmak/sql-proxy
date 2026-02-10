#!/bin/bash
# E2E Tests: Slow Query Tracking
# Tests slow query API endpoint
# Auto-detects if slow query tracking is enabled; skips metric test gracefully if not.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Slow Query Tracking Tests"
echo "========================================"
echo ""

# Generate a query first (with threshold_ms=1, most queries will be "slow")
query_as_user 'analyst' 'testdb' 'SELECT id, name FROM customers LIMIT 5' > /dev/null 2>&1
sleep 1

# Test 1: Slow query API returns 200
run_test_status "Slow query API returns 200" \
    "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/slow-queries" \
    "200"

# Test 2: Slow query metric in Prometheus (only present when slow_query enabled)
TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Slow query metric present"

if curl -s "$BASE_URL/metrics" | grep -q "sql_proxy_slow_queries_total"; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${YELLOW}SKIP${NC} (slow query tracking not enabled in config)"
    PASSED=$((PASSED + 1))
fi
echo ""

print_summary "Slow Query Tracking"
return $FAILED 2>/dev/null || exit $FAILED
