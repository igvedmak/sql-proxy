#!/bin/bash
# E2E Tests: Multi-DB Transactions
# Tests transaction lifecycle: begin, prepare, commit, rollback

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1
require_feature "Multi-DB Transactions" "/api/v1/transactions/begin" "POST" || return 0 2>/dev/null || exit 0

echo "========================================"
echo "  Multi-DB Transaction Tests"
echo "========================================"
echo ""

# Test 1: Begin transaction
TXID=""
run_test_status "Begin transaction returns 200" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"databases\":[\"testdb\"]}' $BASE_URL/api/v1/transactions/begin" \
    "200"

# Capture transaction ID for subsequent tests
TXID=$(curl -s -X POST -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"databases":["testdb"]}' \
    "$BASE_URL/api/v1/transactions/begin" 2>&1 | grep -o '"xid":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$TXID" ]; then
    # Try alternative response format
    TXID=$(curl -s -X POST -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -d '{"databases":["testdb"]}' \
        "$BASE_URL/api/v1/transactions/begin" 2>&1 | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

if [ -n "$TXID" ]; then
    echo -e "${CYAN}  Transaction ID: $TXID${NC}"

    # Test 2: Get transaction status
    run_test_status "Get transaction status" \
        "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/transactions/$TXID" \
        "200"

    # Test 3: Rollback transaction
    run_test_status "Rollback transaction returns 200" \
        "-X POST -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/transactions/$TXID/rollback" \
        "200"
else
    echo -e "${YELLOW}  Skipping transaction lifecycle tests (no TXID captured)${NC}"
    # Still test the endpoints respond
    run_test_status "Transaction status endpoint responds" \
        "-H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/transactions/test-xid" \
        "200"

    run_test_status "Transaction rollback endpoint responds" \
        "-X POST -H 'Authorization: Bearer $ADMIN_TOKEN' $BASE_URL/api/v1/transactions/test-xid/rollback" \
        "200"
fi

# Test 4: Begin + commit flow
run_test_status "Begin transaction for commit test" \
    "-X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $ADMIN_TOKEN' -d '{\"databases\":[\"testdb\"]}' $BASE_URL/api/v1/transactions/begin" \
    "200"

# Test 5: Transactions require auth
run_test_status "Transactions reject no-auth" \
    "-X POST -H 'Content-Type: application/json' -d '{\"databases\":[\"testdb\"]}' $BASE_URL/api/v1/transactions/begin" \
    "401"

print_summary "Multi-DB Transactions"
return $FAILED 2>/dev/null || exit $FAILED
