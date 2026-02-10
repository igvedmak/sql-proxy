#!/bin/bash
# E2E Tests: Core Take-Home Exercise Requirements
# Covers the 6 core requirements from the exercise spec:
#   1. SQL Analysis (statement type, tables, columns)
#   2. Access Policies (ALLOW/BLOCK, specificity, default deny)
#   3. User Management (multiple users, per-user evaluation)
#   4. Query Execution (allowed executes, denied returns clear error)
#   5. Data Classification (email → PII.Email, phone → PII.Phone)
#   6. Audit Logging (every statement produces audit record)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Core Requirements Tests"
echo "========================================"
echo ""

# ============================================================================
# Requirement 1: SQL Analysis
# ============================================================================

echo -e "${CYAN}--- Requirement 1: SQL Analysis ---${NC}"
echo ""

# Test: SELECT query returns columns and rows
run_test "SELECT returns data with columns and rows" \
    "query_as_user 'analyst' 'testdb' 'SELECT id, name FROM customers LIMIT 2'" \
    '"columns":\["id","name"\]'

# Test: DDL statement is recognized (dry-run to avoid DB permission issues)
run_test "DDL statement recognized and handled (dry-run)" \
    "curl -s -X POST $BASE_URL/api/v1/query/dry-run -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"database\":\"testdb\",\"sql\":\"CREATE TABLE e2e_analysis_test (id INT)\"}'" \
    'would_succeed.*true\|ALLOW'

# Test: DML statement is recognized (INSERT)
# Cleanup stale data first to avoid unique constraint violations on re-runs
query_as_user 'developer' 'testdb' "DELETE FROM orders WHERE order_number = 'E2E-REQ-001'" > /dev/null 2>&1

run_test "DML INSERT recognized and executed" \
    "query_as_user 'developer' 'testdb' 'INSERT INTO orders (customer_id, order_number, amount, status) VALUES (1, '\''E2E-REQ-001'\'', 50.00, '\''test'\'')'" \
    '"success":true'

# Test: Dry-run shows policy decision and matched policy name
run_test "Dry-run shows policy_decision and matched_policy" \
    "curl -s -X POST $BASE_URL/api/v1/query/dry-run -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT id FROM customers\"}'" \
    '"policy_decision"'

# Test: Dry-run on blocked query shows BLOCK decision
run_test "Dry-run shows BLOCK for denied queries" \
    "curl -s -X POST $BASE_URL/api/v1/query/dry-run -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"INSERT INTO customers (name) VALUES ('\''x'\'')\"}'"\
    'BLOCK\|would_succeed.*false'

# ============================================================================
# Requirement 2: Access Policies (ALLOW / BLOCK)
# ============================================================================

echo ""
echo -e "${CYAN}--- Requirement 2: Access Policies ---${NC}"
echo ""

# Test: Default deny — unrecognized table blocked
run_test "Default deny: query on unknown table blocked" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM nonexistent_xyz_table'" \
    '"success":false'

# Test: BLOCK overrides — analyst blocked from sensitive_data even though analyst has some ALLOW policies
run_test "BLOCK overrides ALLOW: analyst blocked from sensitive_data" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM sensitive_data'" \
    '"success":false'

# Test: Table-level specificity — auditor has explicit ALLOW on sensitive_data despite general BLOCK
run_test "Specific ALLOW overrides general BLOCK (auditor on sensitive_data)" \
    "query_as_user 'auditor' 'testdb' 'SELECT id, salary FROM sensitive_data LIMIT 1'" \
    '"success":true'

# Test: Error message includes reason for denial
run_test "Denied query returns clear error message" \
    "query_as_user 'analyst' 'testdb' 'INSERT INTO customers (name) VALUES ('\''test'\'')'" \
    'error_message\|error.*role\|Read-only\|Access denied\|BLOCK'

# ============================================================================
# Requirement 3: User Management
# ============================================================================

echo ""
echo -e "${CYAN}--- Requirement 3: User Management ---${NC}"
echo ""

# Test: Same query, different users, different outcomes
run_test "Analyst can SELECT customers" \
    "query_as_user 'analyst' 'testdb' 'SELECT name FROM customers LIMIT 1'" \
    '"success":true'

run_test "Developer can SELECT customers" \
    "query_as_user 'developer' 'testdb' 'SELECT name FROM customers LIMIT 1'" \
    '"success":true'

run_test "Analyst CANNOT INSERT into customers (readonly)" \
    "query_as_user 'analyst' 'testdb' 'INSERT INTO customers (name, email) VALUES ('\''x'\'', '\''x@x.com'\'')'" \
    '"success":false'

# Cleanup stale test data first; sleep ensures rate limit tokens available
sleep 1
query_as_user 'admin' 'testdb' "DELETE FROM customers WHERE email = 'e2e@test.com'" > /dev/null 2>&1
sleep 1

run_test "Developer CAN INSERT into customers" \
    "query_as_user 'developer' 'testdb' 'INSERT INTO customers (name, email) VALUES ('\''E2E Test User'\'', '\''e2e@test.com'\'')'" \
    '"success":true'

# ============================================================================
# Requirement 4: Query Execution
# ============================================================================

echo ""
echo -e "${CYAN}--- Requirement 4: Query Execution ---${NC}"
echo ""

# Test: Allowed SELECT returns actual data rows
run_test "Allowed SELECT returns actual database rows" \
    "query_as_user 'analyst' 'testdb' 'SELECT COUNT(*) as total FROM customers'" \
    '"rows"'

# Test: Denied statement returns error, NOT data
run_test "Denied statement returns error (no data)" \
    "query_as_user 'analyst' 'testdb' 'DROP TABLE customers'" \
    '"success":false'

# Test: Invalid SQL returns parse error
run_test "Invalid SQL returns clear parse error" \
    "query_as_user 'analyst' 'testdb' 'SELECTT FROMM NOPE'" \
    '"success":false'

# ============================================================================
# Requirement 5: Data Classification
# ============================================================================

echo ""
echo -e "${CYAN}--- Requirement 5: Data Classification ---${NC}"
echo ""

# Test: Email column classified as PII.Email
run_test "Email column classified as PII.Email" \
    "query_as_user 'analyst' 'testdb' 'SELECT id, name, email FROM customers LIMIT 1'" \
    'PII.Email'

# Test: Phone column classified as PII.Phone
run_test "Phone column classified as PII.Phone" \
    "query_as_user 'analyst' 'testdb' 'SELECT id, name, phone FROM customers LIMIT 1'" \
    'PII.Phone'

# Test: Classifications appear in response JSON
run_test "Response includes classifications object" \
    "query_as_user 'analyst' 'testdb' 'SELECT email, phone FROM customers LIMIT 1'" \
    '"classifications"'

# ============================================================================
# Requirement 6: Audit Logging
# ============================================================================

echo ""
echo -e "${CYAN}--- Requirement 6: Audit Logging ---${NC}"
echo ""

# Test: Allowed query response includes audit_id
run_test "Allowed query includes audit_id in response" \
    "query_as_user 'analyst' 'testdb' 'SELECT 1 as test'" \
    '"audit_id"'

# Test: Denied query response also includes audit_id
run_test "Denied query also includes audit_id" \
    "query_as_user 'analyst' 'testdb' 'INSERT INTO customers (name) VALUES ('\''x'\'')'" \
    '"audit_id"'

# Test: Audit emitted metric increments (shows audit records are being produced)
# Use admin user to avoid rate limiting during bulk test runs
sleep 2  # Allow rate limit tokens to refill

# First, get the current count
BEFORE=$(curl -s "$BASE_URL/metrics" | grep '^sql_proxy_audit_emitted_total' | awk '{print $2}')

# Execute a query (admin is less likely to be rate-limited)
query_as_user 'admin' 'testdb' 'SELECT 1 as audit_test' > /dev/null 2>&1
sleep 1

# Check that count incremented
AFTER=$(curl -s "$BASE_URL/metrics" | grep '^sql_proxy_audit_emitted_total' | awk '{print $2}')

TOTAL=$((TOTAL + 1))
echo -e "${BLUE}[TEST $TOTAL]${NC} Audit metric increments after query"
echo -e "  ${YELLOW}Before:${NC} $BEFORE, ${YELLOW}After:${NC} $AFTER"
if [ -n "$AFTER" ] && [ -n "$BEFORE" ] && [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null; then
    echo -e "  ${GREEN}PASS${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC} (audit_emitted_total should have increased)"
    FAILED=$((FAILED + 1))
fi
echo ""

# Cleanup test data
query_as_user 'developer' 'testdb' "DELETE FROM customers WHERE name = 'E2E Test User'" > /dev/null 2>&1
query_as_user 'developer' 'testdb' "DELETE FROM orders WHERE order_number = 'E2E-REQ-001'" > /dev/null 2>&1

print_summary "Core Requirements"
return $FAILED 2>/dev/null || exit $FAILED
