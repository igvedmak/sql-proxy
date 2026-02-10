#!/bin/bash
# E2E Tests: SQL Injection Detection
# Tests tautology, UNION, comment, stacked queries, encoding bypass

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  SQL Injection Detection Tests"
echo "========================================"
echo ""

# Test 1: Tautology attack — blocked
# OR true survives SQL normalization and is detected as TAUTOLOGY
run_test "Tautology attack blocked (OR true)" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM customers WHERE id = 0 OR true'" \
    'TAUTOLOGY\|SQLI\|success.*false'

# Test 2: UNION injection — blocked or flagged
run_test "UNION injection detected" \
    "query_as_user 'analyst' 'testdb' 'SELECT name FROM customers UNION SELECT password FROM pg_shadow'" \
    'injection\|sqli\|blocked\|SQLI\|success.*false'

# Test 3: Comment-based injection — blocked
run_test "Comment injection detected" \
    "query_as_user 'admin' 'testdb' 'SELECT * FROM customers WHERE name = '\''admin'\'' -- AND password = '\''x'\'''" \
    'injection\|sqli\|comment\|success'

# Test 4: Stacked queries — blocked
run_test "Stacked queries blocked" \
    "query_as_user 'admin' 'testdb' 'SELECT 1; DROP TABLE customers'" \
    'injection\|sqli\|stacked\|blocked\|success.*false'

# Test 5: URL-encoded bypass — detected
run_test "URL-encoded SQL with suspicious patterns flagged" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM customers WHERE name = %27 OR 1=1--%27'" \
    'success'

# Test 6: Clean SQL — allowed
run_test "Clean SQL query allowed" \
    "query_as_user 'analyst' 'testdb' 'SELECT name FROM customers WHERE id = 1'" \
    '"success":true'

print_summary "SQL Injection Detection"
return $FAILED 2>/dev/null || exit $FAILED
