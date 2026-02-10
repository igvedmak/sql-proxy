#!/bin/bash
# E2E Tests: Policy Engine
# Tests allow, block, column-level, DDL, and default deny policies

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Policy Engine Tests"
echo "========================================"
echo ""

# Test 1: Analyst SELECT on customers — allowed
run_test "Analyst SELECT on customers (allowed)" \
    "query_as_user 'analyst' 'testdb' 'SELECT id, name FROM customers LIMIT 3'" \
    '"success":true'

# Test 2: Analyst INSERT on customers — blocked (readonly role)
run_test "Analyst INSERT blocked (readonly)" \
    "query_as_user 'analyst' 'testdb' 'INSERT INTO customers (name, email) VALUES ('\''Test'\'', '\''test@example.com'\'')'" \
    '"success":false'

# Test 3: Developer INSERT on orders — allowed
# Cleanup stale data first to avoid unique constraint violations on re-runs
query_as_user 'developer' 'testdb' "DELETE FROM orders WHERE order_number = 'E2E-TEST-001'" > /dev/null 2>&1

run_test "Developer INSERT on orders (allowed)" \
    "query_as_user 'developer' 'testdb' 'INSERT INTO orders (customer_id, order_number, amount, status) VALUES (1, '\''E2E-TEST-001'\'', 99.99, '\''pending'\'')'" \
    '"success":true'

# Test 4: Analyst SELECT on sensitive_data — blocked
run_test "Analyst SELECT on sensitive_data (blocked)" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM sensitive_data LIMIT 1'" \
    '"success":false'

# Test 5: Auditor SELECT on sensitive_data — allowed
run_test "Auditor SELECT on sensitive_data (allowed)" \
    "query_as_user 'auditor' 'testdb' 'SELECT id, salary FROM sensitive_data LIMIT 1'" \
    '"success":true'

# Test 6: Admin DDL — policy allows it (dry-run to avoid DB permission issues)
run_test "Admin DDL allowed by policy (dry-run)" \
    "curl -s -X POST $BASE_URL/api/v1/query/dry-run -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"database\":\"testdb\",\"sql\":\"CREATE TABLE e2e_test_table (id SERIAL PRIMARY KEY, val TEXT)\"}'" \
    'would_succeed.*true\|ALLOW'

# Test 7: Analyst DDL — blocked
run_test "Analyst DDL DROP TABLE (blocked)" \
    "query_as_user 'analyst' 'testdb' 'DROP TABLE customers'" \
    '"success":false'

# Test 8: Default deny on unmatched table
run_test "Default deny on unmatched table" \
    "query_as_user 'analyst' 'testdb' 'SELECT * FROM some_random_table'" \
    '"success":false'

# Cleanup test data
query_as_user 'developer' 'testdb' "DELETE FROM orders WHERE order_number = 'E2E-TEST-001'" > /dev/null 2>&1

print_summary "Policy Engine"
return $FAILED 2>/dev/null || exit $FAILED
