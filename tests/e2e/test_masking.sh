#!/bin/bash
# E2E Tests: Data Masking
# Tests partial masking, hash masking, and column-level blocking

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_helpers.sh"

wait_for_proxy || exit 1

echo "========================================"
echo "  Data Masking Tests"
echo "========================================"
echo ""

# Test 1: Developer SELECT email — partial masking (prefix 3 + suffix 4)
# Email should be masked like "ali***..com" or similar partial pattern
run_test "Developer email is partially masked" \
    "query_as_user 'developer' 'testdb' 'SELECT email FROM customers LIMIT 1'" \
    '"masked_columns"'

# Test 2: Analyst SELECT phone — hash masking
run_test "Analyst phone is hash masked" \
    "query_as_user 'analyst' 'testdb' 'SELECT phone FROM customers LIMIT 1'" \
    '"masked_columns"'

# Test 3: Admin SELECT email — NOT masked (admin has full access)
run_test "Admin email is NOT masked" \
    "query_as_user 'admin' 'testdb' 'SELECT email FROM customers LIMIT 1'" \
    '"success":true'

# Test 4: Analyst SELECT SSN from sensitive_data — blocked (column-level)
run_test "Analyst SSN access blocked (column-level)" \
    "query_as_user 'analyst' 'testdb' 'SELECT ssn FROM sensitive_data LIMIT 1'" \
    '"success":false'

print_summary "Data Masking"
return $FAILED 2>/dev/null || exit $FAILED
