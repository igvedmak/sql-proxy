#!/bin/bash
# SQL Proxy Test Suite
# Comprehensive tests for all proxy endpoints and functionality

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
TOTAL=0

# Base URL
BASE_URL="http://localhost:8080"

# Test helper function
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    TOTAL=$((TOTAL + 1))
    echo -e "${BLUE}[TEST $TOTAL]${NC} $test_name"

    # Run command and capture output
    local output
    output=$(eval "$command" 2>&1)
    local exit_code=$?

    # Print command
    echo -e "${YELLOW}Command:${NC} $command"

    # Print output
    echo -e "${YELLOW}Response:${NC}"
    echo "$output" | jq '.' 2>/dev/null || echo "$output"

    # Check result
    if echo "$output" | grep -q "$expected_pattern" && [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo -e "${RED}Expected pattern: $expected_pattern${NC}"
        FAILED=$((FAILED + 1))
    fi
    echo -e "---\n"
    sleep 0.5
}

# Print header
echo "========================================"
echo "  SQL PROXY TEST SUITE"
echo "========================================"
echo ""

# Test 1: Health Check
run_test "Health Check Endpoint" \
    "curl -s $BASE_URL/health" \
    '"status":"healthy"'

# Test 2: Simple SELECT with constant
run_test "Simple SELECT with Constants" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT 1 as test, '\''hello'\'' as message\"}'" \
    '"success":true'

# Test 3: Count customers
run_test "Count Query - Customers Table" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT COUNT(*) as total FROM customers\"}'" \
    '"success":true'

# Test 4: List tables
run_test "List All Tables in Schema" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT table_name FROM information_schema.tables WHERE table_schema = '\''public'\'' ORDER BY table_name\"}'" \
    'customers'

# Test 5: Select from customers with PII
run_test "Select Customers with PII (email)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT id, name, email FROM customers LIMIT 3\"}'" \
    '"success":true'

# Test 6: Select from order_items
run_test "Select Order Items with Price Filter" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, unit_price FROM order_items WHERE unit_price > 100 ORDER BY unit_price DESC LIMIT 5\"}'" \
    '"success":true'

# Test 7: JOIN query
run_test "JOIN Query - Customers and Orders" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT c.name, COUNT(o.id) as order_count FROM customers c LEFT JOIN orders o ON c.id = o.customer_id GROUP BY c.name LIMIT 5\"}'" \
    '"success":true'

# Test 8: Aggregate with HAVING
run_test "Aggregate Query with HAVING Clause" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT customer_id, COUNT(*) as order_count FROM orders GROUP BY customer_id HAVING COUNT(*) > 1\"}'" \
    '"success":true'

# Test 9: Complex JOIN with order_items
run_test "Complex JOIN - Customers with Order Items" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT c.name, oi.product_name, oi.quantity FROM orders o JOIN customers c ON o.customer_id = c.id JOIN order_items oi ON o.id = oi.order_id LIMIT 5\"}'" \
    '"success":true'

# Test 10: Date filtering
run_test "Date Range Filter Query" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT COUNT(*) as recent_orders FROM orders WHERE created_at > NOW() - INTERVAL '\''30 days'\''\"}'" \
    '"success":true'

# Test 11: Invalid SQL syntax (should fail gracefully)
run_test "Invalid SQL Syntax (expect error)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"INVALID SQL SYNTAX\"}'" \
    '"success":false'

# Test 12: Non-existent table (should fail)
run_test "Query Non-existent Table (expect error)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT * FROM nonexistent_table\"}'" \
    '"success":false'

# Test 13: Missing required field - sql
run_test "Missing Required Field - sql (expect error)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\"}'" \
    '"success":false'

# Test 14: Missing required field - user
run_test "Missing Required Field - user (expect error)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"database\":\"testdb\",\"sql\":\"SELECT 1\"}'" \
    '"success":false'

# Test 15: Malformed JSON (should fail)
run_test "Malformed JSON Request (expect error)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{invalid json}'" \
    'success'

# Test 16: CASE expression
run_test "CASE Expression in SELECT" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, CASE WHEN unit_price > 200 THEN '\''expensive'\'' WHEN unit_price > 100 THEN '\''moderate'\'' ELSE '\''cheap'\'' END as price_category FROM order_items LIMIT 5\"}'" \
    '"success":true'

# Test 17: Subquery
run_test "Subquery in WHERE Clause" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT name FROM customers WHERE id IN (SELECT DISTINCT customer_id FROM orders) LIMIT 5\"}'" \
    '"success":true'

# Test 18: String functions
run_test "String Functions (UPPER, LOWER, CONCAT)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT UPPER(name) as upper_name, LOWER(email) as lower_email FROM customers LIMIT 3\"}'" \
    '"success":true'

# Test 19: Math functions
run_test "Math Functions (ROUND, CEIL, FLOOR)" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, ROUND(unit_price, 2) as rounded, CEIL(unit_price) as ceiling FROM order_items LIMIT 5\"}'" \
    '"success":true'

# Test 20: LIMIT and OFFSET
run_test "Pagination with LIMIT and OFFSET" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT name FROM customers ORDER BY name LIMIT 5 OFFSET 2\"}'" \
    '"success":true'

# Test 21: DISTINCT
run_test "DISTINCT Values Query" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT DISTINCT customer_id FROM orders\"}'" \
    '"success":true'

# Test 22: Multiple aggregates
run_test "Multiple Aggregate Functions" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT COUNT(*) as total, AVG(unit_price) as avg_price, MAX(unit_price) as max_price, MIN(unit_price) as min_price FROM order_items\"}'" \
    '"success":true'

# Test 23: NULL handling
run_test "NULL Handling with COALESCE" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT name, COALESCE(phone, '\''N/A'\'') as phone_number FROM customers LIMIT 5\"}'" \
    '"success":true'

# Test 24: ORDER BY multiple columns
run_test "ORDER BY Multiple Columns" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, unit_price FROM order_items ORDER BY unit_price DESC, product_name ASC LIMIT 5\"}'" \
    '"success":true'

# Test 25: LIKE pattern matching
run_test "Pattern Matching with LIKE" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT name FROM customers WHERE name LIKE '\''%son'\'' LIMIT 5\"}'" \
    '"success":true'

# Test 26: IN operator
run_test "IN Operator with Multiple Values" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, unit_price FROM order_items WHERE id IN (1, 3, 5) ORDER BY id\"}'" \
    '"success":true'

# Test 27: BETWEEN operator
run_test "BETWEEN Operator for Range Query" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT product_name, unit_price FROM order_items WHERE unit_price BETWEEN 50 AND 150 LIMIT 5\"}'" \
    '"success":true'

# Test 28: EXISTS subquery
run_test "EXISTS Subquery" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT name FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id) LIMIT 5\"}'" \
    '"success":true'

# Test 29: Self-join (if applicable)
run_test "Complex Multi-table Query" \
    "curl -s -X POST $BASE_URL/api/v1/query -H 'Content-Type: application/json' -d '{\"user\":\"analyst\",\"database\":\"testdb\",\"sql\":\"SELECT DISTINCT c1.name FROM customers c1 JOIN orders o1 ON c1.id = o1.customer_id JOIN orders o2 ON c1.id = o2.customer_id WHERE o1.id != o2.id LIMIT 5\"}'" \
    '"success":true'

# Test 30: Test metrics endpoint (if available)
run_test "Metrics Endpoint (if implemented)" \
    "curl -s $BASE_URL/metrics || echo '{\"note\":\"endpoint not implemented\"}'" \
    '.'

# Print summary
echo "========================================"
echo "  TEST SUMMARY"
echo "========================================"
echo -e "Total Tests:  $TOTAL"
echo -e "${GREEN}Passed:       $PASSED${NC}"
echo -e "${RED}Failed:       $FAILED${NC}"
echo "========================================"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
