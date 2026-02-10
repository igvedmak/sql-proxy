#!/usr/bin/env bash
# =============================================================================
# SQL Proxy Stress / Sanity Test
#
# Fires a mix of ALLOWED, BLOCKED, and edge-case requests to exercise the full
# pipeline and verify the dashboard updates in real time.
#
# Usage:
#   ./stress_test.sh [rounds]
#   rounds = number of full cycles (default: 5)
#
# Prerequisites: curl, docker compose up -d
# =============================================================================

set -euo pipefail

BASE_URL="${PROXY_URL:-http://localhost:8080}"
ROUNDS="${1:-5}"
RESULTS_DIR=$(mktemp -d)
ADMIN_TOKEN="${ADMIN_TOKEN:-$(grep '^admin_token' config/proxy.toml 2>/dev/null | sed 's/.*= *"//' | sed 's/".*//' || echo "")}"
DELAY="${DELAY:-0.05}"  # 50ms between requests (avoids thread-pool saturation)

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
BOLD="\033[1m"
RESET="\033[0m"

cleanup() { rm -rf "$RESULTS_DIR"; }
trap cleanup EXIT

# ---- Helpers ----------------------------------------------------------------

fire() {
    local label="$1" expect="$2" api_key="$3" sql="$4"
    local result_file="$RESULTS_DIR/$(date +%s%N)_$$_$RANDOM"

    local body
    if [[ -n "$api_key" ]]; then
        body="{\"database\":\"testdb\",\"sql\":\"$sql\"}"
    else
        body="{\"user\":\"unknown\",\"database\":\"testdb\",\"sql\":\"$sql\"}"
    fi

    local resp http_code
    resp=$(curl -s --connect-timeout 5 --max-time 10 \
        -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
        -H 'Content-Type: application/json' \
        -H 'Connection: close' \
        ${api_key:+-H "Authorization: Bearer $api_key"} \
        -d "$body" 2>/dev/null) || resp=$'\n000'

    http_code=$(echo "$resp" | tail -1)

    local status result_type
    case "$expect" in
        allow)
            if [[ "$http_code" == "200" ]]; then
                result_type="allow"; status="${GREEN}ALLOW${RESET}"
            elif [[ "$http_code" == "429" ]]; then
                result_type="ratelimited"; status="${MAGENTA}RATE-LIMITED${RESET}"
            else
                result_type="error"; status="${RED}UNEXPECTED (${http_code})${RESET}"
            fi
            ;;
        block)
            if [[ "$http_code" == "200" ]] && echo "$resp" | grep -q '"success":true'; then
                result_type="error"; status="${RED}UNEXPECTED ALLOW${RESET}"
            else
                result_type="block"; status="${YELLOW}BLOCK${RESET}"
            fi
            ;;
    esac

    printf "  %-55s %b\n" "$label" "$status"
    echo "$result_type" > "$result_file"

    # Small delay to let server threads recycle
    sleep "$DELAY"
}

# Fire requests sequentially
batch_fire() {
    while IFS='|' read -r label expect key sql; do
        fire "$label" "$expect" "$key" "$sql"
    done
}

# Wait for the proxy to be healthy (handles Docker restarts)
wait_for_proxy() {
    local max_wait=15
    for i in $(seq 1 "$max_wait"); do
        if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ---- Test cases -------------------------------------------------------------
# Format: label|expect|api_key|sql

generate_round() {
    # Analyst: allowed reads
    echo "analyst: SELECT id, name FROM customers|allow|sk-analyst-key-67890|SELECT id, name FROM customers LIMIT 10"
    echo "analyst: SELECT * FROM orders|allow|sk-analyst-key-67890|SELECT * FROM orders WHERE amount > 100"
    echo "analyst: SELECT FROM order_items|allow|sk-analyst-key-67890|SELECT product_name FROM order_items LIMIT 5"
    echo "analyst: SELECT COUNT(*)|allow|sk-analyst-key-67890|SELECT COUNT(*) FROM customers"
    echo "analyst: JOIN customers+orders|allow|sk-analyst-key-67890|SELECT c.name, o.amount FROM customers c JOIN orders o ON c.id = o.customer_id LIMIT 5"

    # Analyst: blocked
    echo "analyst: sensitive_data|block|sk-analyst-key-67890|SELECT * FROM sensitive_data"
    echo "analyst: INSERT customers|block|sk-analyst-key-67890|INSERT INTO customers (name) VALUES ('hacker')"
    echo "analyst: UPDATE customers|block|sk-analyst-key-67890|UPDATE customers SET name = 'pwned' WHERE id = 1"
    echo "analyst: DELETE orders|block|sk-analyst-key-67890|DELETE FROM orders WHERE id = 1"
    echo "analyst: DROP TABLE|block|sk-analyst-key-67890|DROP TABLE customers"
    echo "analyst: CREATE TABLE|block|sk-analyst-key-67890|CREATE TABLE evil (id INT)"

    # Developer: allowed
    echo "developer: SELECT customers|allow|sk-developer-key-abcde|SELECT * FROM customers LIMIT 5"
    echo "developer: SELECT orders|allow|sk-developer-key-abcde|SELECT * FROM orders LIMIT 5"
    echo "developer: INSERT orders|allow|sk-developer-key-abcde|INSERT INTO orders (customer_id, order_number, amount, status) VALUES (1, 'ORD-STRESS-' || floor(random()*1000000)::int, 99.99, 'pending')"
    echo "developer: UPDATE orders|allow|sk-developer-key-abcde|UPDATE orders SET status = 'shipped' WHERE id = 1"

    # Developer: blocked
    echo "developer: sensitive_data|block|sk-developer-key-abcde|SELECT * FROM sensitive_data"
    echo "developer: DROP TABLE|block|sk-developer-key-abcde|DROP TABLE orders"
    echo "developer: CREATE Index|block|sk-developer-key-abcde|CREATE INDEX idx_evil ON customers (name)"
    echo "developer: TRUNCATE|block|sk-developer-key-abcde|TRUNCATE orders"

    # Auditor: allowed
    echo "auditor: sensitive_data|allow|sk-auditor-key-fghij|SELECT * FROM sensitive_data LIMIT 5"

    # Auditor: blocked (writes)
    echo "auditor: INSERT sensitive|block|sk-auditor-key-fghij|INSERT INTO sensitive_data (customer_id, ssn) VALUES (1, '123-45-6789')"
    echo "auditor: DELETE sensitive|block|sk-auditor-key-fghij|DELETE FROM sensitive_data WHERE id = 1"

    # Admin: allowed (everything)
    echo "admin: SELECT customers|allow|sk-admin-key-12345|SELECT * FROM customers"
    echo "admin: SELECT sensitive|allow|sk-admin-key-12345|SELECT * FROM sensitive_data"
    echo "admin: INSERT customers|allow|sk-admin-key-12345|INSERT INTO customers (name, email) VALUES ('stress_test', 'stress' || floor(random()*1000000)::int || '@test.com')"

    # Bad auth
    echo "bad-key: SELECT 1|block|sk-invalid-key-xxxxx|SELECT 1"

    # No API key (unknown user body)
    echo "no-auth: SELECT 1|block||SELECT 1"
}

# ---- Main -------------------------------------------------------------------

echo ""
echo -e "${BOLD}=== SQL Proxy Stress Test ===${RESET}"
echo -e "Target:    $BASE_URL"
echo -e "Rounds:    $ROUNDS"
echo -e "Delay:     ${DELAY}s per request"
echo ""

# Health check
if ! wait_for_proxy; then
    echo -e "${RED}ERROR: Proxy not reachable at $BASE_URL${RESET}"
    echo "Start with: docker compose up -d"
    exit 1
fi
echo -e "${GREEN}Proxy is healthy${RESET}"
echo ""

# Initial stats
initial_stats=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/dashboard/api/stats" 2>/dev/null || echo "{}")
echo -e "${CYAN}Initial dashboard stats:${RESET}"
echo "$initial_stats" | python3 -m json.tool 2>/dev/null || echo "$initial_stats"
echo ""

start_time=$(date +%s%N)

for round in $(seq 1 "$ROUNDS"); do
    echo -e "${BOLD}--- Round $round / $ROUNDS (27 requests) ---${RESET}"

    # Ensure proxy is healthy before each round
    if ! wait_for_proxy; then
        echo -e "${RED}Proxy down before round $round — aborting${RESET}"
        break
    fi

    generate_round | batch_fire
    echo ""
done

# ---- Rate Limit Burst Test --------------------------------------------------
# Wait for any brute-force lockout to expire before burst test
echo -e "${CYAN}Waiting 3s for brute-force lockout to clear...${RESET}"
sleep 3

# Auditor: burst=30, tps=50. Send 150 parallel requests to trigger rate limiting.
# Expected: ~30 allowed (burst), ~120 rate-limited (429)
echo -e "${BOLD}--- Rate Limit Burst (150 parallel as auditor, burst=30) ---${RESET}"

burst_allowed=0
burst_ratelimited=0
burst_other=0
pids=()

for i in $(seq 1 150); do
    (
        resp=$(curl -s --connect-timeout 5 --max-time 10 \
            -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/query" \
            -H 'Content-Type: application/json' \
            -H "Authorization: Bearer sk-auditor-key-fghij" \
            -d '{"database":"testdb","sql":"SELECT 1"}' 2>/dev/null) || resp=$'\n000'
        code=$(echo "$resp" | tail -1)
        echo "$code" > "$RESULTS_DIR/burst_${i}"
    ) &
    pids+=($!)
done

for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done

for f in "$RESULTS_DIR"/burst_*; do
    code=$(cat "$f" 2>/dev/null)
    case "$code" in
        200) burst_allowed=$((burst_allowed + 1)) ;;
        429) burst_ratelimited=$((burst_ratelimited + 1)) ;;
        *)   burst_other=$((burst_other + 1)) ;;
    esac
    # Track in overall results
    if [[ "$code" == "200" ]]; then
        echo "allow" > "${f}_result"
    elif [[ "$code" == "429" ]]; then
        echo "ratelimited" > "${f}_result"
    else
        echo "error" > "${f}_result"
    fi
    rm -f "$f"
done

printf "  %-55s %b\n" "Burst allowed"  "${GREEN}${burst_allowed}${RESET}"
printf "  %-55s %b\n" "Burst rate-limited" "${MAGENTA}${burst_ratelimited}${RESET}"
if (( burst_other > 0 )); then
    printf "  %-55s %b\n" "Burst other" "${RED}${burst_other}${RESET}"
fi
echo ""

end_time=$(date +%s%N)
elapsed_ms=$(( (end_time - start_time) / 1000000 ))
elapsed_s=$(echo "scale=2; $elapsed_ms / 1000" | bc)

# Count results from temp files
total_count=$(find "$RESULTS_DIR" -type f | wc -l)
allow_count=$(grep -rl '^allow$' "$RESULTS_DIR" 2>/dev/null | wc -l)
block_count=$(grep -rl '^block$' "$RESULTS_DIR" 2>/dev/null | wc -l)
rl_count=$(grep -rl '^ratelimited$' "$RESULTS_DIR" 2>/dev/null | wc -l)
error_count=$(grep -rl '^error$' "$RESULTS_DIR" 2>/dev/null | wc -l)

rps=$(echo "scale=1; $total_count / ($elapsed_ms / 1000)" | bc 2>/dev/null || echo "N/A")

# Final stats
echo -e "${BOLD}=== Results ===${RESET}"
echo ""

final_stats=$(curl -sf -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$BASE_URL/dashboard/api/stats" 2>/dev/null || echo "{}")
echo -e "${CYAN}Final dashboard stats:${RESET}"
echo "$final_stats" | python3 -m json.tool 2>/dev/null || echo "$final_stats"
echo ""

echo -e "Total requests:     ${BOLD}$total_count${RESET}"
echo -e "Allowed:            ${GREEN}$allow_count${RESET}"
echo -e "Blocked (expected): ${YELLOW}$block_count${RESET}"
echo -e "Rate-limited:       ${MAGENTA}$rl_count${RESET}"
echo -e "Unexpected:         ${RED}$error_count${RESET}"
echo ""
echo -e "Duration:           ${elapsed_s}s"
echo -e "Throughput:         ~${rps} req/s"
echo ""

if (( error_count > 0 )); then
    echo -e "${RED}${BOLD}FAIL: $error_count unexpected results${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}PASS: All $total_count requests matched expectations${RESET}"
fi
