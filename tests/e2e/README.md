# SQL Proxy E2E Feature Tests

End-to-end integration tests that verify every feature of the SQL Proxy by sending real HTTP requests to a running proxy instance backed by a PostgreSQL database.

## Quick Start

### Run All Tests via Docker Compose

```bash
# From project root:
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile e2e up --build --abort-on-container-exit

# Clean up:
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile e2e down -v
```

### Run Locally (proxy + postgres already running)

```bash
# Set BASE_URL if not localhost:8080
export BASE_URL=http://localhost:8080
export ADMIN_TOKEN=e2e-admin-token

# Run all tests:
bash tests/e2e/run_all.sh

# Run a single suite:
bash tests/e2e/test_brute_force.sh
```

## Test Suites

| Script | Feature | Tests |
|--------|---------|-------|
| `test_core_requirements.sh` | **Core exercise requirements (all 6)** | **22** |
| `test_health.sh` | Health check depth levels | 4 |
| `test_auth.sh` | Authentication (API key, Bearer, errors) | 6 |
| `test_policies.sh` | Policy engine (allow, block, DDL, default deny) | 8 |
| `test_masking.sh` | Data masking (partial, hash, column block) | 4 |
| `test_query_features.sh` | Query rewriting, dry-run, RLS, tracing | 6 |
| `test_sql_injection.sh` | SQL injection detection + encoding bypass | 6 |
| `test_metrics.sh` | Prometheus metrics coverage | 14 |
| `test_dashboard.sh` | Dashboard API (stats, policies, users, alerts) | 5 |
| `test_compliance.sh` | Compliance endpoints (PII, security, lineage, GDPR) | 5 |
| `test_circuit_breaker.sh` | Circuit breaker events API | 2 |
| `test_config.sh` | Config validation + hot-reload | 4 |
| `test_slow_query.sh` | Slow query tracking | 2 |
| `test_ip_allowlist.sh` | IP allowlisting per user (CIDR) | 4 |
| `test_rate_limiting.sh` | Hierarchical rate limiting | 3 |
| `test_brute_force.sh` | Brute force lockout + exponential backoff | 4 |
| `test_schema_drift.sh` | Schema drift detection API + metrics | 6 |
| `test_query_cost.sh` | Query cost estimation + EXPLAIN metrics | 4 |
| `test_gdpr.sh` | GDPR data subject access endpoint | 6 |
| **Total** | | **115** |

## Core Requirements Coverage

The `test_core_requirements.sh` suite maps directly to the 6 exercise requirements:

| # | Requirement | What is Tested |
|---|-------------|----------------|
| 1 | **SQL Analysis** | SELECT returns columns/rows, DDL/DML recognized, dry-run shows `policy_decision` and `matched_policy` |
| 2 | **Access Policies** | Default deny, BLOCK overrides ALLOW, table-level specificity, error message includes reason |
| 3 | **User Management** | Same query different users different outcomes (analyst blocked, developer allowed) |
| 4 | **Query Execution** | Allowed returns data rows, denied returns error (no data), invalid SQL returns parse error |
| 5 | **Data Classification** | `classifications` field contains `PII.Email` for email, `PII.Phone` for phone |
| 6 | **Audit Logging** | Both allowed and denied queries include `audit_id`, audit metric increments after query |

## E2E Config

The file `config/proxy.toml` is a standalone config with all features enabled and test-friendly thresholds:

- Brute force: `max_attempts=3`, `lockout_seconds=2` (fast testing)
- Slow query: `threshold_ms=1` (catches everything)
- Result cache: enabled
- Audit sampling: 100% sample rate
- IP allowlist: `restricted_user` limited to `10.0.0.0/8` and `192.168.0.0/16`
- Query cost estimation: enabled (`max_cost=100000`, `max_estimated_rows=1000000`)
- Schema drift detection: enabled (`check_interval_seconds=60`)
- Retry with backoff: enabled (`max_retries=2`, `initial_backoff_ms=100`)
- Request timeout: enabled (`timeout_ms=30000`)

## Manual Feature Verification

Below are curl commands to manually verify each feature. All examples assume the proxy runs at `http://localhost:8080`.

---

### 1. Health Checks

The `/health` endpoint supports three depth levels.

```bash
# Shallow (default) — process alive
curl http://localhost:8080/health
# {"status":"healthy","level":"shallow"}

# Deep — checks circuit breaker, pool, audit
curl 'http://localhost:8080/health?level=deep'
# {"status":"healthy","level":"deep","checks":{"circuit_breaker":"ok","connection_pool":"ok","audit_emitter":"ok"}}

# Readiness — deep + rate limiter check
curl 'http://localhost:8080/health?level=readiness'
```

---

### 2. Authentication

```bash
# Bearer token auth (API key)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-analyst-key-67890' \
  -d '{"database":"testdb","sql":"SELECT 1"}'

# JSON body auth (user field)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}'

# Invalid key — expect 401
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer invalid-key' \
  -d '{"database":"testdb","sql":"SELECT 1"}'
```

---

### 3. Policy Engine

```bash
# Analyst can SELECT customers (allowed)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT name FROM customers LIMIT 3"}'

# Analyst INSERT blocked (readonly role)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"INSERT INTO customers (name) VALUES ('\''Test'\'')"}'
# Expect: {"success":false,"error":"Read-only role cannot perform write operations"}

# Analyst SELECT sensitive_data — blocked
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT * FROM sensitive_data"}'
# Expect: {"success":false,...}

# Auditor SELECT sensitive_data — allowed
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"auditor","database":"testdb","sql":"SELECT id FROM sensitive_data LIMIT 1"}'
```

---

### 4. Data Masking

```bash
# Developer sees partially masked email (prefix 3 + suffix 4)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"developer","database":"testdb","sql":"SELECT email FROM customers LIMIT 1"}'
# Look for "masked_columns" in response

# Analyst sees hashed phone
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT phone FROM customers LIMIT 1"}'
# Phone values should be hash strings
```

---

### 5. Rate Limiting

```bash
# Check rate limit header
curl -v -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}'
# Look for X-RateLimit-Remaining header

# Burst test (analyst has 10 burst capacity)
for i in $(seq 1 15); do
  echo "Request $i: $(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8080/api/v1/query \
    -H 'Content-Type: application/json' \
    -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}')"
done
# Some should return 429
```

---

### 6. SQL Injection Detection

```bash
# Tautology attack (OR true survives SQL normalization)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT * FROM customers WHERE id = 0 OR true"}'
# Expect: {"success":false,"error_code":"SQLI_BLOCKED","error_message":"...TAUTOLOGY..."}

# UNION injection
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT name FROM customers UNION SELECT password FROM pg_shadow"}'

# Stacked queries
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","database":"testdb","sql":"SELECT 1; DROP TABLE customers"}'
```

---

### 7. Brute Force Protection

Requires `[security.brute_force] enabled = true` in config.

```bash
# Send 3 failed attempts (invalid key)
for i in 1 2 3; do
  curl -s -o /dev/null -w "Attempt $i: %{http_code}\n" -X POST http://localhost:8080/api/v1/query \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer fake-key-test' \
    -d '{"database":"testdb","sql":"SELECT 1"}'
done

# 4th attempt — should be 429 with Retry-After header
curl -v -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer fake-key-test' \
  -d '{"database":"testdb","sql":"SELECT 1"}'
# Expect: 429 Too Many Requests, Retry-After: 2

# Check metrics
curl -s http://localhost:8080/metrics | grep auth_failures
# sql_proxy_auth_failures_total 3
```

---

### 8. IP Allowlisting

Requires user with `allowed_ips` in config.

```bash
# Allowed IP (10.x.x.x matches 10.0.0.0/8)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-restricted-key-99999' \
  -H 'X-Forwarded-For: 10.0.0.1' \
  -d '{"database":"testdb","sql":"SELECT 1"}'
# Expect: 200

# Disallowed IP
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-restricted-key-99999' \
  -H 'X-Forwarded-For: 203.0.113.1' \
  -d '{"database":"testdb","sql":"SELECT 1"}'
# Expect: 403 "IP address not allowed for this user"

# Check metric
curl -s http://localhost:8080/metrics | grep ip_blocked
```

---

### 9. Prometheus Metrics

```bash
curl http://localhost:8080/metrics

# Key metrics to look for:
# sql_proxy_requests_total              — Total requests processed
# sql_proxy_rate_limit_total{level="global"} — Rate limit rejects by level
# sql_proxy_audit_emitted_total         — Audit records emitted
# sql_proxy_pool_acquire_duration_seconds_bucket — Pool acquire histogram
# sql_proxy_auth_failures_total         — Brute force failures
# sql_proxy_auth_blocks_total           — Brute force blocks
# sql_proxy_ip_blocked_total            — IP allowlist blocks
# sql_proxy_circuit_breaker_transitions_total — CB state changes
# sql_proxy_slow_queries_total          — Slow queries detected
# sql_proxy_cache_hits_total            — Result cache hits
# sql_proxy_query_cost_estimated_total  — Queries cost-estimated
# sql_proxy_query_cost_rejected_total   — Queries rejected by cost
# sql_proxy_schema_drifts_total         — Schema drifts detected
# sql_proxy_schema_drift_checks_total   — Schema drift checks performed
# sql_proxy_info{version="1.0.0"}       — Build info
```

---

### 10. Query Rewriting (Enforce Limit)

```bash
# SELECT * without LIMIT — proxy auto-adds LIMIT 1000
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT * FROM customers"}'
# Expect success with at most 1000 rows
```

---

### 11. Dry-Run Query Evaluation

```bash
curl -X POST http://localhost:8080/api/v1/query/dry-run \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT id, name FROM customers"}'
# Expect: dry_run flag in response, no actual DB execution
```

---

### 12. Row-Level Security (RLS)

```bash
# Analyst has region="us-west" attribute
# RLS rule: customers filtered by "region = '$ATTR.region'"
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT id, name, region FROM customers"}'
# Expect: only rows where region = 'us-west'
```

---

### 13. Distributed Tracing (W3C Trace Context)

```bash
curl -v -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}'
# Look for traceparent header in response
```

---

### 14. Dashboard API

```bash
# Stats snapshot
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/dashboard/api/stats

# Policy listing
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/dashboard/api/policies

# User listing
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/dashboard/api/users

# Alerts
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/dashboard/api/alerts

# SSE metrics stream (Ctrl+C to stop)
curl -N "http://localhost:8080/dashboard/api/metrics/stream?token=e2e-admin-token"
```

---

### 15. Compliance Endpoints

```bash
# PII access report
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/api/v1/compliance/pii-report

# Security summary
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/api/v1/compliance/security-summary

# Data lineage
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/api/v1/compliance/lineage
```

---

### 16. Circuit Breaker

```bash
# View circuit breaker state and events
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/api/v1/circuit-breakers

# Check metrics
curl -s http://localhost:8080/metrics | grep circuit_breaker
```

---

### 17. Config Validation

```bash
# Validate config without applying
curl -X POST http://localhost:8080/api/v1/config/validate \
  -H "Authorization: Bearer e2e-admin-token" \
  --data-binary @config/proxy.toml

# Hot-reload policies
curl -X POST http://localhost:8080/policies/reload \
  -H "Authorization: Bearer e2e-admin-token"
```

---

### 18. Slow Query Tracking

Requires `[slow_query] enabled = true` in config.

```bash
# View recent slow queries
curl -H "Authorization: Bearer e2e-admin-token" http://localhost:8080/api/v1/slow-queries

# Check metric
curl -s http://localhost:8080/metrics | grep slow_queries
```

---

### 19. Result Cache

When enabled, identical SELECT queries within the TTL window return cached results.

```bash
# First query — cache miss
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT COUNT(*) FROM customers"}'

# Second identical query — cache hit (faster)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT COUNT(*) FROM customers"}'

# Check cache metrics
curl -s http://localhost:8080/metrics | grep cache_hits
```

---

### 20. Audit Sampling

When enabled, audit records are sampled at the configured rate. With `default_sample_rate=1.0`, all queries are audited. With lower rates, only a fraction are logged.

```bash
# Check audit metrics (should show emitted records)
curl -s http://localhost:8080/metrics | grep audit_emitted
```

---

### 21. Schema Drift Detection

Background thread periodically snapshots `information_schema.columns` and diffs against baseline.

```bash
# View drift events (admin only)
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/api/v1/schema/drift
# {"drift_events":[],"total_drifts":0,"checks_performed":1,"enabled":true}

# Check metrics
curl -s http://localhost:8080/metrics | grep schema_drift
# sql_proxy_schema_drifts_total 0
# sql_proxy_schema_drift_checks_total 1
```

---

### 22. Query Cost Estimation

Runs `EXPLAIN` on SELECT queries before execution. Rejects queries exceeding cost/row thresholds.

```bash
# Normal SELECT — cost estimated but allowed
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","database":"testdb","sql":"SELECT * FROM customers"}'
# Succeeds — cost within thresholds

# Check metrics
curl -s http://localhost:8080/metrics | grep query_cost
# sql_proxy_query_cost_estimated_total 1
# sql_proxy_query_cost_rejected_total 0
```

---

### 23. GDPR Data Subject Access

Returns all PII access events for a specific user (GDPR Article 15 compliance).

```bash
# Get all PII access events for analyst
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  'http://localhost:8080/api/v1/compliance/data-subject-access?user=analyst'
# {"subject":"analyst","events":[...],"total_events":N}

# Missing user param — 400
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/v1/compliance/data-subject-access
# {"success":false,"error":"Missing required parameter: user"}
```

---

## Troubleshooting

### Proxy not ready
If tests fail with "Proxy not ready after 30s", check:
```bash
docker compose logs proxy
```

### Rate limit tests flaky
Rate limit burst tests depend on timing. If the test host is slow, the burst may not trigger rejection. Try increasing the burst count or lowering the per-user-per-database limit in `e2e_proxy.toml`.

### Brute force lockout persists
Brute force lockouts are in-memory. Restart the proxy to clear:
```bash
docker compose restart proxy
```

### IP allowlist not working
Ensure `X-Forwarded-For` header is being passed correctly. The proxy checks this header before `remote_addr`.
