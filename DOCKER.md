# SQL Proxy - Docker Build & Run

Complete guide for building, running, and testing the SQL Proxy using Docker.

## Prerequisites

- Docker installed and running
- Docker Compose v2+

## Run Modes

The proxy supports two run modes via Docker Compose profiles:

### Core Mode — Exercise Requirements Only

Runs only the 6 core requirements: SQL analysis, access policies, user management, query execution, PII classification (Email/Phone), and audit logging.

```bash
docker compose --profile core up
```

Uses `config/proxy_core.toml` — minimal config with no RLS, masking, encryption, injection detection, tracing, alerting, or schema drift.

### Full Mode — All Features

Runs the full proxy with all features enabled (rate limiting, RLS, masking, injection detection, tracing, alerting, etc.).

```bash
docker compose --profile full up
```

Uses `config/proxy.toml` — complete config with all tiers enabled.

### Build Only

Build the Docker image without starting:

```bash
docker compose --profile full build
# or for core mode:
docker compose --profile core build
```

This will:
- Install all system dependencies (PostgreSQL, OpenSSL, etc.)
- Build libpg_query from source
- Compile the SQL Proxy service
- Create a minimal runtime image (~200MB)

> **Note:** All services use Docker Compose profiles. Plain `docker compose build` without a profile only sees the `postgres` service (a pre-built image). Always specify `--profile`.

## Stop the Service

```bash
docker compose --profile core down
# or
docker compose --profile full down
```

To stop and remove volumes (resets database data):

```bash
docker compose --profile core down -v
# or
docker compose --profile full down -v
```

## Testing

### Unit Tests

Build and run all unit tests:

```bash
docker compose run --rm --build unit-tests
```

The `--build` flag ensures the image reflects your latest code changes. Without it, Docker Compose may use a stale cached image.

Or build directly with the test-builder stage:

```bash
docker build --target test-builder -t sql-proxy-test .
docker run --rm sql-proxy-test /build/sql_proxy/build/sql_proxy_tests --reporter compact
```

> **Note:** The `test-builder` Dockerfile stage runs the full test suite during `docker build`. If the build succeeds, all tests passed.

### E2E Tests

Run the full end-to-end test suite (184 tests across 33 suites) against a live proxy + PostgreSQL:

```bash
# With E2E config (all features enabled):
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile full --profile e2e up --build --abort-on-container-exit

# Or locally (proxy + postgres already running, uses default config):
bash tests/e2e/run_all.sh
```

Feature-gated tests (brute force, IP allowlist, slow query, etc.) auto-detect whether the feature is enabled and gracefully skip when not available.

To clean up E2E containers and volumes afterward:

```bash
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile full --profile e2e down -v
```

**Important:** Always include both `--profile full --profile e2e` in the `down` command. Without them, the e2e-tests container retains a stale network reference and subsequent runs will fail.

### Benchmarks

Build and run performance benchmarks (Google Benchmark):

```bash
docker build --target benchmark-builder -t sql-proxy-bench .
docker run --rm sql-proxy-bench /build/sql_proxy/build/sql_proxy_benchmarks
```

### Running Tests Locally

If the proxy and database are already running:

```bash
bash tests/e2e/run_all.sh
```

### After Schema Changes

If you modify files in `sql/` (e.g., adding columns), the running database won't pick up the changes automatically because PostgreSQL init scripts only run on first volume creation. To apply schema changes:

```bash
docker compose --profile full down -v   # Remove volumes (drops old database)
docker compose --profile full up -d     # Recreate with updated schema
```

Or apply manually without losing data:

```bash
docker exec -i sql_proxy_postgres psql -U postgres -d testdb -c \
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS region VARCHAR(50) DEFAULT 'us-east';"
```

## Rebuild After Code Changes

```bash
docker compose --profile full build
docker compose --profile full up -d   # or --profile core
```

Use `--no-cache` only if dependency layers need refreshing.

## View Logs

```bash
docker compose --profile full logs -f proxy
# or for core mode:
docker compose --profile core logs -f proxy-core
# PostgreSQL logs (always available):
docker compose logs -f postgres
```

## Configuration

Edit configuration files in the `config/` directory:
- `proxy.toml` — Full proxy configuration (policies, rate limits, security, encryption, all tiers)
- `proxy_core.toml` — Minimal core configuration (6 exercise requirements only)

Configuration is mounted read-only into the container. The proxy reads it at startup. To hot-reload policies without restart:

```bash
curl -X POST http://localhost:8080/policies/reload
```

## API Endpoints

### Core

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/query` | Execute SQL through the proxy pipeline |
| `POST` | `/api/v1/query/dry-run` | Dry-run query evaluation (no execution) |
| `POST` | `/api/v1/query/explain` | Explain query in plain English |
| `GET` | `/health` | Health check (supports `?level=shallow\|deep\|readiness`) |
| `GET` | `/metrics` | Prometheus-format metrics |
| `GET` | `/openapi.json` | OpenAPI 3.0 spec |
| `GET` | `/api/docs` | Swagger UI |
| `POST` | `/policies/reload` | Hot-reload policies from config |

### Operations (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/config/validate` | Validate TOML config without applying |
| `GET` | `/api/v1/slow-queries` | Recent slow queries (threshold + buffer) |
| `GET` | `/api/v1/circuit-breakers` | Circuit breaker state + recent events (per-tenant if multi-tenant) |
| `POST` | `/api/v1/plugins/reload` | Hot-reload .so plugins at runtime (admin) |
| `GET` | `/api/v1/index-recommendations` | Suggested indexes for slow queries |

### Security (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/firewall/mode` | SQL firewall mode and stats |
| `POST` | `/api/v1/firewall/mode` | Set firewall mode (disabled/learning/enforcing) |
| `GET` | `/api/v1/firewall/allowlist` | SQL firewall fingerprint allowlist |

### Query Intelligence

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/graphql` | GraphQL-to-SQL queries + mutations (feature-gated) |
| `GET` | `/api/v1/stream` | WebSocket upgrade (RFC 6455) for audit/query/metrics streaming |

### Schema Management (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/schema/history` | Schema change history |
| `GET` | `/api/v1/schema/pending` | Pending schema changes |
| `POST` | `/api/v1/schema/approve` | Approve schema change |
| `POST` | `/api/v1/schema/reject` | Reject schema change |
| `GET` | `/api/v1/schema/drift` | Schema drift report |

### Multi-Tenancy (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/tenants` | List all tenants |
| `POST` | `/admin/tenants` | Create a tenant |
| `GET` | `/admin/tenants/:id` | Get tenant details |
| `DELETE` | `/admin/tenants/:id` | Remove a tenant |
| `GET` | `/admin/residency` | Data residency rules and regions |

### Data Governance (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/column-history` | Column-level change history |
| `POST` | `/api/v1/synthetic-data` | Generate synthetic data from schema |

### Distributed Rate Limiting (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/distributed-rate-limits` | Distributed rate limiter stats (sync cycles, overrides) |

### Multi-Database Transactions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/transactions/begin` | Begin a distributed 2PC transaction |
| `POST` | `/api/v1/transactions/:xid/prepare` | Prepare all participants (phase 1) |
| `POST` | `/api/v1/transactions/:xid/commit` | Commit prepared transaction (phase 2) |
| `POST` | `/api/v1/transactions/:xid/rollback` | Rollback a transaction |
| `GET` | `/api/v1/transactions/:xid` | Get transaction status by XID |

### LLM-Powered Features (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/llm/generate-policy` | AI-generate access policy from query samples |
| `POST` | `/api/v1/llm/explain-anomaly` | AI-explain anomalous behavior |
| `POST` | `/api/v1/llm/nl-to-policy` | Natural language to TOML policy |
| `POST` | `/api/v1/llm/classify-intent` | AI-classify SQL intent |

### Compliance (Admin)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/pii-report` | PII access report (GDPR/SOC2) |
| `GET` | `/api/v1/compliance/security-summary` | Security overview |
| `GET` | `/api/v1/compliance/lineage` | Data lineage summaries |
| `GET` | `/api/v1/compliance/data-subject-access` | GDPR Article 15 export |

### Admin Dashboard

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Admin dashboard SPA (pass `?token=<admin_token>`) |
| `GET` | `/dashboard/api/stats` | Aggregate stats snapshot (JSON) |
| `GET` | `/dashboard/api/policies` | List all access policies (JSON) |
| `GET` | `/dashboard/api/users` | List all configured users (JSON) |
| `GET` | `/dashboard/api/alerts` | Active alerts + history (JSON) |
| `GET` | `/dashboard/api/metrics/stream` | SSE real-time metrics (2s interval) |

All dashboard endpoints require the admin token via `Authorization: Bearer <token>` header, or `?token=<token>` query parameter (for SSE/browser).

## Admin Dashboard

The proxy includes an embedded admin dashboard with real-time metrics, policy/user listing, and alert management.

**Open in browser:**
```
http://localhost:8080/dashboard?token=admin-secret-token
```

**Features:**
- Real-time request rate and audit stats charts (Chart.js + SSE)
- Policy table with name, scope, action, priority, and roles
- User table with roles
- Active alerts with severity badges
- All data auto-refreshes every 2 seconds

**Test via curl:**
```bash
# Stats snapshot
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/stats

# Policies
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/policies

# SSE stream (Ctrl+C to stop)
curl -N "http://localhost:8080/dashboard/api/metrics/stream?token=admin-secret-token"
```

## Distributed Tracing

The proxy supports W3C Trace Context propagation. Pass a `traceparent` header with your query and the proxy will:
- Parse the incoming trace context (or generate a new one)
- Include `trace_id`, `span_id`, `parent_span_id` in audit records
- Return the `traceparent` header on the response

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01' \
  -d '{"user":"analyst","database":"testdb","sql":"SELECT 1"}'
```

## Alerting

The proxy runs a background alert evaluator that checks metrics every 10 seconds. Configure rules in `proxy.toml`:

```toml
[alerting]
enabled = true
evaluation_interval_seconds = 10
alert_log_file = "/app/logs/alerts.jsonl"

[[alerting.rules]]
name = "high_rate_limit_rejects"
condition = "rate_limit_breach"
threshold = 100
window_seconds = 60
severity = "warning"
```

View alerts via the dashboard or API:
```bash
curl -H "Authorization: Bearer admin-secret-token" http://localhost:8080/dashboard/api/alerts
```

## Audit Log Shipping

Audit records are written to pluggable sinks. The file sink is always active; webhook and syslog sinks are optional.

### File Sink (with rotation)

Enabled by default. Configure rotation in `proxy.toml`:

```toml
[audit.rotation]
max_file_size_mb = 100
max_files = 10
interval_hours = 24
time_based = true
size_based = true
```

### Webhook Sink

Ships audit records as NDJSON via HTTP POST:

```toml
[audit.webhook]
enabled = true
url = "https://siem.example.com/api/v1/events"
auth_header = "Bearer your-token-here"
timeout_ms = 5000
max_retries = 3
batch_size = 100
```

### Syslog Sink

Writes to local syslog (POSIX `syslog(3)`):

```toml
[audit.syslog]
enabled = true
ident = "sql-proxy"
```

### Kafka Sink

Ships audit records to Apache Kafka for SIEM integration (Splunk, Elastic, etc.). Requires building with `-DENABLE_KAFKA=ON` (links librdkafka):

```toml
[audit.kafka]
enabled = true
brokers = "kafka1:9092,kafka2:9092"
topic = "sql-proxy-audit"
```

When `ENABLE_KAFKA=OFF` (default), the Kafka code is excluded at compile time — no librdkafka dependency needed.

## Wire Protocol TLS

The PostgreSQL wire protocol (port 5433) supports optional TLS encryption via SSLRequest negotiation:

```toml
[wire_protocol]
enabled = true

[wire_protocol.tls]
enabled = true
cert_file = "config/certs/server.crt"
key_file = "config/certs/server.key"
```

Clients requesting TLS (`sslmode=require`) get an SSL handshake; plaintext clients still work.

```bash
# TLS connection
psql "host=localhost port=5433 sslmode=require dbname=testdb user=analyst"

# Plaintext connection
psql "host=localhost port=5433 sslmode=disable dbname=testdb user=analyst"
```

## OAuth2/OIDC Authentication

The proxy supports enterprise SSO via OIDC (Okta, Auth0, Azure AD). Tokens are verified using public keys fetched from the JWKS endpoint (RS256/ES256):

```toml
[auth.oidc]
issuer = "https://auth.example.com/realms/prod"
audience = "sql-proxy"
roles_claim = "realm_access.roles"
user_claim = "preferred_username"
jwks_cache_seconds = 3600
```

JWKS keys are cached and automatically refreshed on key rotation (unknown `kid` triggers refetch). Existing auth methods (API key, JWT HMAC, LDAP) continue to work alongside OIDC.

## GraphQL Mutations

The GraphQL endpoint now supports INSERT, UPDATE, and DELETE mutations (in addition to queries):

```toml
[graphql]
enabled = true
mutations_enabled = true
```

Example mutations:

```bash
# INSERT
curl -X POST http://localhost:8080/api/v1/graphql \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","database":"testdb","query":"mutation { insert_customers(data: {name: \"Test\", email: \"t@test.com\"}) { id name } }"}'

# UPDATE
curl -X POST http://localhost:8080/api/v1/graphql \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","database":"testdb","query":"mutation { update_customers(where: {id: \"1\"}, set: {name: \"Updated\"}) { id name } }"}'

# DELETE
curl -X POST http://localhost:8080/api/v1/graphql \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","database":"testdb","query":"mutation { delete_customers(where: {id: \"99\"}) { id } }"}'
```

All mutations go through the full pipeline (policy enforcement, audit, masking).

## Plugin Hot-Reload

Reload `.so` plugins at runtime without restarting the proxy:

```bash
curl -X POST http://localhost:8080/api/v1/plugins/reload \
  -H "Authorization: Bearer admin-secret-token" \
  -H 'Content-Type: application/json' \
  -d '{"path": "/app/plugins/custom_classifier.so"}'
```

The old plugin is swapped out atomically under a writer lock. Concurrent requests continue safely.

## Per-Tenant Circuit Breakers

In multi-tenant mode, each tenant gets an isolated circuit breaker keyed by `tenant:database`. One tenant's failures won't trip the breaker for other tenants:

```toml
[[circuit_breaker.per_tenant]]
tenant = "high-value"
failure_threshold = 5
timeout_ms = 3000
```

View per-tenant breaker state:

```bash
curl -H "Authorization: Bearer admin-secret-token" \
  http://localhost:8080/api/v1/circuit-breakers
```

## Testing Queries

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "user": "analyst",
    "database": "testdb",
    "sql": "SELECT id, name, email FROM customers LIMIT 5"
  }'
```

## Troubleshooting

### Build fails with "connection timeout"
Check that Docker has internet access for downloading dependencies (FetchContent pulls from GitHub).

### Container exits immediately
Check logs: `docker compose --profile full logs proxy` (or `--profile core logs proxy-core`)

### Cannot connect to PostgreSQL
Ensure PostgreSQL container is healthy: `docker compose --profile full ps`

### E2E tests fail with "column does not exist"
The database schema is out of date. Recreate volumes: `docker compose --profile full down -v && docker compose --profile full up -d`

### E2E tests fail with "network not found"
The e2e-tests container has a stale network reference. Clean up with the profile flag and prune:

```bash
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile e2e down -v && docker network prune -f
docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml \
  --profile e2e up --build --abort-on-container-exit
```

### Unit tests fail to build
Ensure the test-builder Docker stage has `BUILD_TESTS=ON`. Check `Dockerfile` for the `test-builder` target.

## Config Environment Variable Substitution

Connection strings and secrets in `proxy.toml` support `${VAR_NAME}` substitution:

```toml
[[databases]]
name = "production"
type = "postgresql"
connection_string = "host=${DB_HOST} port=${DB_PORT} user=${DB_USER} password=${DB_PASSWORD} dbname=proddb"
```

Pass env vars via `docker-compose.yml`:

```yaml
services:
  proxy:
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=app
      - DB_PASSWORD=s3cret
```

Missing env vars expand to empty string. Unclosed `${` is a parse error.

## Config Validation

The proxy validates config at load time (port ranges, TLS cert/key presence, connection strings, rate limit values, circuit breaker thresholds). Invalid config returns a clear error at startup.

You can also validate config via API without applying it:

```bash
curl -X POST http://localhost:8080/api/v1/config/validate \
  -H "Authorization: Bearer admin-secret-token" \
  --data-binary @config/proxy.toml
```

## Slow Query Tracking

Enable slow query tracking in `proxy.toml`:

```toml
[slow_query]
enabled = true
threshold_ms = 500
max_entries = 1000
```

Query recent slow queries:

```bash
curl -H "Authorization: Bearer admin-secret-token" \
  http://localhost:8080/api/v1/slow-queries
```

## Health Check Depth Levels

The `/health` endpoint supports three depth levels via query parameter:

```bash
# Shallow (default) — process alive
curl http://localhost:8080/health
curl http://localhost:8080/health?level=shallow

# Deep — checks circuit breaker, connection pool, audit emitter
curl http://localhost:8080/health?level=deep

# Readiness — deep checks + rate limiter reject ratio
curl http://localhost:8080/health?level=readiness
```

Returns 200 when healthy, 503 when unhealthy, with per-component detail:
```json
{
  "status": "healthy",
  "level": "deep",
  "checks": {
    "circuit_breaker": "ok",
    "connection_pool": "ok",
    "audit_emitter": "ok"
  }
}
```

Use `?level=deep` for Kubernetes liveness probes and `?level=readiness` for readiness probes.

## Circuit Breaker Events

The circuit breaker emits structured events on state transitions (CLOSED/OPEN/HALF_OPEN). View recent events via the API:

```bash
curl -H "Authorization: Bearer admin-secret-token" \
  http://localhost:8080/api/v1/circuit-breakers
```

Transition counters are also exposed in `/metrics`:
```
sql_proxy_circuit_breaker_transitions_total{to="open"} N
sql_proxy_circuit_breaker_transitions_total{to="half_open"} N
sql_proxy_circuit_breaker_transitions_total{to="closed"} N
```

## Brute Force Protection

Per-IP and per-username lockout with exponential backoff. Configure in `proxy.toml`:

```toml
[security.brute_force]
enabled = true
max_attempts = 5
window_seconds = 60
lockout_seconds = 300
max_lockout_seconds = 3600
```

When an IP or username exceeds `max_attempts` failures within `window_seconds`, requests return HTTP 429 with a `Retry-After` header. Lockout duration doubles on each subsequent lockout, up to `max_lockout_seconds`. A successful login resets the counter.

Metrics: `sql_proxy_auth_failures_total`, `sql_proxy_auth_blocks_total`

## IP Allowlisting Per User

Restrict user access by source IP or CIDR range:

```toml
[[users]]
name = "admin"
roles = ["admin"]
api_key = "secret"
allowed_ips = ["10.0.0.0/8", "192.168.1.100"]
```

Empty `allowed_ips` (or omitted) allows all IPs. The proxy checks `X-Forwarded-For` first, then `remote_addr`.

Metric: `sql_proxy_ip_blocked_total`

## Encoding Bypass Detection

The SQL injection detector normalizes encoded SQL before pattern matching:
- URL decoding (`%27` → `'`)
- Double URL decoding (`%2527` → `%27` → `'`)
- HTML entity decoding (`&#39;` → `'`, `&lt;` → `<`)

If decoded SQL differs from raw, an `ENCODING_BYPASS` pattern is flagged and all 6 injection checks are re-run on the decoded version.

## Config File Includes

Split config across multiple TOML files using the `include` directive:

```toml
# proxy.toml
include = ["users.toml", "policies.toml"]

[server]
host = "0.0.0.0"
port = 8080
```

Merge semantics: arrays concatenate (included + main), objects deep-merge (main wins for scalar conflicts). Relative paths resolve from the including file's directory. Circular includes are detected and rejected. Max include depth is 10.

## Distributed Rate Limiting

Multi-node rate limiting with backend sync. Each node gets 1/N of the global budget; a background thread reports local usage to a shared backend:

```toml
[distributed_rate_limiting]
enabled = true
node_id = "node-1"
cluster_size = 3
sync_interval_ms = 5000
```

View stats:
```bash
curl -H "Authorization: Bearer admin-secret-token" \
  http://localhost:8080/api/v1/distributed-rate-limits
```

## WebSocket Streaming

RFC 6455 WebSocket endpoint for real-time audit, query, and metrics streaming:

```toml
[websocket]
enabled = true
max_connections = 100
max_frame_size = 65536
```

Connect via any WebSocket client to `ws://localhost:8080/api/v1/stream`.

## Multi-Database Transactions

Coordinate transactions across multiple databases using Two-Phase Commit (2PC):

```toml
[transactions]
enabled = true
timeout_ms = 30000
max_active_transactions = 100
cleanup_interval_seconds = 60
```

Example flow:
```bash
# Begin — returns a transaction ID (xid)
curl -X POST http://localhost:8080/api/v1/transactions/begin \
  -H 'Content-Type: application/json' \
  -d '{"user": "admin"}'

# Enlist participants, then prepare + commit (xid in URL path)
curl -X POST http://localhost:8080/api/v1/transactions/<xid>/prepare \
  -H 'Content-Type: application/json'

curl -X POST http://localhost:8080/api/v1/transactions/<xid>/commit \
  -H 'Content-Type: application/json'
```

Stale transactions are automatically timed out and aborted by a background cleanup thread.

## LLM-Powered Features

AI-powered policy generation, anomaly explanation, natural language to policy, and SQL intent classification:

```toml
[llm]
enabled = true
endpoint = "https://api.openai.com/v1"
api_key = "${LLM_API_KEY}"
default_model = "gpt-4"
timeout_ms = 30000
max_retries = 3
max_requests_per_minute = 60
cache_enabled = true
cache_max_entries = 1000
cache_ttl_seconds = 3600
```

Example:
```bash
# Generate a policy from a query sample
curl -X POST http://localhost:8080/api/v1/llm/generate-policy \
  -H "Authorization: Bearer admin-secret-token" \
  -H 'Content-Type: application/json' \
  -d '{"query": "SELECT salary FROM employees", "context": "HR analytics"}'

# Explain an anomaly
curl -X POST http://localhost:8080/api/v1/llm/explain-anomaly \
  -H "Authorization: Bearer admin-secret-token" \
  -H 'Content-Type: application/json' \
  -d '{"description": "User accessed PII at 3am from unusual IP"}'
```

Responses are cached by use case + input hash. Rate limiting prevents runaway API costs.

## Production Deployment

For production, update `docker-compose.yml`:
1. Set strong PostgreSQL password
2. Configure volume mounts for persistent data
3. Add resource limits (CPU/memory)
4. Enable TLS/SSL for proxy endpoint
5. Configure external logging/monitoring
6. Set `[encryption] enabled = true` with proper key management
7. Review `[security]` settings in `proxy.toml`
8. Use `${ENV_VARS}` in `proxy.toml` for secrets (never commit plaintext passwords)
