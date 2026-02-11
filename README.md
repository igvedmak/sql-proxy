# SQL Proxy Service

A high-performance C++23 SQL proxy service for PostgreSQL with SQL analysis, access control, SQL injection detection, PII classification, data masking, encryption, and audit logging.

## Quick Start

**Build and run with Docker (uses Ninja for fast builds):**

```bash
# Core mode — exercise requirements only (SQL analysis, policies, users, execution, classification, audit)
docker compose --profile core up

# Full mode — all features (rate limiting, RLS, masking, injection detection, tracing, etc.)
docker compose --profile full up
```

The service will be available at http://localhost:8080

**Run the stress test:**

```bash
# Default: 5 rounds (27 sequential requests each) + 150 parallel burst test
./stress_test.sh

# Custom rounds
./stress_test.sh 10
```

## Demo

<video src="demo.mp4" width="100%" autoplay loop muted playsinline></video>

## Documentation

- [DOCKER.md](DOCKER.md) - Build, run, test, and deploy instructions
- [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md) - Detailed architecture and data flow (text)
- [Flow Visualization](docs/flow_visualization.html) - Interactive HTML flow diagram (open in browser)

## Architecture

Multi-layer request pipeline with short-circuit on failure:

```
Client Request
     |
1  RATE LIMIT --------- Hierarchical 4-level token bucket (lock-free CAS)
     |
2  PARSE + CACHE ------ SQL parsing (libpg_query) with sharded LRU cache
     |
3  ANALYZE ------------ Table/column extraction, query classification
     |
3b SECURITY ----------- SQL injection detection + anomaly scoring
     |
4  POLICY ENGINE ------ Table-level access control (radix trie, O(1) lookup)
     |
     +-- DENY -> Audit + 403
     | ALLOW
4b REWRITE ------------ Row-level security + enforce LIMIT
     |
4c COST CHECK --------- EXPLAIN-based query cost estimation
     |
5  EXECUTE ------------ Connection pool + circuit breaker + retry
     |
5b POST-PROCESS ------- Decrypt -> Column ACL -> Data masking
     |
6  CLASSIFY ----------- PII detection (4-strategy chain)
     |
6b LINEAGE ------------ Track PII access for compliance
     |
7  AUDIT -------------- Async ring buffer -> file/webhook/syslog
     |
Response + Classifications
```

## Throughput and Limits

### System Capacity

| Component | Capacity | Bottleneck |
|-----------|----------|------------|
| Rate check (4-level) | ~80 ns per request | Lock-free atomic CAS |
| Parse cache hit | < 1 us | Sharded LRU (16 shards, 10K entries) |
| Policy lookup | O(1) | Radix trie traversal |
| Full pipeline (no DB) | 10,000-50,000 req/s | CPU-bound (JSON parse + policy + audit) |
| Full pipeline (with DB) | ~2,000 req/s @ 5ms queries | DB connection pool (10 connections) |
| Full pipeline (with DB) | ~200 req/s @ 50ms queries | DB connection pool (10 connections) |

### Configured Rate Limits

Hierarchical 4-level token bucket -- **all levels must pass** for a request to succeed:

| Level | Scope | TPS | Burst | Purpose |
|-------|-------|-----|-------|---------|
| 1 | Global | 500 | 200 | Protect proxy CPU |
| 2 | Per-User (admin) | 200 | 50 | Prevent one user starving others |
| 2 | Per-User (developer) | 100 | 30 | |
| 2 | Per-User (analyst) | 50 | 15 | |
| 2 | Per-User (auditor) | 50 | 30 | |
| 2 | Per-User (default) | 20 | 5 | Unknown/new users |
| 3 | Per-Database (testdb) | 300 | 100 | Protect each DB independently |
| 4 | Per-User-Per-DB (analyst/testdb) | 30 | 10 | Most specific control |
| 4 | Per-User-Per-DB (developer/testdb) | 80 | 25 | |

### Request Limits

| Limit | Value | Config Key |
|-------|-------|------------|
| Max SQL length | 100 KB | `server.max_sql_length` |
| Max result rows | 10,000 | `databases.max_result_rows` |
| Max result cache entry | 1 MB | `result_cache.max_result_size_bytes` |
| Request timeout | 30 s | `request_timeout.timeout_ms` |
| Query timeout | 30 s | `databases.query_timeout_ms` |
| Connection timeout | 5 s | `databases.connection_timeout_ms` |
| Pool acquire timeout | 5 s | `databases.pool_acquire_timeout_ms` |

### Connection Pools

| Pool | Connections | Config Key |
|------|-------------|------------|
| HTTP server | 4 threads | `server.threads` |
| PostgreSQL (testdb) | 2-10 | `databases.min/max_connections` |
| Wire protocol | 100 max | `wire_protocol.max_connections` |
| GraphQL | 50 max | `graphql.max_connections` |
| Per-tenant pool | 10 default | `tenants.pools.max_connections` |

### Security Limits

| Feature | Setting | Value |
|---------|---------|-------|
| Brute force protection | Max attempts before lockout | 20 |
| Brute force protection | Lockout duration | 2-10 s (escalating) |
| Brute force protection | Tracking window | 60 s |
| Circuit breaker | Failure threshold (open) | 10 consecutive failures |
| Circuit breaker | Success threshold (close) | 5 consecutive successes |
| Circuit breaker | Half-open timeout | 60 s |
| Adaptive rate limiting | Throttle at P95 latency | 200 ms -> 40% of original TPS |
| Adaptive rate limiting | Protect at P95 latency | 1000 ms -> 10% of original TPS |

### Caches

| Cache | Max Entries | Shards | TTL |
|-------|-------------|--------|-----|
| Parse cache | 10,000 | 16 | 300 s |
| Result cache | 100 | 4 | 30 s |
| Slow query log | 100 | -- | -- |

## Key Features

**Performance**
- Sub-microsecond overhead on cache hits
- Lock-free hot path (parse cache, rate limiter, audit)
- Ninja-based Docker build for fast compilation

**Access Control**
- O(1) policy lookups via radix trie
- Zero-downtime hot-reload (RCU atomic pointer swap)
- Column-level ACL with blocked column removal
- Row-level security via query rewriting

**Security**
- SCRAM-SHA-256 authentication (RFC 5802) for wire protocol
- SQL firewall mode (learning/enforcing) with fingerprint allowlisting
- SQL injection detection (6 pattern checks, no regex)
- Per-user behavioral anomaly detection
- AES-256-GCM column encryption with key rotation
- Brute force protection with escalating lockout
- IP allowlisting per user

**Observability**
- PII classification (email, phone, SSN, credit card)
- Data masking (partial, hash, redact)
- Data lineage tracking for GDPR/SOC2 compliance
- GDPR data subject access endpoint (Article 15)
- Prometheus metrics, W3C distributed tracing
- Per-layer tracing spans (rate_limit, parse, policy, execute, classify, mask)
- Admin dashboard with real-time SSE metrics stream
- OpenAPI 3.0 spec + Swagger UI at `/api/docs`

**Multi-Tenancy**
- Tenant provisioning API (CRUD at `/admin/tenants`)
- Per-tenant connection pools with configurable limits
- Per-tenant circuit breakers and rate limiting

**Query Intelligence**
- Query explanation API (plain-English query summaries)
- Automatic index recommendation from filter patterns
- Query cost estimation (EXPLAIN-based rejection of expensive queries)

**Resilience**
- Hierarchical rate limiting (Global -> User -> DB -> User+DB)
- Adaptive rate limiting (auto-adjust based on DB latency P95)
- Request prioritization (HIGH/NORMAL/LOW/BACKGROUND with weighted tokens)
- Per-database circuit breakers and connection pools
- Configurable alerting rules with webhook/syslog sinks
- Request timeout with query cancellation
- Retry with exponential backoff for transient failures
- Schema drift detection (background monitoring for unauthorized changes)

**Compliance**
- AES-256-GCM audit record encryption at rest
- Hash chain integrity for tamper-evident audit logs

## Feature Flags

All features can be toggled via `config/proxy.toml`. Disabled features skip component creation and route registration:

```toml
[features]
classification = true   # PII detection
masking        = true   # Data masking in query results
openapi        = true   # OpenAPI spec + Swagger UI
dry_run        = true   # Dry-run query endpoint
```

Features with their own config section use `enabled = true/false`:

| Feature | Config Section | Default |
|---------|---------------|---------|
| Rate limiting | `[rate_limiting]` | enabled |
| Parse cache | `[cache]` | enabled |
| Result cache | `[result_cache]` | enabled |
| Circuit breaker | `[circuit_breaker]` | enabled |
| Alerting | `[alerting]` | enabled |
| Query cost estimation | `[query_cost]` | enabled |
| Schema drift detection | `[schema_drift]` | enabled |
| Retry with backoff | `[retry]` | enabled |
| Request timeout | `[request_timeout]` | enabled |
| Tracing spans | `[tracing]` | enabled |
| Request prioritization | `[priority]` | enabled |
| Brute force protection | `[security.brute_force]` | enabled |
| Adaptive rate limiting | `[adaptive_rate_limiting]` | disabled |
| SQL firewall | `[security.firewall]` | disabled |
| Index recommender | `[index_recommender]` | disabled |
| Column encryption | `[encryption]` | disabled |
| Audit encryption | `[audit_encryption]` | disabled |
| Wire protocol | `[wire_protocol]` | disabled |
| SCRAM-SHA-256 auth | `[wire_protocol] prefer_scram` | disabled |
| GraphQL | `[graphql]` | disabled |
| Binary RPC | `[binary_rpc]` | disabled |
| Schema management | `[schema_management]` | disabled |
| Multi-tenancy | `[tenants]` | disabled |

## Configuration

All configuration in `config/proxy.toml`:
- Users, roles, and API keys
- Access control policies (table-level allow/block/mask)
- Hierarchical rate limits and per-user overrides
- Security settings (injection, anomaly, encryption, brute force)
- Audit sinks (file, webhook, syslog) with rotation and encryption
- Alerting rules with severity thresholds
- Feature flags for toggling any feature on/off

## Dashboard

The admin dashboard is available at `http://localhost:8080/dashboard` and provides:
- Real-time SSE metrics stream (2s interval)
- Request counters: allowed, blocked, rate-limited, auth rejected, brute force blocked
- Audit stats: emitted, written, overflow
- Active alerts with severity badges
- Policy and user listings
- Live charts for request rate and audit throughput

Authenticate with the `admin_token` from `config/proxy.toml`.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/query` | API key | Execute a SQL query |
| POST | `/api/v1/query/dry-run` | API key | Validate without executing |
| GET | `/health` | None | Health check |
| GET | `/metrics` | None | Prometheus metrics |
| GET | `/openapi.json` | None | OpenAPI 3.0 spec |
| GET | `/api/docs` | None | Swagger UI |
| POST | `/admin/policies/reload` | Admin | Hot-reload policies |
| POST | `/admin/config/validate` | Admin | Validate TOML config |
| GET | `/admin/slow-queries` | Admin | Recent slow queries |
| GET | `/api/v1/circuit-breakers` | Admin | Circuit breaker states |
| GET | `/compliance/pii-report` | Admin | PII classification report |
| GET | `/compliance/security-summary` | Admin | Security event summary |
| GET | `/compliance/lineage` | Admin | Data lineage graph |
| GET | `/compliance/data-subject-access` | Admin | GDPR Article 15 export |
| GET | `/schema/history` | Admin | Schema change history |
| GET | `/schema/drift` | Admin | Schema drift report |
| POST | `/api/v1/query/explain` | API key | Explain query in plain English |
| GET | `/api/v1/index-recommendations` | Admin | Suggested indexes for slow queries |
| GET | `/api/v1/firewall/mode` | Admin | SQL firewall mode and stats |
| POST | `/api/v1/firewall/mode` | Admin | Set firewall mode (disabled/learning/enforcing) |
| GET | `/api/v1/firewall/allowlist` | Admin | SQL firewall fingerprint allowlist |
| GET | `/admin/tenants` | Admin | List all tenants |
| POST | `/admin/tenants` | Admin | Create a tenant |
| GET | `/admin/tenants/:id` | Admin | Get tenant details |
| DELETE | `/admin/tenants/:id` | Admin | Remove a tenant |
| GET | `/dashboard` | None | Admin dashboard UI |
| GET | `/dashboard/api/stats` | Admin | Stats JSON snapshot |
| GET | `/dashboard/api/metrics/stream` | Admin | SSE real-time stream |
| GET | `/dashboard/api/policies` | Admin | Policy listing |
| GET | `/dashboard/api/users` | Admin | User listing |
| GET | `/dashboard/api/alerts` | Admin | Active alerts |

## Example Query

```bash
# With API key authentication
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sk-analyst-key-67890' \
  -d '{"database": "testdb", "sql": "SELECT id, name, email FROM customers LIMIT 5"}'

# With username in body (legacy)
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"user": "analyst", "database": "testdb", "sql": "SELECT id, name, email FROM customers LIMIT 5"}'
```

## Technology Stack

- C++23 with CMake + Ninja
- libpg_query (PostgreSQL SQL parser)
- libpq (PostgreSQL client library)
- cpp-httplib (HTTP server)
- toml++ (TOML configuration parser)
- glaze (high-performance JSON)
- xxHash (fingerprint hashing)
- Catch2 (unit tests)
- Docker + docker-compose

## License

[Specify License]
