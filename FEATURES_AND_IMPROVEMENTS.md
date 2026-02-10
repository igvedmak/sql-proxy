# SQL Proxy — Features and Improvements Roadmap

This document outlines potential features and improvements for the SQL Proxy system, organized by category. Each item represents a concrete, implementable enhancement that addresses real production concerns.

---

## Performance Optimizations

### 3. Request Prioritization
**Problem:** All queries treated equally — an admin dashboard panel query waits behind a developer's `SELECT *` returning 100K rows.

**Solution:**
- Add priority tiers (HIGH, NORMAL, LOW) per user role
- Implement priority queues in connection pool acquisition
- High-priority requests bypass per-user rate limits (but not global)
- Expose priority in configuration and per-request headers

**Impact:** Ensures critical queries always complete quickly

---

### 4. Adaptive Rate Limiting
**Problem:** Static rate limits can't respond to database health — they allow too many requests when DB is slow or too few when it recovers.

**Solution:**
- Monitor database response latency (P95) in real-time
- Automatically adjust rate limits based on health:
  - Latency < 50ms → full rate (50K global QPS)
  - Latency 50-200ms → throttle to 20K QPS
  - Latency > 200ms → protect mode: 5K QPS
  - Circuit breaker open → 0 QPS
- Emit events when limits auto-adjust

**Impact:** Self-regulating proxy that protects database automatically

---

## Security Enhancements

### 7. SCRAM-SHA-256 Authentication
**Problem:** Wire protocol only supports cleartext and MD5 auth. MD5 is deprecated in PostgreSQL 14+ and vulnerable.

**Solution:**
- Implement SCRAM-SHA-256 (RFC 5802) in WireSession
- Support both SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (channel binding)
- Store password hashes using PBKDF2 iterations
- Maintain backward compatibility with MD5 for legacy clients

**Impact:** Secure authentication aligned with PostgreSQL standards

---

### 8. OAuth2 / OIDC Authentication Provider
**Problem:** Only API keys, JWT HMAC, and LDAP are supported. Enterprise customers use Azure AD, Okta, Auth0.

**Solution:**
- Add `OidcAuthProvider` to auth chain
- Support RS256/ES256 token verification (public key from JWKS endpoint)
- Map claims to roles: `user.roles = token.groups`
- Support token introspection for opaque tokens
- Cache JWKS with configurable TTL

**Impact:** Enterprise SSO integration without custom auth code

---

### 12. Wire Protocol TLS
**Problem:** HTTP has TLS but PostgreSQL wire protocol connections are cleartext — exposes credentials and query data.

**Solution:**
- Implement SSLRequest negotiation (PostgreSQL standard)
- After startup packet, client sends SSLRequest
- Server responds: `S` (SSL supported) or `N` (declined)
- If `S`, perform TLS handshake using OpenSSL
- Same certificate config as HTTP server

**Impact:** Encrypted wire protocol connections

---

## Observability Features

### 18. Per-Layer Distributed Tracing Spans
**Problem:** Trace context exists but no spans are emitted — can't see where time is spent in the pipeline.

**Solution:**
- Create OpenTelemetry-compatible span per layer:
  - `sql_proxy.rate_limit` (52ns)
  - `sql_proxy.parse` (500ns–50μs)
  - `sql_proxy.policy` (5μs)
  - `sql_proxy.execute` (1ms+)
  - `sql_proxy.classify` (100ns)
- Add attributes: user, database, statement_type, cache_hit
- Export to Jaeger via OTLP
- Parent span: entire request (HTTP or wire)

**Impact:** Visual latency breakdown for debugging production issues

---

## Compliance & Governance

### 25. Audit Record Encryption at Rest
**Problem:** Audit JSONL files contain raw SQL with potentially sensitive data. Disk access exposes query content.

**Solution:**
- Encrypt each audit record with AES-256-GCM before writing
- Use separate audit encryption key (not the column encryption key)
- Store IV per record, key ID in header
- Tool to decrypt: `audit-decrypt --key-file audit.key audit.jsonl`
- Support key rotation

**Impact:** Encrypted audit trails meet compliance requirements

---

## Operations Features

### 30. Plugin Hot-Reload
**Problem:** Adding a classifier or audit sink plugin requires full proxy restart. Lost in-flight requests.

**Solution:**
- API: `POST /api/v1/plugins/reload`
- For each plugin:
  1. Build new `LoadedPlugin` with new `.so` file
  2. Call `shutdown()` on old plugin instance
  3. RCU swap pointer (same pattern as policy reload)
  4. `dlclose()` old handle after grace period
- Log plugin version changes to audit

**Impact:** Add custom classifiers without downtime

---

## Multi-Tenancy & Scale

### 32. Per-Tenant Circuit Breakers
**Problem:** Shared per-database breaker means one tenant's bad queries affect all tenants on that database.

**Solution:**
- Change circuit breaker key from `database` to `tenant:database`
- Each tenant gets isolated failure tracking
- One tenant trips their breaker → other tenants unaffected
- Config: per-tenant threshold overrides
- Metrics: `sql_proxy_circuit_breaker_state{tenant="acme", database="prod"}`

**Impact:** Blast radius isolation in multi-tenant SaaS

---

### 33. Per-Tenant Connection Pools
**Problem:** One tenant can exhaust the shared connection pool (noisy neighbor problem).

**Solution:**
- Extend pool key from `database` to `tenant:database`
- Each tenant gets isolated pool with configurable `max_connections`
- Per-tenant pool stats in metrics
- Total connections = sum of all tenant pools (size accordingly)
- Requires more connections but prevents starvation

**Impact:** Guaranteed per-tenant resource allocation

---

### 34. Tenant Provisioning API
**Problem:** Tenants are only configurable in TOML. No runtime management for SaaS onboarding.

**Solution:**
- New endpoints:
  - `POST /admin/tenants` — create tenant with database, policies, rate limits
  - `GET /admin/tenants/{id}` — tenant details
  - `PUT /admin/tenants/{id}` — update tenant config
  - `DELETE /admin/tenants/{id}` — remove tenant
- Persist to TOML or database
- Hot-reload tenant manager on change (RCU pattern)
- Audit all tenant changes

**Impact:** Self-service tenant onboarding without config file edits

---

### 35. Distributed Rate Limiting
**Problem:** In-memory rate limiter is single-node. Multi-node deployments can't enforce global limits accurately.

**Solution:**
- Two-tier approach:
  - **Local tier** (fast path): Each node gets 1/N of global budget, atomic token bucket (~100ns)
  - **Global tier** (slow path): Redis-backed shared counters, reconcile every 5 seconds
- Algorithm:
  1. Check local bucket (immediate)
  2. If rejected locally, check Redis (1ms latency) for true global view
  3. Background sync: periodically report local usage to Redis, fetch adjusted quotas
- Config: `distributed_rate_limiting.backend = "redis"`, connection string

**Impact:** Accurate global rate limits across clusters

---

## Protocol & API Extensions

### 36. WebSocket Streaming
**Problem:** Long-running queries or real-time audit tails require polling. No push updates.

**Solution:**
- New endpoint: `ws://proxy/api/v1/stream`
- Protocols:
  - `audit`: subscribe to live audit stream
  - `query`: execute long query, stream rows incrementally
  - `metrics`: real-time metric updates (for dashboard)
- Message format: JSON frames with type discriminator
- Authentication: same Bearer token as HTTP

**Impact:** Real-time dashboards and SIEM integration without polling

---

### 37. GraphQL Mutations
**Problem:** GraphQL handler is read-only (queries only). Can't use it for writes.

**Solution:**
- Implement mutation resolvers:
  ```graphql
  mutation {
    insertCustomer(name: "Alice", email: "alice@example.com") {
      id
      name
    }
  }
  ```
- Translate to parameterized `INSERT` statements
- Support `update` and `delete` mutations
- Surface validation errors as GraphQL errors
- All mutations flow through full pipeline (policy, audit, etc.)

**Impact:** GraphQL as full CRUD gateway

---

### 38. Kafka / Message Queue Audit Sink
**Problem:** Enterprise SIEM tools (Splunk, Elastic) consume from Kafka, not file tails.

**Solution:**
- New sink: `KafkaSink` implementing `IAuditSink`
- Config:
  ```toml
  [audit.sinks.kafka]
  enabled = true
  brokers = ["kafka:9092"]
  topic = "sql-proxy-audit"
  ```
- Publish each audit record as JSON message
- Partition by user or database for ordering
- Handle producer errors with retry/DLQ

**Impact:** Native SIEM integration

---

### 39. COPY Protocol Support
**Problem:** PostgreSQL's COPY is used for bulk data loading. Wire protocol doesn't support it — blocks data engineering workloads.

**Solution:**
- Implement COPY protocol messages in WireSession:
  - `CopyInResponse`, `CopyData`, `CopyDone`, `CopyFail`
  - `CopyOutResponse`, `CopyData`, `CopyDone`
- Stream data through proxy without buffering entire dataset
- Apply policies (can COPY be performed on this table?)
- Audit COPY operations with row counts

**Impact:** Full wire protocol compatibility for bulk loads

---

### 40. OpenAPI / Swagger Endpoint
**Problem:** No API documentation — teams must read source code to understand endpoints.

**Solution:**
- Generate OpenAPI 3.0 spec at compile time or runtime
- Serve at `GET /api/docs` (Swagger UI)
- Document all endpoints: `/api/v1/query`, `/api/v1/execute`, `/health`, `/metrics`, compliance endpoints
- Include request/response schemas, authentication requirements
- Auto-update on hot-reload

**Impact:** Developer experience — self-documenting API

---

## Advanced / Future Features

### 41. Query Cost-Based Query Rewriting
Automatically optimize expensive queries: push down filters, add LIMIT, suggest indexes.

### 42. Multi-Database Transactions
Coordinate transactions across multiple databases with 2PC.

### 43. Read Replica Routing
Route SELECTs to replicas, writes to primary. Automatic failover detection.

### 44. Data Residency Enforcement
Per-tenant data locality rules (EU data stays in EU region). Block cross-region queries.

### 45. Automatic Index Recommendation
Track slow queries, analyze patterns, recommend indexes to DBA.

### 46. SQL Firewall Mode
After learning period, block any new query fingerprint not in allowlist.

### 47. Column-Level Data Versioning
Track changes to sensitive columns (who changed this salary value, when).

### 48. Synthetic Data Generation
Generate fake data matching real schema for testing environments.

### 49. Query Explanation API
Given a query, explain in plain English what it does and what data it accesses.

### 50. LLM-Powered Features
- AI policy generator (analyze unknown queries, auto-create policies)
- AI anomaly explanation (explain why this behavior is anomalous)
- Natural language to policy (admin types intent, LLM generates TOML)
- SQL intent classification (detect business-logic attacks beyond syntax)

---

## Implementation Priority

**P0 (Critical for Production):**
- Wire protocol TLS (#12)

**P1 (High Impact):**
- OAuth2/OIDC auth (#8)
- Per-layer distributed tracing (#18)

**P2 (Feature Expansion):**
- GraphQL mutations (#37)
- Per-tenant circuit breakers (#32)
- Plugin hot-reload (#30)
- WebSocket streaming (#36)
- Kafka audit sink (#38)

---

*This roadmap represents a mature, production-ready SQL proxy system with enterprise-grade features.*
