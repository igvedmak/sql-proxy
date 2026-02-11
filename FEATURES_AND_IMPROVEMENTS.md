# SQL Proxy — Features and Improvements Roadmap

This document outlines potential features and improvements for the SQL Proxy system, organized by category. Each item represents a concrete, implementable enhancement that addresses real production concerns.

---

## Security Enhancements

### 1. SCRAM-SHA-256 Authentication
**Problem:** Wire protocol only supports cleartext and MD5 auth. MD5 is deprecated in PostgreSQL 14+ and vulnerable.

**Solution:**
- Implement SCRAM-SHA-256 (RFC 5802) in WireSession
- Support both SCRAM-SHA-256 and SCRAM-SHA-256-PLUS (channel binding)
- Store password hashes using PBKDF2 iterations
- Maintain backward compatibility with MD5 for legacy clients

**Impact:** Secure authentication aligned with PostgreSQL standards

---

## Multi-Tenancy & Scale

### 2. Per-Tenant Connection Pools
**Problem:** One tenant can exhaust the shared connection pool (noisy neighbor problem).

**Solution:**
- Extend pool key from `database` to `tenant:database`
- Each tenant gets isolated pool with configurable `max_connections`
- Per-tenant pool stats in metrics
- Total connections = sum of all tenant pools (size accordingly)
- Requires more connections but prevents starvation

**Impact:** Guaranteed per-tenant resource allocation

---

### 3. Tenant Provisioning API
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

### 4. Distributed Rate Limiting
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

### 5. WebSocket Streaming
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

### 6. COPY Protocol Support
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

## Advanced / Future Features

### 7. Query Cost-Based Query Rewriting
Automatically optimize expensive queries: push down filters, add LIMIT, suggest indexes.

### 8. Multi-Database Transactions
Coordinate transactions across multiple databases with 2PC.

### 9. Read Replica Routing
Route SELECTs to replicas, writes to primary. Automatic failover detection.

### 10. Data Residency Enforcement
Per-tenant data locality rules (EU data stays in EU region). Block cross-region queries.

### 11. Automatic Index Recommendation
Track slow queries, analyze patterns, recommend indexes to DBA.

### 12. SQL Firewall Mode
After learning period, block any new query fingerprint not in allowlist.

### 13. Column-Level Data Versioning
Track changes to sensitive columns (who changed this salary value, when).

### 14. Synthetic Data Generation
Generate fake data matching real schema for testing environments.

### 15. Query Explanation API
Given a query, explain in plain English what it does and what data it accesses.

### 16. LLM-Powered Features
- AI policy generator (analyze unknown queries, auto-create policies)
- AI anomaly explanation (explain why this behavior is anomalous)
- Natural language to policy (admin types intent, LLM generates TOML)
- SQL intent classification (detect business-logic attacks beyond syntax)

---

## Implementation Priority

**P1 (High Impact):**
- WebSocket streaming (#5)

**P2 (Feature Expansion):**
- Per-tenant connection pools (#2)
- Distributed rate limiting (#4)
- COPY protocol support (#6)

---

*This roadmap represents a mature, production-ready SQL proxy system with enterprise-grade features.*
