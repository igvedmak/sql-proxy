# SQL Proxy Service

A high-performance C++23 SQL proxy service for PostgreSQL with SQL analysis, access control, SQL injection detection, PII classification, data masking, encryption, and audit logging.

## Quick Start

**Build and run with Docker (uses Ninja for fast builds):**

```bash
docker compose build
docker compose up
```

The service will be available at http://localhost:8080

## Documentation

- [DOCKER.md](DOCKER.md) - Build, run, test, and deploy instructions
- [FLOW_DIAGRAM.md](FLOW_DIAGRAM.md) - Detailed architecture and data flow

## Architecture

Multi-layer request pipeline with short-circuit on failure:

```
Client Request
     ↓
① RATE LIMIT ─────── Hierarchical 4-level token bucket
     ↓
② PARSE + CACHE ──── SQL parsing (libpg_query) with LRU cache
     ↓
③ ANALYZE ────────── Table/column extraction, query classification
     ↓
③½ SECURITY ──────── SQL injection detection + anomaly scoring
     ↓
④ POLICY ENGINE ─── Table-level access control (radix trie)
     │
     ├── DENY → Audit + 403
     ↓ ALLOW
④½ REWRITE ──────── Row-level security + enforce LIMIT
     ↓
⑤ EXECUTE ────────── Connection pool + circuit breaker
     ↓
⑤½ POST-PROCESS ─── Decrypt → Column ACL → Data masking
     ↓
⑥ CLASSIFY ──────── PII detection (4-strategy chain)
     ↓
⑥½ LINEAGE ──────── Track PII access for compliance
     ↓
⑦ AUDIT ──────────── Async ring buffer → file/webhook/syslog
     ↓
Response + Classifications
```

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
- SQL injection detection (6 pattern checks, no regex)
- Per-user behavioral anomaly detection
- AES-256-GCM column encryption with key rotation

**Observability**
- PII classification (email, phone, SSN, credit card)
- Data masking (partial, hash, redact)
- Data lineage tracking for GDPR/SOC2 compliance
- Prometheus metrics, W3C distributed tracing
- Admin dashboard with real-time SSE metrics

**Resilience**
- Hierarchical rate limiting (Global → User → DB → User+DB)
- Per-database circuit breakers and connection pools
- Configurable alerting rules with webhook/syslog sinks

## Configuration

All configuration in `config/proxy.toml`:
- Users, roles, and API keys
- Access control policies
- Rate limits and overrides
- Security settings (injection, anomaly, encryption)
- Audit sinks (file, webhook, syslog)
- Alerting rules

## Example Query

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "user": "analyst",
    "database": "testdb",
    "sql": "SELECT id, name, email FROM customers LIMIT 5"
  }'
```

## Technology Stack

- C++20 with CMake + Ninja
- libpg_query (PostgreSQL SQL parser)
- libpq (PostgreSQL client library)
- cpp-httplib (HTTP server)
- glaze (high-performance JSON)
- xxHash (fingerprint hashing)
- Catch2 (unit tests)
- Docker + docker-compose

## License

[Specify License]
