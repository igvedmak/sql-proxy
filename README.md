# SQL Proxy Service

A high-performance C++20 SQL proxy service for PostgreSQL with SQL analysis, access control, PII classification, and audit logging.

## Quick Start

**Build and run with Docker:**

```bash
docker compose build
docker compose up
```

The service will be available at http://localhost:8080

## Documentation

See [DOCKER.md](DOCKER.md) for complete build and deployment instructions.

## Architecture

7-layer request pipeline:

```
Client Request
     ↓
① INGRESS ────────── Rate limiting, validation
     ↓
② PARSE + CACHE ──── SQL parsing with LRU cache
     ↓
③ ANALYZE ────────── Table/column extraction
     ↓
④ POLICY ENGINE ─── Access control
     │
     ├── DENY → Audit + 403
     ↓ ALLOW
⑤ EXECUTOR ──────── Connection pool + query execution
     ↓
⑥ CLASSIFIER ────── PII detection
     ↓
⑦ AUDIT ──────────── Comprehensive logging
     ↓
Response + Classifications
```

## Key Features

- Sub-microsecond overhead on cache hits
- O(1) policy lookups via radix trie
- Zero-downtime hot-reload for policies
- Lock-free hot path (parse cache, rate limiter, audit)
- Per-database circuit breakers and connection pools
- Hierarchical rate limiting (Global → User → DB → User+DB)
- PII classification (email, phone, SSN, credit card)

## Configuration

Configuration files in `config/` directory:
- `proxy.toml` - Main proxy configuration
- `databases.toml` - Database connections
- `policies.toml` - Access control policies

## Example Query

```bash
curl -X POST http://localhost:8080/api/v1/query \
  -H 'Content-Type: application/json' \
  -d '{
    "user": "analyst",
    "database": "analytics_db",
    "sql": "SELECT id, email FROM users LIMIT 5"
  }'
```

## Technology Stack

- C++20 with CMake
- libpg_query (PostgreSQL parser)
- libpq (PostgreSQL client)
- Drogon (HTTP framework)
- nlohmann-json (JSON parsing)
- xxHash (hashing)
- Docker + docker-compose

## License

[Specify License]
