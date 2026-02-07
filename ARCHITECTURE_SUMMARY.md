# SQL Proxy Service — Architecture Summary

## 1. What We're Building

A high-performance C++20 SQL proxy that sits between clients and PostgreSQL databases. Every SQL statement passes through a 7-layer pipeline that validates, parses, analyzes, authorizes, executes, classifies, and audits — before the result reaches the client.

**Core principle:** Kill requests as early and cheaply as possible. The database is the most expensive resource — every request we stop before it reaches the DB saves 1-100ms.

---

## 2. Tech Stack

| Component | Library | Why |
|---|---|---|
| Language | C++20 | Coroutines, concepts, constexpr, compile-time regex |
| SQL Parsing | libpg_query (C) | PostgreSQL's actual parser — zero ambiguity |
| DB Connection | libpq (raw C API) | Zero overhead, async, full control |
| HTTP Server | Drogon | #1 on TechEmpower benchmarks, coroutine support |
| JSON | nlohmann-json | Industry-standard C++ JSON parser, used for AST walking |
| Config | toml++ (vendored) | Header-only TOML parser |
| Testing | Catch2 v3 | Lightweight, fast compile |
| Regex | CTRE | Compile-time regex, ~100ns/match |
| Hashing | xxHash | ~0.3 bytes/cycle, fastest non-crypto hash |
| Build | CMake + CPM/FetchContent | Dependency management |
| Container | Docker Compose | PostgreSQL + proxy service |

**No Boost.** Every need is covered by smaller, faster, purpose-built libraries.

---

## 3. Pipeline Overview

```
Client Request
     │
     ▼
① INGRESS ──── validate, authenticate, rate limit (4 levels), build context
     │         filters: 10-40%  |  cost: ~1.5μs
     ▼
② PARSE + CACHE ──── fingerprint SQL, check LRU cache, parse on miss (libpg_query)
     │                filters: 3-8%   |  cost: HIT ~500ns / MISS ~50μs
     ▼
③ ANALYZE ──── walk AST once, extract tables/columns/projections/derived_from
     │          filters: 1-2%   |  cost: HIT 0μs (cached) / MISS ~5μs
     ▼
④ POLICY ENGINE ──── radix trie lookup, specificity resolution, ALLOW or DENY
     │                 filters: 15-50%  |  cost: ~100-400ns
     │
     ├── DENY ──→ audit + 403 response
     │
     ▼ ALLOW
⑤ EXECUTOR ──── acquire connection from per-DB pool, execute against PostgreSQL
     │           filters: 2-8% (errors/timeouts)  |  cost: 1ms-10s (DB-dependent)
     │
     ├── ERROR ──→ audit + 5xx response
     │
     ▼ SUCCESS
⑥ CLASSIFIER ──── strategy chain: column names, types, regex values, derived columns
     │              filters: 0% (informational)  |  cost: ~1-50μs
     ▼
⑦ AUDIT ──── lock-free MPSC enqueue → dedicated writer thread → file + DB sinks
     │        cost on hot path: ~750ns (async, never blocks)
     ▼
200 Response + classifications
```

**Result:** 35-75% of requests never touch the database. Proxy overhead on cache hit: ~4μs (invisible).

---

## 4. Layer Details

### 4.1 — Ingress Layer

**Purpose:** The bouncer at the door. Validate, identify, rate-limit, package, dispatch, serialize. Nothing more.

**Components:**

- **HTTP Server (Drogon):** Non-blocking event loop, C++20 coroutine handlers. Routes: `POST /api/v1/query`, `GET /health`, `GET /metrics`, `POST /policies/reload`
- **Request Validation:** JSON well-formed? Required fields present (`user`, `sql`, `database`)? SQL non-empty + within max length? Fail fast before expensive work
- **User Authentication:** Resolve user field → known identity from config. Reject unknown users immediately
- **Hierarchical Rate Limiter (4 levels, ALL must pass):**
  - Level 1 — Global: protects proxy CPU from DDoS (50K req/sec)
  - Level 2 — Per-User: prevents one user starving others (configurable per user/role)
  - Level 3 — Per-Database: protects each DB independently (each DB has different capacity)
  - Level 4 — Per-User-Per-Database: most specific control (analyst on analytics: 50/sec)
  - Implementation: lock-free atomic token buckets, ~80ns for all 4 checks
- **Concurrency Limiter:** Per-database semaphore limiting in-flight queries. Rate limit alone can't prevent pool exhaustion for slow queries. co_await with timeout
- **RequestContext Construction:** Arena-allocated, carries: user_id, raw_sql, database, client_ip, timestamp, request_id. Single object flows through entire pipeline
- **Response Serialization:** Pipeline result → JSON. Error mapping: ParseError→400, PolicyDenied→403, RateLimited→429, AuthError→401, ExecError→502, Timeout→504

**API Contract:**

```
POST /api/v1/query
Request:  { "user": "analyst", "sql": "SELECT ...", "database": "app" }

Response (allowed):  { "status": "allowed", "statement_type": "SELECT",
                       "tables": [...], "classifications": [...],
                       "result": { "columns": [...], "rows": [...] },
                       "execution_time_ms": 2.3, "audit_id": "evt_..." }

Response (denied):   { "status": "denied", "reason": "...",
                       "matched_rule": "rule_022", "audit_id": "evt_..." }

Response (error):    { "status": "error", "error": "...", "audit_id": "evt_..." }
```

---

### 4.2 — Parse + Cache Layer

**Purpose:** Transform raw SQL string into a structured, immutable StatementInfo. Most expensive CPU stage (~50μs on miss), so caching is critical.

**Components:**

- **Query Fingerprinter (single-pass state machine, ~300ns):**
  - Strip comments (block `/* */` and line `-- \n`)
  - Normalize: string literals → `?`, numeric literals → `?`, boolean → `?`
  - Collapse IN-lists: `IN (1,2,3,4,5)` → `IN (?)` (same shape regardless of list length — #1 cache hit killer)
  - Collapse whitespace, lowercase keywords
  - xxHash64 of normalized string (~10ns)
  - All three stages merged into ONE pass — no intermediate allocations

- **Sharded LRU Parse Cache:**
  - `fingerprint_hash` → `shared_ptr<StatementInfo>` (includes AnalysisResult)
  - N shards (= CPU cores), each with own small mutex → near-zero contention
  - Default 10K entries, LRU eviction
  - Never needs explicit invalidation (stores structural analysis, not query results)
  - Collision guard: store normalized string alongside hash, strcmp on hit (~50ns). Correctness is non-negotiable for a security proxy

- **SQL Parser (libpg_query, on cache miss only):**
  - PostgreSQL's actual parser extracted as C library
  - Raw SQL → Protobuf AST → our StatementInfo
  - Same code PG uses internally, handles all edge cases
  - Parse errors short-circuit immediately → audit + 400

**Cache hit rate:** 80-95% for typical applications (50-200 unique query shapes, repeated thousands of times). This turns a 50μs operation into 500ns.

---

### 4.3 — SQL Analyzer Layer

**Purpose:** Walk AST once, extract everything downstream stages need. Single pass.

**Components:**

- **Statement Classifier:** AST root → StatementType (DDL/DML/SELECT) + SubType (CREATE/ALTER/DROP/INSERT/UPDATE/DELETE)
- **Table Extractor:** FROM, JOIN, INTO, UPDATE clauses → TableRef with database, schema, table, alias, usage (READ/WRITE/BOTH)
- **Alias Resolver:** Build alias map from FROM clause, then resolve: `a.name` → `customers.name`
- **Projection Extractor (SELECT):** Target list columns with `derived_from` tracking. `UPPER(email)` → `{column:'formatted', derived_from:['email']}`. Critical for classifier to catch transformed PII
- **Write Column Extractor (DML):** INSERT target columns, UPDATE SET targets. INSERT...SELECT: both read sources and write targets
- **Filter Column Extractor:** WHERE and JOIN ON columns — reveals query intent for audit
- **Schema Cache:** Preloaded from `information_schema.columns` at startup. Resolves `SELECT *` to actual column list. Invalidated async on DDL via RCU pointer swap

**Key insight:** AnalysisResult is embedded in the parse cache entry. Same query shape = same analysis. Zero cost on cache hit.

**Output — AnalysisResult:**

```
StatementType, SubType
source_tables[]     — tables data is READ from
target_tables[]     — tables data is WRITTEN to
projections[]       — columns returned (with derived_from)
write_columns[]     — columns being modified
filter_columns[]    — WHERE/JOIN columns (for audit)
is_star_select, has_subquery, has_join, has_aggregation
limit_value (if present)
```

---

### 4.4 — Policy Engine

**Purpose:** Authorization gate. "Does user X have permission to execute statement type Y on tables Z?" This is the security decision. Not "is it safe?" — just "is it authorized?"

**Components:**

- **Policy Rule Model:** Each rule has: id, user/role, database/schema/table scope (wildcards), statement types (DDL/DML/SELECT), action (ALLOW/BLOCK), human-readable reason
- **Radix Trie (per user/role):** Policies precomputed into trie at config load. Lookup: walk db→schema→table, at most 4 hash lookups. O(1) regardless of rule count
- **Specificity System:** Weighted scoring: db(100) + schema(10) + table(1). `*.*.*`=0, `app.*.*`=100, `app.public.*`=110, `app.public.customers`=111. Highest specificity wins. BLOCK > ALLOW at same level. No match = DEFAULT DENY (closed world)
- **Multi-Table Evaluation:** Query touches N tables → ALL must be allowed. ANY denied = entire query denied. Prevents exfiltration via JOIN with blocked table
- **Statement-Type Scoping:** Same table can have different rules per DDL/DML/SELECT
- **Hot Reload (RCU):** Config change → build new trie → atomic pointer swap. In-flight requests see old config, new requests see new. Zero downtime

**Resolution algorithm:**

1. Collect ALL matching rules (user/role match + scope match + statement type match)
2. Sort by specificity (highest first)
3. At highest specificity: BLOCK wins over ALLOW
4. No rules match → DEFAULT DENY
5. Return: {decision, matched_rule_id, reason, per-table breakdown}

**Trust model:** The proxy holds DB credentials with broad access. Security is enforced by the proxy, not by DB grants. Same model as AWS IAM, Envoy RBAC, ProxySQL.

---

### 4.5 — Query Executor

**Purpose:** Execute allowed SQL against PostgreSQL, return structured results.

**Components:**

- **Per-Database Connection Pool:** Each DB has own bounded pool (analytics: 10, app: 50, staging: 5). Semaphore-guarded acquire with co_await + timeout. One DB failing never affects others
- **Statement Branching:**
  - SELECT: execute + fetch result set → forward to classifier
  - DML: execute + capture affected_rows → skip classifier
  - DDL: execute + trigger SchemaCache invalidation → skip classifier
- **Query Timeout:** PG-level `SET statement_timeout`. If exceeded, PG cancels server-side. Connection stays valid. Returns 504
- **Circuit Breaker (per DB):** CLOSED→OPEN (errors spike)→HALF-OPEN (cooldown, try one)→CLOSED (success). When OPEN: immediate 503, no connection acquired. Prevents cascade failure
- **DDL → Schema Invalidation:** Successful DDL triggers async SchemaCache refresh via RCU. ~100ms staleness window (documented tradeoff)
- **Result Buffering:** Buffer entire result set with configurable max_rows (default 10K). Streaming documented as future work
- **Read/Write Separation (future-ready):** Analyzer knows statement type. SELECT → read pool (replica), DML/DDL → write pool (primary). Zero code change in other stages

---

### 4.6 — Data Classifier

**Purpose:** Scan SELECT result sets for sensitive data. Informational only — never blocks a query. Labels PII exposure for audit and response metadata.

**Why after execution:** Column names alone miss `SELECT data FROM attrs WHERE key='email'`. Only values reveal it's PII.

**Classifier Registry — Strategy Chain (ordered, first high-confidence match wins):**

1. **ColumnNameClassifier (~10ns/col):** Hash-map lookup. email→PII.Email, phone→PII.Phone. Handles camelCase/uppercase/hyphens. Substring fallback at lower confidence
2. **TypeOidClassifier (~5ns/col):** PG type hints. INET→PII.IP, MACADDR→PII.DeviceID, custom domains
3. **RegexValueClassifier (~1-10μs/col):** Scan actual values when name is ambiguous. Sample 20 rows (not full scan — 250x cheaper). Email/phone/SSN/credit card patterns. Uses CTRE compile-time regex
4. **DerivedColumnClassifier (~10ns/col):** Uses `derived_from` from Analyzer. `UPPER(email)` → still PII.Email. Confidence scaled: direct=1.0, function=0.85, aggregate=0.5

**Graceful degradation:** Classifier failure → catch, log, return empty classifications. Query result still returned. Classification is visibility, not security.

**Config-driven rules:** New PII types added by config change, no recompile.

---

### 4.7 — Audit Emitter

**Purpose:** Every single request — allowed, denied, errored — produces a structured audit event. The compliance backbone.

**Cardinal rules:** Never block hot path. Never lose events silently. Never bypassable. Never log raw row data.

**Architecture:**

- **MPSC Ring Buffer:** Lock-free multi-producer single-consumer. Event loop threads enqueue via atomic CAS (~50ns). 64K event capacity. Dedicated audit thread drains
- **Batch Writer:** Drain trigger: 1000 events OR 100ms (whichever first). Amortizes syscall cost
- **File Sink (primary):** JSONL format, append-only, streamable. Configurable fsync. Daily rotation
- **DB Sink (secondary):** `audit_events` table with indexes on: user+time, decision+time, has_pii+time, tables (GIN), fingerprint+time. SEPARATE connection pool from query executor
- **Overflow Policy:** Buffer full → drop newest + increment atomic counter → synthetic WARNING event when drained. Never blocks producers. Never loses silently

**Every-path emission:** Pipeline wrapper emits audit — stages cannot forget. Structural guarantee, not convention.

**AuditEvent schema fields and why:**

| Field | Why |
|---|---|
| event_id (UUID v7) | Globally unique, time-sortable. Merge streams from multiple proxies |
| sequence_num | Monotonic counter. Gap = lost events. Detection |
| received_at + timestamp | Two timestamps = measure queue time. Blame attribution |
| proxy_overhead | Separate from DB time. Our problem vs DB problem |
| session_id | Correlate multi-statement sessions. Detect exfiltration |
| fingerprint | Group by query shape. Detect scraping (same shape, 50K times) |
| columns_filtered | WHERE columns reveal intent. Lookup vs bulk export |
| matched_rule + specificity | Exact answer for "why was I blocked?" Dead rule detection |
| classifications + has_pii | Compliance: "all PII access in last 30 days" — instant |
| cache_hit | Operational: hit rate drop = new query patterns = new deployment |
| rows_returned | Risk signal. 50K rows even if allowed = anomaly |

**NOT logged:** Actual row data (audit would become PII store), DB credentials, full headers, raw AST.

---

## 5. Cross-Cutting Concerns

### 5.1 — Arena Allocator

Per-request memory arena. All allocations for a request come from one pre-allocated block (~1KB). Free entire arena on response — single pointer reset, O(1). No `new`/`delete` on hot path. Zero fragmentation.

### 5.2 — Threading Model

N event loop threads (= CPU cores), each runs full pipeline end-to-end. No hand-off between threads. Dedicated audit writer thread. No cross-thread synchronization on hot path. Audit enqueue = single atomic CAS.

### 5.3 — RCU Config Reload

Policies, rate limits, classifiers, schema cache — all hot-reloadable. Build new config object → atomic pointer swap. In-flight requests finish on old config. New requests see new config. Zero downtime, zero locks.

### 5.4 — Error Taxonomy

Typed, classifiable errors. Each maps to HTTP status code and audit event:

- ParseError → 400
- AuthError → 401
- PolicyDenied → 403
- RateLimited → 429
- ExecError → 502
- Timeout → 504
- InternalError → 500

### 5.5 — Multi-DB Architecture

Each database has independently:

- Connection pool (bounded, different sizes)
- Circuit breaker state
- Rate limit budget
- Concurrency limit
- Query timeout setting
- Health check

One DB failing never affects others. Failure isolation.

### 5.6 — Observability Endpoints

- `GET /health` — DB pool connectivity + config loaded
- `GET /metrics` — req/sec, latency percentiles, cache hit rate, deny rate, classification stats, audit buffer utilization
- `POST /policies/reload` — trigger hot-reload without restart

---

## 6. Scale Story

### Vertical (single instance)

- Drogon event loops = CPU cores → linear throughput scaling
- Per-DB connection pools → protect each DB from overload
- Parse cache → 80-95% hit rate, skip 50μs parse
- Arena allocator → no GC pauses, no fragmentation
- Lock-free hot path → no contention ceiling

### Horizontal (multiple instances)

- Stateless proxy → N instances behind load balancer
- Rate limits: divide by instance count (simple) — future: hybrid local + periodic Redis sync
- Shared policy config → file, etcd, or config service
- Shared audit sink → centralized log aggregator (Kafka/S3)
- Each instance: own pools, own caches, own circuit breakers

### What Breaks First (and fix)

- DB connections → PgBouncer / read replicas
- Audit write throughput → Kafka as intermediate buffer
- Parse cache memory → LRU eviction (bounded size)
- Config propagation → etcd watch / push
- Rate limit accuracy across instances → distributed counter (Redis)

---

## 7. Performance Budget

### Cache Hit Path (80-95% of requests)

```
Ingress validate + auth + rate limit    1.5μs
Parse cache lookup (fingerprint + hit)  0.5μs
Analyze (cached with parse)             0μs
Policy trie lookup                      0.3μs
────────────────────────────────────────
Total to DENY:                          2.3μs   (sub-3μs rejection)
Total to reach DB:                      2.3μs   (proxy overhead before DB)
Execute (DB):                           1-1000ms
Classify:                               1-50μs
Audit enqueue:                          0.75μs
────────────────────────────────────────
Total proxy overhead:                   ~4μs    (invisible)
```

### Cache Miss Path (5-20% of requests)

```
Ingress                                 1.5μs
Fingerprint + parse + analyze           55μs
Policy                                  0.3μs
────────────────────────────────────────
Total to DENY:                          57μs
Total proxy overhead:                   ~60μs   (still <0.01% of DB time)
```

### Throughput Target

- 50K+ queries/sec per instance (16 cores)
- Sub-3μs denial latency on cache hit
- <0.01% overhead for allowed queries

---

## 8. Request Funnel Example (1000 requests)

```
1000 requests arrive
 ├── 150 killed at Ingress        (cost: 225μs total)
 │    ├── 50 malformed JSON
 │    ├── 30 unknown user
 │    ├── 60 rate limited
 │    └── 10 empty/oversized SQL
 ├── 50 killed at Parse            (cost: 2.5ms total)
 │    ├── 40 invalid SQL
 │    └── 10 unsupported statements
 ├── 10 killed at Analyze          (cost: ~0, cached)
 ├── 250 killed at Policy          (cost: 75μs total)
 │    ├── 100 unauthorized table access
 │    ├── 80 unauthorized statement type
 │    └── 70 default deny
 ├── 30 killed at Executor         (cost: 300ms total)
 │    ├── 15 query timeout
 │    ├── 10 PG errors
 │    └── 5 pool exhausted
 └── 510 successful                (cost: 2.55s total)
      ├── 200 with PII classified
      └── 310 no PII detected

490 requests (49%) never touched the database.
All 1000 requests audited.
```

---

## 9. Project Structure

```
sql-proxy/
├── CMakeLists.txt
├── Dockerfile
├── docker-compose.yml
├── config/
│   └── proxy.toml                  ← users, policies, rate limits, classifiers
├── sql/
│   ├── 001_schema.sql              ← customers, orders tables
│   ├── 002_seed.sql                ← sample data
│   └── 003_audit_table.sql         ← audit_events table + indexes
├── src/
│   ├── main.cpp
│   ├── core/
│   │   ├── pipeline.hpp            ← stage chain, audit emission wrapper
│   │   ├── request_context.hpp     ← arena-allocated, flows through pipeline
│   │   ├── arena.hpp               ← per-request arena allocator
│   │   ├── error.hpp               ← ErrorCategory, Result<T>
│   │   └── types.hpp
│   ├── server/
│   │   ├── http_server.hpp/.cpp    ← Drogon setup, coroutine handlers
│   │   ├── handlers.hpp/.cpp       ← route handlers
│   │   └── rate_limiter.hpp/.cpp   ← hierarchical token buckets + concurrency
│   ├── parser/
│   │   ├── sql_parser.hpp/.cpp     ← libpg_query wrapper
│   │   ├── fingerprinter.hpp/.cpp  ← single-pass normalizer + xxHash
│   │   ├── parse_cache.hpp/.cpp    ← sharded LRU
│   │   └── statement_info.hpp
│   ├── analyzer/
│   │   ├── sql_analyzer.hpp/.cpp   ← single AST walk, extract everything
│   │   ├── schema_cache.hpp/.cpp   ← information_schema preload + RCU
│   │   ├── analysis_result.hpp
│   │   └── table_ref.hpp
│   ├── policy/
│   │   ├── policy_engine.hpp/.cpp  ← specificity resolution
│   │   ├── policy_trie.hpp/.cpp    ← radix trie per user/role
│   │   ├── policy.hpp              ← rule model
│   │   └── policy_loader.hpp/.cpp  ← TOML → trie
│   ├── executor/
│   │   ├── connection_pool.hpp/.cpp ← per-DB bounded pools
│   │   ├── circuit_breaker.hpp/.cpp
│   │   └── query_executor.hpp/.cpp
│   ├── classifier/
│   │   ├── classifier_registry.hpp/.cpp
│   │   ├── iclassifier.hpp         ← interface
│   │   ├── column_name_classifier.cpp
│   │   ├── type_oid_classifier.cpp
│   │   ├── regex_value_classifier.cpp
│   │   └── derived_column_classifier.cpp
│   ├── audit/
│   │   ├── audit_event.hpp
│   │   ├── audit_emitter.hpp/.cpp  ← MPSC ring buffer
│   │   ├── audit_writer.hpp/.cpp   ← batch drain loop
│   │   ├── file_sink.cpp
│   │   └── db_sink.cpp
│   └── config/
│       └── config_loader.hpp/.cpp  ← TOML parsing, validation
├── tests/
│   ├── test_fingerprinter.cpp
│   ├── test_parser.cpp
│   ├── test_analyzer.cpp
│   ├── test_policy_engine.cpp
│   ├── test_classifier.cpp
│   ├── test_rate_limiter.cpp
│   └── test_pipeline_integration.cpp
├── scripts/
│   └── demo.sh                     ← curl-based walkthrough
└── README.md                       ← design doc quality
```

---

## 10. Implementation Order

### Phase 0 — Skeleton (2-3 hrs)
CMake project with all dependencies. Docker Compose with PostgreSQL. SQL seed scripts. Verify connectivity. Basic Drogon server running.

### Phase 1 — Parse + Cache (3-4 hrs)
Fingerprinter (single-pass state machine). libpg_query integration. StatementInfo model. Sharded LRU cache. Unit tests.

### Phase 2 — Analyzer (2-3 hrs)
AST walker. Table/column/projection extraction. Alias resolution. Schema cache. derived_from tracking. Embed in cache entry. Unit tests.

### Phase 3 — Policy Engine (2-3 hrs)
Policy rule model. TOML loader. Radix trie builder. Specificity resolution. Multi-table evaluation. Hot reload. Unit tests.

### Phase 4 — Ingress + Pipeline (2-3 hrs)
HTTP handlers. Request validation. User auth. Hierarchical rate limiter. Concurrency limiter. RequestContext. Wire pipeline stages together.

### Phase 5 — Executor (2-3 hrs)
Per-DB connection pools. Statement branching (SELECT/DML/DDL). Query timeout. Circuit breaker. DDL → schema invalidation.

### Phase 6 — Classifier (1-2 hrs)
IClassifier interface. 4 classifier implementations. Registry chain. Config-driven rules. Graceful degradation.

### Phase 7 — Audit (1-2 hrs)
AuditEvent struct. MPSC ring buffer. Batch writer thread. File + DB sinks. Overflow policy. Every-path emission.

### Phase 8 — Polish (2-3 hrs)
README (design-doc quality). Demo script. Integration tests. Code cleanup. Error handling review.

**Total: ~18-22 hours (~2 working days)**

---

## 11. Key Design Decisions to Highlight in README

1. **libpg_query over regex/ANTLR** — it IS PostgreSQL's parser. 20+ years battle-tested.
2. **Arena allocator** — zero fragmentation, O(1) cleanup, cache-friendly. malloc ~50ns, arena bump ~2ns.
3. **Radix trie for policies** — O(depth) where depth ≤ 3. Precomputed at load time.
4. **MPSC ring buffer for audit** — lock-free enqueue, batch writes, audit never blocks queries.
5. **Hierarchical rate limiting** — single flat limiter can't protect individual DBs or ensure fair share.
6. **derived_from tracking** — UPPER(email) still exposes PII. Most systems miss this.
7. **Fingerprint normalization** — IN-list collapse, literal replacement, single-pass. Modeled after pg_stat_statements.
8. **Stateless proxy** — horizontal scaling: N instances behind LB, no shared state.
9. **Policy is authorization, not safety** — gatekeeper not detective. Clean, auditable, predictable.
10. **Three types of "safe"** — syntactically valid (parse), authorized (policy), data-exposure aware (classifier). Each is a different concern in a different layer.

---

## 12. Known Limitations (document honestly in README)

- CTEs with aliased columns: limited classification accuracy
- Prepared statements: not supported (would need PG wire protocol)
- Column-level policies: not implemented (architecture supports it via specificity scoring)
- Distributed rate limiting: divide-by-instance-count (not Redis-backed)
- Schema cache staleness: ~100ms window after DDL
- SELECT * through views: depends on schema cache resolving view definitions
- No query cost estimation: heavy queries only caught by timeout
- Result streaming: buffered with max_rows limit
- No multi-statement transactions: each request is independent
