# SQL Proxy — Flow Audit & Verification Questions

## Part 1: Flow Diagram Gap Analysis

The current `FLOW_DIAGRAM.md` covers the core 7-layer pipeline well but is **missing 20+ features** added in Tiers B–G. Below is a complete inventory of gaps.

### Missing Pipeline Layers (in execution order)

| Layer | Feature | Code Location | Status in Diagram |
|-------|---------|---------------|-------------------|
| 2.5 | **Result Cache Lookup** (SELECT cache hit → skip execution) | `pipeline.cpp:101-114` | MISSING |
| 4.1 | **Schema DDL Interception** (blocks DDL requiring approval) | `pipeline.cpp:130-132` | MISSING |
| 4.5 | **Query Rewriting** (RLS row filters + enforce_limit) | `pipeline.cpp:135` | MISSING |
| 4.8 | **Query Cost Estimation** (EXPLAIN-based, blocks expensive queries) | `pipeline.cpp:138-139` | MISSING |
| 5.01 | **Slow Query Tracking** (records queries exceeding threshold) | `pipeline.cpp:176-188` | MISSING |
| 5.02 | **Parse Cache DDL Invalidation** (invalidate on DDL success) | `pipeline.cpp:191-196` | MISSING |
| 5.05 | **Result Cache Store** (cache successful SELECTs) | `pipeline.cpp:199-205` | MISSING |
| — | **Write-Invalidation** (clear result cache for modified DB) | `pipeline.cpp:208-210` | MISSING |
| 5.1 | **Schema Change Recording** (record DDL to schema manager) | `pipeline.cpp:213-220` | MISSING |

### Missing from HTTP Server / Endpoints Section

| Endpoint | Method | Purpose | Status |
|----------|--------|---------|--------|
| `/api/v1/query/dry-run` | POST | Policy evaluation without execution | MISSING |
| `/api/v1/config/validate` | POST | Validate TOML config syntax | MISSING |
| `/api/v1/slow-queries` | GET | Recent slow queries list | MISSING |
| `/api/v1/compliance/data-subject-access` | GET | GDPR subject access requests | MISSING |
| `/api/v1/schema/history` | GET | DDL change history | MISSING |
| `/api/v1/schema/pending` | GET | Pending DDL approvals | MISSING |
| `/api/v1/schema/approve` | POST | Approve pending DDL | MISSING |
| `/api/v1/schema/reject` | POST | Reject pending DDL | MISSING |
| `/api/v1/schema/drift` | GET | Schema drift events | MISSING |
| `/api/v1/graphql` | POST | GraphQL→SQL translation | MISSING |
| `/openapi.json` | GET | OpenAPI 3.0 spec | MISSING |
| `/api/docs` | GET | Swagger UI | MISSING |
| `/dashboard` | GET | Admin dashboard (HTML) | MISSING |
| `/dashboard/api/stats` | GET | Real-time stats JSON | MISSING |
| `/dashboard/api/policies` | GET | Policy listing | MISSING |
| `/dashboard/api/users` | GET | User listing | MISSING |
| `/dashboard/api/alerts` | GET | Active/historical alerts | MISSING |
| `/dashboard/api/metrics/stream` | GET | SSE metrics stream | MISSING |

### Missing Components (not in Component Diagram)

| Component | Purpose | Code Location |
|-----------|---------|---------------|
| **TenantManager** | Multi-tenant isolation (per-tenant policy/rate/audit) | `tenant/tenant_manager.hpp` |
| **AuditSampler** | Configurable audit sampling rates | `audit/audit_sampler.hpp` |
| **ResultCache** | Full query result caching (16 shards, LRU) | `cache/result_cache.hpp` |
| **QueryCostEstimator** | EXPLAIN-based cost rejection | `core/query_cost_estimator.hpp` |
| **SchemaDriftDetector** | Background schema change detection | `schema/schema_drift_detector.hpp` |
| **AuditEncryptor** | AES-256-GCM audit record encryption | `audit/audit_encryptor.hpp` |
| **AdaptiveRateController** | Latency-based rate limit adjustment | `server/adaptive_rate_controller.hpp` |
| **WaitableRateLimiter** | Request queuing before rate-limit rejection | `server/waitable_rate_limiter.hpp` |
| **ResponseCompressor** | Gzip response compression | `server/response_compressor.hpp` |
| **ShutdownCoordinator** | Graceful shutdown (drain in-flight) | `server/shutdown_coordinator.hpp` |
| **ConfigWatcher** | File-based hot-reload (poll interval) | `config/config_watcher.hpp` |
| **PluginRegistry** | Dynamic classifier/audit sink plugins | `plugin/plugin_loader.hpp` |
| **DashboardHandler** | Admin web UI + JSON API + SSE | `server/dashboard_handler.hpp` |
| **BruteForceProtector** | IP/user lockout after max failures | `security/brute_force_protector.hpp` |
| **IpAllowlist** | Per-user CIDR IP restrictions | `security/ip_allowlist.hpp` |
| **WireServer** | PostgreSQL v3 wire protocol | `server/wire_server.hpp` |
| **BinaryRpcServer** | Custom binary RPC protocol | `server/binary_rpc_server.hpp` |
| **OpenAPIHandler** | OpenAPI spec + Swagger UI | `server/openapi_handler.hpp` |
| **GraphQLHandler** | GraphQL→SQL translation | `server/graphql_handler.hpp` |

### Missing from Thread Model

| Thread | Purpose | Status |
|--------|---------|--------|
| **Config Watcher** thread | Polls config file every N seconds | MISSING |
| **Schema Drift** thread | Background schema checks | MISSING |
| **Alert Evaluator** thread | Periodic alert rule evaluation | MISSING |
| **Adaptive Rate Controller** thread | Periodic rate limit adjustment | MISSING |
| **Wire Protocol** thread pool | PostgreSQL protocol handler | MISSING |
| **Binary RPC** thread pool | Binary protocol handler | MISSING |

### Outdated Information

| Item | Current in Diagram | Actual (after optimizations) |
|------|-------------------|------------------------------|
| Rate limiter perf | "~52ns for all 4 checks" | Now uses `try_acquire_at()` with single timestamp read |
| Fingerprinter perf | "~450ns" | Now uses constexpr 256-byte lookup table (~280ns) |
| Token bucket state | "packed 64-bit atomic" | Actually separate atomics: `tokens_` (32-bit) + `last_refill_ns_` (64-bit) |
| Startup phases | "[1/10] ... 10 phases" | Code shows [1/9] ... [9/9] |
| Classifier strategy | No allocation-free mention | Now uses `iequals()`, `icontains()`, zero-copy scanning |

### Missing Cross-Cutting Concerns

| Feature | Description | Status |
|---------|-------------|--------|
| **W3C Distributed Tracing** | `traceparent`/`tracestate` propagation, ScopedSpan per layer | MISSING |
| **Retry with Backoff** | Exponential backoff on DATABASE_ERROR (configurable) | MISSING |
| **Request Prioritization** | Priority field affects execution order | MISSING |
| **Feature Flags** | Config-driven route and component gating | MISSING |
| **TLS/mTLS** | HTTPS + optional client certificate auth | MISSING |
| **Response Compression** | Gzip for large responses (Accept-Encoding check) | MISSING |
| **Graceful Shutdown** | SIGINT/SIGTERM → drain in-flight → stop | Partially covered |
| **Alerting System** | Rule-based evaluation with severity/thresholds | MISSING |

---

## Part 2: Business Logic Verification Questions

These questions verify that the pipeline flow is correct as a business/security product.

### Q1. Rate Limiting — Order of Operations
**Question**: Rate limiting (Layer 1) runs BEFORE authentication. Is this intentional?
**Current behavior**: An unauthenticated request still consumes rate limit tokens at the global level.
**Risk**: An attacker can exhaust global rate limit tokens by flooding with invalid requests, starving legitimate users.
**Counter-argument**: This prevents unauthenticated users from even reaching the parse layer (expensive). The per-user bucket won't be hit because we use the request's `user` field from JSON — a spoof.
**Audit**: Is the user field from JSON trusted for rate limiting keys? Should rate limiting happen after authentication for user-level buckets?

### Q2. Brute Force vs Rate Limiting Interaction
**Question**: Brute force checks happen in `http_server.cpp` (before pipeline), rate limiting happens in `pipeline.cpp` (Layer 1). If an IP is locked out by brute force, does it still consume rate limit tokens?
**Current behavior**: No — brute force check returns 429 before the pipeline is called. This is correct.
**Audit**: Confirm this holds for both API-key auth and user-field auth paths.

### Q3. Result Cache — Security Implications
**Question**: Result cache uses `(fingerprint_hash, user, database)` as the cache key. Two queries with the same fingerprint hash but different RLS rewrite rules will return the same cached result.
**Current behavior**: Cache lookup (Layer 2.5) happens AFTER parse+analyze but BEFORE policy evaluation (Layer 4), RLS rewriting (Layer 4.5), and execution.
**Risk**: User A with `tenant_id=1` gets cached result from User B with `tenant_id=2` if they share the same fingerprint hash, username pattern, and database.
**Audit**: Should the cache key include `user_attributes` (RLS context) to prevent cross-tenant data leakage?

### Q4. Cache Hit — Skipped Security Layers
**Question**: On a cache hit, the pipeline skips: injection detection (3.5), anomaly detection (3.7), policy evaluation (4), DDL interception (4.1), query rewriting (4.5), cost estimation (4.8), and execution (5).
**Risk**: A query that was allowed yesterday (and cached) continues to serve results even after a policy change blocks it.
**Audit**: Should cache invalidation happen on policy reload? Currently only DDL and write operations invalidate the cache.

### Q5. Masking Before Classification — Correct Order?
**Question**: The pipeline runs masking (Layer 5.6) BEFORE classification (Layer 6). This means classification runs on masked data.
**Current behavior**: Comment in code says "runs on masked data — won't double-report PII". This means if `email` is masked to `a***@example.com`, the pattern classifier won't detect it as PII.
**Audit**: Is this the correct behavior? Should classification see the raw data to accurately report PII exposure, even if the response is masked? Lineage tracking depends on classification results.

### Q6. Lineage Table Attribution
**Question**: When recording lineage for a classified column, the code assigns it to `source_tables[0].table` — always the first table.
**Code**: `pipeline.cpp:671` — `event.table = ctx.analysis.source_tables[0].table`
**Risk**: In a JOIN query `SELECT c.email, o.total FROM customers c JOIN orders o`, the `email` column would be attributed to `customers` (correct), but `total` would also be attributed to `customers` (wrong — it's from `orders`).
**Audit**: Should lineage use the column-to-table mapping from analysis projections instead?

### Q7. Anomaly Detection — Check Then Record Race
**Question**: Anomaly detection does `check()` (read-only) then `record()` (write). Between these two calls on one thread, another thread's `check()` might not see the first thread's data yet.
**Current behavior**: This is by design — check uses shared_lock, record uses unique_lock. The race is acceptable because anomaly detection is informational only (never blocks).
**Audit**: Confirm this is documented as eventual-consistency behavior.

### Q8. Policy Evaluation — Multi-Table ALL-Must-Pass
**Question**: For multi-table queries, ALL tables must be ALLOWED. A query `SELECT * FROM customers JOIN orders` fails if either table is denied.
**Risk**: A user with access to `customers` but not `orders` gets ACCESS_DENIED on the entire query, with no indication of which table caused the denial.
**Audit**: Does the error message specify which table was denied? Is there a way to allow partial results?

### Q9. Circuit Breaker — HALF_OPEN Thundering Herd
**Question**: When the circuit breaker transitions from OPEN to HALF_OPEN, it allows "1 probe request" (`half_open_max_calls`).
**Risk**: If many requests arrive simultaneously at the OPEN→HALF_OPEN transition, do they all try to probe?
**Audit**: Is there an atomic guard that ensures only `half_open_max_calls` requests actually execute in HALF_OPEN state?

### Q10. Shutdown — Audit Completeness
**Question**: On graceful shutdown, the sequence is: stop accepting → drain in-flight → stop server. But the audit writer thread runs independently.
**Risk**: In-flight requests that complete during drain write audit records to the ring buffer. If the audit writer thread stops before draining the ring buffer, the last batch of audit records is lost.
**Audit**: Does the shutdown sequence flush the audit ring buffer before exiting? Is there a `audit_emitter->flush()` call?

---

## Part 3: Performance Verification Questions

### P1. Single Timestamp — Clock Read Amortization
**Question**: The rate limiter now reads `steady_clock::now()` once and passes `now_ns` to all 4 `try_acquire_at()` calls.
**Audit**: Over a ~120ns window (time for 4 CAS operations), is the same timestamp accurate enough? Could a bucket appear to have negative elapsed time if checked later with a fresher timestamp?
**Answer**: No — the timestamp is used for refill calculation. Using a slightly stale timestamp means slightly fewer refill tokens, which is conservative (safe). This is correct.

### P2. Integer Arithmetic Overflow in Token Refill
**Question**: The refill calculation is `elapsed_ns * tokens_per_second / 1'000'000'000LL`.
**Risk**: `elapsed_ns * tokens_per_second` can overflow `int64_t` if elapsed > 18 seconds at 50K TPS (`18e9 * 50000 = 9e14`, well within `int64_t` range of `9.2e18`). But at higher TPS or longer idle periods?
**Audit**: What's the maximum safe combination? With `tokens_per_second = 1'000'000` and `elapsed_ns = 1 hour (3.6e12)`: `3.6e12 * 1e6 = 3.6e18` — still within `int64_t`. Safe up to ~2.5 hours at 1M TPS.

### P3. Parse Cache — Shard Contention
**Question**: The parse cache uses 16 shards with per-shard mutex (not shared_mutex).
**Risk**: On a 32-core machine with 50K req/sec, each shard handles ~3,125 req/sec. With mutex hold time of ~500ns (LRU lookup), contention probability is `3125 * 500e-9 ≈ 0.16%` — very low.
**Audit**: Is 16 shards optimal? Could we benefit from more shards at higher throughput, or is the overhead not worth it?

### P4. Policy Engine — RCU Read Path
**Question**: The policy engine uses `atomic_load(store_)` for lock-free reads during evaluation.
**Audit**: Does `atomic_load` on `shared_ptr` use a spinlock internally on this platform (GCC/libstdc++)? If so, under extreme contention (100K req/sec), could this become a bottleneck?
**Note**: In C++20, `std::atomic<std::shared_ptr>` is standard, but older implementations may use a global spinlock for `atomic_load` on `shared_ptr`.

### P5. Audit Ring Buffer — 65536 Slots Sizing
**Question**: The ring buffer has 65536 slots. At 50K req/sec with 100ms drain interval, up to 5000 records accumulate per drain cycle.
**Audit**: The buffer can hold ~13 drain cycles before overflow. Is this sufficient headroom for I/O stalls? What happens if the filesystem blocks for 2+ seconds (e.g., NFS hang)?

### P6. Connection Pool — Health Check on Every Acquire?
**Question**: The pool performs `SELECT 1` health check when reusing an idle connection.
**Risk**: At high throughput, this adds one round-trip per connection reuse. If most connections are active (not idle), this is rare. But during low-traffic periods when connections go idle, every request pays the health check cost.
**Audit**: Should there be a "recently checked" optimization (skip health check if connection was used within N seconds)?

### P7. Fingerprinter — Constexpr Lookup Table vs Locale
**Question**: The fingerprinter now uses a constexpr 256-byte `CharTable` for character classification, replacing `std::tolower`/`std::isdigit`.
**Audit**: This assumes ASCII input. Is this safe for UTF-8 SQL? PostgreSQL identifiers can contain multibyte characters. The fingerprinter only needs to normalize for caching — is ASCII normalization sufficient for cache key uniqueness?

### P8. Classifier — Sample Size of 20 Rows
**Question**: Pattern-based classification samples up to 20 rows for PII detection.
**Risk**: If PII appears only in row 21+, it won't be detected. Is 20 a good balance between accuracy and performance?
**Audit**: What percentage of real-world queries have PII appearing after row 20? Should this be configurable?

---

## Part 4: Architectural Decision Verification

### A1. Single-Process Architecture
**Decision**: Everything runs in one process — HTTP, wire protocol, binary RPC, audit writer, rate limiter cleanup, config watcher, alert evaluator, schema drift detector, adaptive rate controller.
**Trade-off**: Simple deployment (single binary) vs. blast radius (crash kills everything).
**Audit**: Is there any component whose failure should NOT bring down the entire proxy? (e.g., dashboard crash shouldn't block queries)

### A2. No Connection Pool per Database
**Decision**: Currently one pool per database, but `main.cpp` only creates one pool for `databases[0]`.
**Risk**: If multiple `[[databases]]` sections are configured, only the first gets a pool. The `DatabaseRouter` exists but is only used when explicitly configured.
**Audit**: Is multi-database routing fully implemented and tested?

### A3. JSON Building Without Library
**Decision**: All JSON responses are built via `std::format` + string concatenation rather than using a JSON library (nlohmann_json, rapidjson).
**Trade-off**: Zero allocation overhead for simple responses vs. risk of malformed JSON if field values contain special characters (`"`, `\`, etc.).
**Audit**: Are user-provided strings (usernames, SQL, error messages) properly escaped before embedding in JSON? The `parse_json_field` function also doesn't handle escaped quotes.

### A4. Hot-Reload via ConfigWatcher (File Polling)
**Decision**: Config watcher polls the file every N seconds rather than using inotify/fsnotify.
**Trade-off**: Cross-platform compatibility vs. up to N seconds delay in config changes.
**Audit**: Is there a race condition if the file is partially written when the watcher reads it? (TOML parser should fail cleanly, but does it retry or just skip?)

### A5. Audit Integrity — Hash Chain
**Decision**: Audit records have `integrity_enabled = true` with SHA-256 hash chain.
**Audit**: Is the hash chain actually computed and verified? The `AuditConfig` has the fields, but is the implementation complete?

### A6. Key Manager — LocalKeyManager File Format
**Decision**: Keys are stored in a plaintext file (`key_id:hex_key:active`).
**Risk**: Private keys in plaintext on disk. The Vault and Env providers exist as alternatives.
**Audit**: Is the local key file permission-checked (e.g., 0600)? Is there a warning when using local key manager in production?

### A7. Feature Flags — Route vs Component Gating
**Decision**: Feature flags gate both routes (in `http_server.cpp`) AND component creation (in `main.cpp`).
**Audit**: Are all feature flags consistently applied? For example, if `classification = false`, is the classifier NOT created AND the `/compliance/pii-report` route NOT registered?

### A8. Thread Safety — Global Pointers in Signal Handler
**Decision**: `signal_handler()` accesses global `shared_ptr`s without synchronization.
**Risk**: The signal handler runs asynchronously. If a signal arrives during `main()` initialization (before pointers are fully constructed), we get undefined behavior.
**Audit**: Should signal handlers be deferred until after full initialization? (Register SIGINT/SIGTERM handlers after all components are ready)

### A9. Tenant Manager — Component Swapping
**Decision**: Tenant resolution happens at the start of `Pipeline::execute()` and can swap `policy_engine`, `rate_limiter`, and `audit_emitter` to per-tenant instances.
**Audit**: Are per-tenant components fully isolated? Can a per-tenant rate limiter's bucket leak into the global rate limiter's stats?

### A10. Retry on DATABASE_ERROR — Idempotency
**Decision**: The pipeline retries on `DATABASE_ERROR` with exponential backoff.
**Risk**: If the failed query was a non-idempotent write (`INSERT`), retrying could cause duplicate data.
**Current behavior**: Retry happens for ALL statement types that fail with DATABASE_ERROR.
**Audit**: Should retry be limited to SELECT queries only, or to queries marked as idempotent?

---

## Part 5: Completeness Checklist

### Pipeline Layer Execution Order (from code)

```
1.   Rate Limiting                  → can block (429)
2.   Parse + Cache                  → can block (400)
3.   Analyze                        → can block
2.5  Result Cache Lookup            → short-circuit on hit
3.5  SQL Injection Detection        → can block (403)
3.7  Anomaly Detection              → informational only
4.   Policy Evaluation              → can block (403)
4.1  Schema DDL Interception        → can block (403)
4.5  Query Rewriting (RLS)          → modifies SQL
4.8  Query Cost Estimation          → can block (403)
---  Dry-run check                  → returns early if dry_run=true
5.   Execute                        → with retry on DATABASE_ERROR
---  Adaptive Rate Controller       → observe latency
5.01 Slow Query Tracking            → record if slow
5.02 Parse Cache DDL Invalidation   → invalidate on DDL
5.05 Result Cache Store             → cache successful SELECTs
---  Write-invalidation             → clear cache for modified DB
5.1  Schema Change Recording        → record DDL
5.3  Column Decryption              → transparent
5.5  Column-level ACL + Mask        → remove blocked columns
5.6  Data Masking                   → mask values in-place
6.   Classification                 → PII detection (on masked data)
6.5  Lineage Tracking               → record PII access
---  Build Response                 → before audit (non-blocking)
7.   Audit                          → async ring buffer push
```

### Background Threads
```
1. HTTP Worker Threads      (cpp-httplib pool)
2. Audit Writer Thread      (single, drain ring buffer)
3. Rate Limiter Cleanup     (single, evict idle buckets)
4. Config Watcher           (single, poll config file)
5. Alert Evaluator          (single, periodic rule check)
6. Schema Drift Detector    (single, periodic schema check)
7. Adaptive Rate Controller (single, periodic adjustment)
8. Wire Protocol Threads    (pool, PostgreSQL v3)
9. Binary RPC Threads       (pool, custom protocol)
```

### Signal/Shutdown Sequence
```
SIGINT/SIGTERM received
  → ShutdownCoordinator::initiate_shutdown()    (stop accepting)
  → AdaptiveRateController::stop()
  → SchemaDriftDetector::stop()
  → AlertEvaluator::stop()
  → ConfigWatcher::stop()
  → WireServer::stop()
  → BinaryRpcServer::stop()
  → ShutdownCoordinator::wait_for_drain()       (wait for in-flight)
  → HttpServer::stop()
  → exit(0)
```
