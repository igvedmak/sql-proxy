# SQL Proxy - Complete System Flow Diagram

## High-Level Architecture

```
                              ┌─────────────────────────────────┐
                              │         CLIENT APPLICATION       │
                              │   POST /api/v1/query             │
                              │   { "user", "sql", "database" }  │
                              └───────────────┬─────────────────┘
                                              │ HTTP / PG Wire / Binary RPC
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          HTTP SERVER (cpp-httplib)                           │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Core Endpoints:                                                      │   │
│  │  POST /api/v1/query          → Query execution pipeline              │   │
│  │  POST /api/v1/query/dry-run  → Policy check without execution        │   │
│  │  GET  /health                → Shallow/deep/readiness health check   │   │
│  │  GET  /metrics               → Prometheus metrics (60+ metrics)      │   │
│  │  GET  /openapi.json          → OpenAPI 3.0 spec                      │   │
│  │  GET  /api/docs              → Swagger UI                            │   │
│  │                                                                      │   │
│  │ Admin Endpoints:                                                     │   │
│  │  POST /policies/reload       → Hot-reload policies from TOML         │   │
│  │  POST /api/v1/config/validate→ Validate TOML config                  │   │
│  │  GET  /api/v1/slow-queries   → Recent slow queries                   │   │
│  │  GET  /api/v1/circuit-breakers → Circuit breaker state/events        │   │
│  │                                                                      │   │
│  │ Compliance Endpoints:                                                │   │
│  │  GET  /api/v1/compliance/pii-report       → PII access report        │   │
│  │  GET  /api/v1/compliance/security-summary → Security overview        │   │
│  │  GET  /api/v1/compliance/lineage          → Data lineage summaries   │   │
│  │  GET  /api/v1/compliance/data-subject-access → GDPR subject access   │   │
│  │                                                                      │   │
│  │ Schema Endpoints:                                                    │   │
│  │  GET  /api/v1/schema/history → DDL change history                    │   │
│  │  GET  /api/v1/schema/pending → Pending DDL approvals                 │   │
│  │  POST /api/v1/schema/approve → Approve pending DDL                   │   │
│  │  POST /api/v1/schema/reject  → Reject pending DDL                    │   │
│  │  GET  /api/v1/schema/drift   → Schema drift events                   │   │
│  │                                                                      │   │
│  │ Optional Endpoints:                                                  │   │
│  │  POST /api/v1/graphql        → GraphQL-to-SQL (queries + mutations)  │   │
│  │  POST /api/v1/plugins/reload → Hot-reload .so plugins at runtime    │   │
│  │  GET  /dashboard             → Admin web UI (HTML)                   │   │
│  │  GET  /dashboard/api/stats   → Real-time stats JSON                  │   │
│  │  GET  /dashboard/api/policies→ Policy listing                        │   │
│  │  GET  /dashboard/api/users   → User listing                          │   │
│  │  GET  /dashboard/api/alerts  → Active/historical alerts              │   │
│  │  GET  /dashboard/api/metrics/stream → SSE metrics stream             │   │
│  │                                                                      │   │
│  │ Distributed Rate Limiting:                                           │   │
│  │  GET  /api/v1/distributed-rate-limits → Cluster rate limit stats     │   │
│  │                                                                      │   │
│  │ WebSocket Streaming:                                                 │   │
│  │  GET  /api/v1/stream         → RFC 6455 WebSocket upgrade            │   │
│  │                                                                      │   │
│  │ Multi-Database Transactions:                                         │   │
│  │  POST /api/v1/transactions/begin   → Begin 2PC transaction           │   │
│  │  POST /api/v1/transactions/prepare → Phase 1: prepare                │   │
│  │  POST /api/v1/transactions/commit  → Phase 2: commit                 │   │
│  │  POST /api/v1/transactions/rollback→ Rollback                        │   │
│  │  GET  /api/v1/transactions/:xid    → Transaction status              │   │
│  │                                                                      │   │
│  │ LLM-Powered Features:                                                │   │
│  │  POST /api/v1/llm/generate-policy  → AI policy from query samples    │   │
│  │  POST /api/v1/llm/explain-anomaly  → AI anomaly explanation          │   │
│  │  POST /api/v1/llm/nl-to-policy    → Natural language → TOML policy   │   │
│  │  POST /api/v1/llm/classify-intent → AI SQL intent classification     │   │
│  │  POST /api/v1/nl-query            → Natural language to SQL + execute  │   │
│  │                                                                      │   │
│  │ Data Catalog:                                                          │   │
│  │  GET  /api/v1/catalog/tables      → List cataloged tables             │   │
│  │  GET  /api/v1/catalog/tables/:n/columns → Column details (PII, type)  │   │
│  │  GET  /api/v1/catalog/search      → Search by PII type or text        │   │
│  │  GET  /api/v1/catalog/stats       → Aggregate catalog statistics      │   │
│  │                                                                      │   │
│  │ Policy Simulator:                                                      │   │
│  │  POST /api/v1/admin/policies/simulate → Dry-run policies vs audit log │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Feature Flags (config-driven route gating):                                │
│  ┌─ dry_run, openapi, swagger_ui, metrics, slow_query, schema_drift,       │
│  │  classification, injection_detection, lineage_tracking, masking,         │
│  │  dashboard, distributed_rate_limiting, websocket_streaming,              │
│  └─ multi_db_transactions, llm_features, data_catalog, policy_simulator    │
│                                                                              │
│  Request Validation:                                                         │
│  ┌─ Graceful shutdown check ─────────── DRAINING → 503 Server shutting down │
│  ├─ Content-Type: application/json? ──── NO ──→ 400 Bad Request             │
│  ├─ Body has valid JSON? ──────────────── NO ──→ 400 Bad Request             │
│  ├─ "sql" field present? ──────────────── NO ──→ 400 Missing sql             │
│  ├─ SQL length < max_sql_length? ──────── NO ──→ 400 SQL too long            │
│  ├─ Brute force check (IP/user)? ─────── BLOCKED → 429 + Retry-After        │
│  ├─ User authenticated? ──────────────── NO ──→ 401 (+ record_failure)       │
│  │   (API key, JWT HMAC, LDAP, or OIDC/OAuth2 — RS256/ES256 JWT via JWKS)   │
│  ├─ IP allowlist check? ─────────────── BLOCKED → 403 IP not allowed         │
│  └─ record_success on auth pass                                              │
│                                                                              │
│  Build ProxyRequest:                                                         │
│  ├─ request_id    = UUID                                                     │
│  ├─ user          = from auth (API key → username, or JSON "user")           │
│  ├─ roles         = from UserInfo (resolved by validate_user)                │
│  ├─ sql           = from JSON                                                │
│  ├─ database      = from JSON (fallback: user.default_database, "testdb")    │
│  ├─ source_ip     = X-Forwarded-For (first IP) or remote_addr               │
│  ├─ traceparent   = W3C trace propagation header                             │
│  ├─ tracestate    = W3C trace state header                                   │
│  └─ priority      = from JSON "priority" field (LOW/NORMAL/HIGH/CRITICAL)    │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     PIPELINE ORCHESTRATOR (pipeline.cpp)                      │
│                                                                              │
│  Creates RequestContext (carries state through all layers):                  │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │ RequestContext {                                                   │       │
│  │   // Input                                                        │       │
│  │   request_id, user, roles, database, sql, source_ip               │       │
│  │   user_attributes, tenant_id, priority, dry_run                   │       │
│  │   // W3C Distributed Tracing                                      │       │
│  │   trace_context { trace_id, span_id, parent_span_id, tracestate } │       │
│  │   // Timestamps                                                   │       │
│  │   received_at (system_clock), started_at (steady_clock)           │       │
│  │   // Stage results (populated as pipeline progresses)             │       │
│  │   fingerprint, statement_info, analysis,                          │       │
│  │   policy_result, query_result, classification_result              │       │
│  │   rate_limit_result, injection_result, anomaly_result             │       │
│  │   column_decisions, masking_applied                               │       │
│  │   // Timing breakdown (microseconds)                              │       │
│  │   parse_time, policy_time, execution_time, classification_time    │       │
│  │   column_policy_time, masking_time, injection_check_time          │       │
│  │   // Flags                                                        │       │
│  │   cache_hit, rate_limited, sql_rewritten, ddl_requires_approval   │       │
│  │   // Tracing spans (ScopedSpan per layer)                         │       │
│  │   spans: vector<SpanRecord>                                       │       │
│  │ }                                                                 │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                              │
│  Tenant Resolution (if multi-tenant enabled):                               │
│  ├─ TenantManager::resolve(tenant_id) → per-tenant overrides               │
│  └─ Can swap: policy_engine, rate_limiter, audit_emitter                    │
│                                                                              │
│  Sequential layer execution with short-circuit on failure:                   │
│                                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│  │ Layer 1 │─▶│ Layer 2 │─▶│ Layer 3 │─▶│Lay 2.5  │─▶│Layer3.5 │──┐       │
│  │  RATE   │  │  PARSE  │  │ ANALYZE │  │ RESULT  │  │  SQLI   │  │       │
│  │  LIMIT  │  │ + CACHE │  │         │  │ CACHE?  │  │ DETECT  │  │       │
│  └────┬────┘  └────┬────┘  └─────────┘  └────┬────┘  └────┬────┘  │       │
│       │FAIL        │FAIL                     │HIT         │BLOCK  │       │
│       ▼            ▼                         ▼            ▼       │       │
│   ┌───────┐   ┌───────┐               ┌──────────┐  ┌───────┐    │       │
│   │ AUDIT │   │ AUDIT │               │ CLASSIFY │  │ AUDIT │    │       │
│   │ + RES │   │ + RES │               │ LINEAGE  │  │ + RES │    │PASS   │
│   └───────┘   └───────┘               │ AUDIT+RES│  └───────┘    │       │
│                                        └──────────┘               │       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐│       │
│  │Layer3.7 │─▶│ Layer 4 │─▶│Lay 4.1  │─▶│Lay 4.5  │─▶│Lay 4.8  ││       │
│  │ ANOMALY │  │ POLICY  │  │ DDL     │  │ QUERY   │  │ QUERY   │◀┘       │
│  │ (info)  │  │         │  │INTERCEPT│  │ REWRITE │  │ COST    │         │
│  └─────────┘  └────┬────┘  └────┬────┘  └─────────┘  └────┬────┘         │
│                    │FAIL        │FAIL                      │FAIL          │
│                    ▼            ▼                          ▼              │
│               ┌───────┐   ┌───────┐                  ┌───────┐           │
│               │ AUDIT │   │ AUDIT │                  │ AUDIT │           │
│               │ + RES │   │ + RES │                  │ + RES │           │
│               └───────┘   └───────┘                  └───────┘           │
│                                                                          │
│  ── DRY-RUN CHECK: if ctx.dry_run → skip execution, audit + respond ──  │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │ Layer 5  │─▶│Lay 5.01  │─▶│Lay 5.02  │─▶│Lay 5.05  │──┐              │
│  │ EXECUTE  │  │ SLOW Q   │  │ DDL INVAL│  │ RESULT   │  │              │
│  │(+RETRY)  │  │ TRACK    │  │ CACHE    │  │ CACHE    │  │              │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │              │
│                                                           ▼              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │Layer 5.3 │─▶│Layer 5.5 │─▶│Layer 5.6 │─▶│ Layer 6  │──┐              │
│  │ DECRYPT  │  │ COL ACL  │  │ MASKING  │  │ CLASSIFY │  │              │
│  │ COLUMNS  │  │ (remove) │  │(in-place)│  │          │  │              │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │              │
│                                                           ▼              │
│                                              ┌──────────────────────┐    │
│                                              │ Layer 6.1: CATALOG   │    │
│                                              │ Layer 6.5: LINEAGE   │    │
│                                              │ Layer 7:  AUDIT      │    │
│                                              │ BUILD RESPONSE       │    │
│                                              │ (+ gzip compression) │    │
│                                              └──────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer-by-Layer Detail

### Layer 1: Rate Limiting (Ingress Gate)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: HIERARCHICAL RATE LIMITER                                          │
│  Class: HierarchicalRateLimiter (+ optional WaitableRateLimiter queue)      │
│  Performance: ~48ns for all 4 checks (single timestamp amortization)        │
│                                                                              │
│  Optional request queuing (WaitableRateLimiter):                            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If queue_enabled: rejected requests wait up to queue_timeout_ms     │     │
│  │ before failing. Max queue depth configurable. Prevents burst drops. │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  4 levels - ALL must pass:                                                   │
│                                                                              │
│  ┌────────────────────┐                                                      │
│  │ Level 1: GLOBAL    │  Protects proxy CPU                                  │
│  │ 50K tokens/sec     │  Single TokenBucket for entire proxy                 │
│  │ ~12ns (CAS loop)   │───── FAIL? ──→ { rate_limited=true, level="global" } │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 2: PER-USER  │  Prevents one user starving others                   │
│  │ 1K tokens/sec      │  TokenBucket per username                            │
│  │ ~12ns (shared_lock │───── FAIL? ──→ { rate_limited=true, level="user" }   │
│  │  + CAS)            │                                                      │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 3: PER-DB    │  Protects each database independently                │
│  │ 30K tokens/sec     │  TokenBucket per database name                       │
│  │ ~12ns              │───── FAIL? ──→ { rate_limited=true, level="db" }     │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 4: USER+DB   │  Most specific control                               │
│  │ 100 tokens/sec     │  TokenBucket per "user:database" key                 │
│  │ ~12ns              │───── FAIL? ──→ { rate_limited=true, level="user_db" }│
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│           ▼                                                                  │
│  { allowed=true, tokens_remaining=N }                                        │
│                                                                              │
│  Token Bucket Algorithm (lock-free, integer arithmetic):                     │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ State: tokens_ (atomic<uint32_t>) + last_refill_ns_ (atomic<int64>)│     │
│  │                                                                     │     │
│  │ try_acquire_at(now_ns, 1):  // timestamp passed from check()        │     │
│  │   loop (max 8 retries) {                                            │     │
│  │     current_tokens = tokens_.load()                                 │     │
│  │     last_refill = last_refill_ns_.load()                            │     │
│  │     elapsed_ns = now_ns - last_refill                               │     │
│  │     raw_tokens = elapsed_ns * tps / 1'000'000'000LL  // integer!    │     │
│  │     new_tokens = min(current + raw_tokens, burst) - 1               │     │
│  │     if (new_tokens < 0) return false  // Rate limited               │     │
│  │     if (tokens_.CAS(current, new_tokens)) {                         │     │
│  │       last_refill_ns_.store(now_ns)                                 │     │
│  │       return true                                                   │     │
│  │     }                                                               │     │
│  │   }  // Retry on CAS failure                                        │     │
│  │                                                                     │     │
│  │ check() reads steady_clock::now() ONCE for all 4 levels             │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Bucket Management:                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ std::shared_mutex for bucket map (reader-writer lock)               │     │
│  │                                                                     │     │
│  │ Hot path (bucket exists): shared_lock → O(1) lookup → ~30ns        │     │
│  │ Cold path (new bucket):   double-checked locking                    │     │
│  │   1. shared_lock → lookup → miss                                    │     │
│  │   2. unique_lock → try_emplace → create if needed                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Adaptive Rate Controller (optional, background thread):                    │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Observes P95 execution latency from Pipeline                        │     │
│  │ Adjusts global TPS every adjustment_interval_seconds:               │     │
│  │   P95 < latency_target_ms  → increase TPS (+10%, up to base)       │     │
│  │   P95 > throttle_threshold → throttle to 40% of base TPS           │     │
│  │   P95 > 2x throttle       → protect mode: 10% of base TPS         │     │
│  │ Metrics: current_tps, p95_us, adjustments, throttle/protect events │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Bucket Cleanup (background thread):                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Cleanup thread runs every cleanup_interval_seconds (default: 60)    │     │
│  │ For each bucket map (user, db, user_db):                            │     │
│  │   unique_lock → erase_if: now_ns - last_access > idle_timeout_ns    │     │
│  │ Metrics: buckets_active, buckets_evicted_total                      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 2: Parse + Cache

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 2: SQL PARSING + CACHING                                              │
│  Classes: SQLParser + Fingerprinter + ParseCache                             │
│                                                                              │
│  Input: ctx.sql (raw SQL string)                                             │
│                                                                              │
│  Step 1: FINGERPRINTING (single-pass, constexpr lookup table, ~280ns)        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Fingerprinter::fingerprint(sql):                                    │     │
│  │                                                                     │     │
│  │ Uses constexpr 256-byte CharTable for character classification:     │     │
│  │   table[c] → ALPHA | DIGIT | SPACE | QUOTE | COMMENT | OTHER       │     │
│  │ Replaces locale-dependent std::tolower/std::isdigit calls           │     │
│  │                                                                     │     │
│  │ "SELECT * FROM users WHERE id = 42 /* admin */"                     │     │
│  │                          ↓                                          │     │
│  │ 1. Strip comments:  "SELECT * FROM users WHERE id = 42"             │     │
│  │ 2. Normalize case:  "select * from users where id = 42"             │     │
│  │ 3. Replace numbers: "select * from users where id = ?"              │     │
│  │ 4. Replace strings: (any 'literal' → ?)                             │     │
│  │ 5. Collapse IN:     IN(1,2,3) → IN(?)                              │     │
│  │ 6. Collapse spaces: "select * from users where id = ?"             │     │
│  │ 7. xxHash64:        0xA3F2B1... (64-bit hash)                      │     │
│  │                                                                     │     │
│  │ Output: QueryFingerprint { hash: uint64, normalized: string }       │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Step 2: CACHE LOOKUP (~500ns on hit)                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ ParseCache: 16 shards x 625 entries = 10,000 total                  │     │
│  │                                                                     │     │
│  │ shard = hash % 16                                                   │     │
│  │ shard[shard].mutex.lock()                                           │     │
│  │ LRU lookup by hash + collision guard (compare normalized string)    │     │
│  │                                                                     │     │
│  │ ┌─────────┐ ┌─────────┐     ┌─────────┐                            │     │
│  │ │ Shard 0 │ │ Shard 1 │ ... │Shard 15 │  ← Per-shard mutex         │     │
│  │ │ LRU Map │ │ LRU Map │     │ LRU Map │  ← Low contention          │     │
│  │ └─────────┘ └─────────┘     └─────────┘                            │     │
│  │                                                                     │     │
│  │ HIT  → Return cached StatementInfo (skip libpg_query)              │     │
│  │ MISS → Continue to Step 3                                           │     │
│  │                                                                     │     │
│  │ DDL Invalidation (Layer 5.02):                                      │     │
│  │   On successful DDL → invalidate_table(ddl_object_name)             │     │
│  │   Scans all shards, removes entries referencing affected table       │     │
│  │   Metric: sql_proxy_cache_ddl_invalidations_total                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Step 3: libpg_query PARSE (~50μs on miss)                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ PostgreSQL's actual SQL parser (extracted as C library)              │     │
│  │                                                                     │     │
│  │ pg_query_parse(sql)                                                 │     │
│  │   ├─ On error → ParseResult::error(SYNTAX_ERROR, message)           │     │
│  │   └─ On success:                                                    │     │
│  │       ├─ extract_statement_type() → StatementType enum              │     │
│  │       │   (O(1) hash map lookup: "SelectStmt"→SELECT, etc.)         │     │
│  │       ├─ extract_tables() → vector<TableRef>                        │     │
│  │       └─ Store in cache for next time                               │     │
│  │                                                                     │     │
│  │ Database routing: resolves parser per-database via DatabaseRouter    │     │
│  │                                                                     │     │
│  │ Output → StatementInfo:                                             │     │
│  │   { fingerprint, parsed: { type, tables, columns, is_write } }      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Written to ctx: statement_info, fingerprint, parse_time                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 3: Analyze

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 3: SQL ANALYSIS                                                       │
│  Class: SQLAnalyzer (static methods)                                         │
│                                                                              │
│  Input: ctx.statement_info.parsed (ParsedQuery from Layer 2)                 │
│                                                                              │
│  SQLAnalyzer::analyze(parsed_query, parse_tree) → AnalysisResult:            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ AnalysisResult {                                                    │     │
│  │   statement_type: SELECT | INSERT | UPDATE | DELETE | DDL | ...      │     │
│  │                                                                     │     │
│  │   source_tables: [TableRef]   // Tables being READ FROM             │     │
│  │     (FROM clause, JOIN tables)                                      │     │
│  │                                                                     │     │
│  │   target_tables: [TableRef]   // Tables being WRITTEN TO            │     │
│  │     (INSERT INTO, UPDATE, DELETE FROM targets)                      │     │
│  │                                                                     │     │
│  │   projections: [ProjectionColumn]  // SELECT list                   │     │
│  │     { name, alias, derived_from: [source_column], is_function }     │     │
│  │                                                                     │     │
│  │   filter_columns: [ColumnRef]   // WHERE + JOIN ON columns          │     │
│  │   write_columns: [ColumnRef]    // INSERT cols, UPDATE SET cols      │     │
│  │                                                                     │     │
│  │   query_characteristics:                                            │     │
│  │     { has_join, has_subquery, has_aggregation, limit_value }         │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Written to ctx: analysis                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 2.5: Result Cache Lookup

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 2.5: RESULT CACHE LOOKUP (Short-circuit on hit)                       │
│  Class: ResultCache (16 shards, LRU, configurable TTL)                      │
│                                                                              │
│  Only for SELECT queries with a valid fingerprint.                          │
│                                                                              │
│  Cache key: (fingerprint_hash, user, database)                              │
│                                                                              │
│  HIT → skip Layers 3.5 through 5.05, jump to:                              │
│    classify_results() → record_lineage() → emit_audit() → respond           │
│                                                                              │
│  MISS → continue to Layer 3.5                                               │
│                                                                              │
│  Write-back: After successful execution (Layer 5.05)                        │
│  Write-invalidation: DML/DDL on same database clears that DB's entries      │
│                                                                              │
│  Config: max_entries, num_shards, ttl_seconds, max_result_size_bytes        │
│  Metrics: sql_proxy_cache_hits_total, cache_misses_total,                   │
│           cache_entries, cache_evictions_total                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 3.5: SQL Injection Detection

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 3.5: SQL INJECTION DETECTION (Security Gate)                          │
│  Class: SqlInjectionDetector                                                 │
│                                                                              │
│  Input: ctx.sql (raw SQL), ctx.statement_info.fingerprint.normalized,        │
│         ctx.statement_info.parsed (ParsedQuery)                              │
│                                                                              │
│  6 DETECTION CHECKS (hand-rolled, no regex):                                │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 1. TAUTOLOGY DETECTION (HIGH)                        │           │     │
│  │  │    1=1, 'a'='a', OR true, 1<>2, ''=''                │           │     │
│  │  │    Score: 0.7                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 2. UNION INJECTION (CRITICAL)                        │           │     │
│  │  │    UNION SELECT, UNION ALL SELECT                     │           │     │
│  │  │    Score: 1.0                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 3. COMMENT BYPASS (MEDIUM)                           │           │     │
│  │  │    Inline --, /* mid-statement                        │           │     │
│  │  │    Score: 0.4                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 4. STACKED QUERIES (HIGH)                            │           │     │
│  │  │    Multiple ; separated statements                    │           │     │
│  │  │    Score: 0.7                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 5. TIME-BASED BLIND (HIGH)                           │           │     │
│  │  │    SLEEP(, pg_sleep(, WAITFOR DELAY                   │           │     │
│  │  │    Score: 0.7                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 6. ERROR-BASED (MEDIUM)                              │           │     │
│  │  │    EXTRACTVALUE, UPDATEXML, CONVERT(                  │           │     │
│  │  │    Score: 0.4                                         │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │                                                                     │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ 7. ENCODING BYPASS (MEDIUM, then re-run 1-6)       │           │     │
│  │  │    URL decode (%27→'), HTML entity (&#39;→')         │           │     │
│  │  │    Double URL decode (%2527→%27→')                   │           │     │
│  │  │    If decoded ≠ raw → flag + re-run all 6 checks    │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │                                                                     │     │
│  │  ThreatLevel: NONE < LOW < MEDIUM < HIGH < CRITICAL               │     │
│  │  Block threshold configurable (default: HIGH)                      │     │
│  │  should_block = threat_level >= block_threshold                    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Output: DetectionResult { threat_level, patterns_matched, should_block }    │
│  BLOCK → ErrorCode::SQLI_BLOCKED (HTTP 403)                                 │
│  Written to ctx: injection_result, injection_check_time                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 3.7: Anomaly Detection

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 3.7: ANOMALY DETECTION (Informational — never blocks)                 │
│  Class: AnomalyDetector + UserProfile                                        │
│                                                                              │
│  Input: ctx.user, analysis.source_tables, fingerprint.hash                   │
│                                                                              │
│  PER-USER BEHAVIORAL PROFILING:                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ UserProfile {                                                       │     │
│  │   total_queries     (atomic<uint64_t>)                              │     │
│  │   window_queries    (atomic<uint64_t>, resets each window)          │     │
│  │   known_tables      (unordered_set<string>)                         │     │
│  │   known_fingerprints(unordered_set<uint64_t>)                       │     │
│  │   hour_distribution (map<int, uint64_t>)                            │     │
│  │   avg/stddev_queries_per_window (rolling stats)                     │     │
│  │ }                                                                   │     │
│  │                                                                     │     │
│  │ Profile management:                                                 │     │
│  │   ├─ Double-checked locking for lazy creation                       │     │
│  │   ├─ shared_mutex for concurrent reads                              │     │
│  │   └─ Window rotation every N minutes (configurable)                 │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  4 ANOMALY SIGNALS:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Signal              │ Condition                   │ Score           │     │
│  │ NEW_TABLE:<name>    │ Table not in known set      │ +0.3            │     │
│  │ NEW_QUERY_PATTERN   │ Fingerprint hash not seen   │ +0.2            │     │
│  │ VOLUME_SPIKE:<Nσ>   │ Z-score > 3σ threshold      │ +0.4            │     │
│  │ UNUSUAL_HOUR:<H>    │ Hour never seen before       │ +0.2            │     │
│  │                                                                     │     │
│  │ is_anomalous = (total_score >= 0.5)                                 │     │
│  │ Score capped at 1.0, signals only after baseline established        │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Two operations per request:                                                │
│  1. check()  — score anomaly (shared_lock, read-only)                       │
│  2. record() — update profile (unique_lock, write)                          │
│                                                                              │
│  Written to ctx: anomaly_result (score + anomalies list)                    │
│  Anomaly data flows to audit record and compliance reporting                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 4: Policy Engine

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 4: POLICY ENGINE (Authorization Gate)                                 │
│  Class: PolicyEngine + PolicyTrie                                            │
│                                                                              │
│  Input: ctx.user, ctx.roles, ctx.database, ctx.analysis                      │
│                                                                              │
│  POLICY STORE (RCU - atomic shared_ptr swap):                                │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ PolicyStore {                                                       │     │
│  │   user_tries:     { "admin" → Trie, "analyst" → Trie }             │     │
│  │   role_tries:     { "readonly" → Trie, "developer" → Trie }        │     │
│  │   wildcard_trie:  Trie (for users=["*"] policies)                   │     │
│  │ }                                                                   │     │
│  │                                                                     │     │
│  │ PolicyTrie (Radix Trie):                                            │     │
│  │   database → schema → table → [Policy list]                         │     │
│  │                                                                     │     │
│  │   "testdb" → "public" → "customers" → [allow_read, block_write]     │     │
│  │                       → "orders"    → [allow_read]                  │     │
│  │                       → "*"         → [block_ddl]                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  EVALUATION ALGORITHM:                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  For EACH table in analysis.source_tables + analysis.target_tables: │     │
│  │  ┌────────────────────────────────────────────────────────────┐     │     │
│  │  │ 1. Collect matching policies from:                         │     │     │
│  │  │    ├─ user_tries[ctx.user]  (exact user match)             │     │     │
│  │  │    ├─ role_tries[role] for each role in ctx.roles           │     │     │
│  │  │    └─ wildcard_trie (users=["*"] policies)                 │     │     │
│  │  │                                                            │     │     │
│  │  │ 2. Filter by:                                              │     │     │
│  │  │    ├─ Statement type matches policy.scope.operations       │     │     │
│  │  │    └─ exclude_roles check (exclude takes precedence)       │     │     │
│  │  │                                                            │     │     │
│  │  │ 3. Resolve by SPECIFICITY (highest wins):                  │     │     │
│  │  │    ├─ table specified:    +100 points                      │     │     │
│  │  │    ├─ schema specified:   +10 points                       │     │     │
│  │  │    └─ database specified: +1 point                         │     │     │
│  │  │                                                            │     │     │
│  │  │ 4. At same specificity: BLOCK > ALLOW                     │     │     │
│  │  │                                                            │     │     │
│  │  │ 5. No matching policies → DEFAULT DENY                    │     │     │
│  │  └────────────────────────────────────────────────────────────┘     │     │
│  │                                                                     │     │
│  │  Multi-table rule:                                                  │     │
│  │  ├─ ALL tables must be ALLOWED                                      │     │
│  │  └─ ANY table DENIED → entire query DENIED                          │     │
│  │                                                                     │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  HOT RELOAD (POST /policies/reload or ConfigWatcher):                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ 1. Build new PolicyStore offline (no locks held)                    │     │
│  │ 2. atomic_store(store_, new_store)  // RCU pointer swap             │     │
│  │ 3. Old store destroyed when last reader finishes                    │     │
│  │ Result: Zero-downtime reload, no request blocked                    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Output: PolicyEvaluationResult { decision, matched_policy, reason }         │
│  Written to ctx: policy_result, policy_time                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 4.1: Schema DDL Interception

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 4.1: SCHEMA DDL INTERCEPTION (Optional gate)                          │
│  Class: SchemaManager                                                        │
│                                                                              │
│  Only runs for DDL statements when SchemaManager is enabled.                │
│                                                                              │
│  If require_approval = true:                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ 1. DDL is stored as "pending" for admin review                      │     │
│  │ 2. Request blocked with "DDL requires approval — submitted"         │     │
│  │ 3. Admin uses POST /api/v1/schema/approve or /reject                │     │
│  │ 4. Approved DDL must be re-submitted to execute                     │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  If require_approval = false:                                               │
│  └─ DDL passes through, recorded in history after execution (Layer 5.1)     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 4.5: Query Rewriting (RLS)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 4.5: QUERY REWRITING (Row-Level Security + Enforce Limit)             │
│  Class: QueryRewriter                                                        │
│                                                                              │
│  Input: ctx.sql, ctx.user, ctx.roles, ctx.database, ctx.user_attributes     │
│                                                                              │
│  Two types of rewrite rules:                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ 1. RLS Rules — inject WHERE clause filters                          │     │
│  │    Rule: { table: "orders", filter: "tenant_id = :tenant_id" }      │     │
│  │    Input:  SELECT * FROM orders                                     │     │
│  │    Output: SELECT * FROM orders WHERE tenant_id = '42'              │     │
│  │    (user_attributes["tenant_id"] → '42')                            │     │
│  │                                                                     │     │
│  │ 2. Rewrite Rules — arbitrary SQL transformations                    │     │
│  │    Rule: { match: "table_name", add_limit: 1000 }                   │     │
│  │    Enforces LIMIT on queries that don't have one                    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  If rewritten: ctx.original_sql saved, ctx.sql_rewritten = true             │
│  Hot-reloadable via ConfigWatcher callback                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 4.8: Query Cost Estimation

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 4.8: QUERY COST ESTIMATION (Blocking gate for expensive queries)      │
│  Class: QueryCostEstimator                                                   │
│                                                                              │
│  Only runs for SELECT statements when estimator is enabled.                 │
│                                                                              │
│  Uses EXPLAIN on real connection pool to get PostgreSQL cost estimate:       │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ CostEstimate {                                                      │     │
│  │   total_cost:      float (planner units)                            │     │
│  │   estimated_rows:  int                                              │     │
│  │   plan_type:       string ("Seq Scan", "Index Scan", etc.)          │     │
│  │   is_rejected():   cost > max_cost OR rows > max_estimated_rows     │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  BLOCK → ErrorCode::QUERY_TOO_EXPENSIVE (HTTP 403)                          │
│  Metrics: sql_proxy_query_cost_rejected_total, estimated_total              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 5: Query Executor

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5: QUERY EXECUTOR                                                     │
│  Classes: GenericQueryExecutor + IConnectionPool + CircuitBreaker            │
│                                                                              │
│  Input: ctx.sql, ctx.analysis.statement_type                                 │
│                                                                              │
│  RETRY WITH EXPONENTIAL BACKOFF (on DATABASE_ERROR):                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ if retry_config.enabled && error == DATABASE_ERROR:                  │     │
│  │   for attempt in 0..max_retries:                                    │     │
│  │     sleep(backoff_ms)  // doubles each attempt                      │     │
│  │     retry execute_query()                                           │     │
│  │     if success: break                                               │     │
│  │     backoff_ms = min(backoff_ms * 2, max_backoff_ms)                │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  CIRCUIT BREAKER (per database, or per tenant:database if multi-tenant):      │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  ┌────────┐   N failures    ┌────────┐   timeout     ┌──────────┐ │     │
│  │  │ CLOSED │ ──────────────→ │  OPEN  │ ─────────────→│HALF_OPEN │ │     │
│  │  │(normal)│ ←────────────── │(reject)│               │ (probe)  │ │     │
│  │  └────────┘   M successes   └────────┘               └──────────┘ │     │
│  │       ▲         in half_open                              │       │     │
│  │       └───────────────────────────────────────────────────┘       │     │
│  │                                                                     │     │
│  │  OPEN state → reject immediately (ErrorCode::CIRCUIT_OPEN, 503)   │     │
│  │  State changes exposed via GET /api/v1/circuit-breakers            │     │
│  │  Per-tenant: CircuitBreakerRegistry keys by "tenant:database"     │     │
│  │  One tenant tripping does NOT affect other tenants                │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  CONNECTION POOL (per database):                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Config: min=2, max=10, timeout=5s, max_lifetime=1hr                 │     │
│  │ Semaphore controls max concurrent connections                       │     │
│  │ Health check: SELECT 1 on idle connections                          │     │
│  │ Max lifetime: recycle connections older than max_lifetime            │     │
│  │ RAII Wrapper: PooledConnection auto-returns on destructor           │     │
│  │ Metrics: pool_acquire_duration_seconds (histogram),                 │     │
│  │          pool_connections_recycled_total                             │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  STATEMENT BRANCHING:                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ stmt_type ─┬─ SELECT ──→ execute_select():                          │     │
│  │            │              SET statement_timeout, PQexec(sql)         │     │
│  │            │              Fetch column_names + column_type_oids      │     │
│  │            │              Fetch all rows → vector<vector<string>>    │     │
│  │            ├─ INSERT ──→ execute_dml():                              │     │
│  │            ├─ UPDATE      PQexec(sql), affected_rows = PQcmdTuples  │     │
│  │            ├─ DELETE                                                 │     │
│  │            └─ DDL ─────→ execute_ddl(): PQexec(sql)                  │     │
│  │                                                                     │     │
│  │ On success → circuit_breaker.record_success()                       │     │
│  │ On failure → circuit_breaker.record_failure()                       │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  POST-EXECUTION (latency reporting):                                        │
│  └─ AdaptiveRateController::observe_latency(execution_time_us)              │
│                                                                              │
│  Output: QueryResult { success, columns, rows, affected_rows, error }        │
│  Written to ctx: query_result, execution_time                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layers 5.01–5.1: Post-Execution Bookkeeping

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  POST-EXECUTION BOOKKEEPING (Layers 5.01 – 5.1)                             │
│                                                                              │
│  Layer 5.01: SLOW QUERY TRACKING                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If execution_time > threshold_ms → store SlowQueryRecord             │     │
│  │ Bounded deque (max N entries), exposed via GET /api/v1/slow-queries  │     │
│  │ Metric: sql_proxy_slow_queries_total                                 │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Layer 5.02: PARSE CACHE DDL INVALIDATION                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If DDL succeeded + has ddl_object_name:                              │     │
│  │   parse_cache->invalidate_table(object_name)                        │     │
│  │ Scans all 16 shards, removes entries referencing the table           │     │
│  │ Metric: sql_proxy_cache_ddl_invalidations_total                     │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Layer 5.05: RESULT CACHE STORE                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If SELECT succeeded + fingerprint exists:                            │     │
│  │   result_cache->put(hash, user, database, query_result)             │     │
│  │                                                                     │     │
│  │ Write-invalidation: DML/DDL on database → invalidate(database)      │     │
│  │ Clears all cached entries for the modified database                  │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Layer 5.1: SCHEMA CHANGE RECORDING                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If DDL succeeded + SchemaManager enabled:                            │     │
│  │   schema_manager->record_change(user, database, table, sql, type)   │     │
│  │ Stores in bounded history, exposed via GET /api/v1/schema/history   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 5.3: Decrypt Encrypted Columns

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5.3: COLUMN DECRYPTION (Transparent)                                  │
│  Class: ColumnEncryptor + IKeyManager                                        │
│                                                                              │
│  Input: ctx.query_result (after execution), ctx.analysis.source_tables       │
│  Only runs when encryption is enabled and query returned results.            │
│                                                                              │
│  ENCRYPTED VALUE FORMAT:                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ ENC:v1:<key_id>:<base64(IV + ciphertext + auth_tag)>               │     │
│  │ Algorithm: AES-256-GCM  |  IV: 12B  |  Tag: 16B  |  Key: 256-bit  │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  KEY MANAGEMENT:                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ IKeyManager (interface): get_active_key(), get_key(id), rotate()    │     │
│  │                                                                     │     │
│  │ Implementations:                                                    │     │
│  │   ├─ LocalKeyManager  (file: key_id:hex_key:active)                 │     │
│  │   ├─ VaultKeyManager  (HashiCorp Vault Transit)                     │     │
│  │   └─ EnvKeyManager    (environment variable)                        │     │
│  │                                                                     │     │
│  │ All thread-safe with shared_mutex                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Config: [encryption] section in proxy.toml                                 │
│  Columns: [[encryption.columns]] database/table/column entries              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 5.5: Column-Level ACL + Layer 5.6: Data Masking

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5.5: COLUMN-LEVEL ACL (Remove blocked columns from result)            │
│  Class: PolicyEngine::evaluate_columns()                                     │
│                                                                              │
│  Evaluates per-column policies: which columns the user may see.             │
│  Blocked columns are REMOVED from: column_names, type_oids, rows            │
│  Surviving column_decisions passed to masking layer.                         │
│                                                                              │
│  LAYER 5.6: DATA MASKING (In-place value masking)                            │
│  Class: MaskingEngine::apply()                                               │
│  Gated by: masking_enabled flag (configurable)                              │
│                                                                              │
│  Masking actions per column_decision:                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ PARTIAL  → "alice@example.com" → "a***@example.com"                 │     │
│  │ HASH     → "alice@example.com" → "sha256:a1b2c3..."                 │     │
│  │ REDACT   → "alice@example.com" → "[REDACTED]"                       │     │
│  │ NONE     → passthrough (no masking)                                  │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Written to ctx: column_decisions, masking_applied                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 6: Classification

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 6: PII CLASSIFICATION (Post-masking)                                  │
│  Class: ClassifierRegistry                                                   │
│                                                                              │
│  Input: ctx.query_result (columns + rows), ctx.analysis (projections)        │
│  Only runs on successful queries with results, AFTER masking.               │
│  (Runs on masked data — won't double-report masked PII)                     │
│                                                                              │
│  4-STRATEGY CHAIN (allocation-free, zero-copy where possible):              │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Strategy 1: COLUMN NAME (90% confidence, ~10ns)                     │     │
│  │   Hash map lookup: "email"→PII_EMAIL, "ssn"→PII_SSN, etc.          │     │
│  │   Uses iequals() for case-insensitive comparison                    │     │
│  │                                                                     │     │
│  │ Strategy 2: TYPE OID (85% confidence, ~5ns)                         │     │
│  │   PostgreSQL type OID → PII type mapping                            │     │
│  │                                                                     │     │
│  │ Strategy 3: PATTERN VALUE (80% confidence, ~100ns)                  │     │
│  │   Sample up to 20 rows, hand-rolled O(n) scanners:                  │     │
│  │   ├─ looks_like_email(), looks_like_phone()                         │     │
│  │   ├─ looks_like_ssn(), looks_like_credit_card()                     │     │
│  │   Uses icontains() for zero-copy substring search                   │     │
│  │                                                                     │     │
│  │ Strategy 4: DERIVED COLUMN (inherited PII)                          │     │
│  │   PII-preserving: UPPER(email) → still PII_EMAIL                    │     │
│  │   PII-destroying: COUNT(email), AVG(salary), MD5(ssn) → NOT PII    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Output: ClassificationResult { column → { type, confidence, strategy } }    │
│  Written to ctx: classification_result, classification_time                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 6.1: Data Catalog

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 6.1: DATA CATALOG (Post-classification)                               │
│  Class: DataCatalog                                                          │
│  Feature-gated: data_catalog_enabled                                         │
│                                                                              │
│  Input: ctx.classification_result, ctx.analysis, ctx.user, ctx.masking       │
│  Only runs when classifications are non-empty                                │
│                                                                              │
│  Upserts table/column metadata from live query traffic:                      │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ CatalogColumn {                                                     │     │
│  │   table, column, data_type, pii_type, confidence, strategy          │     │
│  │   access_count, masked_count, accessing_users                       │     │
│  │   first_seen, last_accessed, is_primary_key, is_nullable            │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Thread safety: std::shared_mutex (unique_lock on writes)                    │
│  Can also be seeded at startup from SchemaCache metadata                     │
│                                                                              │
│  Query API: get_tables(), get_columns(), search_pii(), search(), get_stats() │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 6.5: Data Lineage Tracking

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 6.5: DATA LINEAGE TRACKING (Post-classification)                      │
│  Class: LineageTracker                                                       │
│                                                                              │
│  Input: ctx.classification_result, ctx.user, ctx.analysis                    │
│  Only runs when classifications detected (PII columns accessed)             │
│                                                                              │
│  For EACH classified column, creates a LineageEvent:                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ LineageEvent {                                                      │     │
│  │   timestamp, user, database, table, column                          │     │
│  │   classification: "PII.Email" / "PII.SSN" / ...                     │     │
│  │   access_type: "SELECT" / "UPDATE" / ...                            │     │
│  │   query_fingerprint, was_masked, masking_action                     │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  STORAGE:                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Events:     std::deque<LineageEvent> (bounded, max 100K)            │     │
│  │ Summaries:  unordered_map<column_key, LineageSummary>               │     │
│  │   Per column: total_accesses, masked_accesses, accessing_users      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Thread safety: shared_mutex (reads) / unique_lock (writes)                 │
│                                                                              │
│  API: GET /api/v1/compliance/lineage → summaries JSON                       │
│       GET /api/v1/compliance/data-subject-access?user=X → GDPR access       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 7: Audit

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 7: AUDIT EMITTER (Async, Non-blocking)                                │
│  Class: AuditEmitter + MPSCRingBuffer + AuditSampler + AuditEncryptor       │
│                                                                              │
│  ALWAYS fires - on success AND every failure path                            │
│                                                                              │
│  PRE-EMIT: AUDIT SAMPLING (optional)                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ AuditSampler checks before building the record:                     │     │
│  │   always_log_blocked: true    (always log BLOCK decisions)          │     │
│  │   always_log_writes:  true    (always log INSERT/UPDATE/DELETE)      │     │
│  │   always_log_errors:  true    (always log errors)                   │     │
│  │   select_sample_rate: 0.1     (10% of SELECTs sampled)             │     │
│  │   deterministic:      true    (same fingerprint → same decision)    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  AUDIT RECORD (comprehensive):                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ {                                                                   │     │
│  │   "audit_id": "evt_...",           // UUIDv7 (time-sortable)        │     │
│  │   "trace_id": "...",               // W3C distributed tracing       │     │
│  │   "span_id": "...",                // Current span                  │     │
│  │   "timestamp": "2026-02-07T...",                                    │     │
│  │   "user": "analyst",                                                │     │
│  │   "source_ip": "10.0.0.5",                                         │     │
│  │   "database_name": "testdb",                                        │     │
│  │   "sql": "SELECT email FROM customers",                             │     │
│  │   "fingerprint": { "hash": "0xa3f2...", "normalized": "..." },      │     │
│  │   "statement_type": "SELECT",                                       │     │
│  │   "decision": "ALLOW",                                              │     │
│  │   "matched_policy": "allow_analyst_read",                           │     │
│  │   "shadow_blocked": false,         // Shadow policy mode             │     │
│  │   "execution_success": true,                                        │     │
│  │   "rows_returned": 150,                                             │     │
│  │   "detected_classifications": ["PII.Email"],                        │     │
│  │   "masked_columns": ["email"],                                      │     │
│  │   "sql_rewritten": false,                                           │     │
│  │   "parse_time_us": 12,                                              │     │
│  │   "policy_time_us": 5,                                              │     │
│  │   "execution_time_us": 1200,                                        │     │
│  │   "total_duration_us": 1250,                                        │     │
│  │   "rate_limited": false,                                            │     │
│  │   "cache_hit": true,                                                │     │
│  │   "threat_level": "NONE",                                           │     │
│  │   "injection_patterns": [],                                         │     │
│  │   "anomaly_score": 0.3,                                             │     │
│  │   "anomalies": ["NEW_TABLE:sensitive_data"],                        │     │
│  │   "spans": [{"op":"rate_limit","us":48}, ...],  // Per-layer timing │     │
│  │   "priority": "NORMAL"                                              │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  OPTIONAL: AUDIT ENCRYPTION AT REST                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ AuditEncryptor wraps record before writing:                         │     │
│  │   AES-256-GCM encryption using IKeyManager                         │     │
│  │   Encrypted record stored as base64 in audit.jsonl                  │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  ASYNC ARCHITECTURE:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │   HTTP Thread 1 ──emit()──┐                                         │     │
│  │   HTTP Thread 2 ──emit()──┤    ┌──────────────┐    ┌────────────┐  │     │
│  │   HTTP Thread 3 ──emit()──┼──→ │  MPSC Ring   │──→ │  Writer    │  │     │
│  │   HTTP Thread N ──emit()──┘    │  Buffer      │    │  Thread    │  │     │
│  │                                │  65536 slots │    │ Batch drain│  │     │
│  │       ~210ns CAS enqueue       │  lock-free   │    │ 1000/batch │  │     │
│  │                                └──────────────┘    │ or 100ms   │  │     │
│  │                                                    │ fsync/10   │  │     │
│  │                                                    └─────┬──────┘  │     │
│  │                                                          │         │     │
│  │                         ┌──────────────┐                 ▼         │     │
│  │                         │ Webhook Sink │    ┌──────────────────┐   │     │
│  │                         └──────────────┘    │ logs/audit.jsonl │   │     │
│  │                         ┌──────────────┐    │ (append-only)    │   │     │
│  │                         │ Syslog Sink  │    └──────────────────┘   │     │
│  │                         └──────────────┘                           │     │
│  │                         ┌──────────────┐                           │     │
│  │                         │ Kafka Sink   │  (ENABLE_KAFKA build)     │     │
│  │                         │ (librdkafka) │  rd_kafka_produce()       │     │
│  │                         └──────────────┘                           │     │
│  │                                                                     │     │
│  │  Overflow: buffer full → record dropped + overflow counter          │     │
│  │  Stats: total_emitted, total_written, overflow_dropped              │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Response Building

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  RESPONSE BUILDER (build_response)                                           │
│                                                                              │
│  Built BEFORE audit emit (response should not wait on audit I/O)            │
│                                                                              │
│  SUCCESS (HTTP 200):                                                         │
│  {                                                                           │
│    "success": true,                                                          │
│    "audit_id": "evt_...",                                                    │
│    "data": {                                                                 │
│      "columns": ["id", "name", "email"],                                     │
│      "rows": [["1", "Alice", "a***@example.com"], ...]                      │
│    },                                                                        │
│    "classifications": { "email": "PII.Email" },                              │
│    "masked_columns": ["email"],                                              │
│    "blocked_columns": ["ssn"],                                               │
│    "execution_time_us": 1250                                                 │
│  }                                                                           │
│                                                                              │
│  FAILURE (HTTP 4xx/5xx):                                                     │
│  {                                                                           │
│    "success": false,                                                         │
│    "audit_id": "evt_...",                                                    │
│    "error_code": "ACCESS_DENIED",                                            │
│    "error_message": "Policy 'block_ddl' blocks DROP_TABLE on customers",     │
│    "execution_time_us": 45                                                   │
│  }                                                                           │
│                                                                              │
│  RESPONSE HEADERS:                                                           │
│  ├─ X-RateLimit-Remaining: N                                                 │
│  ├─ Retry-After: N (on 429)                                                  │
│  ├─ traceparent: W3C trace propagation                                       │
│  └─ Content-Encoding: gzip (if compressed)                                   │
│                                                                              │
│  RESPONSE COMPRESSION (optional):                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ If compression_enabled && response > min_size_bytes:                 │     │
│  │   Check Accept-Encoding: gzip → try_compress() → set gzip header    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  HTTP STATUS MAPPING:                                                        │
│  ┌───────────────────────────┬──────────┐                                    │
│  │ ErrorCode                 │ HTTP     │                                    │
│  ├───────────────────────────┼──────────┤                                    │
│  │ NONE (success)            │ 200      │                                    │
│  │ PARSE_ERROR               │ 400      │                                    │
│  │ INVALID_REQUEST           │ 400      │                                    │
│  │ ACCESS_DENIED             │ 403      │                                    │
│  │ SQLI_BLOCKED              │ 403      │                                    │
│  │ QUERY_TOO_EXPENSIVE       │ 403      │                                    │
│  │ QUERY_TIMEOUT             │ 408      │                                    │
│  │ RESULT_TOO_LARGE          │ 413      │                                    │
│  │ RATE_LIMITED              │ 429      │                                    │
│  │ DATABASE_ERROR            │ 502      │                                    │
│  │ CIRCUIT_OPEN              │ 503      │                                    │
│  │ INTERNAL_ERROR            │ 500      │                                    │
│  └───────────────────────────┴──────────┘                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Supporting Endpoints

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  HEALTH CHECK                                                                │
│  GET /health?level=shallow|deep|readiness                                    │
│  ├─ shallow (default): {"status":"healthy","service":"sql-proxy"} (200)      │
│  ├─ deep: checks circuit breaker, connection pool, audit emitter (200/503)   │
│  └─ readiness: deep + rate limiter reject ratio check (200/503)              │
│                                                                              │
│  PROMETHEUS METRICS                                                          │
│  GET /metrics (60+ metrics, text/plain Prometheus format)                    │
│  ├─ sql_proxy_requests_total{status="allowed|blocked"}                       │
│  ├─ sql_proxy_rate_limit_total{level="global|user|database|user_database"}   │
│  ├─ sql_proxy_rate_limit_checks_total                                        │
│  ├─ sql_proxy_queue_depth, sql_proxy_queue_total, queue_timeouts_total       │
│  ├─ sql_proxy_audit_emitted_total, written_total, dropped_total, flushes     │
│  ├─ sql_proxy_cache_hits_total, misses, entries, evictions                   │
│  ├─ sql_proxy_slow_queries_total                                             │
│  ├─ sql_proxy_circuit_breaker_transitions_total{to="open|half_open|closed"}  │
│  ├─ sql_proxy_pool_connections_recycled_total                                │
│  ├─ sql_proxy_pool_acquire_duration_seconds{le=...} (histogram)             │
│  ├─ sql_proxy_rate_limiter_buckets_active, buckets_evicted_total            │
│  ├─ sql_proxy_auth_failures_total, auth_blocks_total                        │
│  ├─ sql_proxy_ip_blocked_total                                               │
│  ├─ sql_proxy_cache_ddl_invalidations_total                                  │
│  ├─ sql_proxy_query_cost_rejected_total, estimated_total                    │
│  ├─ sql_proxy_schema_drifts_total, drift_checks_total                       │
│  ├─ sql_proxy_adaptive_rate_current_tps, p95_us, adjustments_total          │
│  ├─ sql_proxy_adaptive_rate_throttle_events, protect_events                 │
│  └─ sql_proxy_info{version="1.0.0"}                                          │
│                                                                              │
│  ADMIN ENDPOINTS                                                             │
│  POST /policies/reload (admin auth required)                                 │
│  ├─ Reloads policies from config/proxy.toml via PolicyLoader                 │
│  └─ Returns: {"success":true,"policies_loaded":20}                           │
│                                                                              │
│  POST /api/v1/config/validate (admin auth required)                          │
│  ├─ Validates TOML config syntax without applying                            │
│  └─ Returns: {"valid":true|false,"errors":[]}                                │
│                                                                              │
│  GET /api/v1/slow-queries (admin, feature-gated)                             │
│  └─ Returns: { slow_queries[], total_slow_queries, threshold_ms, enabled }   │
│                                                                              │
│  GET /api/v1/circuit-breakers (admin)                                        │
│  └─ Returns: { breakers[{ name, state, stats, recent_events }] }            │
│                                                                              │
│  COMPLIANCE ENDPOINTS (admin auth required)                                  │
│  GET /api/v1/compliance/pii-report                                           │
│  └─ Returns: { total_pii_accesses, masking_coverage_pct, entries[] }         │
│                                                                              │
│  GET /api/v1/compliance/security-summary                                     │
│  └─ Returns: { total_queries, blocked, injection_attempts, tracked_users }   │
│                                                                              │
│  GET /api/v1/compliance/lineage                                              │
│  └─ Returns: { summaries[{ column_key, classification, accesses }] }        │
│                                                                              │
│  GET /api/v1/compliance/data-subject-access?user=X                           │
│  └─ Returns: { subject, events[{ timestamp, column, classification }] }     │
│                                                                              │
│  SCHEMA MANAGEMENT (admin, requires SchemaManager enabled)                   │
│  GET  /api/v1/schema/history  → DDL change history                           │
│  GET  /api/v1/schema/pending  → Pending DDL approvals                        │
│  POST /api/v1/schema/approve  → Approve by ID                                │
│  POST /api/v1/schema/reject   → Reject by ID                                 │
│  GET  /api/v1/schema/drift    → Schema drift events (feature-gated)          │
│                                                                              │
│  OPTIONAL ENDPOINTS                                                          │
│  POST /api/v1/query/dry-run   → Policy check without execution              │
│  POST /api/v1/graphql         → GraphQL-to-SQL queries + mutations            │
│  POST /api/v1/plugins/reload  → Hot-reload .so plugins (admin)               │
│  GET  /openapi.json           → OpenAPI 3.0 spec (feature-gated)             │
│  GET  /api/docs               → Swagger UI (feature-gated)                   │
│                                                                              │
│  DASHBOARD (feature-gated, admin auth)                                       │
│  GET  /dashboard               → Embedded single-page web UI (HTML)          │
│  GET  /dashboard/api/stats     → Real-time pipeline + audit stats (JSON)     │
│  GET  /dashboard/api/policies  → Policy listing (JSON)                       │
│  GET  /dashboard/api/users     → User listing (JSON)                         │
│  GET  /dashboard/api/alerts    → Active + historical alerts (JSON)           │
│  GET  /dashboard/api/metrics/stream → SSE, 2s interval, 10 min max          │
│                                                                              │
│  DISTRIBUTED RATE LIMITING (feature-gated, admin)                            │
│  GET  /api/v1/distributed-rate-limits → sync cycles, overrides, errors       │
│                                                                              │
│  WEBSOCKET STREAMING (feature-gated)                                         │
│  GET  /api/v1/stream           → RFC 6455 upgrade (audit/query/metrics)      │
│                                                                              │
│  MULTI-DATABASE TRANSACTIONS (feature-gated)                                 │
│  POST /api/v1/transactions/begin    → Begin 2PC transaction                  │
│  POST /api/v1/transactions/prepare  → Phase 1: prepare all participants      │
│  POST /api/v1/transactions/commit   → Phase 2: commit                        │
│  POST /api/v1/transactions/rollback → Rollback                               │
│  GET  /api/v1/transactions/:xid     → Transaction status                     │
│                                                                              │
│  LLM-POWERED FEATURES (feature-gated, admin)                                 │
│  POST /api/v1/llm/generate-policy   → AI-generate access policy              │
│  POST /api/v1/llm/explain-anomaly   → AI anomaly explanation                 │
│  POST /api/v1/llm/nl-to-policy      → Natural language → TOML policy         │
│  POST /api/v1/llm/classify-intent   → AI SQL intent classification           │
│  POST /api/v1/nl-query              → Natural language → SQL + execute       │
│                                                                              │
│  DATA CATALOG (feature-gated: data_catalog)                                  │
│  GET  /api/v1/catalog/tables        → List tables with access stats          │
│  GET  /api/v1/catalog/tables/:n/columns → Column PII, confidence, users     │
│  GET  /api/v1/catalog/search        → Search by PII type or text             │
│  GET  /api/v1/catalog/stats         → Aggregate catalog statistics           │
│                                                                              │
│  POLICY SIMULATOR (feature-gated: policy_simulator, admin)                   │
│  POST /api/v1/admin/policies/simulate → Dry-run policies vs audit JSONL     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Startup Sequence (main.cpp)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  STARTUP (9 phases)                                                          │
│                                                                              │
│  [1/9] Load configuration from config/proxy.toml (ConfigLoader)              │
│        ├─ Resolve `include` directives (recursive, max depth 10)            │
│        ├─ Deep-merge included files (arrays concat, main wins scalars)      │
│        ├─ Parse users, roles, policies, rate limits                          │
│        ├─ Parse [security] section (injection, anomaly, lineage, brute_force)│
│        ├─ Parse [encryption] section (columns, key_file)                     │
│        ├─ Parse [features] section (feature flags for route gating)         │
│        ├─ Parse users.allowed_ips for IP allowlisting                        │
│        └─ Fallback: 2 hardcoded policies + 4 users if config fails           │
│                                                                              │
│  [2/9] Database backend resolution (PostgreSQL / MySQL)                      │
│        └─ BackendRegistry::create() via static registration                  │
│                                                                              │
│  [3/9] Parse Cache + SQL Parser                                              │
│        ├─ Parse cache: 10K entries, 16 shards                                │
│        └─ Parser created via backend (wraps libpg_query or MySQL parser)     │
│                                                                              │
│  [4/9] Policy Engine + Rate Limiter                                          │
│        ├─ Policy engine: load all policies into trie                         │
│        ├─ Hierarchical rate limiter: 4 levels                                │
│        ├─ Apply per-user/per-database/per-user-per-database overrides        │
│        └─ Optional WaitableRateLimiter queue wrapper                         │
│                                                                              │
│  [5/9] Connection Pool + Circuit Breaker + Query Executor                    │
│        ├─ Pool: pre-warm with min_connections                                │
│        ├─ Circuit breaker: configurable thresholds                           │
│        └─ Executor: timeout, max_result_rows                                 │
│                                                                              │
│  [6/9] Classifier + Audit + Query Rewriter                                   │
│        ├─ ClassifierRegistry (conditional on classification_enabled)          │
│        ├─ AuditEmitter → starts background writer thread                     │
│        └─ QueryRewriter (conditional on RLS/rewrite rules existing)          │
│                                                                              │
│  [7/9] Security + Compliance + Schema + Plugins                              │
│        ├─ SqlInjectionDetector (conditional on injection_detection_enabled)   │
│        ├─ AnomalyDetector (conditional on anomaly_detection_enabled)          │
│        ├─ LineageTracker (conditional on lineage_tracking_enabled)            │
│        ├─ ColumnEncryptor + IKeyManager (if encryption enabled)              │
│        │   └─ Key managers: Local / Vault / Env                              │
│        ├─ ComplianceReporter (lineage + anomaly + audit)                     │
│        ├─ SchemaManager (if schema_management.enabled)                       │
│        ├─ TenantManager (if tenants.enabled)                                 │
│        ├─ PluginRegistry (classifier + audit sink plugins, hot-reload)       │
│        ├─ AuditSampler (if audit_sampling.enabled)                           │
│        ├─ ResultCache (if result_cache.enabled)                              │
│        ├─ SlowQueryTracker (if slow_query.enabled)                           │
│        ├─ QueryCostEstimator (if query_cost.enabled)                         │
│        ├─ SchemaDriftDetector → starts background thread                     │
│        ├─ AuditEncryptor (if audit_encryption.enabled)                       │
│        ├─ AdaptiveRateController → starts background thread                  │
│        ├─ DistributedRateLimiter (wraps local limiter, sync thread)          │
│        ├─ TransactionCoordinator (2PC, cleanup thread)                       │
│        ├─ LlmClient (OpenAI-compatible, cached + rate-limited)              │
│        └─ WebSocketHandler (RFC 6455 framing)                                │
│                                                                              │
│  [8/9] Build Pipeline (via PipelineBuilder, all layers wired)                │
│        ├─ 20+ components wired via builder pattern                           │
│        ├─ Retry config set if retry.enabled                                  │
│        ├─ GraphQLHandler (if graphql.enabled)                                │
│        ├─ AlertEvaluator → starts background thread                          │
│        └─ DashboardHandler (routes from config)                              │
│                                                                              │
│  [9/9] Create servers + start                                                │
│        ├─ HttpServer (TLS/mTLS optional, feature flags, compression)         │
│        ├─ ShutdownCoordinator                                                │
│        ├─ BruteForceProtector (if brute_force.enabled)                       │
│        ├─ WireServer → starts (if wire_protocol.enabled, TLS optional)       │
│        ├─ BinaryRpcServer → starts (if binary_rpc.enabled)                   │
│        ├─ ConfigWatcher → starts (file polling for hot-reload)               │
│        └─ HttpServer::start() — blocking listen on host:port                 │
│                                                                              │
│  Signal handling: SIGINT/SIGTERM → graceful shutdown                          │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ 1. ShutdownCoordinator::initiate_shutdown() (stop accepting)        │     │
│  │ 2. Stop background services:                                        │     │
│  │    AdaptiveRateController, SchemaDriftDetector, AlertEvaluator,     │     │
│  │    ConfigWatcher, WireServer, BinaryRpcServer,                      │     │
│  │    DistributedRateLimiter (stop_sync), TransactionCoordinator       │     │
│  │ 3. ShutdownCoordinator::wait_for_drain() (drain in-flight requests) │     │
│  │ 4. HttpServer::stop()                                               │     │
│  │ 5. exit(0)                                                          │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Dependency Graph

```
                    ┌───────────────┐
                    │   main.cpp    │
                    └───────┬───────┘
                            │ creates
              ┌─────────────┼─────────────────────────────┐
              ▼             ▼                              ▼
      ┌───────────────┐  ┌────────────┐          ┌────────────────┐
      │  HttpServer   │  │ WireServer │          │ BinaryRpcServer│
      │  (cpp-httplib)│  │ (PG v3)    │          │ (custom proto) │
      └───────┬───────┘  └─────┬──────┘          └───────┬────────┘
              │                │                          │
              └────────────────┼──────────────────────────┘
                               │ all use
                               ▼
                       ┌───────────────┐
                       │   Pipeline    │
                       │  (20+ comps)  │
                       └─┬──┬──┬──┬───┘
                         │  │  │  │
       ┌─────────────────┘  │  │  └──────────────────┐
       ▼                    │  │                      ▼
 ┌──────────────┐           │  │              ┌──────────────────┐
 │  SQLParser   │           │  │              │ Security Layer   │
 │  + ParseCache│           │  │              │ ┌─SqlInjection   │
 │  + Fingerprint│          │  │              │ ├─AnomalyDetect  │
 └──────────────┘           │  │              │ ├─ColumnEncryptor│
                            │  │              │ │  └─IKeyManager  │
       ┌────────────────────┘  │              │ └─LineageTracker │
       ▼                       ▼              └──────────────────┘
 ┌──────────────┐     ┌──────────────┐
 │ PolicyEngine │     │QueryExecutor │     ┌──────────────────────┐
 │ + PolicyTrie │     │ + ConnPool   │     │ Post-Exec Components │
 │ (RCU reload) │     │ + CircuitBrk │     │ ┌─ResultCache        │
 └──────────────┘     └──────────────┘     │ ├─SlowQueryTracker   │
                                           │ ├─QueryCostEstimator │
 ┌──────────────┐     ┌──────────────┐     │ ├─SchemaManager      │
 │ Classifier   │     │ AuditEmitter │     │ └─QueryRewriter (RLS)│
 │  Registry    │     │ + RingBuffer │     └──────────────────────┘
 │ (4 strategy) │     │ + Encryptor  │
 └──────────────┘     │ + Sampler    │     ┌──────────────────────┐
                      │ + Sinks      │     │ Background Services  │
 ┌──────────────┐     └──────────────┘     │ ┌─ConfigWatcher      │
 │ RateLimiter  │                          │ ├─AlertEvaluator     │
 │ + Waitable   │     ┌──────────────┐     │ ├─SchemaDriftDetect  │
 │ + Adaptive   │     │ TenantManager│     │ ├─AdaptiveRateCtrl   │
 └──────────────┘     └──────────────┘     │ └─ShutdownCoordinator│
                                           └──────────────────────┘
 ┌──────────────┐     ┌──────────────┐
 │ Compliance   │     │  Dashboard   │     ┌──────────────────────┐
 │  Reporter    │     │  Handler     │     │ HTTP-Level Security  │
 └──────────────┘     │ (HTML+JSON   │     │ ┌─BruteForceProtect  │
                      │  +SSE stream)│     │ ├─IpAllowlist        │
 ┌──────────────┐     └──────────────┘     │ └─ResponseCompressor │
 │ GraphQL      │                          └──────────────────────┘
 │ Handler      │     ┌──────────────┐
 │ (queries +   │     │ Auth Chain   │
 │  mutations)  │     │ ┌─API Key    │
 └──────────────┘     │ ├─JWT HMAC   │
                      │ ├─LDAP       │
 ┌──────────────┐     │ └─OIDC/OAuth2│
 │ CircuitBreaker│    │   (RS256,JWKS│
 │  Registry    │     └──────────────┘
 │ (per-tenant) │
 └──────────────┘     ┌──────────────┐
                      │ OpenAPI +    │
 ┌──────────────┐     │ Swagger UI   │
 │ Distributed  │     └──────────────┘
 │ RateLimiter  │
 │ (decorator)  │     ┌──────────────┐
 └──────────────┘     │  LLM Client  │
                      │ (OpenAI API) │
 ┌──────────────┐     └──────────────┘
 │ WebSocket    │
 │  Handler     │     ┌──────────────┐
 │ (RFC 6455)   │     │ Transaction  │
 └──────────────┘     │ Coordinator  │
                      │ (2PC)        │
                      └──────────────┘
```

---

## Thread Model

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  THREAD MODEL                                                                │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ HTTP Worker Threads (cpp-httplib thread pool, default 4)     │             │
│  │                                                             │             │
│  │  Thread 1 ──→ Pipeline::execute() ──→ all layers ──→ ...   │             │
│  │  Thread 2 ──→ Pipeline::execute() ──→ all layers ──→ ...   │             │
│  │  Thread N ──→ Pipeline::execute() ──→ all layers ──→ ...   │             │
│  │                                                             │             │
│  │  Shared state protection:                                   │             │
│  │  ├─ Rate limiter buckets: atomic CAS (lock-free)            │             │
│  │  ├─ Rate limiter maps: std::shared_mutex (reader-writer)    │             │
│  │  ├─ Parse cache: per-shard mutex (16-way parallel)          │             │
│  │  ├─ Result cache: per-shard mutex (16-way parallel)         │             │
│  │  ├─ Policy store: atomic shared_ptr (RCU, lock-free reads)  │             │
│  │  ├─ Connection pool: std::mutex + semaphore                 │             │
│  │  ├─ Circuit breaker: atomic state transitions               │             │
│  │  ├─ Audit emit: lock-free CAS enqueue to ring buffer        │             │
│  │  ├─ Anomaly profiles: shared_mutex (double-checked locking) │             │
│  │  ├─ Lineage tracker: shared_mutex (reads) / unique (writes) │             │
│  │  ├─ Key manager: shared_mutex (reads) / unique (rotation)   │             │
│  │  ├─ User registry: shared_mutex (reads) / unique (reload)   │             │
│  │  └─ Slow query tracker: mutex (bounded deque)               │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Audit Writer Thread (single, background)                    │             │
│  │  loop: sleep(100ms) → drain ring buffer → batch write       │             │
│  │        encrypt if AuditEncryptor enabled → fsync every 10   │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Rate Limiter Cleanup Thread (single, background)            │             │
│  │  loop: wait(60s) → unique_lock → erase idle buckets         │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Config Watcher Thread (single, background)                  │             │
│  │  loop: poll config file every N seconds (default: 5)        │             │
│  │        on change: reload policies, users, rate limits, RLS  │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Alert Evaluator Thread (single, background)                 │             │
│  │  loop: evaluate rules every evaluation_interval_seconds     │             │
│  │        fire/resolve alerts based on metric thresholds        │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Schema Drift Detector Thread (single, background)           │             │
│  │  loop: query information_schema every check_interval_seconds│             │
│  │        compare with previous snapshot → emit drift events    │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Adaptive Rate Controller Thread (single, background)        │             │
│  │  loop: every adjustment_interval_seconds                    │             │
│  │        compute P95 latency → adjust global TPS              │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Wire Protocol Threads (if enabled, thread pool)             │             │
│  │  Accept PostgreSQL v3 connections → Pipeline::execute()     │             │
│  │  TLS: SSLRequest negotiation → SSL_accept handshake         │             │
│  │  SslConnection RAII wrapper (SSL_read/SSL_write)            │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Binary RPC Threads (if enabled, thread pool)                │             │
│  │  Accept binary protocol connections → Pipeline::execute()   │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Distributed Rate Limiter Sync Thread (single, background)   │             │
│  │  loop: wait(sync_interval_ms) → report local usage to       │             │
│  │        backend → fetch global quotas                         │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Transaction Coordinator Cleanup Thread (single, background) │             │
│  │  loop: wait(cleanup_interval_s) → timeout stale              │             │
│  │        transactions → auto-abort                             │             │
│  └─────────────────────────────────────────────────────────────┘             │
└──────────────────────────────────────────────────────────────────────────────┘
```
