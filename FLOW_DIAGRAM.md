# SQL Proxy - Complete System Flow Diagram

## High-Level Architecture

```
                              ┌─────────────────────────────────┐
                              │         CLIENT APPLICATION       │
                              │   POST /api/v1/query             │
                              │   { "user", "sql", "database" }  │
                              └───────────────┬─────────────────┘
                                              │ HTTP
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                          HTTP SERVER (cpp-httplib)                           │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ Endpoints:                                                           │   │
│  │  POST /api/v1/query      → Query execution pipeline                 │   │
│  │  GET  /health            → {"status":"healthy"}                     │   │
│  │  GET  /metrics           → Prometheus format (rate_limiter + audit)  │   │
│  │  POST /policies/reload   → Hot-reload policies from TOML config     │   │
│  │  GET  /api/v1/compliance/pii-report       → PII access report       │   │
│  │  GET  /api/v1/compliance/security-summary → Security overview       │   │
│  │  GET  /api/v1/compliance/lineage          → Data lineage summaries  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Request Validation:                                                         │
│  ┌─ Content-Type: application/json? ──── NO ──→ 400 Bad Request             │
│  ├─ Body has valid JSON? ──────────────── NO ──→ 400 Bad Request             │
│  ├─ "user" field present? ─────────────── NO ──→ 400 Missing user            │
│  ├─ "sql" field present? ──────────────── NO ──→ 400 Missing sql             │
│  ├─ SQL length < 100KB? ──────────────── NO ──→ 400 SQL too long             │
│  └─ User authenticated? ──────────────── NO ──→ 401 Unknown user             │
│     (lookup in users_ map)                                                   │
│                                                                              │
│  Build ProxyRequest:                                                         │
│  ├─ request_id  = UUID                                                       │
│  ├─ user        = from JSON                                                  │
│  ├─ roles       = from UserInfo (resolved by validate_user)                  │
│  ├─ sql         = from JSON                                                  │
│  ├─ database    = from JSON (default: "testdb")                              │
│  └─ source_ip   = X-Forwarded-For header (fallback: remote_addr)            │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     PIPELINE ORCHESTRATOR (pipeline.cpp)                      │
│                                                                              │
│  Creates RequestContext (carries state through all 7 layers):                │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │ RequestContext {                                                   │       │
│  │   // Input                                                        │       │
│  │   request_id, user, roles, database, sql, source_ip               │       │
│  │   // Timestamps                                                   │       │
│  │   received_at (system_clock), started_at (steady_clock)           │       │
│  │   // Per-request memory arena (1KB initial)                       │       │
│  │   arena                                                           │       │
│  │   // Stage results (populated as pipeline progresses)             │       │
│  │   fingerprint, statement_info, analysis,                          │       │
│  │   policy_result, query_result, classification_result              │       │
│  │   // Timing breakdown (microseconds)                              │       │
│  │   parse_time, policy_time, execution_time, classification_time    │       │
│  │   // Flags                                                        │       │
│  │   cache_hit, rate_limited, circuit_breaker_open                   │       │
│  │ }                                                                 │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                              │
│  Sequential layer execution with short-circuit on failure:                   │
│                                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │
│  │ Layer 1 │─▶│ Layer 2 │─▶│ Layer 3 │─▶│Layer3.5 │─▶│Layer3.7 │──┐       │
│  │  RATE   │  │  PARSE  │  │ ANALYZE │  │  SQLI   │  │ ANOMALY │  │       │
│  │  LIMIT  │  │ + CACHE │  │         │  │ DETECT  │  │ (info)  │  │       │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └─────────┘  │       │
│       │FAIL        │FAIL        │FAIL        │BLOCK               │PASS   │
│       ▼            ▼            ▼            ▼                    ▼       │
│   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐          ┌──────────┐   │
│   │ AUDIT │   │ AUDIT │   │ AUDIT │   │ AUDIT │          │ Layer 4  │   │
│   │ + RES │   │ + RES │   │ + RES │   │ + RES │          │  POLICY  │   │
│   └───────┘   └───────┘   └───────┘   └───────┘          └────┬─────┘   │
│                                                                 │         │
│                                            FAIL ◀───────────────┤         │
│                                            ▼                    │PASS     │
│                                       ┌───────┐           ┌─────▼─────┐  │
│                                       │ AUDIT │           │  Layer 5  │  │
│                                       │ + RES │           │  EXECUTE  │  │
│                                       └───────┘           └─────┬─────┘  │
│                                                                 │        │
│                          ┌──────────────────────────────────────┘        │
│                          ▼                                               │
│                   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│                   │Layer 5.3 │─▶│Layer 5.5 │─▶│ Layer 6  │─▶│Lay 6.5│  │
│                   │ DECRYPT  │  │ COL ACL  │  │ CLASSIFY │  │LINEAGE│  │
│                   │ COLUMNS  │  │ + MASK   │  │          │  │TRACK  │  │
│                   └──────────┘  └──────────┘  └──────────┘  └───┬────┘  │
│                                                                  │       │
│                                                            ┌─────▼─────┐ │
│                                                            │  Layer 7  │ │
│                                                            │   AUDIT   │ │
│                                                            │ + RESPOND │ │
│                                                            └───────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer-by-Layer Detail

### Layer 1: Rate Limiting (Ingress Gate)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: HIERARCHICAL RATE LIMITER                                          │
│  Class: HierarchicalRateLimiter                                              │
│  Performance: ~52ns for all 4 checks                                         │
│                                                                              │
│  4 levels - ALL must pass:                                                   │
│                                                                              │
│  ┌────────────────────┐                                                      │
│  │ Level 1: GLOBAL    │  Protects proxy CPU                                  │
│  │ 50K tokens/sec     │  Single TokenBucket for entire proxy                 │
│  │ ~20ns (CAS loop)   │───── FAIL? ──→ { rate_limited=true, level="global" } │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 2: PER-USER  │  Prevents one user starving others                   │
│  │ 1K tokens/sec      │  TokenBucket per username                            │
│  │ ~30ns (shared_lock │───── FAIL? ──→ { rate_limited=true, level="user" }   │
│  │  + CAS)            │                                                      │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 3: PER-DB    │  Protects each database independently                │
│  │ 30K tokens/sec     │  TokenBucket per database name                       │
│  │ ~30ns              │───── FAIL? ──→ { rate_limited=true, level="db" }     │
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│  ┌────────▼───────────┐                                                      │
│  │ Level 4: USER+DB   │  Most specific control                               │
│  │ 100 tokens/sec     │  TokenBucket per "user:database" key                 │
│  │ ~30ns              │───── FAIL? ──→ { rate_limited=true, level="user_db" }│
│  └────────┬───────────┘                                                      │
│           │ PASS                                                             │
│           ▼                                                                  │
│  { allowed=true, tokens_remaining=N }                                        │
│                                                                              │
│  Token Bucket Algorithm (lock-free):                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ State = packed 64-bit atomic: [tokens:32][timestamp_ms:32]          │     │
│  │                                                                     │     │
│  │ try_acquire(1):                                                     │     │
│  │   loop {                                                            │     │
│  │     old = state.load()                                              │     │
│  │     elapsed = now - old.timestamp                                   │     │
│  │     refilled = old.tokens + elapsed * tokens_per_second             │     │
│  │     new_tokens = min(refilled, burst_capacity) - 1                  │     │
│  │     if (new_tokens < 0) return false  // Rate limited               │     │
│  │     if (state.CAS(old, pack(new_tokens, now))) return true          │     │
│  │   }  // Retry on CAS failure (another thread modified state)        │     │
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
│  Bucket Cleanup (background thread):                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Cleanup thread runs every cleanup_interval_seconds (default: 60)    │     │
│  │                                                                     │     │
│  │ For each bucket map (user, db, user_db):                            │     │
│  │   unique_lock → erase_if:                                           │     │
│  │     now_ns - bucket.last_access_ns() > idle_timeout_ns              │     │
│  │                                                                     │     │
│  │ Metrics: buckets_active, buckets_evicted_total                      │     │
│  │ Config: bucket_idle_timeout_seconds (default: 3600)                 │     │
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
│  Step 1: FINGERPRINTING (single-pass, ~450ns)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Fingerprinter::fingerprint(sql):                                    │     │
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
│  │ DDL Invalidation:                                                   │     │
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
│  │       │   (schema.table from RangeVar nodes in AST)                 │     │
│  │       └─ Store in cache for next time                               │     │
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
│  HOT RELOAD (POST /policies/reload):                                         │
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

### Layer 5: Query Executor

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5: QUERY EXECUTOR                                                     │
│  Classes: QueryExecutor + ConnectionPool + CircuitBreaker                    │
│                                                                              │
│  Input: ctx.sql, ctx.analysis.statement_type                                 │
│                                                                              │
│  CIRCUIT BREAKER (per database):                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  ┌────────┐   10 failures   ┌────────┐   60s timeout  ┌──────────┐│     │
│  │  │ CLOSED │ ──────────────→ │  OPEN  │ ─────────────→ │HALF_OPEN ││     │
│  │  │(normal)│ ←────────────── │(reject)│                │ (probe)  ││     │
│  │  └────────┘   5 successes   └────────┘                └──────────┘│     │
│  │       ▲         in half_open                              │       │     │
│  │       └───────────────────────────────────────────────────┘       │     │
│  │                         5 successes                               │     │
│  │                                                                     │     │
│  │  OPEN state → reject immediately (ErrorCode::CIRCUIT_OPEN)         │     │
│  │  HALF_OPEN  → allow 1 probe request                                │     │
│  │                                                                     │     │
│  │  State Change Events:                                               │     │
│  │  ├─ Emits StateChangeEvent on every transition (from, to, time)    │     │
│  │  ├─ Stored in bounded deque (max 100 recent events)                │     │
│  │  ├─ Optional callback for alerting integrations                    │     │
│  │  └─ Exposed via GET /api/v1/circuit-breakers                       │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  CONNECTION POOL (per database):                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  Config: min=2, max=10, timeout=5s                                  │     │
│  │                                                                     │     │
│  │  ┌──────────────────────────────────────────────────┐               │     │
│  │  │ Semaphore (max_connections)                       │               │     │
│  │  │  Controls max concurrent connections              │               │     │
│  │  └────────────────────┬─────────────────────────────┘               │     │
│  │                       │ try_acquire_for(5s)                         │     │
│  │                       ▼                                             │     │
│  │  ┌──────────────────────────────────────────────────┐               │     │
│  │  │ Idle Pool (std::deque<PGconn*>)                  │               │     │
│  │  │  ├─ Has idle conn? → Pop front + health check    │               │     │
│  │  │  └─ Empty? → create_connection() via PQconnectdb │               │     │
│  │  └──────────────────────────────────────────────────┘               │     │
│  │                       │                                             │     │
│  │                       ▼                                             │     │
│  │  ┌──────────────────────────────────────────────────┐               │     │
│  │  │ Health Check: PQexec(conn, "SELECT 1")           │               │     │
│  │  │  ├─ Healthy → use this connection                │               │     │
│  │  │  └─ Unhealthy → PQfinish + create new            │               │     │
│  │  └──────────────────────────────────────────────────┘               │     │
│  │                       │                                             │     │
│  │                       ▼                                             │     │
│  │  ┌──────────────────────────────────────────────────┐               │     │
│  │  │ Max Lifetime Check:                              │               │     │
│  │  │  now - created_at > max_lifetime (default: 1hr)? │               │     │
│  │  │  ├─ Within lifetime → use connection             │               │     │
│  │  │  └─ Exceeded → close + create new (recycled)     │               │     │
│  │  │  Metric: pool_connections_recycled_total          │               │     │
│  │  └──────────────────────────────────────────────────┘               │     │
│  │                       │                                             │     │
│  │                       ▼                                             │     │
│  │  ┌──────────────────────────────────────────────────┐               │     │
│  │  │ RAII Wrapper: PooledConnection                   │               │     │
│  │  │  Destructor auto-returns conn to idle pool       │               │     │
│  │  │  + releases semaphore slot                        │               │     │
│  │  └──────────────────────────────────────────────────┘               │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  STATEMENT BRANCHING:                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  stmt_type ─┬─ SELECT ──→ execute_select():                         │     │
│  │             │              SET statement_timeout                     │     │
│  │             │              PQexec(sql)                               │     │
│  │             │              Fetch column_names + column_type_oids     │     │
│  │             │              Fetch all rows → vector<vector<string>>   │     │
│  │             │                                                       │     │
│  │             ├─ INSERT ──→ execute_dml():                             │     │
│  │             ├─ UPDATE      PQexec(sql)                              │     │
│  │             ├─ DELETE      Capture affected_rows = PQcmdTuples       │     │
│  │             │                                                       │     │
│  │             └─ DDL ─────→ execute_ddl():                             │     │
│  │               (CREATE,     PQexec(sql)                              │     │
│  │                ALTER,      TODO: Trigger schema cache invalidation  │     │
│  │                DROP)                                                │     │
│  │                                                                     │     │
│  │  On success → circuit_breaker.record_success()                      │     │
│  │  On failure → circuit_breaker.record_failure()                      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Output: QueryResult { success, columns, rows, affected_rows, error }        │
│  Written to ctx: query_result, execution_time                                │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 5.3: Decrypt Encrypted Columns

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 5.3: COLUMN DECRYPTION (Transparent)                                  │
│  Class: ColumnEncryptor + IKeyManager                                        │
│                                                                              │
│  Input: ctx.query_result (after execution), ctx.analysis.source_tables       │
│                                                                              │
│  Only runs when encryption is enabled and query returned results.            │
│                                                                              │
│  ENCRYPTED VALUE FORMAT:                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ ENC:v1:<key_id>:<base64(IV + ciphertext + auth_tag)>               │     │
│  │                                                                     │     │
│  │ Algorithm: AES-256-GCM                                              │     │
│  │ IV:        12 bytes (random per encryption)                         │     │
│  │ Tag:       16 bytes (authentication)                                │     │
│  │ Key:       256-bit from IKeyManager                                 │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  DECRYPTION FLOW:                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ 1. For each column in result, check is_encrypted_column(db,tbl,col) │     │
│  │    (O(1) lookup in unordered_set<string>)                           │     │
│  │ 2. For matching columns, scan each row:                              │     │
│  │    ├─ Starts with "ENC:v1:" → decrypt with key from key_id          │     │
│  │    └─ Plain text → passthrough (not encrypted)                      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  KEY MANAGEMENT:                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ IKeyManager (interface):                                            │     │
│  │   ├─ get_active_key() → current encryption key                      │     │
│  │   ├─ get_key(key_id)  → lookup by ID (for decryption)              │     │
│  │   └─ rotate_key()     → generate new key, deactivate old            │     │
│  │                                                                     │     │
│  │ LocalKeyManager (file-based implementation):                        │     │
│  │   ├─ Stores keys in file: key_id:hex_key:active                     │     │
│  │   ├─ Supports key rotation (old keys kept for decryption)           │     │
│  │   └─ Thread-safe with shared_mutex                                  │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Config: [encryption] section in proxy.toml                                 │
│  Columns: [[encryption.columns]] database/table/column entries              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 6: Classification

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 6: PII CLASSIFICATION (Post-execution)                                │
│  Class: ClassifierRegistry                                                   │
│                                                                              │
│  Input: ctx.query_result (columns + rows), ctx.analysis (projections)        │
│  Only runs on successful SELECT queries with results                         │
│                                                                              │
│  4-STRATEGY CHAIN (highest confidence wins):                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │  For EACH column in query_result.column_names:                      │     │
│  │                                                                     │     │
│  │  ┌──────────────────────────────────────────────────────┐           │     │
│  │  │ Strategy 1: COLUMN NAME (90% confidence, ~10ns)      │           │     │
│  │  │                                                      │           │     │
│  │  │  Hash map lookup:                                    │           │     │
│  │  │  "email"       → PII_EMAIL                           │           │     │
│  │  │  "phone"       → PII_PHONE                           │           │     │
│  │  │  "ssn"         → PII_SSN                             │           │     │
│  │  │  "credit_card" → PII_CREDIT_CARD                     │           │     │
│  │  │  "salary"      → SENSITIVE_SALARY                    │           │     │
│  │  │  "password"    → SENSITIVE_PASSWORD                   │           │     │
│  │  │                                                      │           │     │
│  │  │  Match? → DONE (skip remaining strategies)           │           │     │
│  │  └───────────────────────┬──────────────────────────────┘           │     │
│  │                          │ NO MATCH                                 │     │
│  │  ┌───────────────────────▼──────────────────────────────┐           │     │
│  │  │ Strategy 2: TYPE OID (85% confidence, ~5ns)          │           │     │
│  │  │                                                      │           │     │
│  │  │  PostgreSQL type OID → PII type mapping              │           │     │
│  │  │  (e.g., custom domain types registered as PII)       │           │     │
│  │  │                                                      │           │     │
│  │  │  Match? → DONE                                       │           │     │
│  │  └───────────────────────┬──────────────────────────────┘           │     │
│  │                          │ NO MATCH                                 │     │
│  │  ┌───────────────────────▼──────────────────────────────┐           │     │
│  │  │ Strategy 3: PATTERN VALUE (80% confidence, ~100ns)   │           │     │
│  │  │                                                      │           │     │
│  │  │  Sample up to 20 rows, hand-rolled O(n) scanners:   │           │     │
│  │  │  ├─ looks_like_email():       user@domain.com        │           │     │
│  │  │  ├─ looks_like_phone():       +1-555-123-4567        │           │     │
│  │  │  ├─ looks_like_ssn():         123-45-6789            │           │     │
│  │  │  └─ looks_like_credit_card(): 4111-1111-1111-1111    │           │     │
│  │  │                                                      │           │     │
│  │  │  Match? → DONE                                       │           │     │
│  │  └───────────────────────┬──────────────────────────────┘           │     │
│  │                          │ NO MATCH                                 │     │
│  │  ┌───────────────────────▼──────────────────────────────┐           │     │
│  │  │ Strategy 4: DERIVED COLUMN (inherited PII)           │           │     │
│  │  │                                                      │           │     │
│  │  │  Check projection.derived_from → source column PII   │           │     │
│  │  │                                                      │           │     │
│  │  │  PII-preserving:  UPPER(email) → still PII_EMAIL     │           │     │
│  │  │  PII-destroying:  COUNT(email) → NOT PII             │           │     │
│  │  │                   AVG(salary)  → NOT SENSITIVE        │           │     │
│  │  │                   MD5(ssn)     → NOT PII              │           │     │
│  │  └──────────────────────────────────────────────────────┘           │     │
│  │                                                                     │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Output: ClassificationResult { column → { type, confidence, strategy } }    │
│  Written to ctx: classification_result, classification_time                  │
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
│  │   query_fingerprint (normalized hash)                               │     │
│  │   was_masked: bool (was masking applied?)                           │     │
│  │   masking_action: "PARTIAL" / "HASH" / "REDACT" / ""               │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  STORAGE:                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ Events:     std::deque<LineageEvent> (bounded, max 100K)            │     │
│  │ Summaries:  unordered_map<column_key, LineageSummary>               │     │
│  │                                                                     │     │
│  │ LineageSummary per column:                                          │     │
│  │   column_key:      "testdb.customers.email"                         │     │
│  │   classification:  "PII.Email"                                      │     │
│  │   total_accesses:  count                                            │     │
│  │   masked_accesses: count (GDPR compliance metric)                   │     │
│  │   accessing_users: set<string> (who accessed this column)           │     │
│  │   first/last_access timestamps                                      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  Thread safety: shared_mutex (shared_lock for reads, unique_lock for writes) │
│  Data feeds into: Compliance Reporter (PII reports, security summaries)     │
│                                                                              │
│  API: GET /api/v1/compliance/lineage → summaries JSON                       │
│       GET /api/v1/compliance/lineage/events?user=X&table=Y&limit=N          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Layer 7: Audit

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 7: AUDIT EMITTER (Async, Non-blocking)                                │
│  Class: AuditEmitter + MPSCRingBuffer                                        │
│                                                                              │
│  ALWAYS fires - on success AND every failure path                            │
│                                                                              │
│  AUDIT RECORD (comprehensive):                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │ {                                                                   │     │
│  │   "audit_id": "evt_...",           // UUIDv7 (time-sortable)        │     │
│  │   "sequence_num": 12345,           // Monotonic (gap detection)     │     │
│  │   "timestamp": "2026-02-07T...",                                    │     │
│  │   "user": "analyst",                                                │     │
│  │   "source_ip": "10.0.0.5",                                         │     │
│  │   "database_name": "testdb",                                        │     │
│  │   "sql": "SELECT email FROM customers",                             │     │
│  │   "fingerprint": { "hash": "0xa3f2...", "normalized": "..." },      │     │
│  │   "statement_type": "SELECT",                                       │     │
│  │   "decision": "ALLOW",                                              │     │
│  │   "matched_policy": "allow_analyst_read",                           │     │
│  │   "execution_success": true,                                        │     │
│  │   "rows_returned": 150,                                             │     │
│  │   "detected_classifications": ["PII.Email"],                        │     │
│  │   "parse_time_us": 12,                                              │     │
│  │   "policy_time_us": 5,                                              │     │
│  │   "execution_time_us": 1200,                                        │     │
│  │   "total_duration_us": 1250,                                        │     │
│  │   "rate_limited": false,                                            │     │
│  │   "cache_hit": true,                                                │     │
│  │   // Security fields (Tier 4):                                      │     │
│  │   "threat_level": "NONE",       // SQL injection threat             │     │
│  │   "injection_patterns": [],     // Matched patterns                 │     │
│  │   "injection_blocked": false,   // Was request blocked?             │     │
│  │   "anomaly_score": 0.3,         // Behavioral anomaly score         │     │
│  │   "anomalies": ["NEW_TABLE:sensitive_data"]                         │     │
│  │ }                                                                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│  ASYNC ARCHITECTURE:                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                                                                     │     │
│  │   HTTP Thread 1 ──emit()──┐                                         │     │
│  │   HTTP Thread 2 ──emit()──┤    ┌──────────────┐    ┌────────────┐  │     │
│  │   HTTP Thread 3 ──emit()──┼──→ │  MPSC Ring   │──→ │  Writer    │  │     │
│  │   HTTP Thread N ──emit()──┘    │  Buffer      │    │  Thread    │  │     │
│  │                                │  65536 slots │    │  (single)  │  │     │
│  │       ~210ns CAS enqueue       │  lock-free   │    │            │  │     │
│  │                                └──────────────┘    │ Batch drain│  │     │
│  │                                                    │ 1000/batch │  │     │
│  │                                                    │ or 100ms   │  │     │
│  │                                                    │            │  │     │
│  │                                                    │ fsync every│  │     │
│  │                                                    │ 10 batches │  │     │
│  │                                                    └─────┬──────┘  │     │
│  │                                                          │         │     │
│  │                                                          ▼         │     │
│  │                                               ┌──────────────────┐ │     │
│  │                                               │ logs/audit.jsonl │ │     │
│  │                                               │ (append-only)    │ │     │
│  │                                               └──────────────────┘ │     │
│  │                                                                     │     │
│  │  Overflow handling:                                                  │     │
│  │  Buffer full → record dropped + overflow counter incremented        │     │
│  │  Stats tracked: total_emitted, total_written, overflow_dropped      │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Response Building

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  RESPONSE BUILDER (build_response)                                           │
│                                                                              │
│  Reads from RequestContext, builds ProxyResponse:                             │
│                                                                              │
│  SUCCESS (HTTP 200):                                                         │
│  {                                                                           │
│    "success": true,                                                          │
│    "audit_id": "evt_...",                                                    │
│    "data": {                                                                 │
│      "columns": ["id", "name", "email"],                                     │
│      "rows": [["1", "Alice", "alice@example.com"], ...]                      │
│    },                                                                        │
│    "classifications": { "email": "PII.Email" },                              │
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
│  HTTP STATUS MAPPING:                                                        │
│  ┌───────────────────────┬──────────┐                                        │
│  │ ErrorCode             │ HTTP     │                                        │
│  ├───────────────────────┼──────────┤                                        │
│  │ NONE (success)        │ 200      │                                        │
│  │ PARSE_ERROR           │ 400      │                                        │
│  │ ACCESS_DENIED         │ 403      │                                        │
│  │ SQLI_BLOCKED          │ 403      │                                        │
│  │ RATE_LIMITED          │ 429      │                                        │
│  │ CIRCUIT_OPEN          │ 503      │                                        │
│  │ DATABASE_ERROR        │ 502      │                                        │
│  │ INTERNAL_ERROR        │ 500      │                                        │
│  └───────────────────────┴──────────┘                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Supporting Endpoints

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  GET /health?level=shallow|deep|readiness                                    │
│  ├─ shallow (default): {"status":"healthy","service":"sql-proxy"} (200)      │
│  ├─ deep: checks circuit breaker, connection pool, audit emitter (200/503)   │
│  └─ readiness: deep + rate limiter reject ratio check (200/503)              │
│                                                                              │
│  GET /metrics (Prometheus format)                                            │
│  ├─ sql_proxy_requests_total{status="allowed|blocked"}                       │
│  ├─ sql_proxy_rate_limit_total{level="global|user|database|user_database"}   │
│  ├─ sql_proxy_rate_limit_checks_total                                        │
│  ├─ sql_proxy_audit_emitted_total                                            │
│  ├─ sql_proxy_audit_written_total                                            │
│  ├─ sql_proxy_audit_dropped_total                                            │
│  ├─ sql_proxy_audit_flushes_total                                            │
│  ├─ sql_proxy_info{version="1.0.0"}                                          │
│  ├─ sql_proxy_rate_limiter_buckets_active{level}                             │
│  ├─ sql_proxy_rate_limiter_buckets_evicted_total                             │
│  ├─ sql_proxy_circuit_breaker_transitions_total{to="open|half_open|closed"}  │
│  ├─ sql_proxy_pool_connections_recycled_total                                │
│  └─ sql_proxy_cache_ddl_invalidations_total                                  │
│                                                                              │
│  POST /policies/reload                                                       │
│  ├─ Reads config/proxy.toml                                                  │
│  ├─ Parses policies via PolicyLoader                                         │
│  ├─ Hot-reloads via RCU (atomic pointer swap)                                │
│  └─ Returns: {"success":true,"policies_loaded":20}                           │
│                                                                              │
│  GET /api/v1/circuit-breakers (Admin)                                        │
│  ├─ Returns current state, stats, and recent state change events             │
│  └─ Returns: { state, stats, recent_events[] }                               │
│                                                                              │
│  GET /api/v1/compliance/pii-report (Tier 4)                                  │
│  ├─ Aggregates lineage data into PII access report                           │
│  ├─ Per-column: access counts, masked/unmasked, accessing users              │
│  └─ Returns: { total_pii_accesses, masking_coverage_pct, entries[] }         │
│                                                                              │
│  GET /api/v1/compliance/security-summary (Tier 4)                            │
│  ├─ Aggregates audit stats, anomaly data, lineage counts                     │
│  └─ Returns: { total_queries, blocked, injection_attempts, tracked_users }   │
│                                                                              │
│  GET /api/v1/compliance/lineage (Tier 4)                                     │
│  ├─ Returns data lineage summaries per column                                │
│  └─ Returns: { summaries: [{ column_key, classification, accesses, ... }] }  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Startup Sequence (main.cpp)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  STARTUP (10 phases)                                                         │
│                                                                              │
│  [1/10] Load configuration from config/proxy.toml (ConfigLoader)             │
│         ├─ Parse users, roles, policies, rate limits                         │
│         ├─ Parse [security] section (injection, anomaly, lineage)            │
│         ├─ Parse [encryption] section (columns, key_file)                    │
│         └─ Fallback: 2 hardcoded policies + 4 users if config fails          │
│                                                                              │
│  [2/10] Initialize Parse Cache (10K entries, 16 shards)                      │
│                                                                              │
│  [3/10] Initialize SQL Parser (wraps libpg_query)                            │
│                                                                              │
│  [4/10] Initialize Policy Engine + load policies                             │
│                                                                              │
│  [5/10] Initialize Rate Limiter (4-level hierarchy)                          │
│         ├─ Apply per-user rate limit overrides                               │
│         ├─ Apply per-database rate limit overrides                           │
│         └─ Apply per-user-per-database overrides                             │
│                                                                              │
│  [6/10] Initialize Connection Pool + Circuit Breaker + Query Executor        │
│         └─ Pre-warm pool with min_connections (2)                            │
│                                                                              │
│  [7/10] Initialize ClassifierRegistry + AuditEmitter                         │
│         └─ AuditEmitter starts background writer thread                      │
│                                                                              │
│  [8/10] Initialize Security Components (Tier 4)                              │
│         ├─ SqlInjectionDetector (config from [security] section)              │
│         ├─ AnomalyDetector (per-user behavioral profiling)                   │
│         ├─ LineageTracker (PII access tracking)                              │
│         ├─ ColumnEncryptor + LocalKeyManager (if encryption enabled)         │
│         └─ ComplianceReporter (aggregates lineage + anomaly + audit)         │
│                                                                              │
│  [9/10] Build Pipeline (all 11 layers wired)                                 │
│                                                                              │
│ [10/10] Create HttpServer → server.start()                                   │
│         └─ Listening on 0.0.0.0:8080                                         │
│                                                                              │
│  Signal handling: SIGINT/SIGTERM → graceful shutdown                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Dependency Graph

```
                    ┌───────────────┐
                    │   main.cpp    │
                    └───────┬───────┘
                            │ creates
                            ▼
                    ┌───────────────┐
                    │  HttpServer   │──────────────────────────────────┐
                    │  (cpp-httplib)│                                  │
                    └───────┬───────┘                                  │
                            │ owns                                    │
                            ▼                                         ▼
                    ┌───────────────┐                          ┌──────────────┐
                    │   Pipeline    │──────────────┐           │ Compliance   │
                    └─┬──┬──┬──┬───┘              │           │  Reporter    │
                      │  │  │  │                  │           └──────┬───────┘
        ┌─────────────┘  │  │  └──────┐           │                  │
        ▼                │  │         ▼           ▼           ┌──────▼───────┐
  ┌──────────────┐       │  │  ┌──────────────┐ ┌──────────┐ │  Lineage     │
  │  SQLParser   │       │  │  │ RateLimiter  │ │AuditEmit │ │  Tracker     │
  └──────┬───────┘       │  │  └──────────────┘ └────┬─────┘ └──────────────┘
         │               │  │                        │
         ▼               │  │                        ▼
  ┌──────────────┐       │  │                 ┌──────────────┐
  │  ParseCache  │       │  │                 │  RingBuffer  │
  │  (16 shards) │       │  │                 │  (65536)     │
  └──────┬───────┘       │  │                 └──────────────┘
         │               │  │
         ▼               │  │
  ┌──────────────┐       │  │
  │ Fingerprinter│       │  │
  │ (xxHash64)   │       │  │
  └──────────────┘       │  │
                         │  │
           ┌─────────────┘  └──────────────┐
           ▼                               ▼
  ┌──────────────┐     ┌──────────────┐  ┌──────────────────┐
  │ PolicyEngine │     │QueryExecutor │  │ Security Layer   │
  └──────┬───────┘     └──────┬───────┘  │                  │
         │                    │          │ SqlInjection     │
         ▼                    ▼          │  Detector        │
  ┌──────────────┐     ┌──────────────┐  │ AnomalyDetector  │
  │  PolicyTrie  │     │ ConnPool     │  │ ColumnEncryptor  │
  │  (radix)     │     │ (libpq)      │  │  └─IKeyManager   │
  └──────────────┘     └──────┬───────┘  │    └─LocalKeyMgr │
                              │          └──────────────────┘
                              ▼
                       ┌──────────────┐
                       │CircuitBreaker│
                       │ (per-DB FSM) │
                       └──────────────┘

  ┌──────────────┐
  │ Classifier   │  (4-strategy chain: name → OID → pattern → derived)
  │  Registry    │
  └──────────────┘
```

---

## Thread Model

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  THREAD MODEL                                                                │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ HTTP Worker Threads (cpp-httplib thread pool)               │             │
│  │                                                             │             │
│  │  Thread 1 ──→ Pipeline::execute() ──→ Rate Limit ──→ ...   │             │
│  │  Thread 2 ──→ Pipeline::execute() ──→ Rate Limit ──→ ...   │             │
│  │  Thread N ──→ Pipeline::execute() ──→ Rate Limit ──→ ...   │             │
│  │                                                             │             │
│  │  Shared state protection:                                   │             │
│  │  ├─ Rate limiter buckets: atomic CAS (lock-free)            │             │
│  │  ├─ Rate limiter maps: std::shared_mutex (reader-writer)    │             │
│  │  ├─ Parse cache: per-shard mutex (16-way parallel)          │             │
│  │  ├─ Policy store: atomic shared_ptr (RCU, lock-free reads)  │             │
│  │  ├─ Connection pool: std::mutex + semaphore                 │             │
│  │  ├─ Circuit breaker: atomic state transitions               │             │
│  │  ├─ Audit emit: lock-free CAS enqueue to ring buffer        │             │
│  │  ├─ Anomaly profiles: shared_mutex (double-checked locking) │             │
│  │  ├─ Lineage tracker: shared_mutex (reads) / unique (writes) │             │
│  │  └─ Key manager: shared_mutex (reads) / unique (rotation)   │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Rate Limiter Cleanup Thread (single, background)            │             │
│  │                                                             │             │
│  │  loop:                                                      │             │
│  │    wait(cleanup_interval_seconds) or shutdown signal         │             │
│  │    for each bucket map (user, db, user_db):                 │             │
│  │      unique_lock → erase idle buckets (> idle_timeout)      │             │
│  └─────────────────────────────────────────────────────────────┘             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────┐             │
│  │ Audit Writer Thread (single, background)                    │             │
│  │                                                             │             │
│  │  loop:                                                      │             │
│  │    sleep(100ms) or wake on flush/shutdown signal             │             │
│  │    drain ring buffer → batch of up to 1000 records          │             │
│  │    write batch to audit.jsonl                               │             │
│  │    every 10 batches → fsync                                 │             │
│  └─────────────────────────────────────────────────────────────┘             │
└──────────────────────────────────────────────────────────────────────────────┘
```
