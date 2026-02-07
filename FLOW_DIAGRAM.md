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
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│  │ Layer 1 │───▶│ Layer 2 │───▶│ Layer 3 │───▶│ Layer 4 │──┐               │
│  │  RATE   │    │  PARSE  │    │ ANALYZE │    │ POLICY  │  │               │
│  │  LIMIT  │    │ + CACHE │    │         │    │         │  │               │
│  └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘  │               │
│       │FAIL          │FAIL          │FAIL          │FAIL   │PASS           │
│       ▼              ▼              ▼              ▼       ▼               │
│   ┌───────┐     ┌───────┐     ┌───────┐     ┌───────┐ ┌─────────┐        │
│   │ AUDIT │     │ AUDIT │     │ AUDIT │     │ AUDIT │ │ Layer 5 │──┐     │
│   │ + RES │     │ + RES │     │ + RES │     │ + RES │ │ EXECUTE │  │     │
│   └───────┘     └───────┘     └───────┘     └───────┘ └────┬────┘  │     │
│                                                              │FAIL  │PASS │
│                                                              ▼      ▼     │
│                                                         ┌───────┐┌──────┐ │
│                                                         │ AUDIT ││L6+L7│ │
│                                                         │ + RES ││CLASS│ │
│                                                         └───────┘│+AUD │ │
│                                                                  │+RES │ │
│                                                                  └──────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer-by-Layer Detail

### Layer 1: Rate Limiting (Ingress Gate)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: HIERARCHICAL RATE LIMITER                                          │
│  Class: HierarchicalRateLimiter                                              │
│  Performance: ~80ns for all 4 checks                                         │
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
│  Step 1: FINGERPRINTING (single-pass, ~10ns)                                 │
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
│  │  │ Strategy 3: REGEX VALUE (80% confidence, ~1-10μs)    │           │     │
│  │  │                                                      │           │     │
│  │  │  Sample up to 20 rows, test precompiled regex:       │           │     │
│  │  │  ├─ email_regex_:       user@domain.com patterns     │           │     │
│  │  │  ├─ phone_regex_:       +1-555-123-4567 patterns     │           │     │
│  │  │  ├─ ssn_regex_:         123-45-6789 patterns         │           │     │
│  │  │  └─ credit_card_regex_: 4111-1111-1111-1111 patterns │           │     │
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
│  │   "cache_hit": true                                                 │     │
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
│  │        ~50ns CAS enqueue       │  lock-free   │    │            │  │     │
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
│  GET /health                                                                 │
│  └─ Returns: {"status":"healthy","service":"sql-proxy"}                      │
│  └─ Always 200 (basic liveness check)                                        │
│                                                                              │
│  GET /metrics (Prometheus format)                                            │
│  ├─ sql_proxy_requests_total{status="allowed|blocked"}                       │
│  ├─ sql_proxy_rate_limit_total{level="global|user|database|user_database"}   │
│  ├─ sql_proxy_rate_limit_checks_total                                        │
│  ├─ sql_proxy_audit_emitted_total                                            │
│  ├─ sql_proxy_audit_written_total                                            │
│  ├─ sql_proxy_audit_dropped_total                                            │
│  ├─ sql_proxy_audit_flushes_total                                            │
│  └─ sql_proxy_info{version="1.0.0"}                                          │
│                                                                              │
│  POST /policies/reload                                                       │
│  ├─ Reads config/proxy.toml                                                  │
│  ├─ Parses policies via PolicyLoader                                         │
│  ├─ Hot-reloads via RCU (atomic pointer swap)                                │
│  └─ Returns: {"success":true,"policies_loaded":20}                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Startup Sequence (main.cpp)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  STARTUP (8 phases)                                                          │
│                                                                              │
│  [1/8] Load configuration from config/proxy.toml (ConfigLoader)              │
│        ├─ Parse users, roles, policies, rate limits                          │
│        └─ Fallback: 2 hardcoded policies + 4 users if config fails           │
│                                                                              │
│  [2/8] Initialize Parse Cache (10K entries, 16 shards)                       │
│                                                                              │
│  [3/8] Initialize SQL Parser (wraps libpg_query)                             │
│                                                                              │
│  [4/8] Initialize Policy Engine + load policies                              │
│                                                                              │
│  [5/8] Initialize Rate Limiter (4-level hierarchy)                           │
│        ├─ Apply per-user rate limit overrides                                │
│        ├─ Apply per-database rate limit overrides                            │
│        └─ Apply per-user-per-database overrides                              │
│                                                                              │
│  [6/8] Initialize Connection Pool + Circuit Breaker + Query Executor         │
│        └─ Pre-warm pool with min_connections (2)                             │
│                                                                              │
│  [7/8] Initialize ClassifierRegistry + AuditEmitter                          │
│        └─ AuditEmitter starts background writer thread                       │
│                                                                              │
│  [8/8] Build Pipeline → Create HttpServer → server.start()                   │
│        └─ Listening on 0.0.0.0:8080                                          │
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
                    │  HttpServer   │
                    │  (cpp-httplib)│
                    └───────┬───────┘
                            │ owns
                            ▼
                    ┌───────────────┐
                    │   Pipeline    │──────────────────────────────────┐
                    └───┬───┬───┬──┘                                  │
                        │   │   │                                     │
          ┌─────────────┘   │   └─────────────┐                       │
          ▼                 ▼                 ▼                       ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      ┌──────────────┐
  │  SQLParser   │ │ PolicyEngine │ │ RateLimiter  │      │AuditEmitter  │
  └──────┬───────┘ └──────┬───────┘ └──────────────┘      └──────┬───────┘
         │                │                                       │
         ▼                ▼                                       ▼
  ┌──────────────┐ ┌──────────────┐                        ┌──────────────┐
  │  ParseCache  │ │  PolicyTrie  │                        │  RingBuffer  │
  │  (16 shards) │ │  (radix)     │                        │  (65536)     │
  └──────┬───────┘ └──────────────┘                        └──────────────┘
         │
         ▼
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
  │ Fingerprinter│     │QueryExecutor │────▶│ ConnPool     │
  │ (xxHash64)   │     └──────┬───────┘     │ (libpq)      │
  └──────────────┘            │             └──────────────┘
                              ▼
                       ┌──────────────┐
                       │CircuitBreaker│
                       │ (per-DB FSM) │
                       └──────────────┘

  ┌──────────────┐
  │ Classifier   │  (4-strategy chain: name → OID → regex → derived)
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
│  │  └─ Audit emit: lock-free CAS enqueue to ring buffer        │             │
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
