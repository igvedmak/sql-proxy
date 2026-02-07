import { useState } from "react";

const COLORS = {
  bg: "#0a0e17",
  bgCard: "#111827",
  bgCardHover: "#1a2332",
  border: "#1e2a3a",
  borderAccent: "#2563eb",
  text: "#e2e8f0",
  textMuted: "#64748b",
  textAccent: "#60a5fa",
  hotPath: "#f59e0b",
  coldPath: "#6366f1",
  green: "#10b981",
  red: "#ef4444",
  orange: "#f97316",
  cyan: "#06b6d4",
  pink: "#ec4899",
  lime: "#84cc16",
  purple: "#a855f7",
  rose: "#f43f5e",
};

const layers = [
  {
    id: "ingress",
    num: "①",
    title: "Ingress Layer",
    subtitle: "Drogon Async HTTP + Multi-Level Rate Limiter",
    color: COLORS.cyan,
    perf: "~1.5μs",
    filterRate: "10-40%",
    components: [
      {
        name: "HTTP Server (Drogon)",
        details: "Non-blocking event loop, C++20 coroutines, routes: /query, /health, /metrics, /policies/reload",
      },
      {
        name: "Request Validation",
        details: "JSON well-formed? Required fields present? SQL non-empty + within max length? Fail fast before any expensive work",
      },
      {
        name: "User Authentication",
        details: "Resolve user field → known identity. Reject unknown users immediately. Config-based lookup (JWT/OAuth as future work)",
      },
      {
        name: "Hierarchical Rate Limiter",
        details: "4 levels, ALL must pass: ① Global (protect proxy) → ② Per-User (fair share) → ③ Per-Database (protect each DB) → ④ Per-User-Per-DB (most specific). Lock-free atomic token buckets. ~80ns total",
      },
      {
        name: "Concurrency Limiter",
        details: "Per-database semaphore limiting in-flight queries. Prevents pool exhaustion even when rate limit passes. co_await with timeout",
      },
      {
        name: "RequestContext Construction",
        details: "Arena-allocated context: user_id, raw_sql, database, client_ip, timestamp, request_id (UUID). Single object flows through entire pipeline",
      },
      {
        name: "Response Serialization",
        details: "Pipeline result → JSON. ErrorCategory → HTTP status: ParseError→400, PolicyDenied→403, RateLimited→429, AuthError→401, ExecError→502, Timeout→504",
      },
    ],
    decisions: [
      "HTTP REST over transparent TCP proxy — exercise explicitly allows service interface, better for demo and testability",
      "Rate limiter in ingress, not middleware — cheapest possible rejection point, before any parsing",
      "Hierarchical rate limits — single flat limiter can't protect individual DBs or ensure fair user share",
      "Concurrency + rate = dual limiter — rate alone can't prevent pool exhaustion for slow queries",
    ],
    kills: "Malformed JSON, unknown users, rate limit exceeded, empty/oversized SQL, basic pattern mismatch",
  },
  {
    id: "parse",
    num: "②",
    title: "Parse + Cache Layer",
    subtitle: "Query Fingerprinting + LRU Cache + libpg_query",
    color: COLORS.textAccent,
    perf: "HIT: ~500ns | MISS: ~50μs",
    filterRate: "3-8%",
    components: [
      {
        name: "Query Fingerprinter",
        details: "Single-pass state machine: strip comments → normalize literals to ? → collapse IN-lists → collapse whitespace → lowercase keywords → xxHash64. Same query shape = same cache key. ~300ns",
      },
      {
        name: "Sharded LRU Parse Cache",
        details: "fingerprint_hash → shared_ptr<StatementInfo+AnalysisResult>. N shards (= CPU cores) each with own mutex → near-zero contention. 10K entries default. LRU eviction. Never needs explicit invalidation",
      },
      {
        name: "SQL Parser (libpg_query)",
        details: "On cache miss: PostgreSQL's actual parser extracted as C library. Raw SQL → Protobuf AST → our StatementInfo. Zero ambiguity — same code PG uses. Handles all edge cases",
      },
      {
        name: "Collision Guard",
        details: "64-bit hash could collide. Store normalized string alongside hash, strcmp on cache hit. 50ns cost for correctness guarantee. Non-negotiable for security proxy",
      },
    ],
    decisions: [
      "libpg_query over regex/ANTLR — it IS PostgreSQL's parser, battle-tested 20+ years, zero ambiguity",
      "Fingerprinting merges strip+normalize+collapse into one pass — no intermediate allocations",
      "IN-list normalization — #1 cache hit killer in real apps, PostgreSQL pg_stat_statements does the same",
      "Sharded LRU over lock-free map — simpler, same perf in practice, lower memory overhead per entry",
      "Cache stores AnalysisResult too — analysis is derived from parse, same shape = same analysis, skip 5μs on hit",
      "Cache never needs invalidation — stores structural analysis not query results",
    ],
    kills: "Invalid SQL syntax, unsupported statement types (EXPLAIN, COPY, VACUUM)",
  },
  {
    id: "analyze",
    num: "③",
    title: "SQL Analyzer Layer",
    subtitle: "AST → Structured Metadata (Single Walk)",
    color: COLORS.green,
    perf: "HIT: 0μs (cached) | MISS: ~5μs",
    filterRate: "1-2%",
    components: [
      {
        name: "Statement Classifier",
        details: "AST root node → StatementType (DDL/DML/SELECT) + SubType (CREATE/ALTER/DROP/INSERT/UPDATE/DELETE)",
      },
      {
        name: "Table Extractor",
        details: "Walk FROM, JOIN, INTO, UPDATE clauses. Extract: database, schema, table, alias, usage (READ/WRITE/BOTH). Handle schema-qualified names",
      },
      {
        name: "Alias Resolver",
        details: "Build alias map from FROM clause first. Then resolve all column references: a.name → customers.name. Unqualified columns in single-table → assign. In JOIN with ambiguity → mark unknown",
      },
      {
        name: "Projection Extractor (SELECT)",
        details: "Target list columns with derived_from tracking. UPPER(email) → {column:'formatted', derived_from:['email']}. Critical for classifier to catch transformed PII",
      },
      {
        name: "Write Column Extractor (DML)",
        details: "INSERT: target column list. UPDATE: SET clause targets. DELETE: whole-row (no specific columns). INSERT...SELECT: both read sources and write targets",
      },
      {
        name: "Filter Column Extractor",
        details: "WHERE and JOIN ON clause columns. For audit enrichment — reveals query INTENT (lookup vs bulk export)",
      },
      {
        name: "Schema Cache",
        details: "Preloaded table metadata from information_schema. Resolves SELECT * to actual column list. Invalidated async on DDL via RCU pointer swap. ~100ns lookup",
      },
    ],
    decisions: [
      "Separate from parser — parser answers 'valid SQL?', analyzer answers 'what does it do?'. Different concerns, independently testable",
      "Single AST walk — visit each node once, extract everything. O(n) where n = AST nodes",
      "derived_from tracking on expressions — UPPER(email) still exposes PII. Most systems miss this",
      "Schema cache for SELECT * resolution — without it, classifier is blind to actual columns",
      "Schema cache uses RCU — DDL invalidation never blocks query processing",
      "AnalysisResult embedded in parse cache entry — same shape = same analysis, zero cost on cache hit",
    ],
    kills: "Unresolvable table references, unsupported AST node types",
  },
  {
    id: "policy",
    num: "④",
    title: "Policy Engine",
    subtitle: "Radix Trie + Specificity Resolution",
    color: COLORS.orange,
    perf: "~100-400ns",
    filterRate: "15-50%",
    components: [
      {
        name: "Policy Rule Model",
        details: "Per rule: id, user/role, database/schema/table scope (with * wildcards), statement types (DDL/DML/SELECT), action (ALLOW/BLOCK), human-readable reason",
      },
      {
        name: "Radix Trie (per user/role)",
        details: "Policies precomputed into trie at config load. Lookup: walk db→schema→table, at most 4 hash lookups. O(1) regardless of rule count. Precomputed at config load, zero cost at query time",
      },
      {
        name: "Specificity System",
        details: "Weighted scoring: db(100) + schema(10) + table(1). *.*.* = 0, app.*.* = 100, app.public.* = 110, app.public.customers = 111. Highest specificity wins. BLOCK > ALLOW at same level. No match = DEFAULT DENY",
      },
      {
        name: "Multi-Table Evaluation",
        details: "Query touches N tables → ALL must be allowed. ANY denied = entire query denied. Prevents data exfiltration via JOIN with blocked table. INSERT...SELECT evaluates both read and write separately",
      },
      {
        name: "Statement-Type Scoping",
        details: "Same table can have different rules per statement type. analyst: SELECT on customers ✓, DML on customers ✗, DDL on anything ✗",
      },
      {
        name: "Hot Reload (RCU)",
        details: "Config change → build new trie → atomic pointer swap → old trie freed after grace period. In-flight requests see old config, new requests see new. Zero downtime, zero locks",
      },
    ],
    decisions: [
      "Radix trie over linear scan — O(4) vs O(N), matters at 1000+ rules",
      "Specificity scoring over simple ordering — deterministic, explainable, no rule order dependency",
      "BLOCK wins at same specificity — secure default, defense in depth",
      "Default DENY — closed world assumption. Explicit grants required. Standard security practice",
      "Per-table result in PolicyDecision — audit shows exactly which table caused denial",
      "Hot reload via RCU — policy changes without restart or request interruption",
      "Authorization only, not 'safety' — gatekeeper not detective. Clean, auditable, predictable",
    ],
    kills: "Unauthorized access per user/role/table/statement-type combination. Main filter stage",
  },
  {
    id: "execute",
    num: "⑤",
    title: "Query Executor",
    subtitle: "libpq Async + Per-DB Connection Pool + Circuit Breaker",
    color: COLORS.lime,
    perf: "1ms-10s (DB dependent)",
    filterRate: "2-8%",
    components: [
      {
        name: "Per-Database Connection Pool",
        details: "Each DB has own bounded pool. Semaphore-guarded acquire with co_await. analytics: 10 conns, app: 50 conns, staging: 5. Failure isolation — one DB down doesn't affect others",
      },
      {
        name: "Statement Branching",
        details: "SELECT: execute + fetch result set + forward to classifier. DML: execute + capture affected_rows. DDL: execute + trigger SchemaCache invalidation. Each branch returns appropriate QueryResult",
      },
      {
        name: "Query Timeout",
        details: "PG-level SET statement_timeout. If exceeded, PostgreSQL cancels server-side. Connection stays valid. Returns 504. More reliable than application-level cancel",
      },
      {
        name: "Circuit Breaker",
        details: "CLOSED→OPEN (errors > threshold) → HALF-OPEN (cooldown, try one) → CLOSED (success). Per-database state machine. When OPEN: immediate 503, no connection acquired. Lets DB recover",
      },
      {
        name: "DDL → Schema Invalidation",
        details: "Successful DDL triggers async SchemaCache refresh. Re-query information_schema, RCU swap. ~100ms staleness window — documented tradeoff",
      },
      {
        name: "Result Buffering",
        details: "Buffer entire result set with configurable max_rows (default 10K). Truncate + warn if exceeded. Production: stream rows (documented as future work)",
      },
      {
        name: "Read/Write Pool Separation (future)",
        details: "Analyzer knows statement type. Router maps SELECT → read pool (replica), DML/DDL → write pool (primary). Zero code change in other stages. Documented as architecture-ready",
      },
    ],
    decisions: [
      "libpq (raw C) over libpqxx — zero abstraction overhead for async operations",
      "Per-DB pools — failure isolation, each DB protected independently, different capacities",
      "PG-level timeout over app-level cancel — atomic, reliable, no race conditions",
      "Circuit breaker per DB — prevents cascade failure, fast-fail saves waiting on dead DB",
      "Bounded pool IS the protection — proxy protects DB from connection overload",
      "Buffer with limit over streaming — simpler, classifier needs full result set, streaming is future work",
    ],
    kills: "Pool exhausted (503), query timeout (504), circuit breaker open (503), PG runtime errors (502)",
  },
  {
    id: "classify",
    num: "⑥",
    title: "Data Classifier",
    subtitle: "Strategy Chain — Column Names + Types + Value Regex + Derived Columns",
    color: COLORS.pink,
    perf: "~1-50μs",
    filterRate: "0% (informational, never blocks)",
    components: [
      {
        name: "Classifier Registry (Strategy Chain)",
        details: "Ordered chain of IClassifier implementations. Each gets a chance per column. Highest confidence match wins. Extensible — add new classifiers without touching existing ones",
      },
      {
        name: "① ColumnNameClassifier (~10ns/col)",
        details: "Hash map lookup: email→PII.Email, phone→PII.Phone, ssn→PII.SSN. Handles: camelCase→snake_case, uppercase→lowercase, hyphen strip. Substring fallback at lower confidence",
      },
      {
        name: "② TypeOidClassifier (~5ns/col)",
        details: "PG type OID hints: INET→PII.IP, MACADDR→PII.DeviceID, custom domains. Rarely fires but shows type awareness",
      },
      {
        name: "③ RegexValueClassifier (~1-10μs/col)",
        details: "Scan actual values when column name is ambiguous ('data', 'value'). Sample 20 rows (not full scan — 250x cheaper). Email/phone/SSN/credit card/IP patterns. Uses CTRE (compile-time regex, ~100ns/match)",
      },
      {
        name: "④ DerivedColumnClassifier (~10ns/col)",
        details: "Uses derived_from from Analyzer. UPPER(email)→still PII.Email. CONCAT(first,last)→PII.Name. Scaled confidence: direct=1.0, function=0.85, aggregate=0.5. Principal-level insight most systems miss",
      },
      {
        name: "Classification Merge",
        details: "Multiple classifiers fire on same column → highest confidence wins. Both kept as evidence trail in audit. Low confidence = flag for human review",
      },
      {
        name: "Graceful Degradation",
        details: "Classifier failure → catch, log warning, return empty classifications. Query result STILL returned. Classification is visibility, not security. Never blocks",
      },
    ],
    decisions: [
      "Post-execution classification — column names alone miss 'SELECT data FROM attrs WHERE key=email'. Values reveal truth",
      "Strategy pattern registry — add ML/dictionary/entropy classifiers without code changes, just config",
      "Value sampling (20 rows) over full scan — 250x cheaper, 95%+ accuracy for homogeneous columns",
      "CTRE over std::regex — compile-time regex, ~100ns vs ~5μs per match",
      "derived_from tracking — catches UPPER(email), CONCAT(first,last). Most classification systems miss transformed PII",
      "Informational only — security enforced by Policy Engine. Classification is for compliance visibility",
      "Config-driven rules — new PII types added by config change, no recompile",
    ],
    kills: "Nothing — informational layer. Labels PII exposure for audit and response metadata",
  },
  {
    id: "audit",
    num: "⑦",
    title: "Audit Emitter",
    subtitle: "Lock-Free MPSC Ring Buffer → Multi-Sink Batch Writer",
    color: COLORS.coldPath,
    perf: "Enqueue: ~750ns | Flush: batched async",
    filterRate: "0% (records everything)",
    components: [
      {
        name: "Structured AuditEvent",
        details: "event_id (UUID v7), sequence_num (gap detection), who (user, role, IP, session), what (SQL, fingerprint, type), which data (tables, columns, projections), decision (allow/deny + rule + reason), execution (time, rows, errors), classification (PII types, sensitivity level), meta (cache_hit, proxy_version)",
      },
      {
        name: "Every-Path Emission",
        details: "Pipeline wrapper emits audit — stages cannot forget. Malformed→audit, auth fail→audit, rate limit→audit, parse error→audit, policy deny→audit, DB error→audit, success→audit. Structural guarantee, not convention",
      },
      {
        name: "MPSC Ring Buffer",
        details: "Lock-free multi-producer single-consumer. Event loop threads enqueue via atomic CAS (~50ns). 64K event capacity (~64MB). Dedicated audit thread drains. Hot path NEVER blocks",
      },
      {
        name: "Batch Writer",
        details: "Drain trigger: 1000 events OR 100ms (whichever first). Amortizes syscall cost. Single write() for file, single multi-row INSERT for DB",
      },
      {
        name: "File Sink (primary)",
        details: "JSONL format — one JSON per line. Append-only, streamable (tail -f, Filebeat, Fluentd). grep-friendly. Configurable fsync frequency. Daily rotation or size-based",
      },
      {
        name: "DB Sink (secondary)",
        details: "audit_events table with indexes on: user+time, decision+time, has_pii+time, tables (GIN), fingerprint+time. SEPARATE connection pool from query executor. Enables SQL queries on audit data",
      },
      {
        name: "Overflow Policy",
        details: "Buffer full → drop newest + increment atomic drop counter → synthetic WARNING event when buffer drains. Never blocks producers. Never loses silently. Ops alerted on drop counter",
      },
      {
        name: "What We DON'T Log",
        details: "No actual row data (audit would become PII store). No DB credentials. No full headers. No AST (fingerprint + analysis captures what matters)",
      },
    ],
    decisions: [
      "Async fire-and-forget — audit MUST NOT add latency to query response",
      "MPSC ring buffer over mutex queue — lock-free enqueue, dedicated consumer thread, zero contention",
      "File + DB sinks — file for durability/streaming, DB for queryability/dashboards. Belt and suspenders",
      "Sequence numbers for gap detection — if seq 1000 then 1002, you KNOW 1001 was lost",
      "UUID v7 (time-sortable) — merge audit streams from multiple proxy instances, maintain chronological order",
      "Separate DB pool for audit — audit writes never compete with user queries for connections",
      "session_id for correlation — reconstruct multi-statement sessions, detect exfiltration patterns",
      "fingerprint in audit — group by query shape to detect scraping (same shape, 50K executions)",
      "Don't log row data — audit is accountability, not data replication. Logging PII defeats the purpose",
    ],
    kills: "Nothing — records everything. Enables: compliance queries, anomaly detection, rule effectiveness analysis, session reconstruction",
  },
];

const crossCutting = [
  {
    name: "Arena Allocator",
    icon: "🏗️",
    color: COLORS.hotPath,
    desc: "Per-request memory arena. All allocations from one block. Free entire arena on response — O(1), zero fragmentation. No new/delete on hot path.",
  },
  {
    name: "Threading Model",
    icon: "🧵",
    color: COLORS.cyan,
    desc: "N event loop threads (= CPU cores), each runs full pipeline. No hand-off between threads. Dedicated audit writer thread. No cross-thread sync on hot path.",
  },
  {
    name: "RCU Config Reload",
    icon: "🔄",
    color: COLORS.green,
    desc: "Policy, rate limits, classifiers — all hot-reloadable. Build new config → atomic pointer swap. In-flight requests finish on old config. Zero downtime.",
  },
  {
    name: "Error Taxonomy",
    icon: "🚨",
    color: COLORS.red,
    desc: "Typed errors: ParseError(400), PolicyDenied(403), RateLimited(429), AuthError(401), ExecError(502), Timeout(504), InternalError(500). Each maps to HTTP status + audit event.",
  },
  {
    name: "Multi-DB Architecture",
    icon: "🗄️",
    color: COLORS.purple,
    desc: "Per-DB: connection pool (bounded), circuit breaker, rate limit, concurrency limit, query timeout, health check. One DB failing never affects others.",
  },
  {
    name: "Observability",
    icon: "📊",
    color: COLORS.lime,
    desc: "GET /health (DB connectivity + pool status), GET /metrics (req/sec, latency percentiles, cache hit rate, deny rate, classification stats). POST /policies/reload.",
  },
];

const scaleNumbers = [
  { value: "~3μs", label: "p50 cache-hit overhead", sub: "proxy invisible to user" },
  { value: "~60μs", label: "p50 cache-miss overhead", sub: "first-seen query shape" },
  { value: "50K+", label: "req/sec single instance", sub: "16 cores, lock-free path" },
  { value: "~80ns", label: "4-level rate limit check", sub: "all lock-free atomics" },
  { value: "~750ns", label: "audit enqueue", sub: "never blocks hot path" },
  { value: "∞", label: "horizontal scale", sub: "stateless, shared config" },
];

const filterFunnel = [
  { stage: "Ingress", pct: "100%", filtered: "10-40%", color: COLORS.cyan, reason: "malformed, auth, rate limit" },
  { stage: "Parse", pct: "60-90%", filtered: "3-8%", color: COLORS.textAccent, reason: "invalid SQL, unsupported" },
  { stage: "Analyze", pct: "55-87%", filtered: "1-2%", color: COLORS.green, reason: "unresolvable refs" },
  { stage: "Policy", pct: "53-86%", filtered: "15-50%", color: COLORS.orange, reason: "unauthorized access" },
  { stage: "Execute", pct: "30-70%", filtered: "2-8%", color: COLORS.lime, reason: "DB errors, timeouts" },
  { stage: "→ DB", pct: "25-65%", filtered: "—", color: COLORS.hotPath, reason: "only these reach the database" },
];

function FlowDiagram() {
  const stageFlow = [
    { id: "ingress", label: "Ingress", short: "Validate+Rate", color: COLORS.cyan },
    { id: "parse", label: "Parse", short: "Finger+Cache", color: COLORS.textAccent },
    { id: "analyze", label: "Analyze", short: "AST→Meta", color: COLORS.green },
    { id: "policy", label: "Policy", short: "Allow?", color: COLORS.orange },
    { id: "execute", label: "Execute", short: "→ DB", color: COLORS.lime },
    { id: "classify", label: "Classify", short: "PII?", color: COLORS.pink },
  ];

  return (
    <div style={{ marginBottom: "28px" }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "3px",
        flexWrap: "wrap",
        padding: "18px 10px",
        background: `linear-gradient(135deg, ${COLORS.bgCard}, ${COLORS.bg})`,
        borderRadius: "8px",
        border: `1px solid ${COLORS.border}`,
      }}>
        {stageFlow.map((s, i) => (
          <div key={s.id} style={{ display: "flex", alignItems: "center" }}>
            <div style={{
              display: "flex", flexDirection: "column", alignItems: "center",
              padding: "8px 11px",
              background: `${s.color}12`,
              border: `1px solid ${s.color}40`,
              borderRadius: "8px",
              minWidth: "72px",
            }}>
              <div style={{ color: s.color, fontSize: "12px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{s.label}</div>
              <div style={{ color: COLORS.textMuted, fontSize: "9px", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>{s.short}</div>
            </div>
            {i < stageFlow.length - 1 && (
              <div style={{ color: i < 4 ? COLORS.hotPath : COLORS.hotPath, fontSize: "16px", margin: "0 1px", fontWeight: 700 }}>→</div>
            )}
          </div>
        ))}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginLeft: "10px" }}>
          <div style={{ color: COLORS.coldPath, fontSize: "9px", fontFamily: "'JetBrains Mono', monospace", marginBottom: "3px" }}>async</div>
          <div style={{ color: COLORS.coldPath, fontSize: "14px" }}>⤵</div>
          <div style={{
            padding: "6px 11px",
            background: `${COLORS.coldPath}12`,
            border: `1px dashed ${COLORS.coldPath}40`,
            borderRadius: "8px",
          }}>
            <div style={{ color: COLORS.coldPath, fontSize: "12px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>Audit</div>
            <div style={{ color: COLORS.textMuted, fontSize: "9px", fontFamily: "'JetBrains Mono', monospace" }}>MPSC→Batch</div>
          </div>
        </div>
      </div>
      <div style={{ display: "flex", justifyContent: "center", gap: "20px", marginTop: "10px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <div style={{ width: "10px", height: "3px", background: COLORS.hotPath, borderRadius: "2px" }} />
          <span style={{ color: COLORS.hotPath, fontSize: "10px", fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>HOT PATH (latency-critical)</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
          <div style={{ width: "10px", height: "3px", background: COLORS.coldPath, borderRadius: "2px" }} />
          <span style={{ color: COLORS.coldPath, fontSize: "10px", fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>COLD PATH (async, batched)</span>
        </div>
      </div>
    </div>
  );
}

function FilterFunnel() {
  return (
    <div style={{
      background: COLORS.bgCard,
      border: `1px solid ${COLORS.border}`,
      borderRadius: "8px",
      padding: "18px",
      marginBottom: "24px",
    }}>
      <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "14px", fontFamily: "'JetBrains Mono', monospace" }}>
        Request Funnel — Kill Requests as Early as Possible
      </h3>
      {filterFunnel.map((f, i) => (
        <div key={f.stage} style={{ display: "flex", alignItems: "center", marginBottom: "6px", gap: "10px" }}>
          <div style={{
            width: "70px",
            color: f.color,
            fontSize: "12px",
            fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace",
            textAlign: "right",
          }}>{f.stage}</div>
          <div style={{ flex: 1, position: "relative", height: "24px" }}>
            <div style={{
              position: "absolute",
              left: 0,
              top: 0,
              height: "100%",
              width: f.pct === "100%" ? "100%" : `${parseInt(f.pct)}%`,
              background: `${f.color}20`,
              border: `1px solid ${f.color}40`,
              borderRadius: "4px",
              display: "flex",
              alignItems: "center",
              paddingLeft: "8px",
            }}>
              <span style={{ color: f.color, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                {f.pct} survive
              </span>
            </div>
          </div>
          <div style={{ width: "55px", color: COLORS.rose, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, textAlign: "center" }}>
            {f.filtered !== "—" ? `−${f.filtered}` : ""}
          </div>
          <div style={{ width: "180px", color: COLORS.textMuted, fontSize: "10px", fontFamily: "'JetBrains Mono', monospace" }}>
            {f.reason}
          </div>
        </div>
      ))}
      <div style={{ color: COLORS.textMuted, fontSize: "11px", marginTop: "12px", fontStyle: "italic", textAlign: "center" }}>
        35-75% of requests never touch the database. The expensive thing (DB I/O) is protected by every layer above it.
      </div>
    </div>
  );
}

function LayerCard({ layer, isExpanded, onToggle }) {
  return (
    <div
      onClick={onToggle}
      style={{
        background: isExpanded ? COLORS.bgCardHover : COLORS.bgCard,
        border: `1px solid ${isExpanded ? layer.color : COLORS.border}`,
        borderLeft: `3px solid ${layer.color}`,
        borderRadius: "8px",
        padding: "14px 18px",
        cursor: "pointer",
        transition: "all 0.2s ease",
        marginBottom: "6px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ color: layer.color, fontSize: "15px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {layer.num} {layer.title}
            </span>
            <span style={{
              background: `${COLORS.rose}15`,
              color: COLORS.rose,
              padding: "2px 8px",
              borderRadius: "4px",
              fontSize: "10px",
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 600,
            }}>
              filters {layer.filterRate}
            </span>
          </div>
          <div style={{ color: COLORS.textMuted, fontSize: "12px", marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
            {layer.subtitle}
          </div>
        </div>
        <div style={{
          background: `${layer.color}15`,
          color: layer.color,
          padding: "4px 10px",
          borderRadius: "4px",
          fontSize: "11px",
          fontFamily: "'JetBrains Mono', monospace",
          fontWeight: 600,
          whiteSpace: "nowrap",
        }}>
          {layer.perf}
        </div>
      </div>

      {isExpanded && (
        <div style={{ marginTop: "14px" }} onClick={(e) => e.stopPropagation()}>
          <div style={{ marginBottom: "14px" }}>
            <div style={{ color: layer.color, fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
              Components
            </div>
            {layer.components.map((c, i) => (
              <div key={i} style={{ marginBottom: "8px", paddingLeft: "12px", borderLeft: `2px solid ${layer.color}30` }}>
                <div style={{ color: COLORS.text, fontSize: "12px", fontWeight: 700 }}>{c.name}</div>
                <div style={{ color: COLORS.textMuted, fontSize: "11px", lineHeight: 1.5, marginTop: "2px" }}>{c.details}</div>
              </div>
            ))}
          </div>

          <div style={{
            background: `${layer.color}08`,
            border: `1px solid ${layer.color}20`,
            borderRadius: "6px",
            padding: "12px",
            marginBottom: "10px",
          }}>
            <div style={{ color: layer.color, fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
              Key Design Decisions
            </div>
            {layer.decisions.map((d, i) => (
              <div key={i} style={{ color: COLORS.text, fontSize: "11px", lineHeight: 1.6, paddingLeft: "14px", position: "relative", marginBottom: "4px" }}>
                <span style={{ position: "absolute", left: 0, color: layer.color }}>▸</span>
                {d}
              </div>
            ))}
          </div>

          <div style={{ color: COLORS.textMuted, fontSize: "11px", fontStyle: "italic" }}>
            <span style={{ color: COLORS.rose, fontWeight: 600, fontStyle: "normal" }}>Kills: </span>{layer.kills}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Architecture() {
  const [expandedLayer, setExpandedLayer] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "layers", label: "All Layers" },
    { id: "funnel", label: "Filter Funnel" },
    { id: "crosscut", label: "Cross-Cutting" },
  ];

  return (
    <div style={{
      background: COLORS.bg,
      color: COLORS.text,
      minHeight: "100vh",
      fontFamily: "'Inter', -apple-system, sans-serif",
      padding: "28px 22px",
      maxWidth: "920px",
      margin: "0 auto",
    }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />

      <div style={{ marginBottom: "6px" }}>
        <div style={{ color: COLORS.textMuted, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Principal-Level Architecture
        </div>
        <h1 style={{ fontSize: "26px", fontWeight: 700, color: COLORS.text, margin: "6px 0 4px", fontFamily: "'JetBrains Mono', monospace" }}>
          SQL Proxy Service
        </h1>
        <p style={{ color: COLORS.textMuted, fontSize: "13px", lineHeight: 1.5, margin: 0 }}>
          C++20 · Zero-copy pipeline · Lock-free hot path · Multi-DB · Hierarchical rate limiting · Async audit
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", margin: "20px 0" }}>
        {scaleNumbers.map((s) => (
          <div key={s.label} style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "12px",
            textAlign: "center",
          }}>
            <div style={{ color: COLORS.hotPath, fontSize: "20px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{s.value}</div>
            <div style={{ color: COLORS.text, fontSize: "11px", fontWeight: 600, marginTop: "3px" }}>{s.label}</div>
            <div style={{ color: COLORS.textMuted, fontSize: "9px", marginTop: "2px" }}>{s.sub}</div>
          </div>
        ))}
      </div>

      <FlowDiagram />

      <div style={{ display: "flex", gap: "4px", marginBottom: "14px", borderBottom: `1px solid ${COLORS.border}`, paddingBottom: "8px" }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              background: activeTab === t.id ? `${COLORS.borderAccent}20` : "transparent",
              border: `1px solid ${activeTab === t.id ? COLORS.borderAccent : "transparent"}`,
              color: activeTab === t.id ? COLORS.textAccent : COLORS.textMuted,
              padding: "7px 14px",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "12px",
              fontWeight: 600,
              fontFamily: "'JetBrains Mono', monospace",
              transition: "all 0.15s ease",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && (
        <div>
          <FilterFunnel />
          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
            marginBottom: "20px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Pipeline Latency Breakdown
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 2, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`CACHE HIT PATH (80-95% of requests):
  Ingress validate+auth+rate    1.5μs
  Parse cache lookup             0.5μs  (fingerprint+hit)
  Analyze                        0μs    (cached with parse)
  Policy trie lookup             0.3μs
  ───────────────────────────────────
  Total to DENY:                 2.3μs  ← sub-3μs rejection
  Total to reach DB:             2.3μs  ← proxy overhead before DB
  Execute (DB):                  1-1000ms
  Classify:                      1-50μs
  Audit enqueue:                 0.75μs
  ───────────────────────────────────
  Total proxy overhead:          ~4μs   ← invisible

CACHE MISS PATH (5-20% of requests):
  Ingress                        1.5μs
  Fingerprint + parse + analyze  55μs
  Policy                         0.3μs
  ───────────────────────────────────
  Total to DENY:                 57μs
  Execute (DB):                  1-1000ms
  Classify + Audit:              2-50μs
  ───────────────────────────────────
  Total proxy overhead:          ~60μs  ← still <0.01% of DB time`}</pre>
            </div>
          </div>

          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Trust Model
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`Client ──[untrusted SQL]──→ PROXY ──[trusted]──→ Database(s)

The proxy holds DB credentials with broad access.
Security is enforced by the PROXY, not by DB grants.

Three types of "safe":
  ① Syntactically valid     → Parse Layer
  ② Authorized              → Policy Engine (ALLOW/DENY)
  ③ Data exposure aware     → Classifier (labels, never blocks)

The proxy is a GATEKEEPER, not a DETECTIVE.
It enforces rules humans defined. It doesn't guess intent.`}</pre>
            </div>
          </div>
        </div>
      )}

      {activeTab === "layers" && (
        <div>
          {layers.map((layer) => (
            <LayerCard
              key={layer.id}
              layer={layer}
              isExpanded={expandedLayer === layer.id}
              onToggle={() => setExpandedLayer(expandedLayer === layer.id ? null : layer.id)}
            />
          ))}
        </div>
      )}

      {activeTab === "funnel" && (
        <div>
          <FilterFunnel />
          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
            marginBottom: "20px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Example: 1000 Requests Arrive
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 2, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`1000 requests
 │
 ├─ 150 killed at Ingress       (cost: 150 × 1.5μs = 225μs)
 │   ├─ 50 malformed JSON
 │   ├─ 30 unknown user
 │   ├─ 60 rate limited
 │   └─ 10 empty/oversized SQL
 │
 ├─ 50 killed at Parse           (cost: 50 × 50μs = 2.5ms)
 │   ├─ 40 invalid SQL syntax
 │   └─ 10 unsupported statements
 │
 ├─ 10 killed at Analyze         (cost: ~0, mostly cached)
 │   └─ 10 unresolvable references
 │
 ├─ 250 killed at Policy         (cost: 250 × 0.3μs = 75μs)
 │   ├─ 100 unauthorized table access
 │   ├─ 80 unauthorized statement type (DML/DDL)
 │   └─ 70 default deny (no rule)
 │
 ├─ 30 killed at Executor        (cost: 30 × ~10ms = 300ms)
 │   ├─ 15 query timeout
 │   ├─ 10 PG errors
 │   └─ 5 pool exhausted
 │
 └─ 510 successful               (cost: 510 × ~5ms avg = 2.55s)
     ├─ 200 with PII classified
     └─ 310 no PII detected

Summary:
  490 requests (49%) never touched the database
  Total proxy CPU cost for killed requests: ~3ms
  Total DB cost saved: 490 × ~5ms = ~2.45 seconds
  All 1000 requests audited`}</pre>
            </div>
          </div>
          
          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Multi-DB Rate Limit Hierarchy
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`Request: user="analyst", database="analytics"

  ① Global:         50K/sec budget, at 32K    → PASS  (~10ns)
  ② Per-user:       analyst 2K/sec, at 800    → PASS  (~20ns)
  ③ Per-database:   analytics 500/sec, at 480 → PASS  (~20ns)
  ④ Per-user-per-DB: analyst+analytics 50/sec → PASS  (~30ns)
  ⑤ Concurrency:    analytics 10 slots, 9 used → PASS (~100ns)

  ALL must pass. ANY fails → reject before parsing.
  Total cost: ~180ns. Cheapest rejection point.

Why each level matters:
  Global       → protects proxy CPU from DDoS
  Per-user     → prevents one user starving others
  Per-database → each DB has different capacity
  Per-user-DB  → analyst can't flood analytics DB
  Concurrency  → rate limit alone can't prevent pool exhaustion`}</pre>
            </div>
          </div>
        </div>
      )}

      {activeTab === "crosscut" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "10px", marginBottom: "20px" }}>
            {crossCutting.map((c) => (
              <div key={c.name} style={{
                background: COLORS.bgCard,
                border: `1px solid ${COLORS.border}`,
                borderRadius: "8px",
                padding: "16px",
              }}>
                <div style={{ fontSize: "20px", marginBottom: "6px" }}>{c.icon}</div>
                <div style={{ color: c.color, fontSize: "13px", fontWeight: 700, marginBottom: "6px", fontFamily: "'JetBrains Mono', monospace" }}>{c.name}</div>
                <div style={{ color: COLORS.textMuted, fontSize: "11px", lineHeight: 1.6 }}>{c.desc}</div>
              </div>
            ))}
          </div>

          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
            marginBottom: "20px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Threading Model
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`┌──────────────────────────────────────────────────┐
│  Event Loop Threads (N = CPU cores)               │
│  ┌────────┐ ┌────────┐ ┌────────┐                │
│  │ Loop 0 │ │ Loop 1 │ │ Loop N │   Drogon       │
│  │ full   │ │ full   │ │ full   │   event loops  │
│  │pipeline│ │pipeline│ │pipeline│   no hand-off   │
│  └───┬────┘ └───┬────┘ └───┬────┘                │
│      │          │          │                       │
│      └──────────┼──────────┘                       │
│                 │  lock-free MPSC                   │
│            ┌────▼─────┐                            │
│            │  Audit   │  Dedicated thread           │
│            │  Writer  │  Batch: 1000 events / 100ms │
│            └──────────┘                            │
│                                                     │
│  No cross-thread sync on hot path.                  │
│  Audit enqueue = single atomic CAS (~50ns).         │
└──────────────────────────────────────────────────┘`}</pre>
            </div>
          </div>

          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
            marginBottom: "20px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Memory Model — Per-Request Arena
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`┌───────────────────────────────────────────────┐
│            Request Arena (~1KB)                │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Context  │ │ Cached   │ │AnalysisResult│  │
│  │ user     │ │ Parse    │ │ tables[]     │  │
│  │ sql      │ │ (shared  │ │ columns[]    │  │
│  │ db       │ │  ptr)    │ │ projections  │  │
│  │ ip       │ │          │ │ derived_from │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
│  ┌──────────┐ ┌────────────────────────────┐  │
│  │ Policy   │ │ AuditEvent                 │  │
│  │ Decision │ │ (moved to MPSC on complete)│  │
│  │ rule     │ │                            │  │
│  └──────────┘ └────────────────────────────┘  │
│                                                │
│  Free entire arena on response: O(1)           │
│  No new/delete on hot path. Zero fragmentation.│
└───────────────────────────────────────────────┘`}</pre>
            </div>
          </div>

          <div style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "18px",
          }}>
            <h3 style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              Scale Story
            </h3>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8, color: COLORS.text, background: "#0d1117", padding: "14px", borderRadius: "6px" }}>
              <pre style={{ margin: 0 }}>{`VERTICAL (single instance)
├── Drogon event loops = CPU cores → linear scaling
├── Per-DB connection pools → protect each DB independently
├── Parse cache → 80-95% hit rate, skip 50μs parse
├── Arena allocator → no GC, no fragmentation
└── Lock-free hot path → no contention ceiling

HORIZONTAL (multiple instances)
├── Stateless proxy → N instances behind load balancer
├── Rate limits: divide by instance count (simple)
│   └── Future: hybrid local+periodic Redis sync
├── Shared config → file, etcd, or config service
├── Shared audit → file→Filebeat→ELK or DB→dashboard
└── Each instance: own pools, own caches, own circuit breakers

WHAT BREAKS FIRST
├── DB connections → PgBouncer / read replicas
├── Audit throughput → Kafka as buffer
├── Parse cache memory → LRU eviction (bounded)
├── Config propagation → etcd watch / push
└── Rate limit accuracy → distributed counter (Redis)`}</pre>
            </div>
          </div>
        </div>
      )}

      <div style={{
        borderTop: `1px solid ${COLORS.border}`,
        marginTop: "28px",
        paddingTop: "14px",
        color: COLORS.textMuted,
        fontSize: "10px",
        fontFamily: "'JetBrains Mono', monospace",
        textAlign: "center",
      }}>
        SQL Proxy Service — C++20 · libpg_query · Drogon · glaze · spdlog · libpq
      </div>
    </div>
  );
}
