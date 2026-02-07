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
};

const stages = [
  {
    id: "ingress",
    title: "① Ingress Layer",
    subtitle: "Drogon Async HTTP / io_uring",
    color: COLORS.cyan,
    details: [
      "Non-blocking event loop (epoll/io_uring)",
      "Zero-copy request body parsing",
      "Per-user rate limiter (token bucket, lock-free)",
      "TLS termination at edge",
      "Request → RequestContext arena allocation",
    ],
    perf: "~2μs per request accept",
    principle: "Never block the event loop. Every byte of the request is handled without copying into intermediate buffers.",
  },
  {
    id: "parse",
    title: "② SQL Parse + Cache",
    subtitle: "libpg_query + LRU Parse Cache",
    color: COLORS.textAccent,
    details: [
      "Parameterized query fingerprinting (normalize literals → cache key)",
      "LRU cache: same structure = skip re-parse (80%+ hit rate typical)",
      "Parse once → immutable AST (shared_ptr, no copies downstream)",
      "Cache miss: libpg_query parse → protobuf AST → our StatementInfo",
      "Parse errors short-circuit immediately → audit + error response",
    ],
    perf: "Cache hit: ~200ns | Cache miss: ~50μs",
    principle: "Most apps send the same query shapes repeatedly. Cache the parse, not the result.",
  },
  {
    id: "analyze",
    title: "③ SQL Analyzer",
    subtitle: "AST → Structured Metadata",
    color: COLORS.green,
    details: [
      "Walk AST once: extract statement type, tables, columns, projections",
      "Resolve table aliases → canonical names",
      "Detect cross-schema references",
      "For DML: identify affected columns (INSERT cols, UPDATE SET targets)",
      "For SELECT: extract WHERE predicates for audit enrichment",
    ],
    perf: "~5μs per analysis (single AST walk)",
    principle: "Single-pass extraction. Every downstream stage reads from the same immutable AnalysisResult.",
  },
  {
    id: "policy",
    title: "④ Policy Engine",
    subtitle: "Radix Trie + Precomputed Rules",
    color: COLORS.orange,
    details: [
      "Policies loaded into radix trie: db.schema.table → O(1) lookup",
      "Specificity: db.schema.table > db.schema.* > db.* > *",
      "BLOCK always wins at same specificity level",
      "Default DENY (closed world assumption)",
      "Statement-type scoping: policy can target DDL/DML/SELECT independently",
      "Hot-reload: atomic swap of trie pointer (RCU-style, zero downtime)",
    ],
    perf: "~100ns per policy evaluation",
    principle: "Policy evaluation is the gate. It must be the fastest stage. Precompute everything at config load time.",
  },
  {
    id: "execute",
    title: "⑤ Query Executor",
    subtitle: "libpq Async + Connection Pool",
    color: COLORS.lime,
    details: [
      "Bounded connection pool (semaphore-guarded, no mutex on hot path)",
      "Async query dispatch via libpq PQsendQuery",
      "Coroutine suspension: co_await connection.execute(sql)",
      "Read/write pool separation (future: route SELECTs to replicas)",
      "Circuit breaker: if DB errors spike → fast-fail without pool exhaustion",
      "Query timeout enforcement (cancel long-running queries)",
    ],
    perf: "Pool acquire: ~500ns | Query: depends on DB",
    principle: "The proxy should never be the bottleneck. The DB is always slower. Don't add overhead.",
  },
  {
    id: "classify",
    title: "⑥ Data Classifier",
    subtitle: "Strategy Chain on Result Set",
    color: COLORS.pink,
    details: [
      "Runs ONLY on SELECT results (post-execution)",
      "Classifier registry: ordered chain of IClassifier strategies",
      "ColumnNameClassifier: email→PII.Email, phone→PII.Phone (O(1) hash lookup)",
      "RegexValueClassifier: pattern match on first N rows (sampling, not full scan)",
      "Classification attached to response metadata, not blocking",
      "Extensible: add ML classifier, dictionary, custom rules without code changes",
    ],
    perf: "~10μs for column-name | ~100μs with value sampling",
    principle: "Classification is informational, never blocks. Degrade gracefully on failure.",
  },
  {
    id: "audit",
    title: "⑦ Audit Emitter",
    subtitle: "Async MPSC → Batch Writer",
    color: COLORS.coldPath,
    details: [
      "FIRE AND FORGET from hot path → lock-free MPSC ring buffer",
      "Dedicated audit thread: drain buffer → batch write",
      "Multi-sink: JSON file (append, fsync batch) + DB table (bulk INSERT)",
      "Structured event: user, SQL, tables, decision, classification, latency",
      "Back-pressure: if sinks slow down, buffer grows (bounded) → drop policy",
      "Audit NEVER blocks or slows the query response",
    ],
    perf: "Enqueue: ~50ns (lock-free) | Flush: batched every 100ms or 1000 events",
    principle: "Audit is critical for compliance but must be invisible to latency. Async everything.",
  },
];

const architectureLayers = [
  {
    title: "HOT PATH (Latency-Critical)",
    color: COLORS.hotPath,
    ids: ["ingress", "parse", "analyze", "policy", "execute", "classify"],
    desc: "Every microsecond matters. Zero allocations, zero locks, zero copies on the critical path.",
  },
  {
    title: "COLD PATH (Async, Batched)",
    color: COLORS.coldPath,
    ids: ["audit"],
    desc: "Fire-and-forget via lock-free queue. Never blocks the hot path.",
  },
];

const designPrinciples = [
  {
    icon: "⚡",
    title: "Zero-Copy Pipeline",
    desc: "RequestContext allocated from arena. All stages read shared immutable data. No copying between stages.",
  },
  {
    icon: "🔒",
    title: "Lock-Free Hot Path",
    desc: "No mutexes on request path. Atomic operations only. MPSC queues for cross-thread communication.",
  },
  {
    icon: "🏗️",
    title: "Arena Allocator",
    desc: "Per-request memory arena. All allocations for a request come from one block. Free entire arena on response — no fragmentation.",
  },
  {
    icon: "🔄",
    title: "RCU Config Reload",
    desc: "Policy/config changes swap an atomic pointer. In-flight requests see old config. New requests see new. Zero downtime.",
  },
  {
    icon: "📊",
    title: "Separation of Concerns",
    desc: "Hot path = latency. Cold path = durability. They share data via lock-free queues, never block each other.",
  },
  {
    icon: "🧩",
    title: "Plugin Architecture",
    desc: "Every stage is an interface. Swap SQL parser, add classifiers, change audit sinks — without touching the pipeline.",
  },
];

const scaleNumbers = [
  { value: "~100μs", label: "p50 proxy overhead", sub: "(excluding DB query time)" },
  { value: "~500μs", label: "p99 proxy overhead", sub: "(with parse cache miss)" },
  { value: "50K+", label: "queries/sec", sub: "(single instance, 16 cores)" },
  { value: "0", label: "allocations on cache hit", sub: "(arena pre-allocated)" },
  { value: "<1KB", label: "memory per request", sub: "(arena block size)" },
  { value: "∞", label: "horizontal scale", sub: "(stateless proxy, shared DB)" },
];

function StageCard({ stage, isExpanded, onToggle }) {
  return (
    <div
      onClick={onToggle}
      style={{
        background: isExpanded ? COLORS.bgCardHover : COLORS.bgCard,
        border: `1px solid ${isExpanded ? stage.color : COLORS.border}`,
        borderLeft: `3px solid ${stage.color}`,
        borderRadius: "8px",
        padding: "16px 20px",
        cursor: "pointer",
        transition: "all 0.2s ease",
        marginBottom: "8px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ color: stage.color, fontSize: "16px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
            {stage.title}
          </div>
          <div style={{ color: COLORS.textMuted, fontSize: "13px", marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
            {stage.subtitle}
          </div>
        </div>
        <div style={{
          background: `${stage.color}15`,
          color: stage.color,
          padding: "4px 10px",
          borderRadius: "4px",
          fontSize: "12px",
          fontFamily: "'JetBrains Mono', monospace",
          fontWeight: 600,
          whiteSpace: "nowrap",
        }}>
          {stage.perf}
        </div>
      </div>

      {isExpanded && (
        <div style={{ marginTop: "14px" }}>
          <div style={{
            background: `${stage.color}08`,
            border: `1px solid ${stage.color}25`,
            borderRadius: "6px",
            padding: "12px 14px",
            marginBottom: "12px",
          }}>
            <div style={{ color: stage.color, fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>
              Design Principle
            </div>
            <div style={{ color: COLORS.text, fontSize: "13px", lineHeight: 1.5, fontStyle: "italic" }}>
              {stage.principle}
            </div>
          </div>

          {stage.details.map((d, i) => (
            <div key={i} style={{
              color: COLORS.text,
              fontSize: "13px",
              lineHeight: 1.7,
              paddingLeft: "16px",
              position: "relative",
            }}>
              <span style={{ position: "absolute", left: 0, color: stage.color }}>›</span>
              {d}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FlowDiagram() {
  const stageColors = {
    ingress: COLORS.cyan,
    parse: COLORS.textAccent,
    analyze: COLORS.green,
    policy: COLORS.orange,
    execute: COLORS.lime,
    classify: COLORS.pink,
    audit: COLORS.coldPath,
  };

  const flowStages = [
    { id: "ingress", label: "Ingress", short: "HTTP" },
    { id: "parse", label: "Parse", short: "SQL→AST" },
    { id: "analyze", label: "Analyze", short: "Extract" },
    { id: "policy", label: "Policy", short: "Allow?" },
    { id: "execute", label: "Execute", short: "DB" },
    { id: "classify", label: "Classify", short: "PII?" },
  ];

  return (
    <div style={{ marginBottom: "32px" }}>
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "4px",
        flexWrap: "wrap",
        padding: "20px 10px",
        background: `linear-gradient(135deg, ${COLORS.bgCard}, ${COLORS.bg})`,
        borderRadius: "8px",
        border: `1px solid ${COLORS.border}`,
      }}>
        {flowStages.map((s, i) => (
          <div key={s.id} style={{ display: "flex", alignItems: "center" }}>
            <div style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              padding: "10px 14px",
              background: `${stageColors[s.id]}12`,
              border: `1px solid ${stageColors[s.id]}40`,
              borderRadius: "8px",
              minWidth: "80px",
            }}>
              <div style={{ color: stageColors[s.id], fontSize: "13px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
                {s.label}
              </div>
              <div style={{ color: COLORS.textMuted, fontSize: "10px", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                {s.short}
              </div>
            </div>
            {i < flowStages.length - 1 && (
              <div style={{ color: COLORS.hotPath, fontSize: "18px", margin: "0 2px", fontWeight: 700 }}>→</div>
            )}
          </div>
        ))}

        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginLeft: "12px" }}>
          <div style={{ color: COLORS.coldPath, fontSize: "10px", fontFamily: "'JetBrains Mono', monospace", marginBottom: "4px" }}>
            async
          </div>
          <div style={{ color: COLORS.coldPath, fontSize: "16px" }}>⤵</div>
          <div style={{
            padding: "8px 14px",
            background: `${COLORS.coldPath}12`,
            border: `1px dashed ${COLORS.coldPath}40`,
            borderRadius: "8px",
          }}>
            <div style={{ color: COLORS.coldPath, fontSize: "13px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              Audit
            </div>
            <div style={{ color: COLORS.textMuted, fontSize: "10px", fontFamily: "'JetBrains Mono', monospace" }}>
              MPSC→Batch
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "center", gap: "24px", marginTop: "12px" }}>
        {architectureLayers.map((l) => (
          <div key={l.title} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <div style={{ width: "10px", height: "3px", background: l.color, borderRadius: "2px" }} />
            <span style={{ color: l.color, fontSize: "11px", fontWeight: 600, fontFamily: "'JetBrains Mono', monospace" }}>
              {l.title}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function MemoryModel() {
  return (
    <div style={{
      background: COLORS.bgCard,
      border: `1px solid ${COLORS.border}`,
      borderRadius: "8px",
      padding: "20px",
      marginBottom: "24px",
    }}>
      <h3 style={{ color: COLORS.textAccent, fontSize: "15px", fontWeight: 700, marginBottom: "14px", fontFamily: "'JetBrains Mono', monospace" }}>
        Memory Model — Per-Request Arena
      </h3>
      <div style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: "12px",
        lineHeight: 1.8,
        color: COLORS.text,
        background: "#0d1117",
        padding: "16px",
        borderRadius: "6px",
        overflowX: "auto",
      }}>
        <pre style={{ margin: 0 }}>{`┌─────────────────────────────────────────────────┐
│              Request Arena (~1KB)                │
│  ┌──────────┐ ┌────────────┐ ┌───────────────┐  │
│  │ Context  │ │ ParseCache │ │ AnalysisResult│  │
│  │ user_id  │ │  (shared   │ │  stmt_type    │  │
│  │ raw_sql  │ │   ptr to   │ │  tables[]     │  │
│  │ client_ip│ │   cached   │ │  columns[]    │  │
│  │ session  │ │   AST)     │ │  projections  │  │
│  └──────────┘ └────────────┘ └───────────────┘  │
│  ┌──────────────┐  ┌──────────────────────────┐  │
│  │PolicyDecision│  │ AuditEvent (moved to     │  │
│  │ ALLOW/DENY   │  │ MPSC buffer on complete) │  │
│  │ matched_rule │  │                          │  │
│  └──────────────┘  └──────────────────────────┘  │
│                                                   │
│  free entire arena on response ← ONE operation   │
└─────────────────────────────────────────────────┘`}</pre>
      </div>
      <div style={{ color: COLORS.textMuted, fontSize: "12px", marginTop: "10px", lineHeight: 1.6 }}>
        No <code style={{ color: COLORS.hotPath }}>new</code> / <code style={{ color: COLORS.hotPath }}>delete</code> on the hot path.
        Arena allocates from a pre-allocated slab. Entire request memory freed in O(1) — single pointer reset. Zero fragmentation.
      </div>
    </div>
  );
}

function ThreadModel() {
  return (
    <div style={{
      background: COLORS.bgCard,
      border: `1px solid ${COLORS.border}`,
      borderRadius: "8px",
      padding: "20px",
      marginBottom: "24px",
    }}>
      <h3 style={{ color: COLORS.orange, fontSize: "15px", fontWeight: 700, marginBottom: "14px", fontFamily: "'JetBrains Mono', monospace" }}>
        Threading Model
      </h3>
      <div style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: "12px",
        lineHeight: 1.8,
        color: COLORS.text,
        background: "#0d1117",
        padding: "16px",
        borderRadius: "6px",
        overflowX: "auto",
      }}>
        <pre style={{ margin: 0 }}>{`┌─────────────────────────────────────────────────────┐
│  Event Loop Threads (N = CPU cores)                 │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐               │
│  │ Loop 0  │ │ Loop 1  │ │ Loop N  │  ← Drogon     │
│  │ accept  │ │ accept  │ │ accept  │    event loops │
│  │ parse   │ │ parse   │ │ parse   │                │
│  │ analyze │ │ analyze │ │ analyze │  Each handles  │
│  │ policy  │ │ policy  │ │ policy  │  full pipeline │
│  │ execute │ │ execute │ │ execute │  (no hand-off) │
│  │ classify│ │ classify│ │ classify│                │
│  └────┬────┘ └────┬────┘ └────┬────┘               │
│       │           │           │                      │
│       └───────────┼───────────┘                      │
│                   │  lock-free MPSC                   │
│              ┌────▼─────┐                            │
│              │  Audit   │  ← Dedicated thread        │
│              │  Writer  │    Batch flush every 100ms  │
│              │  Thread  │    or 1000 events           │
│              └──────────┘                            │
└─────────────────────────────────────────────────────┘

No cross-thread synchronization on hot path.
Audit enqueue = single atomic CAS operation.`}</pre>
      </div>
    </div>
  );
}

function PolicyTrie() {
  return (
    <div style={{
      background: COLORS.bgCard,
      border: `1px solid ${COLORS.border}`,
      borderRadius: "8px",
      padding: "20px",
      marginBottom: "24px",
    }}>
      <h3 style={{ color: COLORS.orange, fontSize: "15px", fontWeight: 700, marginBottom: "14px", fontFamily: "'JetBrains Mono', monospace" }}>
        Policy Resolution — Radix Trie
      </h3>
      <div style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: "12px",
        lineHeight: 1.8,
        color: COLORS.text,
        background: "#0d1117",
        padding: "16px",
        borderRadius: "6px",
        overflowX: "auto",
      }}>
        <pre style={{ margin: 0 }}>{`User "analyst" policy lookup for: app.public.customers (SELECT)

                        ┌──────┐
                        │  *   │ → (no rule = DEFAULT DENY)
                        └──┬───┘
                           │
                      ┌────▼───┐
                      │  app   │ → ALLOW (DDL,DML,SELECT)
                      └────┬───┘
                           │
                   ┌───────▼──────┐
                   │  app.public  │ → (inherits from parent)
                   └───────┬──────┘
                           │
            ┌──────────────▼────────────────┐
            │  app.public.customers         │ → ALLOW SELECT
            │  app.public.audit_log         │ → BLOCK *
            │  app.public.orders            │ → ALLOW SELECT,DML
            └───────────────────────────────┘

Resolution: Walk from most specific → root.
            First match wins.
            BLOCK > ALLOW at same level.
            No match anywhere = DENY.

Complexity: O(depth) = O(3) constant for db.schema.table`}</pre>
      </div>
    </div>
  );
}

export default function Architecture() {
  const [expandedStage, setExpandedStage] = useState("parse");
  const [activeTab, setActiveTab] = useState("pipeline");

  const tabs = [
    { id: "pipeline", label: "Pipeline Stages" },
    { id: "memory", label: "Memory Model" },
    { id: "threading", label: "Threading" },
    { id: "policy", label: "Policy Engine" },
  ];

  return (
    <div style={{
      background: COLORS.bg,
      color: COLORS.text,
      minHeight: "100vh",
      fontFamily: "'Inter', -apple-system, sans-serif",
      padding: "32px 24px",
      maxWidth: "900px",
      margin: "0 auto",
    }}>
      <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />

      {/* Header */}
      <div style={{ marginBottom: "8px" }}>
        <div style={{ color: COLORS.textMuted, fontSize: "12px", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Architecture Design
        </div>
        <h1 style={{
          fontSize: "28px",
          fontWeight: 700,
          color: COLORS.text,
          margin: "8px 0 4px",
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          SQL Proxy Service
        </h1>
        <p style={{ color: COLORS.textMuted, fontSize: "14px", lineHeight: 1.6, margin: "4px 0 0" }}>
          High-performance SQL interception layer — zero-copy pipeline, lock-free hot path, async audit
        </p>
      </div>

      {/* Scale Numbers */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        gap: "10px",
        margin: "24px 0",
      }}>
        {scaleNumbers.map((s) => (
          <div key={s.label} style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: "8px",
            padding: "14px",
            textAlign: "center",
          }}>
            <div style={{ color: COLORS.hotPath, fontSize: "22px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {s.value}
            </div>
            <div style={{ color: COLORS.text, fontSize: "12px", fontWeight: 600, marginTop: "4px" }}>
              {s.label}
            </div>
            <div style={{ color: COLORS.textMuted, fontSize: "10px", marginTop: "2px" }}>
              {s.sub}
            </div>
          </div>
        ))}
      </div>

      {/* Flow Diagram */}
      <FlowDiagram />

      {/* Tabs */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px", borderBottom: `1px solid ${COLORS.border}`, paddingBottom: "8px" }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              background: activeTab === t.id ? `${COLORS.borderAccent}20` : "transparent",
              border: `1px solid ${activeTab === t.id ? COLORS.borderAccent : "transparent"}`,
              color: activeTab === t.id ? COLORS.textAccent : COLORS.textMuted,
              padding: "8px 16px",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "13px",
              fontWeight: 600,
              fontFamily: "'JetBrains Mono', monospace",
              transition: "all 0.15s ease",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "pipeline" && (
        <div>
          {stages.map((stage) => (
            <StageCard
              key={stage.id}
              stage={stage}
              isExpanded={expandedStage === stage.id}
              onToggle={() => setExpandedStage(expandedStage === stage.id ? null : stage.id)}
            />
          ))}
        </div>
      )}
      {activeTab === "memory" && <MemoryModel />}
      {activeTab === "threading" && <ThreadModel />}
      {activeTab === "policy" && <PolicyTrie />}

      {/* Design Principles */}
      <div style={{ marginTop: "32px" }}>
        <h2 style={{ color: COLORS.text, fontSize: "18px", fontWeight: 700, marginBottom: "16px", fontFamily: "'JetBrains Mono', monospace" }}>
          Core Design Principles
        </h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "10px" }}>
          {designPrinciples.map((p) => (
            <div key={p.title} style={{
              background: COLORS.bgCard,
              border: `1px solid ${COLORS.border}`,
              borderRadius: "8px",
              padding: "16px",
            }}>
              <div style={{ fontSize: "20px", marginBottom: "6px" }}>{p.icon}</div>
              <div style={{ color: COLORS.text, fontSize: "14px", fontWeight: 700, marginBottom: "6px" }}>
                {p.title}
              </div>
              <div style={{ color: COLORS.textMuted, fontSize: "12px", lineHeight: 1.6 }}>
                {p.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Key Design Decisions */}
      <div style={{ marginTop: "32px" }}>
        <h2 style={{ color: COLORS.text, fontSize: "18px", fontWeight: 700, marginBottom: "16px", fontFamily: "'JetBrains Mono', monospace" }}>
          Key Design Decisions
        </h2>
        <div style={{
          background: COLORS.bgCard,
          border: `1px solid ${COLORS.border}`,
          borderRadius: "8px",
          padding: "20px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "13px",
          lineHeight: 2,
        }}>
          {[
            { q: "Why libpg_query over regex/ANTLR?", a: "It IS PostgreSQL's parser. Zero ambiguity, handles all edge cases, battle-tested in production PG for 20+ years." },
            { q: "Why arena allocator over standard new/delete?", a: "Per-request arena means zero fragmentation, O(1) cleanup, cache-friendly sequential allocation. malloc is ~50ns, arena bump is ~2ns." },
            { q: "Why radix trie for policies?", a: "Hierarchical lookup (db→schema→table) maps naturally to a trie. O(depth) lookup where depth is always ≤3. Precomputed at load time." },
            { q: "Why MPSC queue for audit?", a: "Audit must never block queries. Lock-free enqueue from N event loops to 1 writer thread. Batch writes amortize I/O syscall cost." },
            { q: "Why Drogon over Boost.Beast/custom?", a: "#1 C++ framework on TechEmpower. Built-in coroutine support, connection pooling, non-blocking I/O. Don't reinvent infrastructure." },
            { q: "Why stateless proxy?", a: "Horizontal scaling: spin up N proxies behind a load balancer. No shared state between instances. Policy config is read-only (loaded from file/service)." },
          ].map((d) => (
            <div key={d.q} style={{ marginBottom: "12px" }}>
              <div style={{ color: COLORS.textAccent, fontWeight: 700 }}>{d.q}</div>
              <div style={{ color: COLORS.textMuted, paddingLeft: "12px" }}>{d.a}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Scale Story */}
      <div style={{ marginTop: "32px", marginBottom: "32px" }}>
        <h2 style={{ color: COLORS.text, fontSize: "18px", fontWeight: 700, marginBottom: "16px", fontFamily: "'JetBrains Mono', monospace" }}>
          Scale Story
        </h2>
        <div style={{
          background: COLORS.bgCard,
          border: `1px solid ${COLORS.border}`,
          borderRadius: "8px",
          padding: "20px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "12px",
          lineHeight: 1.8,
          color: COLORS.text,
        }}>
          <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{`VERTICAL SCALE (single instance)
├── Drogon event loops = CPU cores → linear throughput scaling
├── Connection pool bounds → protect DB from overload  
├── Parse cache → eliminate redundant work (80%+ hit rate)
└── Arena allocator → no GC pauses, no fragmentation

HORIZONTAL SCALE (multiple instances)
├── Stateless proxy → N instances behind load balancer
├── Shared policy config → file, etcd, or config service
├── Shared audit sink → centralized log aggregator (Kafka/S3)
└── DB connection pooling per-instance → PgBouncer if needed

WHAT BREAKS FIRST (and how to fix)
├── DB connections → PgBouncer / read replicas / connection limit
├── Audit write throughput → Kafka as intermediate buffer
├── Parse cache memory → LRU eviction, bounded size
└── Policy config propagation → etcd watch / config service push`}</pre>
        </div>
      </div>

      <div style={{
        borderTop: `1px solid ${COLORS.border}`,
        paddingTop: "16px",
        color: COLORS.textMuted,
        fontSize: "11px",
        fontFamily: "'JetBrains Mono', monospace",
        textAlign: "center",
      }}>
        SQL Proxy Service — Principal-Level Architecture — C++20
      </div>
    </div>
  );
}
