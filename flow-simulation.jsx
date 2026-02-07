import { useState, useEffect } from "react";

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
  yellow: "#eab308",
};

const scenarios = [
  {
    id: "allowed_select_cache_hit",
    title: "✅ SELECT מותר (Cache Hit)",
    subtitle: "analyst שולח SELECT על customers — מותר, מזהים PII",
    request: {
      user: "analyst",
      role: "analyst",
      database: "app",
      sql: 'SELECT name, email, phone FROM customers WHERE id = 42',
      client_ip: "10.0.1.100",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין, שדות נדרשים קיימים",
        data: { valid: true },
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "משתמש 'analyst' מזוהה, role: analyst",
        data: { user: "analyst", role: "analyst" },
      },
      {
        layer: "Ingress",
        action: "rate_limit_global",
        status: "pass",
        duration: "0.01μs",
        detail: "Global: 32,000/50,000 req/sec",
        data: { current: 32000, limit: 50000 },
      },
      {
        layer: "Ingress",
        action: "rate_limit_user",
        status: "pass",
        duration: "0.02μs",
        detail: "Per-User: 450/2,000 req/sec",
        data: { current: 450, limit: 2000 },
      },
      {
        layer: "Ingress",
        action: "rate_limit_db",
        status: "pass",
        duration: "0.02μs",
        detail: "Per-DB (app): 5,200/10,000 req/sec",
        data: { current: 5200, limit: 10000 },
      },
      {
        layer: "Ingress",
        action: "rate_limit_user_db",
        status: "pass",
        duration: "0.03μs",
        detail: "Per-User-DB: 120/1,000 req/sec",
        data: { current: 120, limit: 1000 },
      },
      {
        layer: "Ingress",
        action: "concurrency",
        status: "pass",
        duration: "0.1μs",
        detail: "Concurrency (app): 23/50 in-flight",
        data: { current: 23, limit: 50 },
      },
      {
        layer: "Ingress",
        action: "build_context",
        status: "pass",
        duration: "0.05μs",
        detail: "RequestContext נוצר ב-Arena",
        data: { request_id: "req_7f3a2b1c", arena_size: "1KB" },
      },
      {
        layer: "Parse",
        action: "fingerprint",
        status: "pass",
        duration: "0.3μs",
        detail: "Normalized: select name,email,phone from customers where id=?",
        data: { hash: "0x7F3A2B1C", normalized: "select name,email,phone from customers where id=?" },
      },
      {
        layer: "Parse",
        action: "cache_lookup",
        status: "hit",
        duration: "0.15μs",
        detail: "✓ Cache HIT — חוסכים ~50μs של parsing",
        data: { cache_hit: true, cache_size: 1847, shard: 3 },
      },
      {
        layer: "Analyze",
        action: "cached",
        status: "pass",
        duration: "0μs",
        detail: "AnalysisResult משוך מה-cache יחד עם Parse",
        data: { tables: ["public.customers"], columns: ["name", "email", "phone"] },
      },
      {
        layer: "Policy",
        action: "lookup_trie",
        status: "pass",
        duration: "0.1μs",
        detail: "Trie lookup: app.public.customers",
        data: { path: "app → public → customers", depth: 3 },
      },
      {
        layer: "Policy",
        action: "evaluate",
        status: "allow",
        duration: "0.2μs",
        detail: "✓ ALLOW — rule_020: Analysts can query public schema",
        data: { rule: "rule_020", action: "ALLOW", specificity: 110, stmt_type: "SELECT" },
      },
      {
        layer: "Execute",
        action: "pool_acquire",
        status: "pass",
        duration: "0.5μs",
        detail: "Connection acquired from app pool (slot #7)",
        data: { pool: "app", slot: 7, pool_size: 50, in_use: 24 },
      },
      {
        layer: "Execute",
        action: "query",
        status: "pass",
        duration: "2.3ms",
        detail: "Query executed on PostgreSQL",
        data: { rows: 1, columns: 3, exec_time_ms: 2.3 },
      },
      {
        layer: "Execute",
        action: "pool_release",
        status: "pass",
        duration: "0.1μs",
        detail: "Connection returned to pool",
        data: { slot: 7 },
      },
      {
        layer: "Classify",
        action: "column_name",
        status: "detect",
        duration: "0.03μs",
        detail: "Column 'email' → PII.Email (confidence: 1.0)",
        data: { column: "email", type: "PII.Email", confidence: 1.0, classifier: "column_name" },
      },
      {
        layer: "Classify",
        action: "column_name",
        status: "detect",
        duration: "0.02μs",
        detail: "Column 'phone' → PII.Phone (confidence: 1.0)",
        data: { column: "phone", type: "PII.Phone", confidence: 1.0, classifier: "column_name" },
      },
      {
        layer: "Audit",
        action: "build_event",
        status: "pass",
        duration: "0.2μs",
        detail: "AuditEvent נבנה עם כל המידע",
        data: { event_id: "evt_a1b2c3d4", sequence: 847291 },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event נכנס ל-MPSC buffer (atomic CAS)",
        data: { buffer_size: 342, buffer_capacity: 65536 },
      },
      {
        layer: "Response",
        action: "serialize",
        status: "success",
        duration: "0.4μs",
        detail: "200 OK — תוצאות + classifications",
        data: { status: 200, rows: 1, has_pii: true, pii_types: ["PII.Email", "PII.Phone"] },
      },
    ],
    response: {
      status: "allowed",
      http_code: 200,
      statement_type: "SELECT",
      tables: ["public.customers"],
      classifications: [
        { column: "email", type: "PII.Email" },
        { column: "phone", type: "PII.Phone" },
      ],
      result: {
        columns: ["name", "email", "phone"],
        rows: [["John Doe", "john@example.com", "555-0142"]],
      },
      execution_time_ms: 2.3,
      proxy_overhead_us: 4.1,
      audit_id: "evt_a1b2c3d4",
    },
    total_time: "~2.3ms (DB: 2.3ms, Proxy: 4.1μs)",
  },
  {
    id: "denied_dml",
    title: "🚫 UPDATE נדחה (Policy Deny)",
    subtitle: "analyst מנסה לעדכן customers — נחסם על ידי policy",
    request: {
      user: "analyst",
      role: "analyst",
      database: "app",
      sql: "UPDATE customers SET email = 'new@test.com' WHERE id = 42",
      client_ip: "10.0.1.100",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין",
        data: { valid: true },
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "משתמש 'analyst' מזוהה",
        data: { user: "analyst", role: "analyst" },
      },
      {
        layer: "Ingress",
        action: "rate_limit_all",
        status: "pass",
        duration: "0.08μs",
        detail: "כל 4 רמות Rate Limit עברו",
        data: { global: "pass", user: "pass", db: "pass", user_db: "pass" },
      },
      {
        layer: "Ingress",
        action: "concurrency",
        status: "pass",
        duration: "0.1μs",
        detail: "Concurrency OK",
        data: { current: 23, limit: 50 },
      },
      {
        layer: "Parse",
        action: "fingerprint",
        status: "pass",
        duration: "0.3μs",
        detail: "Normalized: update customers set email=? where id=?",
        data: { hash: "0xB2C3D4E5", normalized: "update customers set email=? where id=?" },
      },
      {
        layer: "Parse",
        action: "cache_lookup",
        status: "hit",
        duration: "0.15μs",
        detail: "✓ Cache HIT",
        data: { cache_hit: true },
      },
      {
        layer: "Analyze",
        action: "cached",
        status: "pass",
        duration: "0μs",
        detail: "stmt_type: DML, target: customers, write_columns: [email]",
        data: { stmt_type: "DML", sub_type: "UPDATE", target: "customers", write_cols: ["email"] },
      },
      {
        layer: "Policy",
        action: "lookup_trie",
        status: "pass",
        duration: "0.1μs",
        detail: "Trie lookup: app.public.customers + DML",
        data: { path: "app → public → customers", stmt_type: "DML" },
      },
      {
        layer: "Policy",
        action: "evaluate",
        status: "deny",
        duration: "0.15μs",
        detail: "✗ DENY — rule_022: Customer data protected from analyst DML",
        data: { rule: "rule_022", action: "BLOCK", specificity: 111, reason: "Customer data is protected from analyst modifications" },
      },
      {
        layer: "Audit",
        action: "build_event",
        status: "pass",
        duration: "0.2μs",
        detail: "AuditEvent עם decision: DENY",
        data: { event_id: "evt_e5f6g7h8", decision: "DENY", matched_rule: "rule_022" },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event נכנס ל-buffer",
        data: { buffer_size: 343 },
      },
      {
        layer: "Response",
        action: "serialize",
        status: "denied",
        duration: "0.3μs",
        detail: "403 Forbidden — Policy Denied",
        data: { status: 403, reason: "Customer data is protected from analyst modifications" },
      },
    ],
    response: {
      status: "denied",
      http_code: 403,
      statement_type: "DML",
      tables: ["public.customers"],
      reason: "Customer data is protected from analyst modifications",
      matched_rule: "rule_022",
      audit_id: "evt_e5f6g7h8",
    },
    total_time: "~1.5μs (DB: 0, Proxy: 1.5μs)",
    note: "השאילתה נחסמה לפני שהגיעה ל-DB — אפס עלות",
  },
  {
    id: "parse_error",
    title: "❌ שגיאת Parse",
    subtitle: "SQL לא תקין — נופל ב-Parse Layer",
    request: {
      user: "analyst",
      role: "analyst",
      database: "app",
      sql: "SELCT * FORM customers",
      client_ip: "10.0.1.100",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין",
        data: { valid: true },
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "משתמש מזוהה",
        data: { user: "analyst" },
      },
      {
        layer: "Ingress",
        action: "rate_limit_all",
        status: "pass",
        duration: "0.08μs",
        detail: "Rate limits עברו",
        data: {},
      },
      {
        layer: "Parse",
        action: "fingerprint",
        status: "pass",
        duration: "0.25μs",
        detail: "Fingerprint נוצר (גם ל-SQL שבור)",
        data: { hash: "0xDEADBEEF" },
      },
      {
        layer: "Parse",
        action: "cache_lookup",
        status: "miss",
        duration: "0.15μs",
        detail: "Cache MISS — צורה חדשה",
        data: { cache_hit: false },
      },
      {
        layer: "Parse",
        action: "libpg_query",
        status: "error",
        duration: "12μs",
        detail: "✗ Parse Error: syntax error at position 0, unexpected 'SELCT'",
        data: { error: "syntax error", position: 0, token: "SELCT" },
      },
      {
        layer: "Audit",
        action: "build_event",
        status: "pass",
        duration: "0.2μs",
        detail: "AuditEvent עם decision: ERROR",
        data: { event_id: "evt_bad12345", decision: "ERROR", error_type: "ParseError" },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event נכנס ל-buffer",
        data: {},
      },
      {
        layer: "Response",
        action: "serialize",
        status: "error",
        duration: "0.3μs",
        detail: "400 Bad Request — Parse Error",
        data: { status: 400, error: "syntax error at position 0" },
      },
    ],
    response: {
      status: "error",
      http_code: 400,
      error: "SQL parse error: syntax error at position 0, unexpected 'SELCT'",
      audit_id: "evt_bad12345",
    },
    total_time: "~13μs (Parse failed)",
    note: "SQL לא תקין — נעצר לפני Policy, לפני DB",
  },
  {
    id: "rate_limited",
    title: "⏱️ Rate Limited",
    subtitle: "משתמש חרג מהמכסה שלו",
    request: {
      user: "bot_scraper",
      role: "readonly",
      database: "app",
      sql: "SELECT * FROM customers",
      client_ip: "10.0.1.200",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין",
        data: { valid: true },
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "משתמש 'bot_scraper' מזוהה",
        data: { user: "bot_scraper", role: "readonly" },
      },
      {
        layer: "Ingress",
        action: "rate_limit_global",
        status: "pass",
        duration: "0.01μs",
        detail: "Global: OK",
        data: { current: 32000, limit: 50000 },
      },
      {
        layer: "Ingress",
        action: "rate_limit_user",
        status: "fail",
        duration: "0.02μs",
        detail: "✗ Per-User EXCEEDED: 1,005/1,000 req/sec",
        data: { current: 1005, limit: 1000, exceeded: true },
      },
      {
        layer: "Audit",
        action: "build_event",
        status: "pass",
        duration: "0.2μs",
        detail: "AuditEvent עם decision: DENY (rate_limited)",
        data: { event_id: "evt_rate1234", decision: "DENY", reason: "rate_limit_user" },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event נכנס ל-buffer",
        data: {},
      },
      {
        layer: "Response",
        action: "serialize",
        status: "rate_limited",
        duration: "0.2μs",
        detail: "429 Too Many Requests",
        data: { status: 429, retry_after: 1 },
      },
    ],
    response: {
      status: "denied",
      http_code: 429,
      error: "Rate limit exceeded: user 'bot_scraper' at 1005/1000 req/sec",
      retry_after: 1,
      audit_id: "evt_rate1234",
    },
    total_time: "~1μs (rejected at Ingress)",
    note: "נעצר בשכבה הראשונה — הכי זול שאפשר!",
  },
  {
    id: "cache_miss_full_flow",
    title: "🔄 Cache Miss — Full Parse",
    subtitle: "שאילתה חדשה — עוברת parse מלא",
    request: {
      user: "admin",
      role: "admin",
      database: "analytics",
      sql: "SELECT customer_id, SUM(amount) as total FROM orders GROUP BY customer_id HAVING SUM(amount) > 1000",
      client_ip: "10.0.1.50",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין",
        data: { valid: true },
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "Admin מזוהה — הרשאות מלאות",
        data: { user: "admin", role: "admin" },
      },
      {
        layer: "Ingress",
        action: "rate_limit_all",
        status: "pass",
        duration: "0.08μs",
        detail: "Admin: rate limits גבוהים יותר",
        data: { user_limit: 10000 },
      },
      {
        layer: "Ingress",
        action: "concurrency",
        status: "pass",
        duration: "0.1μs",
        detail: "Analytics pool: 3/10 in-flight",
        data: { current: 3, limit: 10 },
      },
      {
        layer: "Parse",
        action: "fingerprint",
        status: "pass",
        duration: "0.4μs",
        detail: "Normalized: select customer_id,sum(amount) as total from orders group by customer_id having sum(amount)>?",
        data: { hash: "0xNEWQUERY" },
      },
      {
        layer: "Parse",
        action: "cache_lookup",
        status: "miss",
        duration: "0.2μs",
        detail: "✗ Cache MISS — צורה חדשה, צריך parse מלא",
        data: { cache_hit: false, cache_size: 1847 },
      },
      {
        layer: "Parse",
        action: "libpg_query",
        status: "pass",
        duration: "48μs",
        detail: "libpg_query parse — AST נוצר",
        data: { ast_nodes: 23, parse_time_us: 48 },
      },
      {
        layer: "Analyze",
        action: "walk_ast",
        status: "pass",
        duration: "5μs",
        detail: "Single AST walk — extract tables, columns, aggregations",
        data: { tables: ["orders"], projections: ["customer_id", "total"], has_aggregation: true, has_group_by: true },
      },
      {
        layer: "Parse",
        action: "cache_insert",
        status: "pass",
        duration: "0.3μs",
        detail: "StatementInfo + AnalysisResult נשמרים ב-cache",
        data: { cache_size: 1848 },
      },
      {
        layer: "Policy",
        action: "evaluate",
        status: "allow",
        duration: "0.1μs",
        detail: "✓ ALLOW — rule_001: Admin has full access",
        data: { rule: "rule_001", action: "ALLOW", specificity: 0 },
      },
      {
        layer: "Execute",
        action: "pool_acquire",
        status: "pass",
        duration: "0.8μs",
        detail: "Connection from analytics pool (slot #2)",
        data: { pool: "analytics", slot: 2, pool_size: 10 },
      },
      {
        layer: "Execute",
        action: "query",
        status: "pass",
        duration: "127ms",
        detail: "Heavy aggregation query on analytics DB",
        data: { rows: 342, exec_time_ms: 127, scanned_rows: 1500000 },
      },
      {
        layer: "Execute",
        action: "pool_release",
        status: "pass",
        duration: "0.1μs",
        detail: "Connection returned",
        data: {},
      },
      {
        layer: "Classify",
        action: "scan_columns",
        status: "clean",
        duration: "0.02μs",
        detail: "No PII detected — customer_id ו-total הם לא PII",
        data: { classifications: [], has_pii: false },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event לתיעוד — כולל cache_miss flag",
        data: { event_id: "evt_admin999", cache_hit: false },
      },
      {
        layer: "Response",
        action: "serialize",
        status: "success",
        duration: "1.2μs",
        detail: "200 OK — 342 rows",
        data: { status: 200, rows: 342 },
      },
    ],
    response: {
      status: "allowed",
      http_code: 200,
      statement_type: "SELECT",
      tables: ["orders"],
      classifications: [],
      result: {
        columns: ["customer_id", "total"],
        row_count: 342,
      },
      execution_time_ms: 127,
      proxy_overhead_us: 56,
      cache_hit: false,
      audit_id: "evt_admin999",
    },
    total_time: "~127ms (DB: 127ms, Proxy: 56μs including parse)",
    note: "Parse לקח 48μs — בפעם הבאה יהיה cache hit",
  },
  {
    id: "circuit_breaker_open",
    title: "💥 Circuit Breaker Open",
    subtitle: "DB לא זמין — fast-fail",
    request: {
      user: "analyst",
      role: "analyst",
      database: "analytics",
      sql: "SELECT * FROM reports",
      client_ip: "10.0.1.100",
    },
    steps: [
      {
        layer: "Ingress",
        action: "validate",
        status: "pass",
        duration: "0.3μs",
        detail: "JSON תקין",
        data: {},
      },
      {
        layer: "Ingress",
        action: "authenticate",
        status: "pass",
        duration: "0.2μs",
        detail: "משתמש מזוהה",
        data: {},
      },
      {
        layer: "Ingress",
        action: "rate_limit_all",
        status: "pass",
        duration: "0.08μs",
        detail: "Rate limits OK",
        data: {},
      },
      {
        layer: "Parse",
        action: "cache_lookup",
        status: "hit",
        duration: "0.4μs",
        detail: "Cache HIT",
        data: { cache_hit: true },
      },
      {
        layer: "Policy",
        action: "evaluate",
        status: "allow",
        duration: "0.15μs",
        detail: "ALLOW — analyst יכול לקרוא מ-reports",
        data: { rule: "rule_025", action: "ALLOW" },
      },
      {
        layer: "Execute",
        action: "circuit_check",
        status: "fail",
        duration: "0.02μs",
        detail: "✗ Circuit Breaker OPEN — analytics DB down since 30s ago",
        data: { circuit_state: "OPEN", db: "analytics", open_since: "30s", error_count: 15, threshold: 5 },
      },
      {
        layer: "Audit",
        action: "enqueue",
        status: "pass",
        duration: "0.05μs",
        detail: "Event עם circuit_breaker_open flag",
        data: { event_id: "evt_circuit1", circuit_open: true },
      },
      {
        layer: "Response",
        action: "serialize",
        status: "error",
        duration: "0.2μs",
        detail: "503 Service Unavailable — DB temporarily down",
        data: { status: 503, retry_after: 30 },
      },
    ],
    response: {
      status: "error",
      http_code: 503,
      error: "Database 'analytics' temporarily unavailable (circuit breaker open)",
      retry_after: 30,
      audit_id: "evt_circuit1",
    },
    total_time: "~1.4μs (fast-fail, no DB wait)",
    note: "Circuit Breaker מונע המתנה של 5+ שניות לtimeout!",
  },
];

const layerColors = {
  Ingress: COLORS.cyan,
  Parse: COLORS.textAccent,
  Analyze: COLORS.green,
  Policy: COLORS.orange,
  Execute: COLORS.lime,
  Classify: COLORS.pink,
  Audit: COLORS.coldPath,
  Response: COLORS.hotPath,
};

const statusColors = {
  pass: COLORS.green,
  hit: COLORS.green,
  miss: COLORS.yellow,
  allow: COLORS.green,
  deny: COLORS.red,
  fail: COLORS.red,
  error: COLORS.red,
  detect: COLORS.pink,
  clean: COLORS.textMuted,
  success: COLORS.green,
  denied: COLORS.red,
  rate_limited: COLORS.orange,
};

const statusIcons = {
  pass: "✓",
  hit: "⚡",
  miss: "○",
  allow: "✓",
  deny: "✗",
  fail: "✗",
  error: "✗",
  detect: "🔍",
  clean: "·",
  success: "✓",
  denied: "✗",
  rate_limited: "⏱",
};

function StepRow({ step, index, isActive, isComplete }) {
  const layerColor = layerColors[step.layer] || COLORS.textMuted;
  const statusColor = statusColors[step.status] || COLORS.textMuted;
  const statusIcon = statusIcons[step.status] || "·";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        padding: "10px 14px",
        background: isActive ? `${layerColor}15` : isComplete ? COLORS.bgCard : `${COLORS.bg}`,
        borderLeft: `3px solid ${isActive ? layerColor : isComplete ? `${layerColor}60` : COLORS.border}`,
        borderBottom: `1px solid ${COLORS.border}`,
        opacity: isComplete || isActive ? 1 : 0.4,
        transition: "all 0.3s ease",
      }}
    >
      <div style={{ width: "28px", textAlign: "center", marginRight: "10px" }}>
        <span style={{ color: COLORS.textMuted, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>
          {String(index + 1).padStart(2, "0")}
        </span>
      </div>

      <div style={{ width: "70px", marginRight: "10px" }}>
        <span
          style={{
            color: layerColor,
            fontSize: "11px",
            fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          {step.layer}
        </span>
      </div>

      <div style={{ width: "120px", marginRight: "10px" }}>
        <span style={{ color: COLORS.text, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>
          {step.action}
        </span>
      </div>

      <div style={{ width: "50px", marginRight: "10px", textAlign: "center" }}>
        <span
          style={{
            color: statusColor,
            fontSize: "12px",
            fontWeight: 700,
          }}
        >
          {statusIcon}
        </span>
      </div>

      <div style={{ width: "60px", marginRight: "10px", textAlign: "right" }}>
        <span
          style={{
            color: COLORS.hotPath,
            fontSize: "10px",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          {step.duration}
        </span>
      </div>

      <div style={{ flex: 1 }}>
        <div style={{ color: COLORS.text, fontSize: "11px", lineHeight: 1.5 }}>{step.detail}</div>
        {step.data && Object.keys(step.data).length > 0 && (
          <div
            style={{
              marginTop: "4px",
              padding: "4px 8px",
              background: COLORS.bg,
              borderRadius: "4px",
              fontSize: "10px",
              fontFamily: "'JetBrains Mono', monospace",
              color: COLORS.textMuted,
            }}
          >
            {Object.entries(step.data)
              .slice(0, 4)
              .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`)
              .join(" | ")}
          </div>
        )}
      </div>
    </div>
  );
}

function RequestBox({ request }) {
  return (
    <div
      style={{
        background: COLORS.bgCard,
        border: `1px solid ${COLORS.cyan}40`,
        borderRadius: "8px",
        padding: "14px",
        marginBottom: "16px",
      }}
    >
      <div style={{ color: COLORS.cyan, fontSize: "11px", fontWeight: 700, marginBottom: "8px", fontFamily: "'JetBrains Mono', monospace" }}>
        📥 INCOMING REQUEST
      </div>
      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", lineHeight: 1.8 }}>
        <div>
          <span style={{ color: COLORS.textMuted }}>user: </span>
          <span style={{ color: COLORS.text }}>{request.user}</span>
          <span style={{ color: COLORS.textMuted }}> (role: {request.role})</span>
        </div>
        <div>
          <span style={{ color: COLORS.textMuted }}>database: </span>
          <span style={{ color: COLORS.text }}>{request.database}</span>
        </div>
        <div>
          <span style={{ color: COLORS.textMuted }}>client_ip: </span>
          <span style={{ color: COLORS.text }}>{request.client_ip}</span>
        </div>
        <div style={{ marginTop: "8px" }}>
          <span style={{ color: COLORS.textMuted }}>sql: </span>
          <div
            style={{
              marginTop: "4px",
              padding: "8px",
              background: COLORS.bg,
              borderRadius: "4px",
              color: COLORS.yellow,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {request.sql}
          </div>
        </div>
      </div>
    </div>
  );
}

function ResponseBox({ response, isSuccess }) {
  const bgColor = isSuccess ? COLORS.green : response.http_code === 403 || response.http_code === 429 ? COLORS.orange : COLORS.red;

  return (
    <div
      style={{
        background: COLORS.bgCard,
        border: `1px solid ${bgColor}40`,
        borderRadius: "8px",
        padding: "14px",
        marginTop: "16px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
        <div style={{ color: bgColor, fontSize: "11px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
          📤 RESPONSE
        </div>
        <div
          style={{
            background: `${bgColor}20`,
            color: bgColor,
            padding: "4px 10px",
            borderRadius: "4px",
            fontSize: "12px",
            fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          HTTP {response.http_code}
        </div>
      </div>
      <div
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "10px",
          lineHeight: 1.7,
          background: COLORS.bg,
          padding: "10px",
          borderRadius: "4px",
          maxHeight: "200px",
          overflow: "auto",
        }}
      >
        <pre style={{ margin: 0, color: COLORS.text, whiteSpace: "pre-wrap" }}>{JSON.stringify(response, null, 2)}</pre>
      </div>
    </div>
  );
}

function ScenarioSelector({ scenarios, activeId, onSelect }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "20px" }}>
      {scenarios.map((s) => (
        <button
          key={s.id}
          onClick={() => onSelect(s.id)}
          style={{
            background: activeId === s.id ? `${COLORS.borderAccent}30` : COLORS.bgCard,
            border: `1px solid ${activeId === s.id ? COLORS.borderAccent : COLORS.border}`,
            color: activeId === s.id ? COLORS.textAccent : COLORS.textMuted,
            padding: "8px 14px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: 600,
            transition: "all 0.15s ease",
          }}
        >
          {s.title}
        </button>
      ))}
    </div>
  );
}

function TimelineSummary({ scenario }) {
  const layerTimes = {};
  scenario.steps.forEach((s) => {
    const time = parseFloat(s.duration) || 0;
    const unit = s.duration.includes("ms") ? 1000 : s.duration.includes("μs") ? 1 : 0.001;
    layerTimes[s.layer] = (layerTimes[s.layer] || 0) + time * unit;
  });

  const layers = ["Ingress", "Parse", "Analyze", "Policy", "Execute", "Classify", "Audit", "Response"];

  return (
    <div
      style={{
        display: "flex",
        gap: "4px",
        padding: "12px",
        background: COLORS.bgCard,
        borderRadius: "8px",
        marginBottom: "16px",
        overflowX: "auto",
      }}
    >
      {layers.map((layer, i) => {
        const hasLayer = scenario.steps.some((s) => s.layer === layer);
        const failed = scenario.steps.some((s) => s.layer === layer && ["deny", "fail", "error"].includes(s.status));
        const color = layerColors[layer];

        return (
          <div key={layer} style={{ display: "flex", alignItems: "center" }}>
            <div
              style={{
                padding: "6px 10px",
                background: hasLayer ? (failed ? `${COLORS.red}20` : `${color}15`) : COLORS.bg,
                border: `1px solid ${hasLayer ? (failed ? COLORS.red : color) : COLORS.border}40`,
                borderRadius: "6px",
                opacity: hasLayer ? 1 : 0.3,
              }}
            >
              <div style={{ color: hasLayer ? (failed ? COLORS.red : color) : COLORS.textMuted, fontSize: "10px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
                {layer}
              </div>
              {hasLayer && failed && <div style={{ color: COLORS.red, fontSize: "14px", textAlign: "center" }}>✗</div>}
              {hasLayer && !failed && <div style={{ color: color, fontSize: "14px", textAlign: "center" }}>✓</div>}
            </div>
            {i < layers.length - 1 && (
              <div
                style={{
                  width: "20px",
                  height: "2px",
                  background: hasLayer && scenario.steps.some((s) => s.layer === layers[i + 1]) ? COLORS.hotPath : COLORS.border,
                  margin: "0 2px",
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function FlowSimulation() {
  const [activeScenario, setActiveScenario] = useState(scenarios[0].id);
  const [currentStep, setCurrentStep] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playSpeed, setPlaySpeed] = useState(300);

  const scenario = scenarios.find((s) => s.id === activeScenario);

  useEffect(() => {
    setCurrentStep(-1);
    setIsPlaying(false);
  }, [activeScenario]);

  useEffect(() => {
    if (!isPlaying) return;

    if (currentStep >= scenario.steps.length - 1) {
      setIsPlaying(false);
      return;
    }

    const timer = setTimeout(() => {
      setCurrentStep((prev) => prev + 1);
    }, playSpeed);

    return () => clearTimeout(timer);
  }, [isPlaying, currentStep, scenario, playSpeed]);

  const handlePlay = () => {
    if (currentStep >= scenario.steps.length - 1) {
      setCurrentStep(-1);
    }
    setIsPlaying(true);
  };

  const handlePause = () => setIsPlaying(false);
  const handleReset = () => {
    setCurrentStep(-1);
    setIsPlaying(false);
  };
  const handleStepForward = () => {
    if (currentStep < scenario.steps.length - 1) {
      setCurrentStep((prev) => prev + 1);
    }
  };
  const handleShowAll = () => setCurrentStep(scenario.steps.length - 1);

  const isSuccess = scenario.response.http_code === 200;

  return (
    <div
      style={{
        background: COLORS.bg,
        color: COLORS.text,
        minHeight: "100vh",
        fontFamily: "'Inter', -apple-system, sans-serif",
        padding: "24px 20px",
        maxWidth: "1000px",
        margin: "0 auto",
      }}
    >
      <link
        href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap"
        rel="stylesheet"
      />

      <div style={{ marginBottom: "20px" }}>
        <div style={{ color: COLORS.textMuted, fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          SQL Proxy — Request Flow Simulation
        </div>
        <h1 style={{ fontSize: "22px", fontWeight: 700, color: COLORS.text, margin: "6px 0", fontFamily: "'JetBrains Mono', monospace" }}>
          {scenario.title}
        </h1>
        <p style={{ color: COLORS.textMuted, fontSize: "13px", margin: 0 }}>{scenario.subtitle}</p>
      </div>

      <ScenarioSelector scenarios={scenarios} activeId={activeScenario} onSelect={setActiveScenario} />

      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", alignItems: "center" }}>
        <button
          onClick={isPlaying ? handlePause : handlePlay}
          style={{
            background: COLORS.borderAccent,
            border: "none",
            color: COLORS.text,
            padding: "8px 16px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
            fontWeight: 600,
          }}
        >
          {isPlaying ? "⏸ Pause" : "▶ Play"}
        </button>
        <button
          onClick={handleStepForward}
          style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            color: COLORS.text,
            padding: "8px 12px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
          }}
        >
          Step →
        </button>
        <button
          onClick={handleReset}
          style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            color: COLORS.text,
            padding: "8px 12px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
          }}
        >
          Reset
        </button>
        <button
          onClick={handleShowAll}
          style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            color: COLORS.text,
            padding: "8px 12px",
            borderRadius: "6px",
            cursor: "pointer",
            fontSize: "12px",
          }}
        >
          Show All
        </button>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ color: COLORS.textMuted, fontSize: "11px" }}>Speed:</span>
          <input
            type="range"
            min="50"
            max="800"
            value={800 - playSpeed}
            onChange={(e) => setPlaySpeed(800 - parseInt(e.target.value))}
            style={{ width: "80px" }}
          />
        </div>
      </div>

      <TimelineSummary scenario={scenario} />

      <RequestBox request={scenario.request} />

      <div
        style={{
          background: COLORS.bgCard,
          border: `1px solid ${COLORS.border}`,
          borderRadius: "8px",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            padding: "10px 14px",
            background: COLORS.bg,
            borderBottom: `1px solid ${COLORS.border}`,
            fontSize: "10px",
            fontWeight: 700,
            color: COLORS.textMuted,
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          <div style={{ width: "28px", marginRight: "10px", textAlign: "center" }}>#</div>
          <div style={{ width: "70px", marginRight: "10px" }}>LAYER</div>
          <div style={{ width: "120px", marginRight: "10px" }}>ACTION</div>
          <div style={{ width: "50px", marginRight: "10px", textAlign: "center" }}>STATUS</div>
          <div style={{ width: "60px", marginRight: "10px", textAlign: "right" }}>TIME</div>
          <div style={{ flex: 1 }}>DETAILS</div>
        </div>

        {scenario.steps.map((step, index) => (
          <StepRow key={index} step={step} index={index} isActive={index === currentStep} isComplete={index <= currentStep} />
        ))}
      </div>

      {currentStep >= scenario.steps.length - 1 && <ResponseBox response={scenario.response} isSuccess={isSuccess} />}

      <div
        style={{
          marginTop: "16px",
          padding: "14px",
          background: COLORS.bgCard,
          borderRadius: "8px",
          border: `1px solid ${COLORS.border}`,
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <span style={{ color: COLORS.textMuted, fontSize: "11px" }}>Total Time: </span>
            <span style={{ color: COLORS.hotPath, fontSize: "13px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
              {scenario.total_time}
            </span>
          </div>
          <div>
            <span style={{ color: COLORS.textMuted, fontSize: "11px" }}>Steps: </span>
            <span style={{ color: COLORS.text, fontSize: "13px", fontWeight: 600 }}>
              {Math.min(currentStep + 1, scenario.steps.length)} / {scenario.steps.length}
            </span>
          </div>
        </div>
        {scenario.note && (
          <div style={{ marginTop: "8px", color: COLORS.textAccent, fontSize: "12px", fontStyle: "italic" }}>
            💡 {scenario.note}
          </div>
        )}
      </div>
    </div>
  );
}
