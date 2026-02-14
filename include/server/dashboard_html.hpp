#pragma once
namespace sqlproxy {
inline const char* kDashboardHtml = R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQL Proxy Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#e1e4ed;--dim:#8b8fa3;--accent:#6c63ff;--green:#22c55e;--red:#ef4444;--yellow:#eab308}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
header{display:flex;align-items:center;justify-content:space-between;padding:12px 24px;background:var(--card);border-bottom:1px solid var(--border)}
header h1{font-size:18px;font-weight:600;letter-spacing:-.3px}
header h1 span{color:var(--accent)}
.token-bar{display:flex;align-items:center;gap:8px}
.token-bar input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;width:260px;font-size:13px}
.token-bar button{background:var(--accent);color:#fff;border:none;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
.token-bar button:hover{opacity:.85}
#status{font-size:12px;padding:2px 10px;border-radius:10px;font-weight:500}
.connected{background:rgba(34,197,94,.15);color:var(--green)}
.disconnected{background:rgba(239,68,68,.15);color:var(--red)}
main{padding:20px 24px;display:flex;flex-direction:column;gap:16px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.stat-card .label{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:4px}
.stat-card .value{font-size:28px;font-weight:700}
.stat-card .value.green{color:var(--green)}.stat-card .value.red{color:var(--red)}.stat-card .value.yellow{color:var(--yellow)}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px}
.card h2{font-size:14px;font-weight:600;margin-bottom:12px;color:var(--dim)}
.chart-wrap{position:relative;height:220px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:500}
td{padding:6px 10px;border-bottom:1px solid var(--border)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-allow{background:rgba(34,197,94,.15);color:var(--green)}
.badge-block{background:rgba(239,68,68,.15);color:var(--red)}
.badge-mask{background:rgba(234,179,8,.15);color:var(--yellow)}
.badge-warn{background:rgba(234,179,8,.15);color:var(--yellow)}
.badge-crit{background:rgba(239,68,68,.15);color:var(--red)}
.alert-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.alert-row:last-child{border:none}
.empty{color:var(--dim);font-style:italic;padding:16px 0;text-align:center}
</style>
</head>
<body>
<header>
  <h1><span>SQL</span> Proxy Dashboard</h1>
  <div class="token-bar">
    <input id="token" type="password" placeholder="Admin token">
    <button onclick="connectDashboard()">Connect</button>
    <span id="status" class="disconnected">Disconnected</span>
  </div>
</header>
<main>
  <section class="stats-grid">
    <div class="stat-card"><div class="label">Allowed</div><div class="value green" id="s-allowed">--</div></div>
    <div class="stat-card"><div class="label">Blocked</div><div class="value red" id="s-blocked">--</div></div>
    <div class="stat-card"><div class="label">Rate Limited</div><div class="value yellow" id="s-ratelimit">--</div></div>
    <div class="stat-card"><div class="label">Auth Rejected</div><div class="value red" id="s-authreject">--</div></div>
    <div class="stat-card"><div class="label">Brute Force</div><div class="value red" id="s-bruteforce">--</div></div>
    <div class="stat-card"><div class="label">Audit Emitted</div><div class="value" id="s-emitted">--</div></div>
    <div class="stat-card"><div class="label">Audit Written</div><div class="value" id="s-written">--</div></div>
    <div class="stat-card"><div class="label">Audit Overflow</div><div class="value red" id="s-overflow">--</div></div>
    <div class="stat-card"><div class="label">Active Alerts</div><div class="value yellow" id="s-alerts">--</div></div>
  </section>
  <section class="grid-2">
    <div class="card"><h2>Request Rate (live)</h2><div class="chart-wrap"><canvas id="rateChart"></canvas></div></div>
    <div class="card"><h2>Audit Stats</h2><div class="chart-wrap"><canvas id="auditChart"></canvas></div></div>
  </section>
  <section class="grid-2">
    <div class="card"><h2>Policies</h2><div id="policies-table"><div class="empty">Connect to load</div></div></div>
    <div class="card"><h2>Users</h2><div id="users-table"><div class="empty">Connect to load</div></div></div>
  </section>
  <section class="card">
    <h2>Active Alerts</h2>
    <div id="alerts-list"><div class="empty">Connect to load</div></div>
  </section>
</main>
<script>
const MAX_POINTS = 60;
let evtSource = null;
const ts = [], allowed = [], blocked = [], ratelimited = [], emitted = [], written = [], overflow = [];

const chartOpts = (title) => ({
  responsive: true, maintainAspectRatio: false, animation: { duration: 200 },
  plugins: { legend: { labels: { color: '#8b8fa3', font: { size: 11 } } } },
  scales: {
    x: { ticks: { color: '#8b8fa3', maxTicksLimit: 8, font: { size: 10 } }, grid: { color: '#2a2d3a' } },
    y: { beginAtZero: true, ticks: { color: '#8b8fa3', font: { size: 10 } }, grid: { color: '#2a2d3a' } }
  }
});

const rateChart = new Chart(document.getElementById('rateChart'), {
  type: 'line', data: {
    labels: ts,
    datasets: [
      { label: 'Allowed', data: allowed, borderColor: '#22c55e', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false },
      { label: 'Blocked', data: blocked, borderColor: '#ef4444', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false },
      { label: 'Rate Limited', data: ratelimited, borderColor: '#eab308', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false }
    ]
  }, options: chartOpts()
});

const auditChart = new Chart(document.getElementById('auditChart'), {
  type: 'line', data: {
    labels: ts,
    datasets: [
      { label: 'Emitted', data: emitted, borderColor: '#6c63ff', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false },
      { label: 'Written', data: written, borderColor: '#22c55e', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false },
      { label: 'Overflow', data: overflow, borderColor: '#ef4444', borderWidth: 1.5, pointRadius: 0, tension: .3, fill: false }
    ]
  }, options: chartOpts()
});

function authHeaders() { return { 'Authorization': 'Bearer ' + document.getElementById('token').value }; }

function pushPoint(d) {
  const t = d.timestamp ? d.timestamp.substring(11, 19) : new Date().toLocaleTimeString();
  ts.push(t);
  allowed.push(d.requests_allowed || 0);
  blocked.push(d.requests_blocked || 0);
  ratelimited.push(d.rate_limit_rejects || 0);
  emitted.push(d.audit_emitted || 0);
  written.push(d.audit_written || 0);
  overflow.push(d.audit_overflow || 0);
  if (ts.length > MAX_POINTS) { [ts, allowed, blocked, ratelimited, emitted, written, overflow].forEach(a => a.shift()); }
  rateChart.update(); auditChart.update();
  document.getElementById('s-allowed').textContent = d.requests_allowed ?? '--';
  document.getElementById('s-blocked').textContent = d.requests_blocked ?? '--';
  document.getElementById('s-ratelimit').textContent = d.rate_limit_rejects ?? '--';
  document.getElementById('s-authreject').textContent = d.auth_rejects ?? '--';
  document.getElementById('s-bruteforce').textContent = d.brute_force_blocks ?? '--';
  document.getElementById('s-emitted').textContent = d.audit_emitted ?? '--';
  document.getElementById('s-written').textContent = d.audit_written ?? '--';
  document.getElementById('s-overflow').textContent = d.audit_overflow ?? '--';
  document.getElementById('s-alerts').textContent = d.active_alerts ?? '--';
}

function actionBadge(a) {
  const cls = { allow: 'badge-allow', block: 'badge-block', mask: 'badge-mask' }[a] || 'badge-allow';
  return `<span class="badge ${cls}">${a}</span>`;
}

function severityBadge(s) {
  const cls = { warning: 'badge-warn', critical: 'badge-crit' }[s] || 'badge-warn';
  return `<span class="badge ${cls}">${s}</span>`;
}

async function apiFetch(path) {
  const r = await fetch(path, { headers: authHeaders() });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

async function loadPolicies() {
  try {
    const data = await apiFetch('/dashboard/api/policies');
    const rows = Array.isArray(data) ? data : (data.policies || []);
    if (!rows.length) { document.getElementById('policies-table').innerHTML = '<div class="empty">No policies</div>'; return; }
    let html = '<table><tr><th>Name</th><th>Database</th><th>Table</th><th>Action</th><th>Priority</th><th>Roles</th></tr>';
    rows.forEach(p => {
      html += `<tr><td>${p.name||'--'}</td><td>${p.database||'*'}</td><td>${p.table||p.object||'*'}</td><td>${actionBadge(p.action||'allow')}</td><td>${p.priority??'--'}</td><td>${(p.roles||[]).join(', ')||'--'}</td></tr>`;
    });
    document.getElementById('policies-table').innerHTML = html + '</table>';
  } catch(e) { document.getElementById('policies-table').innerHTML = `<div class="empty">Error: ${e.message}</div>`; }
}

async function loadUsers() {
  try {
    const data = await apiFetch('/dashboard/api/users');
    const rows = Array.isArray(data) ? data : (data.users || []);
    if (!rows.length) { document.getElementById('users-table').innerHTML = '<div class="empty">No users</div>'; return; }
    let html = '<table><tr><th>User</th><th>Roles</th></tr>';
    rows.forEach(u => {
      html += `<tr><td>${u.username||u.name||'--'}</td><td>${(u.roles||[]).join(', ')||'--'}</td></tr>`;
    });
    document.getElementById('users-table').innerHTML = html + '</table>';
  } catch(e) { document.getElementById('users-table').innerHTML = `<div class="empty">Error: ${e.message}</div>`; }
}

async function loadAlerts() {
  try {
    const data = await apiFetch('/dashboard/api/alerts');
    const rows = Array.isArray(data) ? data : (data.active || data.alerts || []);
    if (!rows.length) { document.getElementById('alerts-list').innerHTML = '<div class="empty">No active alerts</div>'; return; }
    let html = '';
    rows.forEach(a => {
      html += `<div class="alert-row"><span>${a.rule||a.name||'Alert'}: ${a.message||a.description||''}</span>${severityBadge(a.severity||'warning')}</div>`;
    });
    document.getElementById('alerts-list').innerHTML = html;
  } catch(e) { document.getElementById('alerts-list').innerHTML = `<div class="empty">Error: ${e.message}</div>`; }
}

function connectDashboard() {
  if (evtSource) { evtSource.close(); }
  const token = document.getElementById('token').value;
  if (!token) { alert('Enter an admin token'); return; }

  loadPolicies(); loadUsers(); loadAlerts();
  setInterval(() => { loadAlerts(); }, 15000);

  const url = `/dashboard/api/metrics/stream?token=${encodeURIComponent(token)}`;
  evtSource = new EventSource(url);
  evtSource.onmessage = (e) => { try { pushPoint(JSON.parse(e.data)); } catch(_){} };
  evtSource.onopen = () => {
    document.getElementById('status').className = 'connected';
    document.getElementById('status').textContent = 'Connected';
  };
  evtSource.onerror = () => {
    document.getElementById('status').className = 'disconnected';
    document.getElementById('status').textContent = 'Disconnected';
  };
}

document.getElementById('token').addEventListener('keydown', (e) => { if (e.key === 'Enter') connectDashboard(); });
</script>
</body>
</html>
)HTML";

inline const char* kPlaygroundHtml = R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SQL Proxy - Query Playground</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/theme/material-darker.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/sql/sql.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/hint/show-hint.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/hint/sql-hint.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/hint/show-hint.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#e1e4ed;--dim:#8b8fa3;--accent:#6c63ff;--green:#22c55e;--red:#ef4444;--yellow:#eab308}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column}
header{display:flex;align-items:center;justify-content:space-between;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--border);flex-shrink:0}
header h1{font-size:16px;font-weight:600}header h1 span{color:var(--accent)}
header a{color:var(--dim);text-decoration:none;font-size:13px}header a:hover{color:var(--text)}
.toolbar{display:flex;gap:8px;padding:10px 20px;background:var(--card);border-bottom:1px solid var(--border);flex-shrink:0;align-items:center}
.toolbar input,.toolbar select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
.toolbar input.wide{flex:1;min-width:200px}
.toolbar button{border:none;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;color:#fff}
.toolbar button:hover{opacity:.85}
.btn-run{background:var(--green)}.btn-dry{background:var(--accent)}.btn-nl{background:#e97316}
.main-area{display:flex;flex:1;overflow:hidden}
.sidebar{width:240px;background:var(--card);border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;padding:12px}
.sidebar h3{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:8px;font-weight:500}
.schema-table{margin-bottom:10px}
.schema-table summary{cursor:pointer;font-size:13px;font-weight:500;padding:4px 0;color:var(--text)}
.schema-table summary:hover{color:var(--accent)}
.schema-col{font-size:12px;color:var(--dim);padding:2px 0 2px 16px;cursor:pointer}
.schema-col:hover{color:var(--text)}
.schema-col .type{color:#6c63ff88;margin-left:4px;font-size:11px}
.schema-col .pk{color:var(--yellow);font-size:10px;margin-left:4px}
.editor-area{display:flex;flex-direction:column;flex:1;overflow:hidden}
.editor-wrap{flex:0 0 280px;overflow:hidden;border-bottom:1px solid var(--border)}
.CodeMirror{height:100%!important;font-size:14px;background:var(--bg)}
.results-area{flex:1;overflow:auto;padding:12px 20px}
.results-area h3{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:8px}
.results-table{width:100%;border-collapse:collapse;font-size:13px}
.results-table th{text-align:left;padding:6px 10px;border-bottom:2px solid var(--border);color:var(--dim);font-size:11px;text-transform:uppercase;font-weight:600;position:sticky;top:0;background:var(--bg)}
.results-table td{padding:5px 10px;border-bottom:1px solid var(--border);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.results-table tr:hover td{background:var(--card)}
.msg{padding:20px;font-size:14px}.msg.error{color:var(--red)}.msg.info{color:var(--dim)}
.status-bar{display:flex;align-items:center;justify-content:space-between;padding:4px 20px;background:var(--card);border-top:1px solid var(--border);font-size:11px;color:var(--dim);flex-shrink:0}
.nl-bar{display:flex;gap:8px;padding:8px 20px;background:#1e2030;border-bottom:1px solid var(--border);flex-shrink:0}
.nl-bar input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px}
.nl-bar button{background:#e97316;color:#fff;border:none;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
.nl-bar button:hover{opacity:.85}
.history-panel{width:220px;background:var(--card);border-left:1px solid var(--border);overflow-y:auto;flex-shrink:0;padding:12px}
.history-panel h3{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:8px;font-weight:500}
.history-item{font-size:12px;padding:6px 8px;border-radius:4px;cursor:pointer;margin-bottom:4px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.history-item:hover{background:var(--bg);color:var(--text)}
.history-time{font-size:10px;color:#555}
</style>
</head>
<body>
<header>
  <h1><span>SQL</span> Proxy Playground</h1>
  <a href="/dashboard">&larr; Dashboard</a>
</header>
<div class="toolbar">
  <input id="apiKey" type="password" placeholder="API Key (Bearer token)" class="wide" value="">
  <input id="dbName" type="text" placeholder="Database" value="testdb" style="width:120px">
  <button class="btn-run" onclick="runQuery()">Run (Ctrl+Enter)</button>
  <button class="btn-dry" onclick="dryRun()">Dry Run</button>
</div>
<div class="nl-bar">
  <input id="nlInput" type="text" placeholder="Ask in English: &quot;Show all customers from California with orders over $100&quot;">
  <button class="btn-nl" onclick="nlToSql()">Generate SQL</button>
</div>
<div class="main-area">
  <div class="sidebar" id="schemaSidebar">
    <h3>Schema</h3>
    <div id="schemaTree"><div class="msg info">Enter admin token in Dashboard first to load schema</div></div>
  </div>
  <div class="editor-area">
    <div class="editor-wrap"><textarea id="sqlEditor">SELECT * FROM customers LIMIT 10;</textarea></div>
    <div class="results-area" id="results">
      <div class="msg info">Press Ctrl+Enter or click Run to execute a query</div>
    </div>
  </div>
  <div class="history-panel">
    <h3>History</h3>
    <div id="historyList"></div>
  </div>
</div>
<div class="status-bar">
  <span id="statusText">Ready</span>
  <span id="rowCount"></span>
</div>
<script>
const editor = CodeMirror.fromTextArea(document.getElementById('sqlEditor'), {
  mode: 'text/x-pgsql',
  theme: 'material-darker',
  lineNumbers: true,
  indentWithTabs: false,
  indentUnit: 2,
  lineWrapping: true,
  extraKeys: {
    'Ctrl-Enter': () => runQuery(),
    'Ctrl-Space': 'autocomplete'
  },
  hintOptions: { tables: {} }
});

let schemaHints = {};

// Load schema from admin endpoint
async function loadSchema() {
  const token = localStorage.getItem('sp_admin_token') || '';
  if (!token) return;
  try {
    const r = await fetch('/dashboard/api/schema', { headers: { 'Authorization': 'Bearer ' + token } });
    if (!r.ok) return;
    const data = await r.json();
    const tables = data.tables || [];
    if (!tables.length) {
      document.getElementById('schemaTree').innerHTML = '<div class="msg info">No tables found</div>';
      return;
    }
    let html = '';
    schemaHints = {};
    tables.forEach(t => {
      const fullName = t.schema ? t.schema + '.' + t.name : t.name;
      const cols = t.columns || [];
      schemaHints[fullName] = cols.map(c => c.name);
      schemaHints[t.name] = cols.map(c => c.name);
      html += '<details class="schema-table"><summary>' + t.name + '</summary>';
      cols.forEach(c => {
        html += '<div class="schema-col" onclick="insertText(\'' + c.name + '\')">';
        html += c.name + '<span class="type">' + c.type + '</span>';
        if (c.primary_key) html += '<span class="pk">PK</span>';
        html += '</div>';
      });
      html += '</details>';
    });
    document.getElementById('schemaTree').innerHTML = html;
    editor.setOption('hintOptions', { tables: schemaHints });
  } catch(e) { /* silent */ }
}

function insertText(text) {
  editor.replaceSelection(text);
  editor.focus();
}

function authHeaders() {
  return { 'Authorization': 'Bearer ' + document.getElementById('apiKey').value, 'Content-Type': 'application/json' };
}

function addHistory(sql) {
  let history = JSON.parse(localStorage.getItem('sp_query_history') || '[]');
  history.unshift({ sql: sql, time: new Date().toLocaleTimeString() });
  if (history.length > 20) history = history.slice(0, 20);
  localStorage.setItem('sp_query_history', JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const history = JSON.parse(localStorage.getItem('sp_query_history') || '[]');
  let html = '';
  history.forEach((h, i) => {
    html += '<div class="history-item" onclick="loadHistory(' + i + ')" title="' + h.sql.replace(/"/g,'&quot;') + '">';
    html += '<span class="history-time">' + h.time + '</span> ' + h.sql.substring(0, 40);
    html += '</div>';
  });
  document.getElementById('historyList').innerHTML = html || '<div class="msg info">No history yet</div>';
}

function loadHistory(idx) {
  const history = JSON.parse(localStorage.getItem('sp_query_history') || '[]');
  if (history[idx]) { editor.setValue(history[idx].sql); editor.focus(); }
}

function setStatus(text) { document.getElementById('statusText').textContent = text; }
function setRowCount(text) { document.getElementById('rowCount').textContent = text; }

function renderResults(data) {
  if (!data.success) {
    document.getElementById('results').innerHTML = '<div class="msg error">Error: ' + (data.error || 'Unknown error') + '</div>';
    setStatus('Error'); setRowCount('');
    return;
  }
  const cols = data.columns || data.column_names || [];
  const rows = data.rows || [];
  if (!cols.length) {
    document.getElementById('results').innerHTML = '<div class="msg info">Query executed successfully (no results)</div>';
    setStatus('OK'); setRowCount('0 rows');
    return;
  }
  let html = '<table class="results-table"><thead><tr>';
  cols.forEach(c => { html += '<th>' + c + '</th>'; });
  html += '</tr></thead><tbody>';
  rows.forEach(row => {
    html += '<tr>';
    (Array.isArray(row) ? row : Object.values(row)).forEach(v => {
      html += '<td title="' + String(v).replace(/"/g,'&quot;') + '">' + String(v) + '</td>';
    });
    html += '</tr>';
  });
  html += '</tbody></table>';
  document.getElementById('results').innerHTML = html;
  setStatus('OK - ' + (data.latency_ms ? data.latency_ms + 'ms' : '')); setRowCount(rows.length + ' rows');
}

async function runQuery() {
  const sql = editor.getValue().trim();
  if (!sql) return;
  setStatus('Executing...'); setRowCount('');
  addHistory(sql);
  try {
    const r = await fetch('/api/v1/query', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ sql: sql, database: document.getElementById('dbName').value })
    });
    const data = await r.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('results').innerHTML = '<div class="msg error">Network error: ' + e.message + '</div>';
    setStatus('Error'); setRowCount('');
  }
}

async function dryRun() {
  const sql = editor.getValue().trim();
  if (!sql) return;
  setStatus('Dry run...'); setRowCount('');
  try {
    const r = await fetch('/api/v1/query/dry-run', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ sql: sql, database: document.getElementById('dbName').value })
    });
    const data = await r.json();
    let html = '<h3>Dry Run Result</h3><pre style="padding:12px;background:var(--card);border-radius:6px;overflow-x:auto;font-size:13px">';
    html += JSON.stringify(data, null, 2) + '</pre>';
    document.getElementById('results').innerHTML = html;
    setStatus('Dry run complete'); setRowCount('');
  } catch(e) {
    document.getElementById('results').innerHTML = '<div class="msg error">Network error: ' + e.message + '</div>';
    setStatus('Error');
  }
}

async function nlToSql() {
  const question = document.getElementById('nlInput').value.trim();
  if (!question) return;
  setStatus('Generating SQL...'); setRowCount('');
  try {
    const r = await fetch('/api/v1/nl-query', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ question: question, database: document.getElementById('dbName').value, execute: false })
    });
    const data = await r.json();
    if (data.success && data.sql) {
      editor.setValue(data.sql);
      setStatus('SQL generated (' + (data.latency_ms || '?') + 'ms) - review and press Run');
      document.getElementById('results').innerHTML = '<div class="msg info">SQL generated from your question. Review it above, then press Run to execute.</div>';
    } else {
      document.getElementById('results').innerHTML = '<div class="msg error">NL-to-SQL error: ' + (data.error || 'Unknown') + '</div>';
      setStatus('Error');
    }
  } catch(e) {
    document.getElementById('results').innerHTML = '<div class="msg error">Network error: ' + e.message + '</div>';
    setStatus('Error');
  }
}

document.getElementById('nlInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') nlToSql(); });

// Init
renderHistory();
loadSchema();
// Try to load API key from localStorage
const savedKey = localStorage.getItem('sp_api_key');
if (savedKey) document.getElementById('apiKey').value = savedKey;
document.getElementById('apiKey').addEventListener('change', (e) => localStorage.setItem('sp_api_key', e.target.value));
// Save admin token if present in dashboard
const savedAdminToken = localStorage.getItem('sp_admin_token');
</script>
</body>
</html>
)HTML";
} // namespace sqlproxy
