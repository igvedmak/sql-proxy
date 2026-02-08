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
} // namespace sqlproxy
