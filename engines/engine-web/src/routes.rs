use axum::{
    Router,
    routing::{get, post},
    response::{Json, Html},
    extract::State,
    Form,
};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

use crate::server::{AppState, AttackStatus, AttackConfig};

// ─── API Response Types ────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatusResponse {
    pub hash_rate: f64,
    pub total_cracked: u64,
    pub total_tested: u64,
    pub uptime_secs: u64,
    pub status: String,
    pub workers: Vec<serde_json::Value>,
    pub session: String,
    pub attack_config: Option<AttackConfig>,
}

#[derive(Serialize)]
pub struct ApiResult {
    pub success: bool,
    pub message: String,
}

// ─── Static Routes ─────────────────────────────────────────────────────

pub fn static_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(root_page))
        .route("/style.css", get(css_handler))
        .route("/app.js", get(js_handler))
}

async fn root_page() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>pwdcrack</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><h1><a href="/">pwdcrack</a></h1><nav><a href="/dashboard">Dashboard</a> | <a href="/api/status">API</a></nav></header>
<main><h2>Universal Password Cracker</h2>
<p>Multi-engine password cracking platform supporting CPU, GPU, FPGA, distributed nodes, web dashboard, and more.</p>
<ul><li><a href="/dashboard">Real-time Dashboard</a></li><li><a href="/api/status">Status API</a></li></ul>
</main></body></html>"#)
}

async fn css_handler() -> Html<&'static str> {
    Html(CSS)
}

async fn js_handler() -> Html<&'static str> {
    Html(JS)
}

// ─── API Routes ────────────────────────────────────────────────────────

pub fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(get_status))
        .route("/start", post(start_attack))
        .route("/stop", post(stop_attack))
        .route("/pause", post(pause_attack))
        .route("/resume", post(resume_attack))
        .route("/config", post(set_config))
        .route("/log", get(get_log))
}

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Json<StatusResponse> {
    let workers: Vec<serde_json::Value> = state.workers.read().await.iter().map(|w| {
        serde_json::json!({
            "name": w.name,
            "hashes_sec": w.hashes_sec,
            "total_cracked": w.total_cracked,
            "alive": w.alive,
        })
    }).collect();

    Json(StatusResponse {
        hash_rate: *state.hash_rate.read().await,
        total_cracked: *state.total_cracked.read().await,
        total_tested: *state.total_tested.read().await,
        uptime_secs: state.start_time.elapsed().as_secs(),
        status: format!("{:?}", *state.status.read().await),
        workers,
        session: state.session_name.read().await.clone(),
        attack_config: state.attack_config.read().await.clone(),
    })
}

#[derive(Deserialize)]
pub struct StartRequest {
    pub attack_type: String,
    pub hash_type: Option<String>,
    pub target_hashes: Option<Vec<String>>,
    pub mask: Option<String>,
    pub wordlist: Option<String>,
    pub rules: Option<Vec<String>>,
}

async fn start_attack(
    State(state): State<Arc<AppState>>,
    Form(req): Form<StartRequest>,
) -> Json<ApiResult> {
    let mut status = state.status.write().await;
    if *status == AttackStatus::Running {
        return Json(ApiResult { success: false, message: "Attack already running".into() });
    }

    let config = AttackConfig {
        attack_type: req.attack_type.clone(),
        hash_type: req.hash_type.unwrap_or_else(|| "MD5".into()),
        target_hashes: req.target_hashes.unwrap_or_default(),
        mask: req.mask,
        wordlist: req.wordlist,
        rules: req.rules.unwrap_or_default(),
    };

    *state.attack_config.write().await = Some(config.clone());
    *status = AttackStatus::Running;
    state.log_message(format!("Attack started: {:?}", config.attack_type)).await;
    drop(status);

    Json(ApiResult { success: true, message: "Attack started".into() })
}

async fn stop_attack(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResult> {
    let mut status = state.status.write().await;
    *status = AttackStatus::Idle;
    state.log_message("Attack stopped".to_string()).await;
    drop(status);

    Json(ApiResult { success: true, message: "Attack stopped".into() })
}

async fn pause_attack(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResult> {
    let mut status = state.status.write().await;
    if *status != AttackStatus::Running {
        return Json(ApiResult { success: false, message: "No running attack to pause".into() });
    }
    *status = AttackStatus::Paused;
    state.log_message("Attack paused".to_string()).await;
    drop(status);

    Json(ApiResult { success: true, message: "Attack paused".into() })
}

async fn resume_attack(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResult> {
    let mut status = state.status.write().await;
    if *status != AttackStatus::Paused {
        return Json(ApiResult { success: false, message: "No paused attack to resume".into() });
    }
    *status = AttackStatus::Running;
    state.log_message("Attack resumed".to_string()).await;
    drop(status);

    Json(ApiResult { success: true, message: "Attack resumed".into() })
}

#[derive(Deserialize)]
pub struct ConfigRequest {
    pub session_name: Option<String>,
}

async fn set_config(
    State(state): State<Arc<AppState>>,
    Form(req): Form<ConfigRequest>,
) -> Json<ApiResult> {
    if let Some(name) = req.session_name {
        *state.session_name.write().await = name.clone();
        state.log_message(format!("Session set: {}", name)).await;
    }
    Json(ApiResult { success: true, message: "Config updated".into() })
}

async fn get_log(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<String>> {
    Json(state.message_log.read().await.clone())
}

// ─── Dashboard Routes ─────────────────────────────────────────────────

pub fn dashboard_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/ws", get(crate::websocket::ws_handler))
}

async fn dashboard_page() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

// ─── Static Assets ─────────────────────────────────────────────────────

const CSS: &str = r#":root{--bg:#0d1117;--fg:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--border:#30363d}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,monospace;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;justify-content:space-between;align-items:center;padding:1rem 2rem;border-bottom:1px solid var(--border);background:#161b22}
header h1{font-size:1.2rem}
header h1 a{color:var(--fg)}
header nav{font-size:0.9rem}
main{padding:2rem;max-width:1200px;margin:0 auto}
h1,h2,h3{color:var(--fg)}
.card{background:#161b22;border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{text-align:center}
.stat .value{font-size:2rem;font-weight:700;color:var(--accent)}
.stat .label{font-size:0.85rem;color:#8b949e}
.status-running{color:var(--green)}
.status-paused{color:var(--yellow)}
.status-idle{color:#8b949e}
.status-error{color:var(--red)}
button,input,select{padding:0.5rem 1rem;border:1px solid var(--border);border-radius:6px;background:#21262d;color:var(--fg);font-size:0.9rem;cursor:pointer}
button:hover{background:#30363d}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.primary:hover{filter:brightness(1.1)}
button.danger{background:var(--red);color:#fff;border-color:var(--red)}
button.success{background:var(--green);color:#fff;border-color:var(--green)}
input[type=text]{width:100%;padding:0.5rem;background:#0d1117;border:1px solid var(--border);border-radius:6px;color:var(--fg)}
table{width:100%;border-collapse:collapse}
th,td{padding:0.75rem;text-align:left;border-bottom:1px solid var(--border)}
th{color:#8b949e;font-weight:600;font-size:0.85rem;text-transform:uppercase}
.log{font-family:monospace;font-size:0.85rem;max-height:300px;overflow-y:auto;background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:0.75rem}
.log p{padding:2px 0;border-bottom:1px solid rgba(48,54,61,0.3)}
.control-group{display:flex;gap:0.5rem;flex-wrap:wrap;margin:1rem 0}
.form-group{margin-bottom:1rem}
.form-group label{display:block;font-size:0.85rem;color:#8b949e;margin-bottom:0.25rem}
.progress-bar{height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin:0.5rem 0}
.progress-bar .fill{height:100%;background:var(--accent);transition:width 0.3s}"#;

const JS: &str = r#"
let ws = null;
function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(proto + '//' + location.host + '/dashboard/ws');
    ws.onmessage = (e) => {
        try {
            const d = JSON.parse(e.data);
            document.getElementById('hash-rate').textContent = (d.hash_rate || 0).toFixed(1);
            document.getElementById('total-tested').textContent = (d.total_tested || 0).toLocaleString();
            document.getElementById('total-cracked').textContent = (d.total_cracked || 0).toLocaleString();
            document.getElementById('uptime').textContent = formatDuration(d.uptime_secs || 0);
            const statusEl = document.getElementById('attack-status');
            if (d.status) {
                statusEl.textContent = d.status;
                statusEl.className = 'status-' + d.status.toLowerCase();
            }
            if (d.hash_rate > 0) {
                document.getElementById('progress-fill').style.width = Math.min(100, d.total_tested / 1000) + '%';
            }
        } catch(e) { console.error('WS parse error', e); }
    };
    ws.onclose = () => setTimeout(connectWS, 2000);
}
connectWS();
function formatDuration(s) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + sec + 's';
}
setInterval(() => {
    fetch('/api/status').then(r => r.json()).then(d => {
        document.getElementById('hash-rate').textContent = (d.hash_rate || 0).toFixed(1);
        document.getElementById('total-tested').textContent = (d.total_tested || 0).toLocaleString();
        document.getElementById('total-cracked').textContent = (d.total_cracked || 0).toLocaleString();
        document.getElementById('uptime').textContent = formatDuration(d.uptime_secs || 0);
        if (d.workers && d.workers.length) {
            const tbody = document.querySelector('#workers-table tbody');
            if (tbody) tbody.innerHTML = d.workers.map(w =>
                `<tr><td>${w.name}</td><td>${(w.hashes_sec||0).toFixed(0)}</td><td>${(w.total_cracked||0).toLocaleString()}</td><td style="color:${w.alive?'var(--green)':'var(--red)'}">${w.alive?'●':'○'}</td></tr>`
            ).join('');
        }
    }).catch(() => {});
}, 2000);
function startAttack() {
    const form = document.getElementById('attack-form');
    const data = new FormData(form);
    fetch('/api/start', { method: 'POST', body: new URLSearchParams(data) })
    .then(r => r.json()).then(d => alert(d.message));
}
function stopAttack() {
    fetch('/api/stop', { method: 'POST' }).then(r => r.json()).then(d => alert(d.message));
}
function pauseAttack() {
    fetch('/api/pause', { method: 'POST' }).then(r => r.json()).then(d => alert(d.message));
}
function resumeAttack() {
    fetch('/api/resume', { method: 'POST' }).then(r => r.json()).then(d => alert(d.message));
}
function setSession() {
    const name = document.getElementById('session-input').value;
    const data = new FormData();
    data.append('session_name', name);
    fetch('/api/config', { method: 'POST', body: new URLSearchParams(data) })
    .then(r => r.json()).then(d => alert(d.message));
}
function toggleAdvanced() {
    const el = document.getElementById('advanced-config');
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
"#;

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>pwdcrack Dashboard</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header>
<h1><a href="/">pwdcrack</a></h1>
<nav><a href="/dashboard">Dashboard</a> | <a href="/api/status">API</a> | <a href="/" onclick="event.preventDefault();document.getElementById('session-input').value='';setSession()">New Session</a></nav>
</header>
<main>
<h2>Dashboard</h2>
<div class="grid">
  <div class="card stat"><div class="value" id="hash-rate">0.0</div><div class="label">Hashes/s</div></div>
  <div class="card stat"><div class="value" id="total-tested">0</div><div class="label">Tested</div></div>
  <div class="card stat"><div class="value" id="total-cracked">0</div><div class="label">Cracked</div></div>
  <div class="card stat"><div class="value" id="uptime">0s</div><div class="label">Uptime</div></div>
</div>

<div class="card">
  <h3>Status: <span id="attack-status" class="status-idle">Idle</span></h3>
  <div class="progress-bar"><div class="fill" id="progress-fill" style="width:0%"></div></div>
  <div class="control-group">
    <button class="success" onclick="startAttack()">▶ Start</button>
    <button class="danger" onclick="stopAttack()">■ Stop</button>
    <button onclick="pauseAttack()">⏸ Pause</button>
    <button class="primary" onclick="resumeAttack()">▶ Resume</button>
  </div>
</div>

<div class="card">
  <h3>Attack Configuration</h3>
  <form id="attack-form" onsubmit="return false">
    <div class="form-group">
      <label>Attack Type</label>
      <select name="attack_type">
        <option value="bruteforce">Brute Force</option>
        <option value="dictionary">Dictionary</option>
        <option value="combinator">Combinator</option>
      </select>
    </div>
    <div class="form-group">
      <label>Hash Type</label>
      <select name="hash_type">
        <option value="MD5">MD5</option>
        <option value="SHA1">SHA1</option>
        <option value="SHA256">SHA256</option>
        <option value="NTLM">NTLM</option>
        <option value="BCRYPT">bcrypt</option>
      </select>
    </div>
    <div class="form-group">
      <label>Target Hashes (comma-separated)</label>
      <input type="text" name="target_hashes" placeholder="5d41402abc4b2a76b9719d911017c592,...">
    </div>
    <div class="form-group">
      <label>Mask (for brute force, e.g. ?l?l?l?d?d)</label>
      <input type="text" name="mask" placeholder="?l?l?l?l?d?d">
    </div>
    <div class="form-group">
      <label>Wordlist path (for dictionary)</label>
      <input type="text" name="wordlist" placeholder="/usr/share/wordlists/rockyou.txt">
    </div>
    <button class="primary" onclick="startAttack()">Launch Attack</button>
  </form>
</div>

<div class="card">
  <h3>Session</h3>
  <div style="display:flex;gap:0.5rem">
    <input type="text" id="session-input" placeholder="Session name">
    <button onclick="setSession()">Set</button>
  </div>
</div>

<div class="card">
  <h3>Workers <span style="font-size:0.8rem;color:#8b949e">(connected nodes)</span></h3>
  <table id="workers-table">
    <thead><tr><th>Name</th><th>H/s</th><th>Cracked</th><th>Status</th></tr></thead>
    <tbody><tr><td colspan="4" style="color:#8b949e;text-align:center">No workers connected</td></tr></tbody>
  </table>
</div>

<div class="card">
  <h3>Activity Log</h3>
  <div class="log" id="activity-log">
    <p style="color:#8b949e">Waiting for activity...</p>
  </div>
</div>
</main>
<script src="/app.js"></script>
</body>
</html>"#;
