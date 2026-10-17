//! Routes, and the guard in front of the mutating ones.
//!
//! # The guard
//!
//! Every state changing request passes [`guard`], which applies three checks and
//! records the outcome whether it passes or not:
//!
//!   * rate limit, per source address, before anything expensive;
//!   * bearer token, compared in constant time;
//!   * the CSRF header, which a browser will not attach cross site because this
//!     server sends no CORS headers and a custom header needs a preflight.
//!
//! A refusal is recorded in the audit log. A flood of unauthenticated requests
//! produces no successful request to trigger a log write, so recording only
//! successes would make the one event an operator needs to see invisible.
//!
//! Read only routes are not guarded. `/api/status` reports counters and the
//! current status, and an operator polling it every two seconds should not need
//! to present a token on every request to keep the page live. That is a
//! deliberate trade: on a loopback default nothing is exposed, and on an exposed
//! bind the operator has already accepted that the port is reachable.
//!
//! # CSP and the pages
//!
//! [`security_headers`] sets a policy with no `unsafe-inline` and no
//! `unsafe-eval`. The HTML and JavaScript here are written to comply: no `style`
//! attributes, no `onclick` handlers, no inline `<script>` blocks. A policy the
//! page violates is a self inflicted outage, so the two were written together.
//!
//! What script cannot do inline, `app.js` does through `addEventListener`, which
//! a CSP does not restrict because it is not an inline handler.

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::extract::Request;
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::attack::{self, AttackRequest};
use crate::auth::{
    self, CONTENT_SECURITY_POLICY, CSRF_HEADER, CSRF_HEADER_VALUE, RateOutcome,
};
use crate::server::{AppState, AttackConfig, WorkerEntry};

/// Largest request body the dashboard accepts.
///
/// An attack request carries hash lists and a wordlist path. A megabyte is far
/// more than that needs and small enough that a body cannot be used to exhaust
/// memory on a machine that is already running a cracker.
const MAX_BODY_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// The single response shape for every mutating route.
///
/// `success` is the body and the HTTP status are two different signals: a 400
/// with `success: false` and a 200 with `success: false` mean different things to
/// a client, and collapsing them is how a caller ends up treating a refusal as a
/// success.
#[derive(Serialize)]
pub struct ApiResult {
    pub success: bool,
    pub message: String,
}

impl ApiResult {
    fn ok(message: impl Into<String>) -> Self {
        ApiResult {
            success: true,
            message: message.into(),
        }
    }

    fn refused(message: impl Into<String>) -> Self {
        ApiResult {
            success: false,
            message: message.into(),
        }
    }
}

/// A refusal with the status that describes it.
struct Refusal {
    status: StatusCode,
    message: String,
    /// Set on 429 so a client knows how long to back off.
    retry_after: Option<u64>,
}

impl Refusal {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Refusal {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    fn too_many(retry_after_ms: u64) -> Self {
        Refusal {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: format!(
                "too many mutating requests; retry in {} ms",
                retry_after_ms
            ),
            retry_after: Some(retry_after_ms),
        }
    }

    fn into_response(self) -> Response {
        let mut body = Json(ApiResult::refused(self.message)).into_response();
        *body.status_mut() = self.status;
        if let Some(ms) = self.retry_after {
            let secs = (ms / 1000) + 1;
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                body.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        body
    }
}

type Checked = Result<Request, Refusal>;

/// One line describing what the guard decided, for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Allowed,
    RateLimited,
    NoToken,
    BadToken,
    NoCsrfHeader,
    BadCsrfHeader,
}

impl Decision {
    fn auth_code(self) -> u8 {
        match self {
            Decision::Allowed => 1,
            Decision::NoToken | Decision::BadToken => 0,
            _ => 0,
        }
    }

    fn refusal(self) -> Option<&'static str> {
        match self {
            Decision::Allowed => None,
            Decision::RateLimited => Some("rate limited"),
            Decision::NoToken => Some("no bearer token"),
            Decision::BadToken => Some("bearer token did not match"),
            Decision::NoCsrfHeader => Some("CSRF header absent"),
            Decision::BadCsrfHeader => Some("CSRF header had the wrong value"),
        }
    }
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// Rate limit, token, CSRF. In that order.
async fn guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let source = source_of(&req);
    let headers = req.headers().clone();

    match check(&state, &headers, &source) {
        Ok(()) => next.run(req).await,
        Err((decision, refusal)) => {
            let limited = decision == Decision::RateLimited;
            state.audit.record(
                method.as_str(),
                &path,
                &source,
                decision.auth_code(),
                decision.refusal().unwrap_or(""),
                limited,
            );
            refusal.into_response()
        }
    }
}

/// The three checks, kept separate from the middleware so a test can drive them
/// without building a request.
fn check(state: &AppState, headers: &HeaderMap, source: &str) -> Result<(), (Decision, Refusal)> {
    match state.rate_limiter.check(source) {
        RateOutcome::Allowed { .. } => {}
        RateOutcome::Refused { retry_after_ms } => {
            return Err((
                Decision::RateLimited,
                Refusal::too_many(retry_after_ms),
            ));
        }
    }

    // No token configured means no mutating request can be authorised. Failing
    // closed here rather than allowing an open listener is the point of the
    // check, so an operator who deleted the token file locks themselves out of
    // the write routes rather than exposing them.
    let Some(expected) = state.token.as_deref() else {
        return Err((
            Decision::NoToken,
            Refusal::new(
                StatusCode::UNAUTHORIZED,
                "this dashboard has no token, so no mutating request can be authorised",
            ),
        ));
    };

    let presented = auth::parse_bearer(header_str(headers, auth::AUTH_HEADER));
    match auth::verify_token(expected, presented) {
        auth::AuthOutcome::Allowed => {}
        auth::AuthOutcome::Rejected => {
            let why = if presented.is_none() {
                "missing Authorization: Bearer <token>"
            } else {
                "the bearer token does not match"
            };
            return Err((
                Decision::NoToken,
                Refusal::new(StatusCode::UNAUTHORIZED, why),
            ));
        }
    }

    match auth::check_csrf(header_str(headers, CSRF_HEADER)) {
        auth::CsrfOutcome::Allowed => Ok(()),
        auth::CsrfOutcome::MissingHeader => Err((
            Decision::NoCsrfHeader,
            Refusal::new(
                StatusCode::BAD_REQUEST,
                format!("missing the {CSRF_HEADER} header; send {CSRF_HEADER}: {CSRF_HEADER_VALUE}"),
            ),
        )),
        auth::CsrfOutcome::WrongValue => Err((
            Decision::BadCsrfHeader,
            Refusal::new(
                StatusCode::BAD_REQUEST,
                format!("{CSRF_HEADER} must be exactly {CSRF_HEADER_VALUE:?}"),
            ),
        )),
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The client address, or `unknown` when the server was not given one.
///
/// `axum::serve` has to be built with `into_make_service_with_connect_info` for
/// this to be populated. When it is not, every source shares one bucket, which
/// is safe (it is stricter) and is reported in the audit log so it is visible.
fn source_of(req: &Request) -> String {
    match req.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(addr)) => addr.ip().to_string(),
        None => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/// Adds the policy and the headers that keep a browser honest.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();

    // `from_static` is infallible in this http version and panics only on a
    // malformed literal, which would be a compile time mistake caught here.
    //
    // The policy forbids inline script, so any inline handler or script block in
    // the pages below is a bug rather than a style choice. There are tests for
    // exactly that.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("deny"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // Cross origin isolation. Nothing here loads a remote asset, so these say
    // so explicitly rather than leaving the browser to infer it from the CSP.
    for name in ["cross-origin-opener-policy", "cross-origin-resource-policy"] {
        h.insert(
            axum::http::HeaderName::from_static(name),
            HeaderValue::from_static("same-origin"),
        );
    }
    response
}

// ---------------------------------------------------------------------------
// Read only routes
// ---------------------------------------------------------------------------

/// What `/api/status` reports.
#[derive(Serialize)]
pub struct StatusResponse {
    pub hash_rate: f64,
    pub total_cracked: u64,
    pub total_tested: u64,
    pub uptime_secs: u64,
    pub status: String,
    pub workers: Vec<WorkerEntry>,
    pub session: String,
    pub attack_config: Option<AttackConfig>,
    pub hits: Vec<attack::CrackedHit>,
    /// False when no executor is wired, so the page can say attacks cannot run
    /// before anyone clicks start.
    pub executor_wired: bool,
    /// Whether this listener is reachable from another machine.
    pub exposed: bool,
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let snapshot = state.snapshot().await;
    let workers = state.workers.read().await.clone();

    Json(StatusResponse {
        hash_rate: snapshot.hash_rate,
        total_cracked: snapshot.cracked,
        total_tested: snapshot.tested,
        uptime_secs: state.start_time.elapsed().as_secs(),
        status: snapshot.status.to_string(),
        workers,
        session: state.session_name.read().await.clone(),
        attack_config: state.attack_config.read().await.clone(),
        hits: snapshot.hits,
        executor_wired: snapshot.executor_wired,
        exposed: state.bind_policy.is_exposed(),
    })
}

/// The session log. Read only, no token.
async fn get_log(State(state): State<Arc<AppState>>) -> Json<Vec<String>> {
    Json(state.message_log.read().await.clone())
}

/// What was attempted against the mutating routes.
async fn get_audit(State(state): State<Arc<AppState>>) -> Json<Vec<auth::AuditEntry>> {
    Json(state.audit.snapshot())
}

// ---------------------------------------------------------------------------
// Mutating routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct StartRequest {
    pub attack_type: String,
    pub hash_type: Option<String>,
    pub target_hashes: Option<Vec<String>>,
    pub mask: Option<String>,
    pub wordlist: Option<String>,
    pub rules: Option<String>,
}

/// Starts a real attack.
///
/// The old version set a status enum to `Running`, wrote "Attack started" to
/// the log and returned success. Nothing was hashed. This one builds an
/// [`AttackRequest`], hands it to the executor, and stores the resulting handle,
/// which is what `stop`, `pause` and `resume` act on.
async fn start_attack(
    State(state): State<Arc<AppState>>,
    Form(req): Form<StartRequest>,
) -> Response {
    // Refuse before parsing the target list if there is no executor, so the
    // message is about the real problem.
    if !state.executor_wired {
        return Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no attack executor is wired: this build of the dashboard cannot run attacks",
        )
        .into_response();
    }

    let request = AttackRequest {
        attack_type: req.attack_type.clone(),
        hash_type: req.hash_type.clone().unwrap_or_else(|| "MD5".into()),
        target_hashes: req.target_hashes.clone().unwrap_or_default(),
        mask: req.mask.clone(),
        wordlist: req.wordlist.clone(),
        rules: req
            .rules
            .as_ref()
            .map(|r| {
                r.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    };

    if let Err(why) = request.validate() {
        state
            .log_message(format!("start refused: {why}"))
            .await;
        return Refusal::new(StatusCode::BAD_REQUEST, why).into_response();
    }

    let config = AttackConfig {
        attack_type: request.attack_type.clone(),
        hash_type: request.hash_type.clone(),
        target_hashes: request.target_hashes.clone(),
        mask: request.mask.clone(),
        wordlist: request.wordlist.clone(),
        rules: request.rules.clone(),
    };

    match attack::spawn(Arc::clone(&state.executor), request) {
        Ok(handle) => {
            *state.attack_config.write().await = Some(config.clone());
            // Installing the handle aborts whatever was running, so a second
            // start does not leave two attacks hashing the same machine.
            state.attack.replace(handle).await;
            state
                .log_message(format!("attack started ({})", config.attack_type))
                .await;
            (StatusCode::OK, Json(ApiResult::ok("attack started"))).into_response()
        }
        Err(why) => {
            state.log_message(format!("start refused: {why}")).await;
            Refusal::new(StatusCode::BAD_REQUEST, why).into_response()
        }
    }
}

async fn stop_attack(State(state): State<Arc<AppState>>) -> Response {
    if state.attack.take_and_stop().await {
        state.log_message("attack stopped".into()).await;
        (StatusCode::OK, Json(ApiResult::ok("attack stopped"))).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(ApiResult::refused("no attack is running")),
        )
            .into_response()
    }
}

async fn pause_attack(State(state): State<Arc<AppState>>) -> Response {
    let slot = state.attack.0.lock().await;
    match slot.as_ref() {
        None => {
            drop(slot);
            (
                StatusCode::CONFLICT,
                Json(ApiResult::refused("no attack is running")),
            )
                .into_response()
        }
        Some(handle) => {
            // The handle reports whether the state actually changed, so a second
            // pause is told so rather than reported as a success that did
            // nothing.
            let changed = handle.pause();
            drop(slot);
            state
                .log_message(if changed {
                    "attack paused".into()
                } else {
                    "attack was already paused".to_string()
                })
                .await;
            let message = if changed {
                "attack paused"
            } else {
                "attack was already paused"
            };
            (StatusCode::OK, Json(ApiResult::ok(message))).into_response()
        }
    }
}

async fn resume_attack(State(state): State<Arc<AppState>>) -> Response {
    let slot = state.attack.0.lock().await;
    match slot.as_ref() {
        None => {
            drop(slot);
            (
                StatusCode::CONFLICT,
                Json(ApiResult::refused("no attack is running")),
            )
                .into_response()
        }
        Some(handle) => {
            let changed = handle.resume();
            drop(slot);
            let message = if changed {
                "attack resumed"
            } else {
                "attack was not paused"
            };
            state.log_message(message.to_string()).await;
            (StatusCode::OK, Json(ApiResult::ok(message))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ConfigRequest {
    pub session_name: Option<String>,
}

async fn set_config(
    State(state): State<Arc<AppState>>,
    Form(req): Form<ConfigRequest>,
) -> Response {
    match req.session_name {
        Some(name) => {
            // Bounded, because it is echoed into the page and the audit log.
            if name.len() > 128 {
                return Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "session name is longer than 128 characters",
                )
                .into_response();
            }
            *state.session_name.write().await = name.clone();
            state.log_message(format!("session set: {name}")).await;
            (StatusCode::OK, Json(ApiResult::ok("config updated"))).into_response()
        }
        None => Refusal::new(StatusCode::BAD_REQUEST, "session_name is required").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/// Builds the whole router.
pub fn build(state: Arc<AppState>) -> Router {
    // Guarded routes first, so `route_layer` applies to exactly these.
    let mutating = Router::new()
        .route("/start", post(start_attack))
        .route("/stop", post(stop_attack))
        .route("/pause", post(pause_attack))
        .route("/resume", post(resume_attack))
        .route("/config", post(set_config))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            guard,
        ));

    let readonly = Router::new()
        .route("/status", get(get_status))
        .route("/log", get(get_log))
        .route("/audit", get(get_audit));

    let api = Router::new().merge(readonly).merge(mutating);

    Router::new()
        .route("/", get(root_page))
        .route("/style.css", get(css_handler))
        .route("/app.js", get(js_handler))
        .nest("/api", api)
        .nest("/dashboard", dashboard())
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn dashboard() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/ws", get(crate::websocket::ws_handler))
}

// ---------------------------------------------------------------------------
// Static assets
// ---------------------------------------------------------------------------

async fn root_page() -> Html<&'static str> {
    Html(ROOT_HTML)
}

async fn css_handler() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}

async fn js_handler() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        JS,
    )
}

async fn dashboard_page() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const ROOT_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>pwdcrack</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header><h1><a href="/">pwdcrack</a></h1><nav><a href="/dashboard">Dashboard</a> | <a href="/api/status">API</a></nav></header>
<main>
<h2>Universal Password Cracker</h2>
<p>Multi-engine password cracking across CPU, GPU, FPGA and distributed nodes.</p>
<ul><li><a href="/dashboard">Dashboard</a></li><li><a href="/api/status">Status API</a></li></ul>
</main>
<script src="/app.js"></script>
</body>
</html>"#;

// No `style` attributes and no `onclick` attributes anywhere below. The CSP
// forbids both, and a page that violates its own policy is an outage.
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
<nav><a href="/dashboard">Dashboard</a> | <a href="/api/status">API</a></nav>
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
  <p class="warn" id="executor-warning" hidden>No attack executor is wired, so attacks cannot run.</p>
  <div class="progress-bar"><div class="fill" id="progress-fill"></div></div>
  <div class="control-group">
    <button class="success" id="btn-start" type="button">Start</button>
    <button class="danger" id="btn-stop" type="button">Stop</button>
    <button id="btn-pause" type="button">Pause</button>
    <button class="primary" id="btn-resume" type="button">Resume</button>
  </div>
</div>

<div class="card">
  <h3>Attack Configuration</h3>
  <form id="attack-form">
    <div class="form-group">
      <label for="attack-type">Attack Type</label>
      <select id="attack-type" name="attack_type">
        <option value="bruteforce">Brute Force</option>
        <option value="dictionary">Dictionary</option>
      </select>
    </div>
    <div class="form-group">
      <label for="hash-type">Hash Type</label>
      <select id="hash-type" name="hash_type">
        <option value="MD5">MD5</option>
        <option value="SHA1">SHA1</option>
        <option value="SHA256">SHA256</option>
        <option value="NTLM">NTLM</option>
        <option value="BCRYPT">bcrypt</option>
      </select>
    </div>
    <div class="form-group">
      <label for="target-hashes">Target Hashes, one per line</label>
      <textarea id="target-hashes" name="target_hashes" rows="4"></textarea>
    </div>
    <div class="form-group">
      <label for="mask">Mask, for brute force</label>
      <input type="text" id="mask" name="mask" placeholder="?l?l?l?l?d?d">
    </div>
    <div class="form-group">
      <label for="wordlist">Wordlist Path, for dictionary</label>
      <input type="text" id="wordlist" name="wordlist" placeholder="/usr/share/wordlists/rockyou.txt">
    </div>
  </form>
</div>

<div class="card">
  <h3>Session</h3>
  <div class="control-group">
    <input type="text" id="session-input" placeholder="Session name">
    <button id="btn-session" type="button">Set</button>
  </div>
</div>

<div class="card">
  <h3>Cracked</h3>
  <table id="cracked-table">
    <thead><tr><th>Hash</th><th>Password</th></tr></thead>
    <tbody><tr class="empty"><td colspan="2">Nothing cracked yet</td></tr></tbody>
  </table>
</div>

<div class="card">
  <h3>Workers</h3>
  <table id="workers-table">
    <thead><tr><th>Name</th><th>H/s</th><th>Cracked</th><th>Status</th></tr></thead>
    <tbody><tr class="empty"><td colspan="4">No workers connected</td></tr></tbody>
  </table>
</div>

<div class="card">
  <h3>Activity</h3>
  <div class="log" id="activity-log"><p class="empty">Waiting for activity</p></div>
</div>
</main>
<script src="/app.js"></script>
</body>
</html>"#;

const CSS: &str = r#":root{--bg:#0d1117;--fg:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--border:#30363d;--muted:#8b949e;--panel:#161b22}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,monospace;background:var(--bg);color:var(--fg);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;justify-content:space-between;align-items:center;padding:1rem 2rem;border-bottom:1px solid var(--border);background:var(--panel)}
header h1{font-size:1.2rem}
header h1 a{color:var(--fg)}
header nav{font-size:0.9rem}
main{padding:2rem;max-width:1200px;margin:0 auto}
h1,h2,h3{color:var(--fg)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{text-align:center}
.stat .value{font-size:2rem;font-weight:700;color:var(--accent)}
.stat .label{font-size:0.85rem;color:var(--muted)}
.status-running{color:var(--green)}
.status-paused{color:var(--yellow)}
.status-idle,.status-finished{color:var(--muted)}
.status-error{color:var(--red)}
.warn{color:var(--yellow);font-size:0.85rem;margin:0.5rem 0}
button,input,select,textarea{padding:0.5rem 1rem;border:1px solid var(--border);border-radius:6px;background:#21262d;color:var(--fg);font-size:0.9rem;cursor:pointer;font-family:inherit}
button:hover{background:#30363d}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.danger{background:var(--red);color:#fff;border-color:var(--red)}
button.success{background:var(--green);color:#fff;border-color:var(--green)}
button[disabled]{opacity:0.5;cursor:not-allowed}
input[type=text],textarea{width:100%;cursor:text}
table{width:100%;border-collapse:collapse}
th,td{padding:0.75rem;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:0.85rem;text-transform:uppercase}
tr.empty td{color:var(--muted);text-align:center}
.control-group{display:flex;gap:0.5rem;flex-wrap:wrap;margin:1rem 0;align-items:center}
.form-group{margin-bottom:1rem}
.form-group label{display:block;font-size:0.85rem;color:var(--muted);margin-bottom:0.25rem}
.progress-bar{height:8px;background:#21262d;border-radius:4px;overflow:hidden;margin:0.5rem 0}
.progress-bar .fill{height:100%;width:0;background:var(--accent);transition:width 0.3s}
.log{font-family:monospace;font-size:0.85rem;max-height:300px;overflow-y:auto;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem}
.log p{padding:2px 0;border-bottom:1px solid var(--border)}
"#;

const JS: &str = r#"
// Every mutating request carries two things the server requires: the bearer
// token and the CSRF header. The token is asked for once per page load and
// kept in a variable; it is never written into the DOM or a URL, because a URL
// ends up in browser history and server logs.
//
// The header is what stops another site in this browser from spending the token.
// A browser will not attach a custom header to a cross site request unless the
// server answers a preflight, and this server sends no CORS headers.
const CSRF_HEADER = 'X-Pwdcrack-Request';
const CSRF_VALUE = 'dashboard';

let ws = null;
let bearer = '';

function el(id) { return document.getElementById(id); }

function say(text, isError) {
    const log = el('activity-log');
    const p = document.createElement('p');
    p.textContent = text;
    if (isError) p.className = 'status-error';
    log.prepend(p);
    while (log.children.length > 200) log.removeChild(log.lastChild);
}

async function post(path, body) {
    const headers = { [CSRF_HEADER]: CSRF_VALUE };
    if (bearer) headers['Authorization'] = 'Bearer ' + bearer;
    const init = { method: 'POST', headers };
    if (body) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
        init.body = new URLSearchParams(body).toString();
    }
    const response = await fetch(path, init);
    let data = {};
    try { data = await response.json(); } catch (e) { /* a non JSON body is still an outcome */ }
    if (!response.ok && !data.message) data.message = response.status + ' ' + response.statusText;
    return { ok: response.ok, status: response.status, data };
}

function formatDuration(s) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + (s % 60) + 's';
}

function renderCracked(hits) {
    const tbody = el('cracked-table').querySelector('tbody');
    tbody.replaceChildren();
    if (!hits.length) {
        const tr = document.createElement('tr');
        tr.className = 'empty';
        const td = document.createElement('td');
        td.colSpan = 2;
        td.textContent = 'Nothing cracked yet';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    for (const hit of hits) {
        const tr = document.createElement('tr');
        const a = document.createElement('td');
        a.textContent = hit.hash;
        const b = document.createElement('td');
        b.textContent = hit.password;
        tr.appendChild(a);
        tr.appendChild(b);
        tbody.appendChild(tr);
    }
}

function renderWorkers(workers) {
    const tbody = el('workers-table').querySelector('tbody');
    tbody.replaceChildren();
    if (!workers.length) {
        const tr = document.createElement('tr');
        tr.className = 'empty';
        const td = document.createElement('td');
        td.colSpan = 4;
        td.textContent = 'No workers connected';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }
    for (const w of workers) {
        const tr = document.createElement('tr');
        const cells = [w.name, (w.hashes_sec || 0).toFixed(0), (w.total_cracked || 0).toLocaleString()];
        for (const text of cells) {
            const td = document.createElement('td');
            td.textContent = text;
            tr.appendChild(td);
        }
        const state = document.createElement('td');
        state.textContent = w.alive ? 'live' : 'down';
        state.className = w.alive ? 'status-running' : 'status-error';
        tr.appendChild(state);
        tbody.appendChild(tr);
    }
}

function apply(d) {
    el('hash-rate').textContent = (d.hash_rate || 0).toFixed(1);
    el('total-tested').textContent = (d.total_tested || 0).toLocaleString();
    el('total-cracked').textContent = (d.total_cracked || 0).toLocaleString();
    el('uptime').textContent = formatDuration(d.uptime_secs || 0);
    const status = el('attack-status');
    status.textContent = d.status || 'Idle';
    status.className = 'status-' + (d.status || 'Idle').toLowerCase();

    el('executor-warning').hidden = d.executor_wired !== false;
    el('btn-start').disabled = d.executor_wired === false;

    if (d.hits) renderCracked(d.hits);
    if (d.workers) renderWorkers(d.workers);

    const fill = el('progress-fill');
    const tested = d.total_tested || 0;
    if (tested > 0 && d.status === 'Running') {
        fill.style.width = '100%';
    } else if (tested === 0) {
        fill.style.width = '0';
    }
}

async function poll() {
    try {
        const response = await fetch('/api/status');
        apply(await response.json());
    } catch (e) { /* the websocket carries the same data; a poll failure is not fatal */ }
}

function connectWs() {
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(scheme + '//' + location.host + '/dashboard/ws');
    ws.onmessage = (e) => {
        try { apply(JSON.parse(e.data)); } catch (err) { say('websocket payload was not JSON', true); }
    };
    ws.onclose = () => setTimeout(connectWs, 2000);
}

async function startAttack() {
    const hashes = el('target-hashes').value.split(/\s+/).filter(Boolean);
    const result = await post('/api/start', {
        attack_type: el('attack-type').value,
        hash_type: el('hash-type').value,
        target_hashes: hashes,
        mask: el('mask').value,
        wordlist: el('wordlist').value
    });
    say(result.data.message || ('start returned ' + result.status), !result.ok);
}

async function control(path) {
    const result = await post(path);
    say(result.data.message || (path + ' returned ' + result.status), !result.ok);
}

function wire() {
    el('btn-start').addEventListener('click', startAttack);
    el('btn-stop').addEventListener('click', () => control('/api/stop'));
    el('btn-pause').addEventListener('click', () => control('/api/pause'));
    el('btn-resume').addEventListener('click', () => control('/api/resume'));
    el('btn-session').addEventListener('click', async () => {
        const result = await post('/api/config', { session_name: el('session-input').value });
        say(result.data.message || ('config returned ' + result.status), !result.ok);
    });

    // The token is asked for once, not stored in localStorage, so closing the
    // tab forgets it. A token in localStorage survives an XSS that this CSP is
    // supposed to prevent; asking again costs one click.
    const remembered = sessionStorage.getItem('pwdcrack-token');
    if (remembered) {
        bearer = remembered;
        say('token restored for this tab');
    } else {
        const entered = window.prompt('Dashboard token (Authorization: Bearer)');
        if (entered) {
            bearer = entered.trim();
            sessionStorage.setItem('pwdcrack-token', bearer);
            say('token accepted by the server if requests succeed');
        }
    }

    connectWs();
    poll();
    setInterval(poll, 2000);
}

wire();
"#;

#[cfg(test)]
mod tests {
    use super::*;
    fn headers_with(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            auth::AUTH_HEADER,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h.insert(CSRF_HEADER, HeaderValue::from_static(CSRF_HEADER_VALUE));
        h
    }

    /// The gate P10.1.07 names.
    #[test]
    fn an_unauthenticated_mutating_request_is_refused() {
        let state = AppState::inert(None);
        let empty = HeaderMap::new();
        let (decision, refusal) = check(&state, &empty, "1.2.3.4")
            .expect_err("no token must not be allowed");
        assert_eq!(decision, Decision::NoToken);
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let state = AppState::inert(Some("aa".repeat(32)));
        let mut h = headers_with("aa");
        h.insert(
            auth::AUTH_HEADER,
            HeaderValue::from_static("Bearer bb"),
        );
        let (decision, refusal) = check(&state, &h, "1.2.3.4").expect_err("wrong token");
        assert_eq!(decision, Decision::NoToken);
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn the_right_token_without_the_csrf_header_is_refused() {
        let token = "aa".repeat(32);
        let state = AppState::inert(Some(token.clone()));
        let mut h = HeaderMap::new();
        h.insert(
            auth::AUTH_HEADER,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let (decision, refusal) = check(&state, &h, "1.2.3.4").expect_err("no csrf header");
        assert_eq!(decision, Decision::NoCsrfHeader);
        assert_eq!(refusal.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_right_token_and_header_are_allowed() {
        let token = "ab".repeat(32);
        let state = AppState::inert(Some(token.clone()));
        let h = headers_with(&token);
        assert!(check(&state, &h, "1.2.3.4").is_ok(), "the operator's own request must pass");
    }

    /// A valid token is not enough on its own; the header is separate.
    #[test]
    fn a_token_without_the_header_is_still_refused() {
        let token = "cd".repeat(32);
        let state = AppState::inert(Some(token.clone()));
        let mut h = HeaderMap::new();
        h.insert(
            auth::AUTH_HEADER,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h.insert(CSRF_HEADER, HeaderValue::from_static("wrong"));
        let (decision, _) = check(&state, &h, "1.2.3.4").expect_err("wrong value");
        assert_eq!(decision, Decision::BadCsrfHeader);
    }

    #[test]
    fn a_flood_is_refused_after_the_burst() {
        let token = "ef".repeat(32);
        let state = AppState::inert(Some(token.clone()));
        let h = headers_with(&token);
        let mut refused = 0;
        for _ in 0..40 {
            if check(&state, &h, "9.9.9.9").is_err() {
                refused += 1;
            }
        }
        assert!(refused > 0, "40 requests at 10/s with a burst of 20 must be refused");
    }

    #[test]
    fn a_different_source_keeps_its_own_budget() {
        let token = "12".repeat(32);
        let state = AppState::inert(Some(token.clone()));
        let h = headers_with(&token);
        for _ in 0..25 {
            let _ = check(&state, &h, "9.9.9.9");
        }
        assert!(
            check(&state, &h, "8.8.8.8").is_ok(),
            "one flooder must not lock out the operator"
        );
    }

    // ---- pages comply with the policy that is served ----

    /// If the CSP forbids inline script and a page uses onclick, the page
    /// silently stops working. These are the checks that keep the two honest.
    #[test]
    fn no_page_carries_an_inline_event_handler() {
        for (name, html) in [
            ("root", ROOT_HTML),
            ("dashboard", DASHBOARD_HTML),
        ] {
            assert!(
                !html.contains("onclick="),
                "{name}.html has an onclick handler, which the CSP blocks"
            );
            assert!(!html.contains("onsubmit="), "{name}.html has onsubmit");
        }
    }

    #[test]
    fn no_page_carries_an_inline_style_attribute() {
        for (name, html) in [("root", ROOT_HTML), ("dashboard", DASHBOARD_HTML)] {
            assert!(
                !html.contains("style="),
                "{name}.html has a style attribute, which style-src 'self' blocks"
            );
        }
    }

    #[test]
    fn no_page_carries_an_inline_script_block() {
        for (name, html) in [("root", ROOT_HTML), ("dashboard", DASHBOARD_HTML)] {
            assert!(
                !html.contains("<script>"),
                "{name}.html has an inline script block, which script-src 'self' blocks"
            );
            assert!(
                html.contains(r#"<script src="/app.js"></script>"#),
                "{name}.html must load its script from a file"
            );
        }
    }

    /// The pages must not depend on an asset from another origin, or
    /// `default-src 'none'` will block them.
    #[test]
    fn every_asset_the_pages_reference_is_same_origin() {
        for (name, html) in [("root", ROOT_HTML), ("dashboard", DASHBOARD_HTML)] {
            assert!(!html.contains("//cdn"), "{name}.html loads a remote asset");
            assert!(!html.contains("https://"), "{name}.html references https");
            assert!(!html.contains("http://"), "{name}.html references http");
        }
    }

    #[test]
    fn the_javascript_sends_the_header_the_server_requires() {
        assert!(JS.contains("X-Pwdcrack-Request"), "the client must send the CSRF header");
        assert!(JS.contains("Authorization"), "the client must send the bearer token");
        assert!(!JS.contains("token="), "the token must never reach a URL");
    }

    #[test]
    fn the_javascript_wires_handlers_with_add_event_listener() {
        assert!(
            JS.contains("addEventListener"),
            "handlers must be registered from app.js, since inline ones are blocked"
        );
        assert!(!JS.contains("onclick ="), "no inline handler assignment");
    }

    #[test]
    fn the_start_route_sends_target_hashes_as_repeated_fields() {
        // `Form` with `Option<Vec<String>>` needs one field per value, which is
        // what `URLSearchParams` from a repeated key produces.
        assert!(JS.contains("target_hashes"), "the form field must be present");
        assert!(
            JS.contains("target_hashes: hashes"),
            "the array must be sent, not stringified into one field"
        );
    }
}