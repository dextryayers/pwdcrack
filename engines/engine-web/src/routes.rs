use axum::{
    Router,
    routing::{get, post},
    response::Json,
    extract::State,
};

use crate::server::AppState;
use std::sync::Arc;

#[derive(serde::Serialize)]
struct StatusResponse {
    hash_rate: f64,
    total_cracked: u64,
    total_tested: u64,
    uptime_secs: u64,
    workers: Vec<serde_json::Value>,
    session: String,
}

pub fn static_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async { axum::response::Html(INDEX_HTML) }))
        .route("/style.css", get(|| async { axum::response::Html(CSS) }))
        .route("/app.js", get(|| async { axum::response::Html(JS) }))
}

pub fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status", get(get_status))
        .route("/start", post(start_attack))
        .route("/stop", post(stop_attack))
}

pub fn dashboard_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(dashboard_page))
        .route("/ws", get(crate::websocket::ws_handler))
}

async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Json<StatusResponse> {
    Json(StatusResponse {
        hash_rate: *state.hash_rate.read().await,
        total_cracked: *state.total_cracked.read().await,
        total_tested: *state.total_tested.read().await,
        uptime_secs: state.start_time.elapsed().as_secs(),
        workers: Vec::new(),
        session: state.session_name.read().await.clone(),
    })
}

async fn start_attack() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "not_implemented"}))
}

async fn stop_attack() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "not_implemented"}))
}

async fn dashboard_page() -> axum::response::Html<&'static str> {
    axum::response::Html(DASHBOARD_HTML)
}

const INDEX_HTML: &str = r#"<!DOCTYPE html><html><head><title>pwdcrack</title><link rel="stylesheet" href="/style.css"></head><body><h1>pwdcrack</h1><p>Dashboard: <a href="/dashboard">/dashboard</a></p><p>API: <a href="/api/status">/api/status</a></p></body></html>"#;

const CSS: &str = r#"body{font-family:monospace;background:#111;color:#0f0;margin:2rem}td,th{padding:0.5rem;border:1px solid #333}input,button{background:#222;color:#0f0;border:1px solid #0f0;padding:0.5rem}"#;

const JS: &str = r#"setInterval(async()=>{const r=await fetch('/api/status');const d=await r.json();document.getElementById('rate').textContent=d.hash_rate.toFixed(1);document.getElementById('cracked').textContent=d.total_cracked;document.getElementById('uptime').textContent=d.uptime_secs;},1000);"#;

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html><html><head><title>pwdcrack Dashboard</title><link rel="stylesheet" href="/style.css"></head><body><h1>Dashboard</h1><p>Rate: <span id="rate">0</span> H/s</p><p>Cracked: <span id="cracked">0</span></p><p>Uptime: <span id="uptime">0</span>s</p><script src="/app.js"></script></body></html>"#;
