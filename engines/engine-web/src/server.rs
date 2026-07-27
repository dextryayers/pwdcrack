use std::sync::Arc;
use tokio::sync::RwLock;

use crate::WebConfig;
use crate::routes::{dashboard_routes, api_routes, static_routes};

pub struct AppState {
    pub config: WebConfig,
    pub hash_rate: RwLock<f64>,
    pub total_cracked: RwLock<u64>,
    pub total_tested: RwLock<u64>,
    pub workers: RwLock<Vec<WorkerEntry>>,
    pub session_name: RwLock<String>,
    pub start_time: std::time::Instant,
}

#[derive(Clone, serde::Serialize)]
pub struct WorkerEntry {
    pub name: String,
    pub hashes_sec: f64,
    pub total_cracked: u64,
    pub alive: bool,
}

impl AppState {
    pub fn new(config: WebConfig) -> Self {
        AppState {
            hash_rate: RwLock::new(0.0),
            total_cracked: RwLock::new(0),
            total_tested: RwLock::new(0),
            workers: RwLock::new(Vec::new()),
            session_name: RwLock::new(String::new()),
            start_time: std::time::Instant::now(),
            config,
        }
    }
}

pub async fn start(config: WebConfig) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AppState::new(config.clone()));

    let app = axum::Router::new()
        .nest("/", static_routes())
        .nest("/api", api_routes())
        .nest("/dashboard", dashboard_routes())
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    log::info!("Web dashboard starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
