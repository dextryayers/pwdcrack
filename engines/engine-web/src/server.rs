use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::WebConfig;
use crate::routes::{dashboard_routes, api_routes, static_routes};

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct WorkerEntry {
    pub name: String,
    pub hashes_sec: f64,
    pub total_cracked: u64,
    pub alive: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct AttackConfig {
    pub attack_type: String,        // "dictionary" | "bruteforce" | "combinator"
    pub hash_type: String,          // "MD5" | "SHA256" | ...
    pub target_hashes: Vec<String>, // list of hash strings
    pub mask: Option<String>,       // for brute force
    pub wordlist: Option<String>,   // for dictionary
    pub rules: Vec<String>,         // for dictionary with rules
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub enum AttackStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Error(String),
}

pub struct AppState {
    pub config: WebConfig,
    pub hash_rate: RwLock<f64>,
    pub total_cracked: RwLock<u64>,
    pub total_tested: RwLock<u64>,
    pub workers: RwLock<Vec<WorkerEntry>>,
    pub session_name: RwLock<String>,
    pub status: RwLock<AttackStatus>,
    pub attack_config: RwLock<Option<AttackConfig>>,
    pub message_log: RwLock<Vec<String>>,
    pub start_time: Instant,
}

impl AppState {
    pub fn new(config: WebConfig) -> Self {
        AppState {
            hash_rate: RwLock::new(0.0),
            total_cracked: RwLock::new(0),
            total_tested: RwLock::new(0),
            workers: RwLock::new(Vec::new()),
            session_name: RwLock::new(String::new()),
            status: RwLock::new(AttackStatus::Idle),
            attack_config: RwLock::new(None),
            message_log: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            config,
        }
    }

    pub async fn update_stats(&self, hash_rate: f64, tested: u64, cracked: u64) {
        *self.hash_rate.write().await = hash_rate;
        *self.total_tested.write().await = tested;
        *self.total_cracked.write().await = cracked;
    }

    pub async fn log_message(&self, msg: String) {
        let mut log = self.message_log.write().await;
        log.push(format!("[{}] {}", chrono::Utc::now().format("%H:%M:%S"), msg));
        if log.len() > 1000 { log.remove(0); }
    }

    pub async fn add_worker(&self, name: &str, hps: f64) {
        let mut workers = self.workers.write().await;
        if let Some(w) = workers.iter_mut().find(|w| w.name == name) {
            w.hashes_sec = hps;
            w.alive = true;
        } else {
            workers.push(WorkerEntry {
                name: name.to_string(),
                hashes_sec: hps,
                total_cracked: 0,
                alive: true,
            });
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
