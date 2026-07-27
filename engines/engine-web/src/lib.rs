//! engine-web — Real-time web dashboard for pwdcrack
//!
//! REST API + WebSocket for monitoring cracking progress,
//! managing sessions, and viewing cluster status.

pub mod server;
pub mod routes;
pub mod websocket;

#[derive(Clone)]
pub struct WebConfig {
    pub port: u16,
    pub host: String,
    pub auth_token: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            port: 8080,
            host: "0.0.0.0".to_string(),
            auth_token: None,
        }
    }
}
