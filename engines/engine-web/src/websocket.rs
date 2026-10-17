//! The status stream.
//!
//! # Read only, and why that is acceptable
//!
//! This endpoint is not behind the bearer token, exactly like `/api/status`, and
//! for the same reason: the page polls every two seconds and an operator should
//! not have to present a token twenty seven times a minute to keep a chart
//! moving. What it can send is counters, the current status, cracked hashes and
//! passwords, and worker names.
//!
//! Cracked passwords are the part that deserves thought. On the loopback default
//! nothing else can reach this port, which is the case the default is chosen
//! for. On an exposed bind the operator has already accepted reachability, and
//! this is strictly less than what `/api/status` already returns unauthenticated.
//! If that trade is wrong for a given deployment, the fix is not to special case
//! this route; it is to leave the dashboard on loopback, which is the default.
//!
//! Every payload is read from the live attack handle through
//! [`AppState::snapshot`], so nothing here can report a running attack that is
//! not running.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use tokio::time::interval;

use crate::server::AppState;

/// How often a frame is pushed.
const TICK: Duration = Duration::from_secs(1);

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut tick = interval(TICK);

    loop {
        tick.tick().await;

        let snapshot = state.snapshot().await;
        let workers = state.workers.read().await.clone();

        let payload = serde_json::json!({
            "status": snapshot.status.to_string(),
            "hash_rate": snapshot.hash_rate,
            "total_tested": snapshot.tested,
            "total_cracked": snapshot.cracked,
            "uptime_secs": state.start_time.elapsed().as_secs(),
            "executor_wired": snapshot.executor_wired,
            "exposed": state.bind_policy.is_exposed(),
            "hits": snapshot.hits,
            "workers": workers,
        });

        // A send failure means the client is gone. Breaking rather than looping
        // is what stops a disconnected browser from being pushed a frame a
        // second forever.
        if socket
            .send(Message::Text(payload.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
    }
}