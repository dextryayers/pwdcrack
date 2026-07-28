use axum::extract::ws::{WebSocket, WebSocketUpgrade, Message};
use axum::response::IntoResponse;
use axum::extract::State;

use std::sync::Arc;
use tokio::time::{interval, Duration};

use crate::server::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut tick = interval(Duration::from_secs(1));

    loop {
        tick.tick().await;

        let hr = *state.hash_rate.read().await;
        let tc = *state.total_cracked.read().await;
        let tt = *state.total_tested.read().await;
        let status = format!("{:?}", *state.status.read().await);
        let workers: Vec<serde_json::Value> = state.workers.read().await.iter().map(|w| {
            serde_json::json!({
                "name": w.name,
                "hashes_sec": w.hashes_sec,
                "total_cracked": w.total_cracked,
                "alive": w.alive,
            })
        }).collect();

        let payload = serde_json::json!({
            "hash_rate": hr,
            "total_cracked": tc,
            "total_tested": tt,
            "uptime_secs": state.start_time.elapsed().as_secs(),
            "status": status,
            "workers": workers,
        });

        if socket
            .send(Message::Text(payload.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
    }
}
