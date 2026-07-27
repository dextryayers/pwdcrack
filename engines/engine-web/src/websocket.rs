use axum::extract::ws::{WebSocket, WebSocketUpgrade, Message};
use axum::response::IntoResponse;
use axum::extract::State;

use std::sync::Arc;

use crate::server::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    use tokio::time::{interval, Duration};

    let mut tick = interval(Duration::from_secs(1));

    loop {
        tick.tick().await;

        let payload = serde_json::json!({
            "hash_rate": *state.hash_rate.read().await,
            "total_cracked": *state.total_cracked.read().await,
            "total_tested": *state.total_tested.read().await,
            "uptime_secs": state.start_time.elapsed().as_secs(),
            "workers": [],
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
