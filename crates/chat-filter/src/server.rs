//! HTTP front of the chat filter service, mirroring Python `src/chat_filter/main.py`.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde::Serialize;

use crate::blocklist::State as AppState;
use crate::engine::Engine;

#[derive(Clone)]
struct Api {
    state: AppState,
    engine: Arc<Engine>,
}

#[derive(Deserialize)]
struct CheckRequest {
    text: String,
}

#[derive(Serialize)]
struct CheckResponse {
    allowed: bool,
}

#[derive(Deserialize)]
struct BlocklistWordsRequest {
    words: Vec<String>,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy", "service": "chat_filter"}))
}

async fn check(State(api): State<Api>, Json(body): Json<CheckRequest>) -> Json<CheckResponse> {
    let allowed = api.engine.is_allowed(&api.state.blocklist, &body.text);
    Json(CheckResponse { allowed })
}

async fn blocklist_list(State(api): State<Api>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "words": api.state.blocklist.get_blocklist() }))
}

async fn blocklist_add(
    State(api): State<Api>,
    Json(body): Json<BlocklistWordsRequest>,
) -> Json<serde_json::Value> {
    let (added, words) = api.state.blocklist.add_words(body.words);
    Json(serde_json::json!({ "added": added, "words": words }))
}

async fn blocklist_remove(
    State(api): State<Api>,
    Json(body): Json<BlocklistWordsRequest>,
) -> Json<serde_json::Value> {
    let (removed, words) = api.state.blocklist.remove_words(body.words);
    Json(serde_json::json!({ "removed": removed, "words": words }))
}

async fn blocklist_clear(State(api): State<Api>) -> Json<serde_json::Value> {
    api.state.blocklist.clear_blocklist();
    Json(serde_json::json!({ "words": [] }))
}

/// Build the chat filter app.
pub fn app(config: fc_shared::config::Config) -> Router {
    let state = AppState::new(&config);
    let engine = Arc::new(Engine::new());
    let api = Api { state, engine };
    Router::new()
        .route("/health", get(health))
        .route("/check", post(check))
        .route("/blocklist", get(blocklist_list))
        .route("/blocklist/add", post(blocklist_add))
        .route("/blocklist/remove", post(blocklist_remove))
        .route("/blocklist/clear", post(blocklist_clear))
        .with_state(api)
}