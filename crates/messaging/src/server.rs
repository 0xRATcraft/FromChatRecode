//! HTTP front of the messaging service, mirroring Python `src/messaging/main.py`.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use fc_shared::config::{Config, MessageRetention};

use crate::crypto;

/// Ephemeral transport key state kept in memory (never persisted).
struct KeyState {
    private_bytes: Vec<u8>,
    public_key_b64: String,
    key_id_ms: u128,
    created_at_secs: u64,
}

struct AppState {
    config: Arc<Config>,
    key: Mutex<Option<KeyState>>,
}

#[derive(Clone)]
struct Api(Arc<AppState>);

#[derive(Deserialize)]
struct ProcessMessageRequest {
    client_public_key_b64: String,
    transport_nonce_b64: String,
    transport_ciphertext_b64: String,
    compliance_public_key_b64: String,
    sender_public_key_b64: String,
    recipient_public_key_b64: String,
}

fn state(config: Config) -> Api {
    let key = crypto::generate_ephemeral_keypair();
    let key = KeyState {
        private_bytes: key.private_bytes().to_vec(),
        public_key_b64: key.public_key_b64().to_string(),
        key_id_ms: key.key_id_ms(),
        created_at_secs: key.created_at_secs(),
    };
    Api(Arc::new(AppState {
        config: Arc::new(config),
        key: Mutex::new(Some(key)),
    }))
}

fn store_compliance(cfg: &Config) -> bool {
    !matches!(cfg.retention(), MessageRetention::NeverStoreComplianceMek)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy", "service": "messaging"}))
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({"message": "FromChat Messaging Service", "status": "operational"}))
}

async fn get_transport_public_key(State(api): State<Api>) -> Json<serde_json::Value> {
    let guard = api.0.key.lock().expect("key lock");
    let key = guard.as_ref().expect("ephemeral key initialised");
    Json(serde_json::json!({
        "key_id": &key.key_id_ms,
        "public_key_b64": &key.public_key_b64,
        "created_at": &key.created_at_secs,
    }))
}

async fn process_message(
    State(api): State<Api>,
    Json(req): Json<ProcessMessageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let private = {
        let guard = api.0.key.lock().expect("key lock");
        guard
            .as_ref()
            .map(|k| k.private_bytes.clone())
            .expect("ephemeral key initialised")
    };
    let store = store_compliance(&api.0.config);
    let compliance_key = api.0.config.compliance_public_key.clone();

    let result = crypto::process_encrypted_message(
        &req.client_public_key_b64,
        &req.transport_nonce_b64,
        &req.transport_ciphertext_b64,
        if store {
            if req.compliance_public_key_b64.trim().is_empty() {
                &compliance_key
            } else {
                &req.compliance_public_key_b64
            }
        } else {
            ""
        },
        &req.sender_public_key_b64,
        &req.recipient_public_key_b64,
        &private,
        store,
    );

    match result {
        Ok(v) => Ok(Json(v)),
        Err(e) => {
            tracing::warn!("process message failed: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": format!("{}", e)})),
            ))
        }
    }
}

/// Build the messaging service app.
pub fn app(config: Config) -> Router {
    let api = state(config);
    Router::new()
        .route("/health", get(health))
        .route("/", get(root))
        .route("/key/transport/public", get(get_transport_public_key))
        .route("/process", post(process_message))
        .with_state(api)
}