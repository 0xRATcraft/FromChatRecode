//! Application assembly for the main service.

use axum::routing::get;
use axum::Router;

use crate::dependencies::AppState;

/// Build the main service application with the given shared state.
/// Route modules (envelope_messaging) are mounted in a later step;
/// account + auth_steps + public_messaging + websocket + `/health` are live here.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async { axum::Json(serde_json::json!({"status": "healthy", "service": "main"})) }),
        )
        .merge(crate::routes::account::router())
        .merge(crate::routes::auth_steps::router())
        .merge(crate::routes::public_messaging::router())
        .merge(crate::routes::dm::router())
        .route("/chat/ws", get(crate::routes::ws_routes::chat_ws))
        .with_state(state)
}

/// Convenience: build an `AppState` from a connection pool and JWT secret.
pub fn app_state(db: sqlx::PgPool, jwt_secret: String) -> AppState {
    AppState::new(db, jwt_secret)
}