use fc_shared::config::{Config, ports};

#[tokio::main]
async fn main() {
    fc_shared::init_tracing("fc-messaging");
    let mut config = Config::from_env(ports::MESSAGING);
    // Messaging may run without a DATABASE_URL; ensure a sane default is not required.
    if config.jwt_secret.is_empty() {
        config.jwt_secret = "messaging-no-jwt".to_string();
    }
    let app = fc_messaging::app(config.clone());
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    tracing::info!("messaging listening on {}", addr);
    axum::serve(listener, app).await.expect("axum serve");
}