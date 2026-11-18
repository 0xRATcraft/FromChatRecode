use fc_shared::config::{Config, ports};

#[tokio::main]
async fn main() {
    fc_shared::init_tracing("fc-chat-filter");
    let config = Config::from_env(ports::CHAT_FILTER);
    let app = fc_chat_filter::app(config.clone());
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    tracing::info!("chat_filter listening on {}", addr);
    axum::serve(listener, app).await.expect("axum serve");
}