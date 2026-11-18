use fc_shared::config::{Config, ports};

#[tokio::main]
async fn main() {
    fc_shared::init_tracing("fc-file-storage");
    let config = Config::from_env(ports::FILE_STORAGE);
    let app = fc_file_storage::app(config.clone());
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    tracing::info!("file_storage listening on {}", addr);
    axum::serve(listener, app).await.expect("axum serve");
}