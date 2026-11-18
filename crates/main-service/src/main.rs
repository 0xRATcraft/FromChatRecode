use fc_main::db;
use fc_shared::{init_tracing, Config};
use fc_shared::config::ports;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing("fc-main");

    let config = Config::from_env(ports::MAIN);
    let database_url = config
        .database_url
        .clone()
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required for fc-main"))?;
    let jwt_secret = if config.jwt_secret.is_empty() {
        "dev-secret-do-not-use".to_string()
    } else {
        config.jwt_secret.clone()
    };

    let pool = db::create_pool(&database_url).await?;

    // Bootstrap schema once if the DB is empty.
    let schema = include_str!("../migrations/0001_schema.sql");
    db::ensure_schema_from_file(&pool, schema).await?;

    let state = fc_main::dependencies::AppState::new(pool, jwt_secret);
    let app = fc_main::app(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("fc-main listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}