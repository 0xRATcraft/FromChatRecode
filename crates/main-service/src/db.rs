//! Database pool and helpers for the main service.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Build a connection pool from the configured DATABASE_URL with retry.
pub async fn create_pool(url: &str) -> anyhow::Result<PgPool> {
    let mut pool = None;
    for attempt in 1..=15 {
        match PgPoolOptions::new()
            .max_connections(20)
            .min_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(1800))
            .connect(url)
            .await
        {
            Ok(p) => {
                pool = Some(p);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    "db connection failed (attempt {}/15): {}",
                    attempt,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if attempt == 15 {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(pool.expect("pool built"))
}

/// Run the bootstrap schema if the DB is empty; idempotent.
pub async fn ensure_schema_from_file(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    // Only run when the `user` table is missing, mirroring migration.py.
    let has_user = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='user'",
    )
    .fetch_one(pool)
    .await?;
    if has_user > 0 {
        return Ok(());
    }
    tracing::info!("bootstrapping schema (no user table found)");
    for statement in sql.split(';') {
        let s = statement.trim();
        if s.is_empty() {
            continue;
        }
        sqlx::raw_sql(s).execute(pool).await?;
    }
    Ok(())
}