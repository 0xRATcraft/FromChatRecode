//! Username lookup and uniqueness helpers, mirroring `username.py`.

use sqlx::PgPool;

use crate::error::ApiResult;

/// Return true if another account already uses this username (case-insensitive).
pub async fn username_taken(db: &PgPool, username: &str, exclude_user_id: Option<i64>) -> ApiResult<bool> {
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM \"user\" WHERE lower(username) = lower($1) AND ($2::bigint IS NULL OR id <> $2) LIMIT 1",
    )
    .bind(username)
    .bind(exclude_user_id)
    .fetch_optional(db)
    .await?;
    Ok(id.is_some())
}