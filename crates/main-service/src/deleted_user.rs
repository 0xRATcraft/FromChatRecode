//! Deleted-user handling mirroring `deleted_user.py`.

use chrono::Utc;

use crate::error::ApiResult;
use crate::models::User;

/// Deleted username format for a user id: `#deleted{id}`.
pub fn deleted_username_for(user_id: i64) -> String {
    format!("#deleted{}", user_id)
}

/// The fixed "deleted" users' last_seen sentinel (Unix epoch).
pub fn deleted_last_seen() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).expect("epoch timestamp")
}

/// A user account is marked deleted.
pub fn is_deleted_user(user: &User) -> bool {
    user.deleted
}

/// A user is suspended (and not deleted).
pub fn is_suspended_user(user: &User) -> bool {
    user.suspended && !user.deleted
}

/// Whether a user is deleted or suspended.
pub fn is_deleted_or_suspended(user: &User) -> bool {
    is_deleted_user(user) || is_suspended_user(user)
}

/// Hide peer PII from strangers; self and admin (id 1) still see suspended users.
pub fn should_redact_for_viewer(user: &User, viewer_id: Option<i64>) -> bool {
    if is_deleted_user(user) {
        return true;
    }
    if !is_suspended_user(user) {
        return false;
    }
    match viewer_id {
        None => true,
        Some(id) => id != user.id && id != 1,
    }
}

/// Apply the DB-side "deleted" fields to a single row, mirroring `apply_deleted_user_db_fields`.
/// Keeps `yandex_id` (see yandex_id_lifecycle hold period).
pub async fn apply_deleted_fields_to_db(
    db: &sqlx::PgPool,
    user_id: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE \"user\" SET \
         deleted = TRUE, \
         deleted_at = now(), \
         username = $1, \
         display_name = '', \
         bio = NULL, \
         password_hash = '', \
         profile_picture = NULL, \
         last_seen = '1970-01-01T00:00:00Z'::timestamptz, \
         created_at = NULL, \
         online = FALSE \
         WHERE id = $2",
    )
    .bind(deleted_username_for(user_id))
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Current UTC timestamp (small helper for last_seen fallbacks).
pub fn _now() -> chrono::DateTime<chrono::Utc> {
    Utc::now()
}