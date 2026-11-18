//! User → API payload conversion, mirroring `convert_user` in `account.py`.

use chrono::Utc;

use crate::deleted_user::{
    deleted_last_seen, deleted_username_for, is_deleted_user, is_suspended_user, should_redact_for_viewer,
};
use crate::error::ApiResult;
use crate::models::User;
use crate::presence::PresenceService;
use crate::verification::{compute_verification_status, VerifiedUserData};
use serde_json::{json, Value};

fn is_admin(user: &User) -> bool {
    user.id == 1
}

/// Full user payload for authenticated contexts.
pub async fn convert_user(
    db: &sqlx::PgPool,
    presence: &PresenceService,
    user: &User,
    viewer_id: Option<i64>,
) -> ApiResult<Value> {
    if should_redact_for_viewer(user, viewer_id) {
        return Ok(json!({
            "id": user.id,
            "admin": is_admin(user),
            "username": deleted_username_for(user.id),
            "display_name": "",
            "profile_picture": null,
            "bio": null,
            "online": false,
            "last_seen": deleted_last_seen().to_rfc3339(),
            "created_at": null,
            "verified": false,
            "verification_status": "none",
            "suspended": false,
            "suspension_reason": null,
            "deleted": true,
        }));
    }

    let (online, last_seen) = presence.get_presence(user.id);
    let verified_users = load_verified_users(db).await?;
    let status = compute_verification_status(user, &verified_users);
    let effective_last_seen = last_seen.or(user.last_seen).or(user.created_at);

    Ok(json!({
        "id": user.id,
        "created_at": user.created_at.map(|d| d.to_rfc3339()),
        "last_seen": effective_last_seen.unwrap_or_else(Utc::now).to_rfc3339(),
        "online": online,
        "username": user.username,
        "display_name": user.display_name,
        "profile_picture": user.profile_picture,
        "bio": user.bio,
        "admin": is_admin(user),
        "verified": user.verified,
        "verification_status": status.as_str(),
        "suspended": user.suspended,
        "suspension_reason": user.suspension_reason,
        "deleted": false,
    }))
}

/// Minimal user payload for DM conversation list entries.
pub async fn convert_user_for_dm_conversation(
    db: &sqlx::PgPool,
    presence: &PresenceService,
    user: &User,
    viewer_id: Option<i64>,
) -> ApiResult<Value> {
    if should_redact_for_viewer(user, viewer_id) {
        return Ok(json!({
            "id": user.id,
            "username": deleted_username_for(user.id),
            "display_name": "",
            "profile_picture": null,
            "deleted": true,
            "verification_status": "none",
            "online": false,
            "last_seen": deleted_last_seen().to_rfc3339(),
        }));
    }

    let (online, last_seen) = presence.get_presence(user.id);
    let verified_users = load_verified_users(db).await?;
    let status = compute_verification_status(user, &verified_users);
    let effective_last_seen = last_seen.or(user.last_seen).or(user.created_at);

    let mut payload = json!({
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "profile_picture": user.profile_picture,
        "deleted": false,
        "verification_status": status.as_str(),
        "online": online,
        "last_seen": effective_last_seen.unwrap_or_else(Utc::now).to_rfc3339(),
    });

    if is_suspended_user(user) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("suspended".into(), json!(true));
            obj.insert("suspension_reason".into(), json!(user.suspension_reason));
        }
    }
    Ok(payload)
}

/// Load verified, non-deleted, non-suspended users for similarity computation.
pub async fn load_verified_users(db: &sqlx::PgPool) -> ApiResult<Vec<VerifiedUserData>> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT username, display_name FROM \"user\" WHERE verified = TRUE AND deleted = FALSE AND suspended = FALSE")
            .fetch_all(db)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(username, display_name)| VerifiedUserData { username, display_name })
        .collect())
}

/// Mark `unused` to keep clippy silent when callers only need redaction helpers.
pub fn _unused() {
    let _ = is_deleted_user;
}