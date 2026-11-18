//! Public-chat message conversion and page helpers, mirroring the corresponding
//! functions in `routes/messaging.py`. DM conversion helpers live in `dm.rs`.

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::error::ApiResult;
use crate::models::{Message, Reaction, User};
use crate::verification::{compute_verification_status, VerifiedUserData};

/// Minimal reaction identity: a deleted/suspended user is shown as deleted.
pub fn reaction_user_payload(user: Option<&User>, user_id: i64) -> Value {
    let deleted = user.map(|u| u.deleted || u.suspended).unwrap_or(true);
    if user.is_none() || deleted {
        json!({
            "id": user_id,
            "username": crate::deleted_user::deleted_username_for(user_id),
            "display_name": "",
        })
    } else {
        let u = user.unwrap();
        json!({
            "id": user_id,
            "username": u.username,
            "display_name": u.display_name,
        })
    }
}

/// Group reactions by emoji into the API shape.
pub fn group_reactions(reactions: &[Reaction], users_by_id: &std::collections::HashMap<i64, User>) -> Vec<Value> {
    let mut map: std::collections::BTreeMap<String, (i64, Vec<Value>)> = std::collections::BTreeMap::new();
    for r in reactions {
        let e = map.entry(r.emoji.clone()).or_insert((0, Vec::new()));
        e.0 += 1;
        e.1.push(reaction_user_payload(users_by_id.get(&r.user_id), r.user_id));
    }
    map.into_iter()
        .map(|(emoji, (count, users))| json!({ "emoji": emoji, "count": count, "users": users }))
        .collect()
}

/// Full public JSON payload for a message, mirroring `convert_message`.
pub fn convert_message(
    msg: &Message,
    author: Option<&User>,
    reactions: &[Reaction],
    users_by_id: &std::collections::HashMap<i64, User>,
    verified_users_data: &[VerifiedUserData],
) -> Value {
    let is_deleted_susp = author.map(|u| u.deleted || u.suspended).unwrap_or(true);
    let (username, display_name, profile_picture, verified, verification_status) = if is_deleted_susp {
        (
            crate::deleted_user::deleted_username_for(msg.user_id),
            String::new(),
            None,
            false,
            "none",
        )
    } else {
        let a = author.unwrap();
        let status = compute_verification_status(a, verified_users_data);
        (
            a.username.clone(),
            a.display_name.clone(),
            a.profile_picture.clone(),
            a.verified,
            status.as_str(),
        )
    };

    json!({
        "id": msg.id,
        "user_id": msg.user_id,
        "content": msg.content,
        "timestamp": msg.timestamp.unwrap_or_else(Utc::now).to_rfc3339(),
        "is_read": msg.is_read,
        "is_edited": msg.is_edited,
        "username": username,
        "display_name": display_name,
        "profile_picture": profile_picture,
        "verified": verified,
        "verification_status": verification_status,
        "reply_to": null,
        "reactions": group_reactions(reactions, users_by_id),
        "files": [],
    })
}

/// A `User`'s raw tuple for `convert_message` per-user (adds client_message_id to sender).
pub fn convert_message_for_user(
    msg: &Message,
    author: Option<&User>,
    reactions: &[Reaction],
    users_by_id: &std::collections::HashMap<i64, User>,
    verified_users_data: &[VerifiedUserData],
    viewer_user_id: Option<i64>,
    sender_client_message_id: Option<&str>,
) -> Value {
    let mut payload = convert_message(msg, author, reactions, users_by_id, verified_users_data);
    if let Some(cid) = sender_client_message_id {
        if viewer_user_id == Some(msg.user_id) {
            if let Some(o) = payload.as_object_mut() {
                o.insert("client_message_id".into(), json!(cid));
            }
        }
    }
    payload
}

/// Fetch a user by id (returns None if absent), for message joins.
pub async fn load_users_by_ids(db: &sqlx::PgPool, ids: &[i64]) -> ApiResult<std::collections::HashMap<i64, User>> {
    let mut out = std::collections::HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    // Small paging to stay within Postgres parameter limits.
    for chunk in ids.chunks(500) {
        let rows: Vec<User> = sqlx::query_as(&format!(
            "SELECT id, username, display_name, password_hash, profile_picture, bio, online, last_seen, \
             created_at, verified, suspended, suspension_reason, deleted, deleted_at, yandex_id \
             FROM \"user\" WHERE id = ANY($1)"
        ))
        .bind(chunk.to_vec())
        .fetch_all(db)
        .await?;
        for u in rows {
            out.insert(u.id, u);
        }
    }
    Ok(out)
}

/// Iso-format a timestamp used across public/DM conversions.
pub fn iso(ts: Option<DateTime<Utc>>) -> String {
    ts.unwrap_or_else(Utc::now).to_rfc3339()
}