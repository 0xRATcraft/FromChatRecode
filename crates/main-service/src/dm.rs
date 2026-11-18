//! DM envelope conversion helpers + inbound read-id computation,
//! port of `convert_dm_envelope*` and `_inbound_dm_read_ids*` in `routes/messaging.py`.

use chrono::Utc;
use serde_json::{json, Value};

use crate::error::ApiResult;
use crate::models::{DmEnvelope, DmReadReceipt, User};
use crate::verification::{compute_verification_status, VerifiedUserData};

#[derive(Clone)]
pub struct DmCtx {
    pub db: sqlx::PgPool,
}

impl DmCtx {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }
}

/// Inbound read ids for a set of envelopes from a viewer's perspective.
pub async fn inbound_dm_read_ids(ctx: &DmCtx, user_id: i64, envelopes: &[DmEnvelope]) -> ApiResult<std::collections::HashSet<i64>> {
    let inbound: Vec<&DmEnvelope> = envelopes
        .iter()
        .filter(|e| e.recipient_id == user_id && e.sender_id != user_id)
        .collect();
    if inbound.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let other_ids: Vec<i64> = inbound.iter().map(|e| e.sender_id).collect();
    let mut read_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    // Prefs: last_read_envelope_id by other_user_id.
    let prefs: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT other_user_id, last_read_envelope_id FROM dm_conversation_preference \
         WHERE user_id=$1 AND other_user_id = ANY($2)",
    )
    .bind(user_id)
    .bind(&other_ids)
    .fetch_all(&ctx.db)
    .await
    .unwrap_or_default();
    let last_read_by_other: std::collections::HashMap<i64, i64> = prefs.into_iter().collect();
    let mut remaining: Vec<i64> = Vec::new();
    for e in &inbound {
        if e.id <= *last_read_by_other.get(&e.sender_id).unwrap_or(&0) {
            read_ids.insert(e.id);
        } else {
            remaining.push(e.id);
        }
    }
    if !remaining.is_empty() {
        let receipts: Vec<DmReadReceipt> = sqlx::query_as(
            "SELECT user_id, envelope_id, other_user_id FROM dm_read_receipt \
             WHERE user_id=$1 AND envelope_id = ANY($2)",
        )
        .bind(user_id)
        .bind(&remaining)
        .fetch_all(&ctx.db)
        .await
        .unwrap_or_default();
        for r in &receipts {
            read_ids.insert(r.envelope_id);
        }
    }
    Ok(read_ids)
}

/// Is a DM envelope read from a viewer's perspective?
pub async fn dm_envelope_is_read_for_viewer(
    ctx: &DmCtx,
    envelope: &DmEnvelope,
    user_id: Option<i64>,
    read_ids: Option<&std::collections::HashSet<i64>>,
) -> ApiResult<bool> {
    let Some(user_id) = user_id else { return Ok(false) };
    if envelope.sender_id == user_id {
        return Ok(true);
    }
    if envelope.recipient_id != user_id {
        return Ok(false);
    }
    if let Some(ids) = read_ids {
        return Ok(ids.contains(&envelope.id));
    }
    let ids = inbound_dm_read_ids(ctx, user_id, &[envelope.clone()]).await?;
    Ok(ids.contains(&envelope.id))
}

async fn load_user(ctx: &DmCtx, id: i64) -> ApiResult<Option<User>> {
    Ok(sqlx::query_as(crate::USER_SELECT_BY_ID).bind(id).fetch_optional(&ctx.db).await?)
}

/// Full DM envelope JSON payload for a viewer, mirroring `convert_dm_envelope`.
pub async fn convert_dm_envelope(
    ctx: &DmCtx,
    envelope: &DmEnvelope,
    user_id: Option<i64>,
    read_ids: Option<&std::collections::HashSet<i64>>,
    verified: Option<&[VerifiedUserData]>,
) -> ApiResult<Value> {
    let sender = load_user(ctx, envelope.sender_id).await?;
    let (sender_username, sender_display_name, sender_verified, verification_status) =
        if let Some(s) = &sender {
            if s.deleted || s.suspended {
                (
                    crate::deleted_user::deleted_username_for(s.id),
                    String::new(),
                    false,
                    "none",
                )
            } else {
                let status = if let Some(vd) = verified {
                    compute_verification_status(s, vd)
                } else {
                    crate::verification::VerificationStatus::None
                };
                let vs = status.as_str();
                (s.username.clone(), s.display_name.clone(), s.verified, vs)
            }
        } else {
            (format!("user_{}", envelope.sender_id), String::new(), false, "none")
        };

    let wrapped_mek_b64: Option<String> = if user_id == Some(envelope.sender_id) {
        Some(envelope.sender_wrapped_mek_b64.clone())
    } else if user_id == Some(envelope.recipient_id) {
        Some(envelope.recipient_wrapped_mek_b64.clone())
    } else if user_id == Some(1) {
        envelope.compliance_wrapped_mek_b64.clone()
    } else {
        None
    };

    let is_read = dm_envelope_is_read_for_viewer(ctx, envelope, user_id, read_ids).await?;

    let files: Vec<Value> = sqlx::query_as::<_, (i64, String, String, Option<String>)>(
        "SELECT id, path, name, nonce_b64 FROM dm_file WHERE message_id=$1",
    )
    .bind(envelope.id)
    .fetch_all(&ctx.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, path, name, _nonce)| {
        let safe = format!("/uploads/files/encrypted/{}", path.rsplit('/').next().unwrap_or(&path));
        json!({
            "path": safe,
            "id": id,
            "name": name,
            "dm_envelope_id": envelope.id,
            "wrapped_mek_b64": wrapped_mek_b64.clone(),
            "nonce_b64": null,
        })
    })
    .collect();

    Ok(json!({
        "id": envelope.id,
        "senderId": envelope.sender_id,
        "recipientId": envelope.recipient_id,
        "sender_username": sender_username,
        "sender_display_name": sender_display_name,
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "wrapped_mek_b64": wrapped_mek_b64,
        "timestamp": envelope.timestamp.unwrap_or_else(Utc::now).to_rfc3339(),
        "verified": sender_verified,
        "verification_status": verification_status,
        "reactions": [],
        "files": files,
        "isRead": is_read,
    }))
}

/// Per-user DM payload that adds `client_message_id` only for the sender.
pub async fn convert_dm_envelope_for_user(
    ctx: &DmCtx,
    envelope: &DmEnvelope,
    user_id: Option<i64>,
    sender_client_message_id: Option<&str>,
    read_ids: Option<&std::collections::HashSet<i64>>,
) -> ApiResult<Value> {
    let mut payload = convert_dm_envelope(ctx, envelope, user_id, read_ids, None).await?;
    if let Some(cid) = sender_client_message_id {
        if user_id == Some(envelope.sender_id) {
            if let Some(o) = payload.as_object_mut() {
                o.insert("client_message_id".into(), json!(cid));
            }
        }
    }
    Ok(payload)
}

/// Minimal last-message payload for DM conversation previews.
pub async fn convert_dm_envelope_for_conversation_preview(
    ctx: &DmCtx,
    envelope: &DmEnvelope,
    user_id: Option<i64>,
) -> ApiResult<Value> {
    let _ = ctx;
    let wrapped_mek_b64: Option<String> = if user_id == Some(envelope.sender_id) {
        Some(envelope.sender_wrapped_mek_b64.clone())
    } else if user_id == Some(envelope.recipient_id) {
        Some(envelope.recipient_wrapped_mek_b64.clone())
    } else if user_id == Some(1) {
        envelope.compliance_wrapped_mek_b64.clone()
    } else {
        None
    };
    Ok(json!({
        "id": envelope.id,
        "senderId": envelope.sender_id,
        "recipientId": envelope.recipient_id,
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "wrapped_mek_b64": wrapped_mek_b64,
        "timestamp": envelope.timestamp.unwrap_or_else(Utc::now).to_rfc3339(),
    }))
}