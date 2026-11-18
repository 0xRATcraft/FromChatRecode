//! DM envelope messaging routes, port of `routes/envelope_messaging.py`.
//! Includes send, conversation retrieval, compliance extract/view, edit, soft-delete.

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::dependencies::{AppState, AuthUser};
use crate::dm as dm_helpers;
use crate::error::{ApiError, ApiResult};
use crate::models::{DmEditHistory, DmEnvelope, User};
use crate::service_calls;

/// Per-user DM send rate limiter (port of `dm_rate_limit.py`).
#[derive(Clone, Default)]
pub struct DmRateLimiter {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>>>,
}

impl DmRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }
    fn check(&self, key: &str, window: std::time::Duration, limit: usize) -> bool {
        let now = std::time::Instant::now();
        let mut g = self.inner.lock().unwrap();
        let q = g.entry(key.to_string()).or_default();
        while q.front().map(|t| now.duration_since(*t) > window).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= limit {
            return false;
        }
        q.push_back(now);
        true
    }
    pub fn enforce_dm_send(&self, user_id: i64) -> ApiResult<()> {
        let key = format!("dm_send:{}", user_id);
        if !self.check(&key, std::time::Duration::from_secs(1), 1) {
            return Err(ApiError {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited".into(),
                detail: "Too many messages. Please slow down.".into(),
            });
        }
        if !self.check(&key, std::time::Duration::from_secs(60), 60) {
            return Err(ApiError {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited".into(),
                detail: "Too many messages. Please slow down.".into(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct SendEncryptedMessageRequest {
    #[serde(rename = "recipientId", alias = "recipient_id")]
    recipient_id: i64,
    #[serde(rename = "client_public_key_b64")]
    client_public_key_b64: String,
    #[serde(rename = "transport_nonce_b64")]
    transport_nonce_b64: String,
    #[serde(rename = "transport_ciphertext_b64")]
    transport_ciphertext_b64: String,
    #[serde(rename = "sender_public_key_b64")]
    sender_public_key_b64: String,
    #[serde(rename = "recipient_public_key_b64")]
    recipient_public_key_b64: String,
    #[serde(rename = "client_message_id")]
    client_message_id: Option<String>,
    #[serde(rename = "reply_to_id")]
    reply_to_id: Option<i64>,
    #[serde(rename = "transport_files", default)]
    transport_files: Vec<TransportFile>,
    #[serde(rename = "uploaded_file_ids", default)]
    uploaded_file_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct TransportFile {
    #[serde(rename = "encrypted_file_data_b64")]
    encrypted_file_data_b64: String,
    filename: String,
    #[serde(rename = "file_size")]
    file_size: i64,
}

#[derive(Deserialize)]
pub struct EditEncryptedMessageRequest {
    #[serde(rename = "client_public_key_b64")]
    client_public_key_b64: String,
    #[serde(rename = "transport_nonce_b64")]
    transport_nonce_b64: String,
    #[serde(rename = "transport_ciphertext_b64")]
    transport_ciphertext_b64: String,
    #[serde(rename = "sender_public_key_b64")]
    sender_public_key_b64: String,
    #[serde(rename = "recipient_public_key_b64")]
    recipient_public_key_b64: String,
}

#[derive(Deserialize)]
pub struct InitResumableUploadRequest {
    filename: String,
    #[serde(rename = "total_size")]
    total_size: i64,
    #[serde(rename = "recipient_id")]
    recipient_id: i64,
    #[serde(rename = "chunk_size")]
    chunk_size: Option<i64>,
}

#[derive(Deserialize)]
pub struct UploadChunkRequest {
    offset: i64,
    #[serde(rename = "data_b64")]
    data_b64: String,
}

/// Whether the compliance public key is required for send/edit.
fn compliance_public_key_required() -> bool {
    !crate::config::retention_never_store_compliance()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dm/key/transport/public", get(get_transport_public_key))
        .route("/dm/upload/init", post(init_resumable_upload))
        .route("/dm/upload/{upload_id}", get(get_resumable_upload_status).patch(upload_resumable_chunk).delete(delete_resumable_upload))
        .route("/dm/upload/{upload_id}/complete", post(complete_resumable_upload))
        .route("/dm/send", post(send_encrypted_message))
        .route("/dm/conversation/{other_user_id}", get(get_encrypted_conversation))
        .route("/dm/edit/{message_id}", put(edit_encrypted_message))
        .route("/dm/{message_id}", delete(delete_encrypted_message))
        .route("/dm/compliance/extract/{message_id}", get(extract_message_for_compliance))
        .route("/dm/compliance/edit-history/dm/{message_id}", get(get_dm_edit_history_for_compliance))
        .route("/dm/owner/compliance-view", get(get_owner_compliance_view))
}

async fn get_transport_public_key() -> ApiResult<Json<Value>> {
    let result = service_calls::get_messaging_transport_public_key().await?;
    Ok(Json(result))
}

async fn init_resumable_upload(
    State(_state): State<AppState>,
    user: AuthUser,
    Json(req): Json<InitResumableUploadRequest>,
) -> ApiResult<Json<Value>> {
    if req.total_size <= 0 {
        return Err(ApiError::bad_request("invalid_size", "total_size must be > 0"));
    }
    if user.user_id() == req.recipient_id {
        return Err(ApiError::bad_request("self_send", "Cannot send files to yourself"));
    }
    let payload = service_calls::init_resumable_upload_in_storage(
        &req.filename,
        req.total_size,
        &[user.user_id(), req.recipient_id],
        req.chunk_size,
    )
    .await?;
    Ok(Json(payload))
}

async fn get_resumable_upload_status(
    State(_state): State<AppState>,
    Path(upload_id): Path<String>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(service_calls::get_resumable_upload_status_in_storage(&upload_id, user.user_id()).await?))
}

async fn upload_resumable_chunk(
    State(_state): State<AppState>,
    Path(upload_id): Path<String>,
    user: AuthUser,
    Json(req): Json<UploadChunkRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(service_calls::upload_resumable_chunk_in_storage(&upload_id, user.user_id(), req.offset, &req.data_b64).await?))
}

async fn complete_resumable_upload(
    State(_state): State<AppState>,
    Path(upload_id): Path<String>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(service_calls::complete_resumable_upload_in_storage(&upload_id, user.user_id()).await?))
}

async fn delete_resumable_upload(
    State(_state): State<AppState>,
    Path(upload_id): Path<String>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    Ok(Json(service_calls::delete_resumable_upload_in_storage(&upload_id, user.user_id()).await?))
}

async fn send_encrypted_message(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SendEncryptedMessageRequest>,
) -> ApiResult<Json<Value>> {
    let limiter = state.dm_rate_limiter.clone();
    limiter.enforce_dm_send(user.user_id())?;

    // Verify recipient exists.
    let recipient: Option<User> = sqlx::query_as(crate::USER_SELECT_BY_ID)
        .bind(req.recipient_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(_recipient) = recipient else {
        return Err(ApiError::not_found("recipient_not_found", "Recipient not found"));
    };
    if user.user_id() == req.recipient_id {
        return Err(ApiError::bad_request("self_send", "Cannot send messages to yourself"));
    }

    // Ensure the messaging service / process-with-files returns a compliance-key result.
    // The messaging service reads COMPLIANCE_PUBLIC_KEY itself; here we only enforce config.
    if compliance_public_key_required() {
        // If retention needs a compliance key, ensure env is set so the messaging service can wrap it.
        let _self_key = service_calls::compliance_public_key().map_err(|_| {
            ApiError {
                status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                code: "compliance_key_missing".into(),
                detail: "Failed to retrieve compliance key".into(),
            }
        })?;
    }

    // Build transport files list for messaging service (resumable_upload_id based).
    let mut all_transport_files: Vec<Value> = Vec::new();
    let mut held_upload_ids: Vec<String> = Vec::new();

    // Files supplied inline as base64 transport ciphertext → stage as resumable uploads.
    for f in &req.transport_files {
        let bytes_maybe = B64.decode(&f.encrypted_file_data_b64).ok();
        let upload_id = if let Some(bytes) = bytes_maybe {
            match service_calls::stage_transport_ciphertext_resumable_upload(
                &bytes,
                &f.filename,
                &[user.user_id(), req.recipient_id],
                user.user_id(),
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    return Err(ApiError {
                        status: axum::http::StatusCode::BAD_REQUEST,
                        code: "transport_decrypt_failed".into(),
                        detail: e.detail,
                    })
                }
            }
        } else {
            f.filename.clone() // placeholder; valid base64 expected
        };
        held_upload_ids.push(upload_id.clone());
        all_transport_files.push(json!({
            "resumable_upload_id": upload_id,
            "filename": f.filename,
            "file_size": f.file_size,
        }));
    }

    // Referenced uploads.
    for upload_id in &req.uploaded_file_ids {
        let status = service_calls::get_resumable_upload_status_in_storage(upload_id, user.user_id()).await?;
        all_transport_files.push(json!({
            "resumable_upload_id": upload_id,
            "filename": status.get("filename").and_then(|v| v.as_str()).unwrap_or("file"),
            "file_size": status.get("total_size").and_then(|v| v.as_i64()).unwrap_or(0),
            "upload_id": upload_id,
        }));
        held_upload_ids.push(upload_id.clone());
    }

    // Process through messaging service (single MEK for message + files).
    let processed = service_calls::process_message_with_files_in_messaging_service(
        &req.client_public_key_b64,
        &req.transport_nonce_b64,
        &req.transport_ciphertext_b64,
        "", // messaging service uses its own configured compliance key
        &req.sender_public_key_b64,
        &req.recipient_public_key_b64,
        &all_transport_files,
        user.user_id(),
        req.recipient_id,
    )
    .await?;

    let msg = processed.get("message").cloned().unwrap_or_else(|| json!({}));
    let envelope = DmEnvelope {
        id: 0,
        sender_id: user.user_id(),
        recipient_id: req.recipient_id,
        iv_b64: msg.get("nonce").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        ciphertext_b64: msg.get("ciphertext").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        sender_wrapped_mek_b64: processed.get("sender_wrapped_mek").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        recipient_wrapped_mek_b64: processed.get("recipient_wrapped_mek").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        compliance_wrapped_mek_b64: processed.get("compliance_wrapped_mek").and_then(|v| v.as_str()).map(str::to_string),
        reply_to_id: req.reply_to_id,
        timestamp: Some(chrono::Utc::now()),
        is_edited: false,
        created_at: Some(chrono::Utc::now()),
        deleted_at: None,
    };

    let stored: DmEnvelope = sqlx::query_as(
        "INSERT INTO dm_envelope \
         (sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
          recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now()) \
         RETURNING id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at",
    )
    .bind(envelope.sender_id)
    .bind(envelope.recipient_id)
    .bind(&envelope.iv_b64)
    .bind(&envelope.ciphertext_b64)
    .bind(&envelope.sender_wrapped_mek_b64)
    .bind(&envelope.recipient_wrapped_mek_b64)
    .bind(&envelope.compliance_wrapped_mek_b64)
    .bind(envelope.reply_to_id)
    .fetch_one(&state.db)
    .await?;

    // Store DM files for transport_files (encrypted with same MEK).
    let file_results = processed.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if !file_results.is_empty() {
        for (i, tf) in req.transport_files.iter().enumerate() {
            let fr = file_results.get(i).cloned().unwrap_or_else(|| json!({}));
            let storage = fr.get("storage").cloned().unwrap_or_else(|| json!({}));
            let path = storage.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let _ = sqlx::query(
                "INSERT INTO dm_file (message_id, sender_id, recipient_id, name, path, nonce_b64) \
                 VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(stored.id)
            .bind(stored.sender_id)
            .bind(stored.recipient_id)
            .bind(&tf.filename)
            .bind(path.clone())
            .bind(fr.get("nonce").and_then(|v| v.as_str()))
            .execute(&state.db)
            .await;
        }
    }

    // Cleanup held upload ids.
    for upload_id in held_upload_ids {
        let _ = service_calls::delete_resumable_upload_in_storage(&upload_id, user.user_id()).await;
    }

    // Fan-out to recipient + sender (each gets only their own MEK).
    state.ws.enqueue_update_for_user(
        stored.recipient_id,
        "dmNew",
        dm_helpers::convert_dm_envelope_for_user(&dm_helpers::DmCtx::new(state.db.clone()), &stored, Some(stored.recipient_id), None, None).await?,
        Some(&state.db),
    )
    .await;
    let sender_payload = dm_helpers::convert_dm_envelope_for_user(
        &dm_helpers::DmCtx::new(state.db.clone()),
        &stored,
        Some(stored.sender_id),
        req.client_message_id.as_deref(),
        None,
    )
    .await?;
    state.ws
        .enqueue_update_for_user(stored.sender_id, "dmNew", sender_payload, Some(&state.db))
        .await;

    Ok(Json(json!({
        "id": stored.id,
        "sender_id": stored.sender_id,
        "recipient_id": stored.recipient_id,
        "timestamp": stored.timestamp.map(|d| d.to_rfc3339()),
        "client_message_id": req.client_message_id,
        "reply_to_id": stored.reply_to_id,
    })))
}

async fn get_encrypted_conversation(
    State(state): State<AppState>,
    Path(other_user_id): Path<i64>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let limit: i64 = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50);
    let offset: i64 = params.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);

    let other: Option<(i64,)> = sqlx::query_as("SELECT id FROM \"user\" WHERE id=$1")
        .bind(other_user_id)
        .fetch_optional(&state.db)
        .await?;
    if other.is_none() {
        return Err(ApiError::not_found("user_not_found", "User not found"));
    }

    let envelopes: Vec<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE ((sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)) \
         AND deleted_at IS NULL ORDER BY timestamp DESC LIMIT $3 OFFSET $4",
    )
    .bind(user.user_id())
    .bind(other_user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let mut result: Vec<Value> = Vec::new();
    for msg in envelopes.iter().rev() {
        let wrapped_mek = if msg.sender_id == user.user_id() {
            msg.sender_wrapped_mek_b64.clone()
        } else {
            msg.recipient_wrapped_mek_b64.clone()
        };
        result.push(json!({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "recipient_id": msg.recipient_id,
            "nonce": msg.iv_b64,
            "ciphertext": msg.ciphertext_b64,
            "wrapped_mek": wrapped_mek,
            "timestamp": msg.timestamp.map(|d| d.to_rfc3339()),
            "reply_to_id": msg.reply_to_id,
            "is_edited": msg.is_edited,
        }));
    }
    Ok(Json(Value::Array(result)))
}

async fn edit_encrypted_message(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
    Json(req): Json<EditEncryptedMessageRequest>,
) -> ApiResult<Json<Value>> {
    let msg: Option<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE id=$1 AND deleted_at IS NULL",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(msg) = msg else { return Err(ApiError::not_found("message_not_found", "Message not found")) };
    if msg.sender_id != user.user_id() {
        return Err(ApiError::forbidden("not_owner", "Cannot edit others' messages"));
    }

    // Process edit through messaging service (no files).
    let processed = service_calls::process_message_in_messaging_service(
        &req.client_public_key_b64,
        &req.transport_nonce_b64,
        &req.transport_ciphertext_b64,
        "",
        &req.sender_public_key_b64,
        &req.recipient_public_key_b64,
    )
    .await?;

    let processed_msg = processed.get("message").cloned().unwrap_or_else(|| json!({}));
    let prev_ciphertext = msg.ciphertext_b64.clone();
    let prev_iv = msg.iv_b64.clone();
    let prev_wrapped = msg.compliance_wrapped_mek_b64.clone().unwrap_or_default();

    sqlx::query(
        "UPDATE dm_envelope SET ciphertext_b64=$1, iv_b64=$2, sender_wrapped_mek_b64=$3, \
         recipient_wrapped_mek_b64=$4, compliance_wrapped_mek_b64=$5, is_edited=TRUE WHERE id=$6",
    )
    .bind(processed_msg.get("ciphertext").and_then(|v| v.as_str()).unwrap_or(""))
    .bind(processed_msg.get("nonce").and_then(|v| v.as_str()).unwrap_or(""))
    .bind(processed.get("sender_wrapped_mek").and_then(|v| v.as_str()).unwrap_or(""))
    .bind(processed.get("recipient_wrapped_mek").and_then(|v| v.as_str()).unwrap_or(""))
    .bind(processed.get("compliance_wrapped_mek").and_then(|v| v.as_str()).unwrap_or(""))
    .bind(message_id)
    .execute(&state.db)
    .await?;

    // Best-effort edit history.
    let _ = sqlx::query(
        "INSERT INTO dm_edit_history (message_id, dm_envelope_id, previous_ciphertext_b64, \
         previous_iv_b64, previous_compliance_wrapped_mek_b64, edited_by, edited_by_user_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(message_id)
    .bind(message_id)
    .bind(&prev_ciphertext)
    .bind(&prev_iv)
    .bind(&prev_wrapped)
    .bind(user.user_id())
    .bind(user.user_id())
    .execute(&state.db)
    .await;

    let updated: DmEnvelope = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE id=$1",
    )
    .bind(message_id)
    .fetch_one(&state.db)
    .await?;

    state.ws
        .enqueue_update_for_user(
            updated.recipient_id,
            "dmEdited",
            dm_helpers::convert_dm_envelope(&dm_helpers::DmCtx::new(state.db.clone()), &updated, Some(updated.recipient_id), None, None).await?,
            Some(&state.db),
        )
        .await;
    state.ws
        .enqueue_update_for_user(
            updated.sender_id,
            "dmEdited",
            dm_helpers::convert_dm_envelope(&dm_helpers::DmCtx::new(state.db.clone()), &updated, Some(updated.sender_id), None, None).await?,
            Some(&state.db),
        )
        .await;

    Ok(Json(json!({
        "id": updated.id,
        "sender_id": updated.sender_id,
        "recipient_id": updated.recipient_id,
        "timestamp": updated.timestamp.map(|d| d.to_rfc3339()),
        "is_edited": updated.is_edited,
    })))
}

async fn delete_encrypted_message(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    let msg: Option<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE id=$1",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(msg) = msg else { return Err(ApiError::not_found("message_not_found", "Message not found")) };
    if msg.sender_id != user.user_id() {
        return Err(ApiError::forbidden("not_owner", "Cannot delete others' messages"));
    }
    sqlx::query("UPDATE dm_envelope SET deleted_at=now() WHERE id=$1")
        .bind(message_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "status": "deleted", "message_id": message_id })))
}

async fn extract_message_for_compliance(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    if user.user_id() != 1 {
        return Err(ApiError::forbidden(
            "compliance_only",
            "Access denied. This endpoint is restricted to compliance officers.",
        ));
    }
    let envelope: Option<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE id=$1",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(envelope) = envelope else { return Err(ApiError::not_found("message_not_found", "Message not found")) };

    let files: Vec<Value> = sqlx::query_as::<_, (i64, String, String, Option<String>)>(
        "SELECT id, name, path, nonce_b64 FROM dm_file WHERE message_id=$1",
    )
    .bind(envelope.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, path, nonce)| {
        json!({
            "id": id, "name": name, "path": path,
            "wrapped_mek_b64": envelope.compliance_wrapped_mek_b64.clone(),
            "nonce_b64": nonce,
        })
    })
    .collect();

    let edit_history: Vec<DmEditHistory> = sqlx::query_as(
        "SELECT id, message_id, dm_envelope_id, previous_ciphertext_b64, previous_iv_b64, \
         previous_compliance_wrapped_mek_b64, edited_at, edited_by, edited_by_user_id \
         FROM dm_edit_history WHERE message_id=$1 ORDER BY edited_at",
    )
    .bind(message_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let compliance_data = json!({
        "message_id": envelope.id,
        "sender_id": envelope.sender_id,
        "recipient_id": envelope.recipient_id,
        "timestamp": envelope.timestamp.map(|d| d.to_rfc3339()),
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "compliance_wrapped_mek_b64": envelope.compliance_wrapped_mek_b64,
        "files": files,
        "edit_history": edit_history.iter().map(|e| json!({
            "edit_id": e.id,
            "edited_at": e.edited_at.map(|d| d.to_rfc3339()),
            "edited_by_user_id": e.edited_by,
            "previous_ciphertext_b64": e.previous_ciphertext_b64,
            "previous_iv_b64": e.previous_iv_b64,
            "previous_compliance_wrapped_mek_b64": e.previous_compliance_wrapped_mek_b64,
        })).collect::<Vec<_>>(),
        "total_edits": edit_history.len(),
        "extraction_timestamp": chrono::Utc::now().to_rfc3339(),
        "extracted_by_user_id": user.user_id(),
        "compliance_system_ready": envelope.compliance_wrapped_mek_b64.is_some(),
    });

    Ok(Json(json!({
        "status": "success",
        "message": "Message data extracted for compliance review",
        "data": compliance_data,
        "instructions": [
            "Transfer this data to an air-gapped machine",
            "Use scripts/compliance/decryption/main.py decrypt --input-file <json_file>",
            "Keep the compliance private key offline at all times"
        ]
    })))
}

async fn get_dm_edit_history_for_compliance(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    if user.user_id() != 1 {
        return Err(ApiError::forbidden(
            "compliance_only",
            "Access denied. This endpoint is restricted to compliance officers.",
        ));
    }
    let message: Option<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE id=$1",
    )
    .bind(message_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(message) = message else { return Err(ApiError::not_found("message_not_found", "Message not found")) };

    let history: Vec<DmEditHistory> = sqlx::query_as(
        "SELECT id, message_id, dm_envelope_id, previous_ciphertext_b64, previous_iv_b64, \
         previous_compliance_wrapped_mek_b64, edited_at, edited_by, edited_by_user_id \
         FROM dm_edit_history WHERE message_id=$1 ORDER BY edited_at",
    )
    .bind(message_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let entries: Vec<Value> = history.iter().map(|e| json!({
        "id": e.id,
        "dm_envelope_id": e.message_id,
        "previous_ciphertext_b64": e.previous_ciphertext_b64,
        "previous_iv_b64": e.previous_iv_b64,
        "previous_compliance_wrapped_mek_b64": e.previous_compliance_wrapped_mek_b64,
        "edited_at": e.edited_at.map(|d| d.to_rfc3339()),
        "edited_by_user_id": e.edited_by,
    })).collect();

    Ok(Json(json!({
        "message_id": message_id,
        "current_version": {
            "id": message.id,
            "sender_id": message.sender_id,
            "recipient_id": message.recipient_id,
            "ciphertext_b64": message.ciphertext_b64,
            "iv_b64": message.iv_b64,
            "sender_wrapped_mek_b64": message.sender_wrapped_mek_b64,
            "recipient_wrapped_mek_b64": message.recipient_wrapped_mek_b64,
            "compliance_wrapped_mek_b64": message.compliance_wrapped_mek_b64,
            "timestamp": message.timestamp.map(|d| d.to_rfc3339()),
            "is_edited": message.is_edited,
        },
        "edit_history": entries,
        "total_edits": entries.len(),
    })))
}

async fn get_owner_compliance_view(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    if user.user_id() != 1 {
        return Err(ApiError::forbidden(
            "owner_only",
            "Only owner (user_id 1) can access compliance view",
        ));
    }
    let messages: Vec<DmEnvelope> = sqlx::query_as(
        "SELECT id, sender_id, recipient_id, iv_b64, ciphertext_b64, sender_wrapped_mek_b64, \
         recipient_wrapped_mek_b64, compliance_wrapped_mek_b64, reply_to_id, timestamp, is_edited, created_at, deleted_at \
         FROM dm_envelope WHERE deleted_at IS NULL ORDER BY timestamp DESC",
    )
    .fetch_all(&state.db)
    .await?;
    let result: Vec<Value> = messages.iter().map(|m| json!({
        "id": m.id,
        "sender_id": m.sender_id,
        "recipient_id": m.recipient_id,
        "nonce": m.iv_b64,
        "ciphertext": m.ciphertext_b64,
        "compliance_wrapped_mek": m.compliance_wrapped_mek_b64,
        "timestamp": m.timestamp.map(|d| d.to_rfc3339()),
    })).collect();
    Ok(Json(Value::Array(result)))
}