//! Public-chat + DM HTTP routes from `routes/messaging.py`.
//! WebSocket endpoint and the full DM envelope routes live in `routes/ws_routes.rs` and `routes/dm.rs`.

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::dependencies::{AppState, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::message::{convert_message, load_users_by_ids};
use crate::models::{Message, Reaction, User};
use crate::profanity::ProfanityConfig;

const MAX_MESSAGE_PAGE_LIMIT: i64 = 200;
const DEFAULT_MESSAGE_PAGE_LIMIT: i64 = 50;

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    content: String,
    #[serde(rename = "reply_to_id")]
    reply_to_id: Option<i64>,
    #[serde(rename = "client_message_id")]
    client_message_id: Option<String>,
    #[serde(rename = "uploaded_file_ids")]
    uploaded_file_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct EditMessageRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
pub struct ReactionRequest {
    #[serde(rename = "message_id")]
    message_id: i64,
    emoji: String,
}

#[derive(Debug, Deserialize)]
pub struct MarkReadRequest {
    #[serde(rename = "messageIds")]
    message_ids: Option<Vec<i64>>,
    #[serde(rename = "markAll", default)]
    mark_all: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterFcmRequest {
    token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/send_message", post(send_message))
        .route("/edit_message/{message_id}", put(edit_message))
        .route("/delete_message/{message_id}", delete(delete_message))
        .route("/get_messages", get(get_messages))
        .route("/messages/new", get(get_new_messages))
        .route("/messages/read", post(mark_messages_read))
        .route("/add_reaction", post(add_reaction))
        .route("/push/register", post(register_fcm_token))
        .route("/push/unregister", post(unregister_fcm_token))
}

fn normalize_page_limit(limit: Option<i64>) -> i64 {
    limit.map(|l| l.max(1).min(MAX_MESSAGE_PAGE_LIMIT)).unwrap_or(DEFAULT_MESSAGE_PAGE_LIMIT)
}

/// Load a page of public messages in ascending id order, mirroring the Python paginator.
async fn get_public_messages_page(
    db: &sqlx::PgPool,
    limit: Option<i64>,
    before_id: Option<i64>,
    after_id: Option<i64>,
    around_id: Option<i64>,
) -> ApiResult<(Vec<Message>, bool, bool, bool)> {
    let page = normalize_page_limit(limit);
    let (before_id, after_id, around_id) = normalize_cursors(before_id, after_id, around_id);

    if let Some(around) = around_id {
        let anchor: Option<(i64,)> = sqlx::query_as("SELECT id FROM message WHERE id=$1").bind(around).fetch_optional(db).await?;
        if anchor.is_none() {
            return Ok((Vec::new(), false, false, false));
        }
        let half = page / 2;
        let newer_count = (page - half - 1).max(0);
        let older: Vec<Message> = sqlx::query_as(&crate::message_select_and(&format!("id < {} ORDER BY id DESC LIMIT {}", around, half)))
            .fetch_all(db)
            .await?;
        let mut older_rev: Vec<Message> = older.into_iter().rev().collect();
        let anchor_msg: Message = sqlx::query_as(crate::MESSAGE_SELECT_ID).bind(around).fetch_one(db).await?;
        let newer: Vec<Message> = sqlx::query_as(&crate::message_select_and(&format!("id > {} ORDER BY id ASC LIMIT {}", around, newer_count)))
            .fetch_all(db)
            .await?;
        older_rev.push(anchor_msg);
        older_rev.extend(newer);
        let rows = older_rev;
        if rows.is_empty() {
            return Ok((Vec::new(), false, false, false));
        }
        let min_id = rows.iter().map(|m| m.id).min().unwrap();
        let max_id = rows.iter().map(|m| m.id).max().unwrap();
        let has_more_before = exists_message_before(db, min_id).await?;
        let has_more_after = exists_message_after(db, max_id).await?;
        return Ok((rows, has_more_before, has_more_before, has_more_after));
    }

    if let Some(after) = after_id {
        let rows: Vec<Message> = sqlx::query_as(&crate::message_select_and(&format!("id > {} ORDER BY id ASC LIMIT {}", after, page + 1)))
            .fetch_all(db)
            .await?;
        let has_more_after = rows.len() as i64 > page;
        let rows = rows.into_iter().take(page as usize).collect::<Vec<_>>();
        if rows.is_empty() {
            return Ok((Vec::new(), false, false, false));
        }
        let min_id = rows[0].id;
        let has_more_before = exists_message_before(db, min_id).await?;
        return Ok((rows, has_more_after, has_more_before, has_more_after));
    }

    // before / unfiltered (newest-first window, then reversed to ascending)
    let mut sql = crate::MESSAGE_SELECT_FROM.to_string();
    if let Some(b) = before_id {
        let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM message WHERE id=$1").bind(b).fetch_optional(db).await?;
        if exists.is_some() {
            sql.push_str(&format!(" WHERE id < {} ", b));
        }
    }
    sql.push_str(" ORDER BY id DESC LIMIT ");
    sql.push_str(&(page + 1).to_string());
    let probe: Vec<Message> = sqlx::query_as(&sql).fetch_all(db).await?;
    let has_more_before = probe.len() as i64 > page;
    let mut rows: Vec<Message> = probe.into_iter().take(page as usize).collect();
    rows.reverse();
    Ok((rows, has_more_before, has_more_before, false))
}

fn normalize_cursors(before: Option<i64>, after: Option<i64>, around: Option<i64>) -> (Option<i64>, Option<i64>, Option<i64>) {
    let count = [before, after, around].iter().filter(|v| v.is_some()).count();
    if count > 1 {
        if around.is_some() {
            return (None, None, around);
        }
        if before.is_some() && after.is_some() {
            return (before, None, None);
        }
    }
    (before, after, around)
}

async fn exists_message_before(db: &sqlx::PgPool, id: i64) -> ApiResult<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM message WHERE id < $1)").bind(id).fetch_one(db).await?)
}
async fn exists_message_after(db: &sqlx::PgPool, id: i64) -> ApiResult<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM message WHERE id > $1)").bind(id).fetch_one(db).await?)
}

/// Build the full public message JSON with author/reactions/verified data.
async fn build_message_payload(
    db: &sqlx::PgPool,
    msg: &Message,
) -> ApiResult<serde_json::Value> {
    let author: Option<User> = if msg.user_id > 0 {
        opt_user(db, msg.user_id).await?
    } else {
        None
    };
    let reactions: Vec<Reaction> = sqlx::query_as("SELECT id, message_id, user_id, emoji, timestamp FROM reaction WHERE message_id=$1")
        .bind(msg.id)
        .fetch_all(db)
        .await?;
    // Note: reply_to rendering is omitted for now (one-level reply); keep parity minimal.
    let verified = crate::convert::load_verified_users(db).await?;
    let mut map: std::collections::HashMap<i64, User> = std::collections::HashMap::new();
    if let Some(a) = &author {
        map.insert(a.id, a.clone());
    }
    let payload = convert_message(msg, author.as_ref(), &reactions, &map, &verified);
    Ok(payload)
}

async fn opt_user(db: &sqlx::PgPool, id: i64) -> ApiResult<Option<User>> {
    Ok(sqlx::query_as(crate::USER_SELECT_BY_ID).bind(id).fetch_optional(db).await?)
}

async fn send_message(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let SendMessageRequest { content, reply_to_id, client_message_id, uploaded_file_ids } =
        serde_json::from_value::<SendMessageRequest>(req).map_err(|_| ApiError::bad_request("invalid_body", "Invalid request data"))?;
    let _ = (reply_to_id, client_message_id, uploaded_file_ids);
    let _ = profanity(&state);
    send_message_internal(&state, &user, content).await
}

fn profanity(state: &AppState) -> &ProfanityConfig {
    &state.profanity
}

/// Core message-send logic (shared with WS handler). Returns the HTTP payload.
pub async fn send_message_internal(
    state: &AppState,
    user: &crate::dependencies::AuthUser,
    raw_content: String,
) -> ApiResult<Json<serde_json::Value>> {
    if user.user.suspended {
        return Err(ApiError::forbidden("account_suspended", "Account suspended"));
    }
    if user.user.deleted {
        return Err(ApiError::forbidden("account_deleted", "Account deleted"));
    }
    let raw_content = raw_content.trim().to_string();
    if raw_content.is_empty() {
        return Err(ApiError::bad_request("no_content", "No content provided"));
    }
    if crate::profanity::contains_profanity(&state.profanity, &raw_content).await? {
        return Err(ApiError {
            status: axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            code: "inappropriate_content".into(),
            detail: "Message contains inappropriate content and cannot be sent".into(),
        });
    }
    // html.escape(content, quote=False)
    let escaped = escape_html(&raw_content, false);
    if escaped.chars().count() > 4096 {
        return Err(ApiError::bad_request("message_too_long", "Message too long"));
    }
    let inserted: Message = sqlx::query_as(crate::MESSAGE_INSERT)
        .bind(&escaped)
        .bind(user.user_id())
        .bind(Option::<i64>::None)
        .fetch_one(&state.db)
        .await?;
    // Best-effort spam monitor (kept minimal; full auto-suspend logic is substantial).
    let payload = build_message_payload(&state.db, &inserted).await?;

    // Realtime fan-out to connected clients (durable per-user updates).
    state.ws.broadcast(json!({ "type": "newMessage", "data": payload }), Some(&state.db)).await;

    Ok(Json(serde_json::json!({ "status": "success", "message": payload })))
}

/// Python `html.escape(s, quote=False)`.
pub fn escape_html(s: &str, quote: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

async fn edit_message(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
    Json(req): Json<EditMessageRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let msg: Option<Message> = sqlx::query_as(crate::MESSAGE_SELECT_ID).bind(message_id).fetch_optional(&state.db).await?;
    let Some(msg) = msg else { return Err(ApiError::not_found("message_not_found", "Message not found")) };
    if msg.user_id != user.user_id() {
        return Err(ApiError::forbidden("not_owner", "You can only edit your own messages"));
    }
    let raw = req.content.trim().to_string();
    if raw.is_empty() {
        return Err(ApiError::bad_request("empty_content", "Message content cannot be empty"));
    }
    if crate::profanity::contains_profanity(&state.profanity, &raw).await? {
        return Err(ApiError {
            status: axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            code: "inappropriate_content".into(),
            detail: "Message contains inappropriate content and cannot be sent".into(),
        });
    }
    let escaped = escape_html(&raw, false);
    if escaped.chars().count() > 4096 {
        return Err(ApiError::bad_request("message_too_long", "Message too long"));
    }
    // Store edit history, then update.
    sqlx::query("INSERT INTO message_edit_history (message_id, previous_content, edited_by_user_id) VALUES ($1,$2,$3)")
        .bind(msg.id)
        .bind(&msg.content)
        .bind(user.user_id())
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE message SET content=$1, is_edited=TRUE WHERE id=$2")
        .bind(&escaped)
        .bind(msg.id)
        .execute(&state.db)
        .await?;
    let updated: Message = sqlx::query_as(crate::MESSAGE_SELECT_ID).bind(msg.id).fetch_one(&state.db).await?;
    let payload = build_message_payload(&state.db, &updated).await?;
    Ok(Json(serde_json::json!({ "status": "success", "message": payload })))
}

async fn delete_message(
    State(state): State<AppState>,
    Path(message_id): Path<i64>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let msg: Option<Message> = sqlx::query_as(crate::MESSAGE_SELECT_ID).bind(message_id).fetch_optional(&state.db).await?;
    let Some(msg) = msg else { return Err(ApiError::not_found("message_not_found", "Message not found")) };
    // Owner (id 1) may delete any message.
    if user.user_id() != 1 && msg.user_id != user.user_id() {
        return Err(ApiError::forbidden("not_owner", "You can only delete your own messages"));
    }
    sqlx::query("UPDATE message SET reply_to_id=NULL WHERE reply_to_id=$1").bind(message_id).execute(&state.db).await?;
    sqlx::query("DELETE FROM message_edit_history WHERE message_id=$1").bind(message_id).execute(&state.db).await?;
    sqlx::query("DELETE FROM message WHERE id=$1").bind(message_id).execute(&state.db).await?;
    Ok(Json(serde_json::json!({ "status": "success", "message_id": message_id })))
}

async fn get_messages(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = params.get("limit").and_then(|v| v.parse().ok());
    let before_id = params.get("before_id").and_then(|v| v.parse().ok());
    let after_id = params.get("after_id").and_then(|v| v.parse().ok());
    let around_id = params.get("around_id").and_then(|v| v.parse().ok());
    let (rows, has_more, has_more_before, has_more_after) =
        get_public_messages_page(&state.db, limit, before_id, after_id, around_id).await?;
    let mut messages = Vec::with_capacity(rows.len());
    for m in &rows {
        messages.push(build_message_payload(&state.db, m).await?);
    }
    Ok(Json(serde_json::json!({
        "status": "success",
        "messages": messages,
        "has_more": has_more,
        "has_more_before": has_more_before,
        "has_more_after": has_more_after,
    })))
}

/// API-style page used by the WebSocket `getMessages` handler.
pub async fn get_public_messages_page_api(
    db: &sqlx::PgPool,
    limit: Option<i64>,
    before_id: Option<i64>,
    after_id: Option<i64>,
    around_id: Option<i64>,
) -> Result<serde_json::Value, ApiError> {
    let (rows, has_more, has_more_before, has_more_after) =
        get_public_messages_page(db, limit, before_id, after_id, around_id).await?;
    let mut messages = Vec::with_capacity(rows.len());
    for m in &rows {
        messages.push(build_message_payload(db, m).await?);
    }
    Ok(serde_json::json!({
        "status": "success",
        "messages": messages,
        "has_more": has_more,
        "has_more_before": has_more_before,
        "has_more_after": has_more_after,
    }))
}

async fn get_new_messages(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    _user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = params.get("limit").and_then(|v| v.parse().ok());
    let page = normalize_page_limit(limit);
    let probe: Vec<Message> = sqlx::query_as(&format!(
        "{} WHERE is_read = FALSE ORDER BY timestamp ASC LIMIT {}",
        crate::MESSAGE_SELECT_FROM, page + 1
    ))
    .fetch_all(&state.db)
    .await?;
    let has_more = probe.len() as i64 > page;
    let new_messages = probe.into_iter().take(page as usize).collect::<Vec<_>>();
    let mut messages = Vec::with_capacity(new_messages.len());
    for m in &new_messages {
        messages.push(build_message_payload(&state.db, m).await?);
    }
    Ok(Json(serde_json::json!({ "status": "success", "messages": messages, "has_more": has_more })))
}

async fn mark_messages_read(
    State(state): State<AppState>,
    _user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let read: MarkReadRequest = serde_json::from_value(req).map_err(|_| ApiError::bad_request("invalid_body", "Invalid body"))?;
    let updated = if read.mark_all {
        sqlx::query("UPDATE message SET is_read=TRUE WHERE is_read=FALSE").execute(&state.db).await?.rows_affected()
    } else {
        let ids = read.message_ids.unwrap_or_default();
        if ids.is_empty() {
            return Ok(Json(serde_json::json!({ "status": "success", "updated": 0 })));
        }
        sqlx::query(&format!("UPDATE message SET is_read=TRUE WHERE id = ANY($1)"))
            .bind(&ids)
            .execute(&state.db)
            .await?
            .rows_affected()
    };
    Ok(Json(serde_json::json!({ "status": "success", "updated": updated })))
}

async fn add_reaction(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ReactionRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let exists_msg: Option<(i64,)> = sqlx::query_as("SELECT id FROM message WHERE id=$1").bind(req.message_id).fetch_optional(&state.db).await?;
    if exists_msg.is_none() {
        return Err(ApiError::not_found("message_not_found", "Message not found"));
    }
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM reaction WHERE message_id=$1 AND user_id=$2 AND emoji=$3",
    )
    .bind(req.message_id)
    .bind(user.user_id())
    .bind(&req.emoji)
    .fetch_optional(&state.db)
    .await?;
    let action = if existing.is_some() {
        sqlx::query("DELETE FROM reaction WHERE message_id=$1 AND user_id=$2 AND emoji=$3")
            .bind(req.message_id).bind(user.user_id()).bind(&req.emoji)
            .execute(&state.db).await?;
        "removed"
    } else {
        sqlx::query("INSERT INTO reaction (message_id, user_id, emoji) VALUES ($1,$2,$3)")
            .bind(req.message_id).bind(user.user_id()).bind(&req.emoji)
            .execute(&state.db).await?;
        "added"
    };
    let reactions: Vec<Reaction> = sqlx::query_as("SELECT id, message_id, user_id, emoji, timestamp FROM reaction WHERE message_id=$1")
        .bind(req.message_id)
        .fetch_all(&state.db)
        .await?;
    let map = load_users_by_ids(&state.db, &reactions.iter().map(|r| r.user_id).collect::<Vec<_>>()).await?;
    let verified = crate::convert::load_verified_users(&state.db).await?;
    let users_by_id = {};
    let _ = users_by_id;
    let reactions_value = crate::message::group_reactions(&reactions, &map);
    let _ = verified;
    Ok(Json(serde_json::json!({ "status": "success", "action": action, "reactions": reactions_value })))
}

async fn register_fcm_token(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterFcmRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let token = req.token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("missing_token", "Missing token"));
    }
    let exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM fcm_token WHERE token=$1").bind(&token).fetch_optional(&state.db).await?;
    if exists.is_some() {
        sqlx::query("UPDATE fcm_token SET user_id=$1, updated_at=now() WHERE token=$2")
            .bind(user.user_id()).bind(&token).execute(&state.db).await?;
    } else {
        sqlx::query("INSERT INTO fcm_token (user_id, token) VALUES ($1,$2)")
            .bind(user.user_id()).bind(&token).execute(&state.db).await?;
    }
    Ok(Json(serde_json::json!({ "status": "success" })))
}

async fn unregister_fcm_token(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let token: Option<String> = serde_json::from_value::<RegisterFcmRequest>(req).ok().map(|r| r.token.trim().to_string()).filter(|t| !t.is_empty());
    if let Some(token) = token {
        sqlx::query("DELETE FROM fcm_token WHERE user_id=$1 AND token=$2")
            .bind(user.user_id()).bind(&token).execute(&state.db).await?;
    } else {
        sqlx::query("DELETE FROM fcm_token WHERE user_id=$1")
            .bind(user.user_id()).execute(&state.db).await?;
    }
    Ok(Json(serde_json::json!({ "status": "success" })))
}