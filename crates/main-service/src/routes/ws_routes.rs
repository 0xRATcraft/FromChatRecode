//! WebSocket endpoint `/chat/ws` and its handler loop, port of
//! `routes/messaging.py::chat_websocket` + `websocket/handlers.py`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tracing::warn;

use crate::dependencies::AppState;
use crate::error::ApiError;
use crate::models::User;
use crate::ws::{ConnId, Sink};

/// Per-connection id generator.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

fn next_conn() -> ConnId {
    NEXT_CONN.fetch_add(1, Ordering::SeqCst)
}

/// A sink that pushes outbound frames into an mpsc channel; the connection loop
/// forwards them onto the real socket.
struct ChannelSink {
    tx: mpsc::UnboundedSender<Value>,
}

#[async_trait]
impl Sink for ChannelSink {
    async fn send_json(&self, _conn: ConnId, msg: Value) {
        let _ = self.tx.send(msg);
    }
    async fn close(&self, conn: ConnId, code: u16, reason: &str) {
        let _ = self.tx.send(json!({
            "__close": true, "code": code, "reason": reason
        }));
        let _ = conn;
    }
}

fn ws_text(v: Value) -> WsMessage {
    WsMessage::Text(v.to_string().into())
}

/// The `/chat/ws` route handler.
pub async fn chat_ws(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

/// Authenticate a WS frame's credentials; root helper mirroring `websocket/utils.py`.
fn extract_token_from_data(data: &Value) -> Option<String> {
    data.get("credentials")
        .and_then(|c| c.get("credentials"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

async fn authenticate_user(
    data: &Value,
    db: &PgPool,
    jwt_secret: &str,
    auth_required: bool,
) -> Result<Option<User>, ApiError> {
    let token = extract_token_from_data(data);
    if !auth_required {
        let Some(token) = token else { return Ok(None) };
        return Ok(fetch_user_by_token(db, jwt_secret, &token).await);
    }
    let token = token.ok_or_else(|| ApiError::unauthorized("missing_credentials", "Missing credentials"))?;
    let user = fetch_user_by_token(db, jwt_secret, &token)
        .await
        .ok_or_else(|| ApiError::unauthorized("invalid_credentials", "Invalid credentials"))?;
    if user.suspended {
        return Err(ApiError::forbidden("account_suspended", "Account suspended"));
    }
    if user.deleted {
        return Err(ApiError::forbidden("account_deleted", "Account deleted"));
    }
    Ok(Some(user))
}

async fn fetch_user_by_token(db: &PgPool, jwt_secret: &str, token: &str) -> Option<User> {
    let claims = crate::auth::verify_token(jwt_secret, token)?;
    let row: Option<(String, Option<chrono::DateTime<chrono::Utc>>, bool)> = sqlx::query_as(
        "SELECT session_kind, expires_at, revoked FROM device_session WHERE user_id=$1 AND session_id=$2",
    )
    .bind(claims.user_id)
    .bind(&claims.session_id)
    .fetch_optional(db)
    .await
    .ok()?;
    let (_kind, expires_at, revoked) = row?;
    if revoked {
        return None;
    }
    if expires_at.map(|e| e <= chrono::Utc::now()).unwrap_or(false) {
        return None;
    }
    let user: User = sqlx::query_as(crate::USER_SELECT_BY_ID).bind(claims.user_id).fetch_optional(db).await.ok()??;
    Some(user)
}

/// Handle an established socket: register presence, dispatch messages, cleanup.
async fn handle_socket(state: AppState, mut socket: WebSocket) {
    let conn = next_conn();
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let sink: Arc<dyn Sink> = Arc::new(ChannelSink { tx });
    state.ws.register_sink(conn, sink).await;
    let manager = &state.ws;
    let mut authed_user_id: Option<i64> = None;

    loop {
        tokio::select! {
            maybe_msg = socket.next() => {
                let Some(msg) = maybe_msg else { break };
                let Ok(msg) = msg else { break };
                match msg {
                    WsMessage::Text(text) => {
                        let data: Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => {
                                let _ = socket.send(ws_text(json!({"type":"error","error":{"code":400,"detail":"Invalid JSON"}}))).await;
                                continue;
                            }
                        };
                        let msg_type = data.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if handle_frame(&state, conn, &mut authed_user_id, msg_type, &data, &mut socket).await {
                            // frame asked to close
                            break;
                        }
                    }
                    WsMessage::Close(_) => break,
                    _ => { /* ignore binary/ping/pong */ }
                }
            }
            Some(out) = rx.recv() => {
                if out.get("__close").is_some() {
                    let code = out.get("code").and_then(|v| v.as_u64()).unwrap_or(1001) as u16;
                    let reason = out.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                    let _ = socket.close().await;
                    let _ = (code, reason);
                    break;
                }
                let _ = socket.send(ws_text(out)).await;
            }
        }
    }

    if let Some(uid) = authed_user_id.take() {
        manager.unbind_conn(conn).await;
        let (_offline, _last_seen) = manager.unregister_connection(uid, conn).await;
    }
}

/// Process one authenticated frame. Returns true when the connection should be closed.
async fn handle_frame(
    state: &AppState,
    conn: ConnId,
    authed_user_id: &mut Option<i64>,
    msg_type: &str,
    data: &Value,
    socket: &mut WebSocket,
) -> bool {
    let manager = &state.ws;
    let auth_required = matches!(
        msg_type,
        "getUpdates" | "ackUpdates" | "ping" | "getMessages" | "sendMessage" | "dmSend" |
        "editMessage" | "dmEdit" | "dmDelete" | "dmMarkRead" | "dmMarkAllRead" |
        "messagesMarkAllRead" | "deleteMessage" | "addReaction" | "addDmReaction" |
        "subscribeStatus" | "unsubscribeStatus" | "typing" | "stopTyping" | "dmTyping" | "stopDmTyping"
    );
    if auth_required {
        match authenticate_user(data, &state.db, &state.jwt_secret, true).await {
            Ok(Some(u)) => {
                if *authed_user_id != Some(u.id) {
                    if let Some(old) = authed_user_id.take() {
                        manager.unbind_conn(conn).await;
                        let (_o, _l) = manager.unregister_connection(old, conn).await;
                    }
                    manager.bind_conn(conn, u.id).await;
                    *authed_user_id = Some(u.id);
                }
            }
            Ok(None) => {
                let _ = socket.send(ws_text(json!({"type":msg_type,"error":{"code":401,"detail":"Invalid credentials"}}))).await;
                return false;
            }
            Err(e) => {
                let code = e.status.as_u16();
                let _ = socket.send(ws_text(json!({"type":msg_type,"error":{"code":code,"detail":e.to_string()}}))).await;
                return false;
            }
        }
    }

    let Some(uid) = *authed_user_id else {
        return false;
    };
    let result = dispatch(state, conn, uid, msg_type, data).await;
    if let Some(result) = result {
        let _ = socket.send(ws_text(json!({"type":msg_type,"data":result}))).await;
    }
    false
}

/// Dispatch a single WS message to the matching handler. Returns Some(payload) to echo back,
/// or None for silent handlers.
async fn dispatch(
    state: &AppState,
    conn: ConnId,
    uid: i64,
    msg_type: &str,
    data: &Value,
) -> Option<Value> {
    let manager = &state.ws;
    match msg_type {
        "ping" => {
            let (_nconn, became_online) = manager.register_connection(uid).await;
            if became_online {
                // Broadcast online status to subscribers.
                let last_seen = state.presence.get_last_seen(uid).map(|d| d.to_rfc3339());
                let _ = manager.broadcast(json!({
                    "type": "statusUpdate",
                    "data": { "userId": uid, "online": true, "lastSeen": last_seen }
                }), Some(&state.db)).await;
            }
            Some(json!({"status":"success"}))
        }
        "getUpdates" => {
            let last_seq = data.get("lastSeq").and_then(|v| v.as_i64()).unwrap_or(0);
            Some(manager.get_updates(conn, uid, &state.db, last_seq).await)
        }
        "ackUpdates" => {
            let acked = data.get("lastSeq").and_then(|v| v.as_i64()).unwrap_or(0);
            Some(manager.ack_updates(conn, uid, &state.db, acked).await)
        }
        "getMessages" => {
            let limit = int_opt(data, "limit");
            let before = int_opt(data, "before_id").or_else(|| int_opt(data, "beforeId"));
            let after = int_opt(data, "after_id").or_else(|| int_opt(data, "afterId"));
            let around = int_opt(data, "around_id").or_else(|| int_opt(data, "aroundId"));
            match crate::routes::public_messaging::get_public_messages_page_api(
                &state.db, limit, before, after, around,
            )
            .await
            {
                Ok(p) => Some(p),
                Err(e) => Some(json!({"status":"error","error":{"code":e.status.as_u16(),"detail":e.detail}})),
            }
        }
        "sendMessage" => {
            let content = data.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let user = match state.models_user_cache(uid).await {
                Ok(u) => u,
                Err(_) => return Some(json!({"status":"error"})),
            };
            let auth = crate::dependencies::AuthUser {
                user,
                claims: crate::auth::Claims {
                    user_id: uid,
                    username: String::new(),
                    session_id: String::new(),
                    exp: 0,
                },
                incognito: false,
            };
            match crate::routes::public_messaging::send_message_internal(state, &auth, content).await {
                Ok(j) => Some(j.0),
                Err(e) => Some(json!({"status":"error","error":{"code":e.status.as_u16(),"detail":e.detail}})),
            }
        }
        "subscribeStatus" => {
            let target = int_opt(data, "userId").unwrap_or(0);
            if target > 0 {
                manager.subscribe_status(conn, target).await;
            }
            Some(json!({"status":"ok"}))
        }
        "unsubscribeStatus" => {
            let target = int_opt(data, "userId").unwrap_or(0);
            if target > 0 {
                manager.unsubscribe_status(conn, target).await;
            }
            Some(json!({"status":"ok"}))
        }
        "messagesMarkAllRead" => {
            let _ = sqlx::query("UPDATE message SET is_read=TRUE WHERE is_read=FALSE")
                .execute(&state.db).await;
            Some(json!({"status":"ok","markAll":true,"updated":0}))
        }
        "typing" => {
            if manager.typing_start(uid).await {
                let username = manager.username_for(Some(&state.db), uid).await;
                let _ = manager.broadcast(json!({"type":"typing","data":{"userId":uid,"username":username}}), Some(&state.db)).await;
            }
            None
        }
        "stopTyping" => {
            if manager.typing_stop(uid).await {
                let username = manager.username_for(Some(&state.db), uid).await;
                let _ = manager.broadcast(json!({"type":"stopTyping","data":{"userId":uid,"username":username}}), Some(&state.db)).await;
            }
            None
        }
        "dmTyping" => {
            let recipient = int_opt(data, "recipientId").unwrap_or(0);
            if recipient > 0 {
                if manager.dm_typing_start(uid, recipient).await {
                    let username = manager.username_for(Some(&state.db), uid).await;
                    let _ = manager.enqueue_update_for_user(recipient, "dmTyping", json!({"userId":uid,"username":username}), Some(&state.db)).await;
                }
            }
            None
        }
        "stopDmTyping" => {
            let recipient = int_opt(data, "recipientId").unwrap_or(0);
            if recipient > 0 {
                if manager.dm_typing_stop(uid, recipient).await {
                    let username = manager.username_for(Some(&state.db), uid).await;
                    let _ = manager.enqueue_update_for_user(recipient, "stopDmTyping", json!({"userId":uid,"username":username}), Some(&state.db)).await;
                }
            }
            None
        }
        _ => {
            warn!("Unhandled WS type: {}", msg_type);
            Some(json!({"status":"unsupported"}))
        }
    }
}

fn int_opt(data: &Value, key: &str) -> Option<i64> {
    data.get(key).and_then(|v| v.as_i64())
}