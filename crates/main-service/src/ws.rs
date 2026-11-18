//! WebSocket connection manager, port of `messaging.py::MessaggingSocketManager`.
//!
//! This abstracts the per-user durable update queue (UpdateLog), live fan-out,
//! typing indicators, status subscriptions, and presence registration.
//! A concrete transport (axum/tokio-tungstenite) is injected via the `Sink`
//! trait so the same logic serves HTTP route broadcasts and the WS endpoint.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::presence::PresenceService;

/// A connection token produced by the transport; opaque to the manager.
pub type ConnId = u64;

/// Outbound frame sink capability the transport must provide.
#[async_trait]
pub trait Sink: Send + Sync + 'static {
    async fn send_json(&self, conn: ConnId, msg: Value);
    async fn close(&self, conn: ConnId, code: u16, reason: &str);
}

/// Ephemeral update types: live-only, never written to UpdateLog.
const EPHEMERAL: &[&str] = &[
    "typing",
    "stopTyping",
    "dmTyping",
    "stopDmTyping",
    "statusUpdate",
    "registeredUserCount",
    "session_ended",
];

fn is_ephemeral(t: &str) -> bool {
    EPHEMERAL.contains(&t)
}

/// Per-user queue entry.
#[derive(Default)]
struct UserQueue {
    pending: Vec<Value>,
    recent_signatures: HashSet<String>,
}

/// Shared manager state.
#[derive(Default)]
struct Inner {
    /// conn_id → user_id
    user_by_conn: HashMap<ConnId, i64>,
    /// conn_id → subscribed user ids
    ws_subscriptions: HashMap<ConnId, HashSet<i64>>,
    /// conn_id → last acked sequence
    last_seq_by_conn: HashMap<ConnId, i64>,
    /// conn_id → outbound sink registered by the connection
    sinks: HashMap<ConnId, Arc<dyn Sink>>,
    /// user_id → pending updates + dedupe signatures
    queues: HashMap<i64, UserQueue>,
    /// user_id → current sequence
    sequence_numbers: HashMap<i64, i64>,
    /// (user_id, sequence) already stored flag
    stored_sequences: HashSet<(i64, i64)>,
    /// user_id → public typing timestamp
    typing_users: HashMap<i64, Instant>,
    /// user_id → is typing (public)
    typing_state: HashMap<i64, bool>,
    /// user_id → {recipient_id -> timestamp} (DM typing)
    dm_typing_users: HashMap<i64, HashMap<i64, Instant>>,
    /// user_id → {recipient_id -> is_typing}
    dm_typing_state: HashMap<i64, HashMap<i64, bool>>,
}

/// Public WebSocket manager (shared, thread-safe).
#[derive(Clone)]
pub struct WsManager {
    inner: Arc<Mutex<Inner>>,
    presence: PresenceService,
    /// Sequence logging requires a pool (optional).
    seq_lock: Arc<tokio::sync::Mutex<()>>,
}

impl WsManager {
    pub fn new(presence: PresenceService) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            presence,
            seq_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn presence(&self) -> &PresenceService {
        &self.presence
    }

    pub async fn bind_conn(&self, conn: ConnId, user_id: i64) {
        let mut g = self.inner.lock().await;
        g.user_by_conn.insert(conn, user_id);
        g.last_seq_by_conn.insert(conn, 0);
    }

    /// Register the outbound sink for a connection so fan-out reaches its socket.
    pub async fn register_sink(&self, conn: ConnId, sink: Arc<dyn Sink>) {
        let mut g = self.inner.lock().await;
        g.sinks.insert(conn, sink);
    }

    pub async fn unbind_conn(&self, conn: ConnId) {
        let mut g = self.inner.lock().await;
        g.user_by_conn.remove(&conn);
        g.ws_subscriptions.remove(&conn);
        g.last_seq_by_conn.remove(&conn);
        g.sinks.remove(&conn);
    }

    /// Snapshots the sink for a connection, if registered.
    async fn sink_for(&self, conn: ConnId) -> Option<Arc<dyn Sink>> {
        let g = self.inner.lock().await;
        g.sinks.get(&conn).cloned()
    }

    /// Snapshots all live sinks for a user's connections.
    async fn sinks_for_user(&self, user_id: i64) -> Vec<(ConnId, Arc<dyn Sink>)> {
        let g = self.inner.lock().await;
        g.user_by_conn
            .iter()
            .filter(|(_, uid)| **uid == user_id)
            .filter_map(|(c, _)| g.sinks.get(c).map(|s| (*c, s.clone())))
            .collect()
    }

    async fn subscribe(&self, conn: ConnId, user_id: i64) {
        let mut g = self.inner.lock().await;
        g.ws_subscriptions.entry(conn).or_default().insert(user_id);
    }
    async fn unsubscribe(&self, conn: ConnId, user_id: i64) {
        let mut g = self.inner.lock().await;
        if let Some(s) = g.ws_subscriptions.get_mut(&conn) {
            s.remove(&user_id);
        }
    }

    /// Public broadcast recipient set: connected users + any non-revoked device-session owner.
    async fn public_update_recipient_ids(&self, db: Option<&PgPool>) -> HashSet<i64> {
        let mut ids: HashSet<i64> = {
            let g = self.inner.lock().await;
            g.user_by_conn.values().copied().collect()
        };
        if let Some(db) = db {
            if let Ok(rows) = sqlx::query_as::<_, (i64,)>(
                "SELECT DISTINCT user_id FROM device_session WHERE revoked = FALSE",
            )
            .fetch_all(db)
            .await
            {
                for (uid,) in rows {
                    ids.insert(uid);
                }
            }
        }
        ids
    }

    /// Get the current sequence for a user (memory, else DB).
    async fn get_current_sequence(&self, user_id: i64, db: Option<&PgPool>) -> i64 {
        {
            let g = self.inner.lock().await;
            if let Some(s) = g.sequence_numbers.get(&user_id) {
                return *s;
            }
        }
        if let Some(db) = db {
            if let Ok(seq) = sqlx::query_scalar::<_, i64>(
                "SELECT COALESCE(MAX(sequence),0) FROM update_log WHERE user_id=$1",
            )
            .bind(user_id)
            .fetch_one(db)
            .await
            {
                return seq;
            }
        }
        0
    }

    /// Next sequence for a user (locked).
    async fn next_sequence(&self, user_id: i64, db: Option<&PgPool>) -> i64 {
        let _guard = self.seq_lock.lock().await;
        let mut g = self.inner.lock().await;
        if !g.sequence_numbers.contains_key(&user_id) {
            let mut init = 0i64;
            if let Some(db) = db {
                if let Ok(seq) = sqlx::query_scalar::<_, i64>(
                    "SELECT COALESCE(MAX(sequence),0) FROM update_log WHERE user_id=$1",
                )
                .bind(user_id)
                .fetch_one(db)
                .await
                {
                    init = seq;
                }
            }
            g.sequence_numbers.insert(user_id, init);
        }
        let next = g.sequence_numbers.get(&user_id).copied().unwrap_or(0) + 1;
        g.sequence_numbers.insert(user_id, next);
        drop(g);
        next
    }

    /// Update signature for dedup, ported from `_get_update_signature`.
    fn update_signature(update: &Value) -> String {
        let t = update.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let data = update.get("data").cloned().unwrap_or_else(|| json!({}));
        let sig_data = match t {
            "newMessage" | "messageEdited" | "dmNew" | "dmEdited" | "dmDeleted" => {
                json!({"type": t, "id": data.get("id")})
            }
            "messageDeleted" => json!({"type": t, "id": data.get("id").or_else(|| data.get("message_id"))}),
            "reactionUpdate" => json!({
                "type": t,
                "messageId": data.get("message_id"),
                "emoji": data.get("emoji"),
                "userId": data.get("userId")
            }),
            "dmReactionUpdate" => json!({
                "type": t,
                "dmEnvelopeId": data.get("dm_envelope_id"),
                "emoji": data.get("emoji"),
                "userId": data.get("userId")
            }),
            "typing" | "stopTyping" | "dmTyping" | "stopDmTyping" | "statusUpdate" => {
                json!({"type": t, "userId": data.get("userId")})
            }
            "registeredUserCount" => json!({"type": t, "count": data.get("count")}),
            "dmConversationArchive" => json!({
                "type": t,
                "otherUserId": data.get("otherUserId"),
                "archived": data.get("archived")
            }),
            _ => json!({"type": t, "data": data}),
        };
        // Deterministic hash of sorted JSON.
        let bytes = serde_json::to_vec(&sig_data).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    }

    /// Add an update to the user's pending queue; false if duplicate.
    async fn add_update(&self, user_id: i64, update: Value) -> bool {
        let sig = Self::update_signature(&update);
        let mut g = self.inner.lock().await;
        let q = g.queues.entry(user_id).or_default();
        if q.recent_signatures.contains(&sig) {
            warn!("Update skipped due to duplicate signature {}", sig);
            return false;
        }
        q.pending.push(update);
        q.recent_signatures.insert(sig);
        if q.recent_signatures.len() > 100 {
            let drop_count = q.recent_signatures.len() - 50;
            let to_remove: Vec<String> = q.recent_signatures.iter().take(drop_count).cloned().collect();
            for s in to_remove {
                q.recent_signatures.remove(&s);
            }
        }
        true
    }

    /// Flush a user's pending durable + ephemeral updates to their live sinks.
    async fn flush_user_updates(&self, user_id: i64, db: Option<&PgPool>) {
        let pending = {
            let mut g = self.inner.lock().await;
            let Some(q) = g.queues.get_mut(&user_id) else {
                return;
            };
            if q.pending.is_empty() {
                return;
            }
            std::mem::take(&mut q.pending)
        };
        let durable: Vec<Value> = pending.iter().filter(|u| !is_ephemeral(u.get("type").and_then(|v| v.as_str()).unwrap_or(""))).cloned().collect();
        let ephemeral: Vec<Value> = pending.iter().filter(|u| is_ephemeral(u.get("type").and_then(|v| v.as_str()).unwrap_or(""))).cloned().collect();

        let sinks = self.sinks_for_user(user_id).await;

        let current_seq = self.get_current_sequence(user_id, db).await;

        // Ephemeral: live sockets only.
        if !ephemeral.is_empty() {
            for (conn, sink) in &sinks {
                sink.send_json(*conn, json!({ "type": "updates", "seq": current_seq, "updates": ephemeral })).await;
            }
        }
        if durable.is_empty() {
            return;
        }

        let seq = self.next_sequence(user_id, db).await;

        if let Some(db) = db {
            let key = (user_id, seq);
            let mut store = false;
            {
                let mut g = self.inner.lock().await;
                if !g.stored_sequences.contains(&key) {
                    store = true;
                    g.stored_sequences.insert(key);
                }
            }
            if store {
                if let Err(e) = sqlx::query(
                    "INSERT INTO update_log (user_id, sequence, updates) VALUES ($1,$2,$3) \
                     ON CONFLICT (user_id, sequence) DO NOTHING",
                )
                .bind(user_id)
                .bind(seq)
                .bind(serde_json::to_string(&durable).unwrap_or_else(|_| "[]".into()))
                .execute(db)
                .await
                {
                    debug!("Failed to store update_log: {}", e);
                }
                if seq % 50 == 0 {
                    let _ = self.prune_update_log(db, Some(user_id)).await;
                }
            }
        }

for (conn, sink) in &sinks {
            sink.send_json(*conn, json!({ "type": "updates", "seq": seq, "updates": durable })).await;
        }
    }

    /// Age-based retention prune of update_log.
    async fn prune_update_log(&self, db: &PgPool, user_id: Option<i64>) -> i64 {
        const RETENTION_DAYS: i64 = 14;
        let cutoff = Utc::now() - chrono::Duration::days(RETENTION_DAYS);
        let res = if let Some(uid) = user_id {
            sqlx::query("DELETE FROM update_log WHERE user_id=$1 AND timestamp < $2")
                .bind(uid)
                .bind(cutoff)
                .execute(db)
                .await
        } else {
            sqlx::query("DELETE FROM update_log WHERE timestamp < $1")
                .bind(cutoff)
                .execute(db)
                .await
        };
        res.map(|r| r.rows_affected() as i64).unwrap_or(0)
    }

    /// Durable queue an update for a user (batched) and schedule flush.
    pub async fn enqueue_update_for_user(&self, user_id: i64, update_type: &str, update_data: Value, db: Option<&PgPool>) {
        let added = self.add_update(user_id, json!({"type": update_type, "data": update_data})).await;
        if !added {
            return;
        }
        // Small delay to batch (mirror the 75ms flush in Python).
        tokio::time::sleep(Duration::from_millis(75)).await;
        self.flush_user_updates(user_id, db).await;
    }

    /// Broadcast a message to all recipients as a durable per-user update.
    pub async fn broadcast(&self, message: Value, db: Option<&PgPool>) {
        let t = message.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let data = message.get("data").cloned().unwrap_or_else(|| json!({}));
        if is_ephemeral(t) {
            let sockets = {
                let g = self.inner.lock().await;
                g.user_by_conn.keys().copied().collect::<Vec<_>>()
            };
            for conn in sockets {
                if let Some(uid) = { let g = self.inner.lock().await; g.user_by_conn.get(&conn).copied() } {
                    self.enqueue_update_for_user(uid, t, data.clone(), db).await;
                }
            }
            return;
        }
        for uid in self.public_update_recipient_ids(db).await {
            self.enqueue_update_for_user(uid, t, data.clone(), db).await;
        }
    }

    /// Send a live (non-batched) message to a specific user's live connections.
    pub async fn send_to_user(&self, user_id: i64, message: Value) {
        for (conn, sink) in self.sinks_for_user(user_id).await {
            sink.send_json(conn, message.clone()).await;
        }
    }

    /// Force-close every connection for a user.
    pub async fn disconnect_user(&self, user_id: i64, code: u16, reason: &str) {
        for (conn, sink) in self.sinks_for_user(user_id).await {
            sink.close(conn, code, reason).await;
        }
    }

    /// Register presence for a connection; returns whether the user just went online.
    pub async fn register_connection(&self, user_id: i64) -> (ConnId, bool) {
        self.presence.register_connection(user_id)
    }
    pub async fn unregister_connection(&self, user_id: i64, conn: ConnId) -> (bool, Option<DateTime<Utc>>) {
        self.presence.unregister_connection(user_id, conn)
    }

    /// Status-subscription helpers.
    pub async fn subscribe_status(&self, conn: ConnId, user_id: i64) { self.subscribe(conn, user_id).await; }
    pub async fn unsubscribe_status(&self, conn: ConnId, user_id: i64) { self.unsubscribe(conn, user_id).await; }

    pub async fn typing_start(&self, user_id: i64) -> bool {
        let mut g = self.inner.lock().await;
        let was = g.typing_state.get(&user_id).copied().unwrap_or(false);
        g.typing_users.insert(user_id, Instant::now());
        if !was {
            g.typing_state.insert(user_id, true);
        }
        !was
    }
    pub async fn typing_stop(&self, user_id: i64) -> bool {
        let mut g = self.inner.lock().await;
        let was = g.typing_state.get(&user_id).copied().unwrap_or(false);
        g.typing_users.remove(&user_id);
        if was {
            g.typing_state.insert(user_id, false);
        }
        was
    }
    pub async fn dm_typing_start(&self, user_id: i64, recipient: i64) -> bool {
        let mut g = self.inner.lock().await;
        let was = g
            .dm_typing_state
            .get(&user_id)
            .and_then(|m| m.get(&recipient))
            .copied()
            .unwrap_or(false);
        let map = g.dm_typing_users.entry(user_id).or_default();
        map.insert(recipient, Instant::now());
        let state = g.dm_typing_state.entry(user_id).or_default();
        if !was {
            state.insert(recipient, true);
        }
        !was
    }
    pub async fn dm_typing_stop(&self, user_id: i64, recipient: i64) -> bool {
        let mut g = self.inner.lock().await;
        let was = g.dm_typing_state.get(&user_id).and_then(|m| m.get(&recipient)).copied().unwrap_or(false);
        if let Some(map) = g.dm_typing_users.get_mut(&user_id) {
            map.remove(&recipient);
            if map.is_empty() {
                g.dm_typing_users.remove(&user_id);
            }
        }
        if was {
            if let Some(m) = g.dm_typing_state.get_mut(&user_id) {
                m.insert(recipient, false);
            }
        }
        was
    }

    /// Clear all typing state for a user (suspend/delete/disconnect).
    pub async fn clear_typing_for_user(&self, user_id: i64) -> (bool, HashSet<i64>) {
        let mut g = self.inner.lock().await;
        let was_public = g.typing_state.remove(&user_id);
        g.typing_users.remove(&user_id);
        let dm_recips: HashSet<i64> = g.dm_typing_users.remove(&user_id).map(|m| m.into_keys().collect()).unwrap_or_default();
        g.dm_typing_state.remove(&user_id);
        (was_public.unwrap_or(false), dm_recips)
    }

    /// Fetch a user's username for typing broadcasts (deleted → #deletedN).
    pub async fn username_for(&self, db: Option<&PgPool>, user_id: i64) -> String {
        if let Some(db) = db {
            let row: Option<(String, bool, bool)> = sqlx::query_as(
                "SELECT username, deleted, suspended FROM \"user\" WHERE id=$1",
            )
            .bind(user_id)
            .fetch_optional(db)
            .await
            .unwrap_or(None);
            if let Some((username, deleted, suspended)) = row {
                if deleted || suspended {
                    return crate::deleted_user::deleted_username_for(user_id);
                }
                return username;
            }
        }
        crate::deleted_user::deleted_username_for(user_id)
    }

    /// Handle `getUpdates`: gap detection, replay durable logs, or signal tooLong.
    pub async fn get_updates(&self, conn: ConnId, user_id: i64, db: &PgPool, last_seq: i64) -> Value {
        const TOO_LONG: i64 = 500;
        const CHUNK: i64 = 50;
        {
            let mut g = self.inner.lock().await;
            g.last_seq_by_conn.insert(conn, last_seq);
        }
        let current = self.get_current_sequence(user_id, Some(db)).await;
        if current <= last_seq {
            return json!({ "status": "ok", "lastSeq": current, "missedCount": 0, "hasMore": false });
        }
        let gap = current - last_seq;
        if last_seq == 0 || gap > TOO_LONG {
            {
                let mut g = self.inner.lock().await;
                g.last_seq_by_conn.insert(conn, current);
            }
            return json!({ "status": "tooLong", "lastSeq": current, "missedCount": gap, "hasMore": false });
        }

        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT sequence, updates FROM update_log WHERE user_id=$1 AND sequence > $2 AND sequence <= $3 \
             ORDER BY sequence ASC LIMIT $4",
        )
        .bind(user_id)
        .bind(last_seq)
        .bind(current)
        .bind(CHUNK)
        .fetch_all(db)
        .await
        .unwrap_or_default();

        if rows.is_empty() || rows[0].0 != last_seq + 1 {
            let mut g = self.inner.lock().await;
            g.last_seq_by_conn.insert(conn, current);
            return json!({ "status": "tooLong", "lastSeq": current, "missedCount": gap, "hasMore": false });
        }

        let matching_sink = self.sink_for(conn).await;
        if !rows.is_empty() {
            for (seq, updates) in &rows {
                let parsed: Value = serde_json::from_str(updates).unwrap_or_else(|_| json!([]));
                if let Some(sink) = &matching_sink {
                    sink.send_json(conn, json!({ "type": "updates", "seq": seq, "updates": parsed })).await;
                }
            }
        }
        let sent_last = rows.last().map(|(s, _)| *s).unwrap_or(last_seq);
        let has_more = sent_last < current;
        {
            let mut g = self.inner.lock().await;
            g.last_seq_by_conn.insert(conn, sent_last);
        }
        json!({ "status": "ok", "lastSeq": sent_last, "missedCount": rows.len(), "hasMore": has_more })
    }

    /// Handle `ackUpdates`.
    pub async fn ack_updates(&self, conn: ConnId, user_id: i64, db: &PgPool, acked: i64) -> Value {
        let mut g = self.inner.lock().await;
        let prev = g.last_seq_by_conn.get(&conn).copied().unwrap_or(0);
        let new = prev.max(acked);
        g.last_seq_by_conn.insert(conn, new);
        drop(g);
        if acked > 0 && acked % 100 == 0 {
            let _ = self.prune_update_log(db, Some(user_id)).await;
        }
        json!({ "status": "ok", "lastSeq": new })
    }
}