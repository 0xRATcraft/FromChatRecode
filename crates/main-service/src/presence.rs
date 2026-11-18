//! In-memory user presence derived from WebSocket connections.
//! Mirror of `presence_service.py`.

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

/// A connection token; in practice an abstract handle for a live WebSocket.
pub type ConnId = u64;

#[derive(Default)]
struct Inner {
    /// user_id → set of live connection ids.
    connections: HashMap<i64, HashSet<ConnId>>,
    /// user_id → last seen timestamp.
    last_seen: HashMap<i64, DateTime<Utc>>,
    /// session_id → set of connection ids.
    session_connections: HashMap<String, HashSet<ConnId>>,
    /// connection id → session id.
    conn_to_session: HashMap<ConnId, String>,
}

/// Thread-safe presence service.
#[derive(Clone)]
pub struct PresenceService {
    inner: std::sync::Arc<std::sync::Mutex<Inner>>,
    next_conn: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Default for PresenceService {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceService {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(Inner::default())),
            next_conn: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn alloc_conn(&self) -> ConnId {
        self.next_conn.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Register a live session connection; returns its connection id.
    pub fn register_session_connection(&self, session_id: &str) -> ConnId {
        let conn = self.alloc_conn();
        let mut g = self.inner.lock().expect("presence lock");
        g.conn_to_session.insert(conn, session_id.to_string());
        g.session_connections.entry(session_id.to_string()).or_default().insert(conn);
        conn
    }

    pub fn unregister_session_connection(&self, conn: ConnId) {
        let mut g = self.inner.lock().expect("presence lock");
        let session_id = g.conn_to_session.remove(&conn);
        if let Some(sid) = session_id {
            if let Some(set) = g.session_connections.get_mut(&sid) {
                set.remove(&conn);
                if set.is_empty() {
                    g.session_connections.remove(&sid);
                }
            }
        }
    }

    pub fn is_session_online(&self, session_id: &str) -> bool {
        let g = self.inner.lock().expect("presence lock");
        g.session_connections.get(session_id).map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// Register a user connection; returns the connection id and whether user became online.
    pub fn register_connection(&self, user_id: i64) -> (ConnId, bool) {
        let conn = self.alloc_conn();
        let mut g = self.inner.lock().expect("presence lock");
        let set = g.connections.entry(user_id).or_default();
        let was_online = !set.is_empty();
        set.insert(conn);
        (conn, !was_online)
    }

    /// Remove a connection. Returns (became_offline, last_seen).
    pub fn unregister_connection(&self, user_id: i64, conn: ConnId) -> (bool, Option<DateTime<Utc>>) {
        let mut g = self.inner.lock().expect("presence lock");
        let became_offline = {
            if let Some(set) = g.connections.get_mut(&user_id) {
                set.remove(&conn);
                if set.is_empty() {
                    g.connections.remove(&user_id);
                    let ts = Utc::now();
                    g.last_seen.insert(user_id, ts);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        self.unregister_session_connection_locked(&mut g, conn);
        let last_seen = if became_offline {
            g.last_seen.get(&user_id).copied()
        } else {
            None
        };
        (became_offline, last_seen)
    }

    fn unregister_session_connection_locked(&self, g: &mut Inner, conn: ConnId) {
        let session_id = g.conn_to_session.remove(&conn);
        if let Some(sid) = session_id {
            if let Some(set) = g.session_connections.get_mut(&sid) {
                set.remove(&conn);
                if set.is_empty() {
                    g.session_connections.remove(&sid);
                }
            }
        }
    }

    pub fn is_online(&self, user_id: i64) -> bool {
        let g = self.inner.lock().expect("presence lock");
        g.connections.get(&user_id).map(|s| !s.is_empty()).unwrap_or(false)
    }

    pub fn touch(&self, user_id: i64) {
        let mut g = self.inner.lock().expect("presence lock");
        if g.connections.get(&user_id).map(|s| !s.is_empty()).unwrap_or(false) {
            g.last_seen.insert(user_id, Utc::now());
        }
    }

    pub fn get_last_seen(&self, user_id: i64) -> Option<DateTime<Utc>> {
        let g = self.inner.lock().expect("presence lock");
        if g.connections.get(&user_id).map(|s| !s.is_empty()).unwrap_or(false) {
            Some(g.last_seen.get(&user_id).copied().unwrap_or_else(Utc::now))
        } else {
            g.last_seen.get(&user_id).copied()
        }
    }

    pub fn get_presence(&self, user_id: i64) -> (bool, Option<DateTime<Utc>>) {
        (self.is_online(user_id), self.get_last_seen(user_id))
    }

    pub fn remove_user(&self, user_id: i64) {
        let mut g = self.inner.lock().expect("presence lock");
        g.connections.remove(&user_id);
        g.last_seen.remove(&user_id);
    }
}

use std::sync::OnceLock;

/// Global presence service used where a shared instance is convenient.
pub fn app_presence() -> &'static PresenceService {
    static P: OnceLock<PresenceService> = OnceLock::new();
    P.get_or_init(PresenceService::new)
}