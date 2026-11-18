//! Configuration for the main service, mirroring `constants.py`.

/// JWT claims constants.
pub mod jwt {
    /// Default lifetime of a token before hard expiry (hours).
    pub const MAX_TOKEN_LIFETIME_HOURS: i64 = 365 * 24; // 8760
    /// Wallet of hours after which an inactive session's token expires.
    pub const TOKEN_INACTIVITY_EXPIRE_HOURS: i64 = 720;
}

/// Message retention days.
pub mod retention {
    pub const MESSAGE_RETENTION_DAYS: i64 = -1; // -1: keep forever
}

/// True when compliance MEK must never be stored (MESSAGE_RETENTION_DAYS = -1).
pub fn retention_never_store_compliance() -> bool {
    std::env::var("MESSAGE_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|n| n == -1)
        .unwrap_or(true)
}

/// Read ENABLE_CHAT_FILTER: unset → false (enabled); 0/false/no/off → true (disabled).
pub fn chat_filter_disabled_from_env() -> bool {
    match std::env::var("ENABLE_CHAT_FILTER") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => false,
    }
}