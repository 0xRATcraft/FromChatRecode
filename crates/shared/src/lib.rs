//! Shared configuration, constants and helpers used across FromChat services.

use std::collections::HashMap;
use std::env;

pub mod config;
pub mod security;
pub mod utils;

pub use config::Config;
pub use utils::init_tracing;

/// Server instance id header used by the main service for every response.
pub const INSTANCE_ID_HEADER: &str = "X-FromChat-Instance-Id";

/// Opaque Yandex subject header semantics carried by clients in incognito mode.
pub const INCOGNITO_REQUEST_HEADER: &str = "X-FromChat-Incognito";

/// Environment variables with defaults (compose injects the real values).
pub fn env_var(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Parse an integer env var if present and parseable.
pub fn env_int(key: &str) -> Option<i64> {
    env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

/// Parse a boolean-ish env var following the Python project's convention.
pub fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

/// Application data dir (mirrors Python `resolve_data_dir`).
pub fn data_dir() -> std::path::PathBuf {
    match env::var("DATA_DIR") {
        Ok(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
        _ => std::path::PathBuf::from("/app/data"),
    }
}

/// Build a string map describing the source of a request for audit logs.
pub fn request_context(ip: &str, method: &str, path: &str, user: Option<&str>) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("ip".to_string(), ip.to_string());
    m.insert("method".to_string(), method.to_string());
    m.insert("path".to_string(), path.to_string());
    if let Some(u) = user {
        m.insert("user".to_string(), u.to_string());
    }
    m
}