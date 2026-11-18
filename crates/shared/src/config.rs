//! Runtime configuration assembled from environment variables.

use std::path::PathBuf;

use serde::Serialize;

use crate::env_bool;

/// Message retention policy mirroring the Python `message_retention` module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MessageRetention {
    /// MESSAGE_RETENTION_DAYS = -1 → never store the compliance MEK.
    NeverStoreComplianceMek,
    /// MESSAGE_RETENTION_DAYS = 0 → keys (except compliance) live indefinitely.
    KeepForever,
    /// Positive value → key lifecycle processor prunes after N days.
    Days(i64),
}

impl MessageRetention {
    pub fn from_env() -> Self {
        let raw = crate::env_int("MESSAGE_RETENTION_DAYS").unwrap_or(30);
        match raw {
            -1 | 0 if raw == -1 => Self::NeverStoreComplianceMek,
            0 => Self::KeepForever,
            n if n > 0 => Self::Days(n),
            _ => Self::Days(30),
        }
    }

    pub fn never_store_compliance_mek(&self) -> bool {
        matches!(self, Self::NeverStoreComplianceMek)
    }
}

/// Concrete config for a single service.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen port (defaults differ per service).
    pub port: u16,
    /// TCP bind address.
    pub host: String,
    /// Postgres connection string (main service only).
    pub database_url: Option<String>,
    /// JWT HMAC secret (main service only).
    pub jwt_secret: String,
    /// Base URLs of internal services.
    pub messaging_url: Option<String>,
    pub file_storage_url: Option<String>,
    pub chat_filter_url: Option<String>,
    /// Compliance public key (base64 raw X25519).
    pub compliance_public_key: String,
    /// Retention policy.
    pub retention: MessageRetention,
    /// Where plain attachment data is written (file_storage only).
    pub files_dir: PathBuf,
    /// Whether the chat filter is disabled via ENABLE_CHAT_FILTER=0.
    pub chat_filter_disabled: bool,
    /// Extra CORS origins for the main service.
    pub cors_extra_origins: Vec<String>,
    pub cors_allow_lan: bool,
}

impl Config {
    /// Build a per-service config. `default_port` is used when PORT is unset.
    pub fn from_env(default_port: u16) -> Self {
        let port = crate::env_var("PORT", &default_port.to_string())
            .parse::<u16>()
            .unwrap_or(default_port);

        let retention = MessageRetention::from_env();
        let chat_filter_disabled = env_bool("ENABLE_CHAT_FILTER", false);

        let cors_extra = crate::env_var("CORS_EXTRA_ORIGINS", "");
        let cors_origins = cors_extra
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            port,
            host: crate::env_var("HOST", "0.0.0.0"),
            database_url: std::env::var("DATABASE_URL").ok(),
            jwt_secret: crate::env_var("JWT_SECRET", ""),
            messaging_url: std::env::var("MESSAGING_SERVICE_URL").ok(),
            file_storage_url: std::env::var("FILE_STORAGE_SERVICE_URL").ok(),
            chat_filter_url: std::env::var("CHAT_FILTER_URL").ok(),
            compliance_public_key: crate::env_var("COMPLIANCE_PUBLIC_KEY", ""),
            retention,
            files_dir: crate::env_var("FILES_DIR", "/app/files").into(),
            chat_filter_disabled,
            cors_extra_origins: cors_origins,
            cors_allow_lan: env_bool("CORS_ALLOW_LAN", true),
        }
    }

    pub fn retention(&self) -> MessageRetention {
        self.retention
    }
}

/// Well-known default ports from the Python compose layout.
pub mod ports {
    pub const MAIN: u16 = 8300;
    pub const MESSAGING: u16 = 8301;
    pub const FILE_STORAGE: u16 = 8302;
    pub const CHAT_FILTER: u16 = 8305;
}