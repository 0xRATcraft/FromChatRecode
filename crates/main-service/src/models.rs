//! SQLx row structs mirroring the Python SQLAlchemy models in `models.py`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub profile_picture: Option<String>,
    pub bio: Option<String>,
    pub online: bool,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub verified: bool,
    pub suspended: bool,
    pub suspension_reason: Option<String>,
    pub deleted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
    pub yandex_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Message {
    pub id: i64,
    pub content: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub user_id: i64,
    pub is_read: bool,
    pub reply_to_id: Option<i64>,
    pub is_edited: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageFile {
    pub id: i64,
    pub message_id: i64,
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CryptoPublicKey {
    pub id: i64,
    pub user_id: i64,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CryptoBackup {
    pub id: i64,
    pub user_id: i64,
    pub blob_json: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmEnvelope {
    pub id: i64,
    pub sender_id: i64,
    pub recipient_id: i64,
    pub iv_b64: String,
    pub ciphertext_b64: String,
    pub sender_wrapped_mek_b64: String,
    pub recipient_wrapped_mek_b64: String,
    pub compliance_wrapped_mek_b64: Option<String>,
    pub reply_to_id: Option<i64>,
    pub timestamp: Option<DateTime<Utc>>,
    pub is_edited: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmFile {
    pub id: i64,
    pub message_id: i64,
    pub sender_id: i64,
    pub recipient_id: i64,
    pub name: String,
    pub path: String,
    pub nonce_b64: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PushSubscription {
    pub id: i64,
    pub user_id: i64,
    pub endpoint: String,
    pub p256dh_key: String,
    pub auth_key: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FcmToken {
    pub id: i64,
    pub user_id: i64,
    pub token: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Reaction {
    pub id: i64,
    pub message_id: i64,
    pub user_id: i64,
    pub emoji: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmReaction {
    pub id: i64,
    pub dm_envelope_id: i64,
    pub user_id: i64,
    pub emoji: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmConversationPreference {
    pub id: i64,
    pub user_id: i64,
    pub other_user_id: i64,
    pub archived: bool,
    pub last_read_envelope_id: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceSession {
    pub id: i64,
    pub user_id: i64,
    pub raw_user_agent: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub browser_name: Option<String>,
    pub browser_version: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub session_id: String,
    pub session_kind: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UpdateLog {
    pub id: i64,
    pub user_id: i64,
    pub sequence: i64,
    pub updates: String,
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MessageEditHistory {
    pub id: i64,
    pub message_id: i64,
    pub previous_content: String,
    pub edited_at: Option<DateTime<Utc>>,
    pub edited_by_user_id: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DmEditHistory {
    pub id: i64,
    pub message_id: i64,
    pub dm_envelope_id: i64,
    pub previous_ciphertext_b64: String,
    pub previous_iv_b64: String,
    pub previous_compliance_wrapped_mek_b64: String,
    pub edited_at: Option<DateTime<Utc>>,
    pub edited_by: i64,
    pub edited_by_user_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DmReadReceipt {
    pub user_id: i64,
    pub envelope_id: i64,
    pub other_user_id: i64,
}