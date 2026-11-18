pub mod auth;
pub mod config;
pub mod convert;
pub mod db;
pub mod deleted_user;
pub mod dependencies;
pub mod dm;
pub mod error;
pub mod main_service;
pub mod message;
pub mod middleware;
pub mod models;
pub mod presence;
pub mod profanity;
pub mod routes;
pub mod service_calls;
pub mod session;
pub mod similarity;
pub mod username;
pub mod utils;
pub mod validation;
pub mod verification;
pub mod ws;

pub use main_service::app;

/// Shared column list for fetching `User` rows (matches `models::User` order).
pub const USER_SELECT: &str = concat!(
    "SELECT id, username, display_name, password_hash, profile_picture, bio, online, last_seen, ",
    "created_at, verified, suspended, suspension_reason, deleted, deleted_at, yandex_id ",
    "FROM \"user\" WHERE lower(username) = lower($1) LIMIT 1"
);

/// INSERT ... RETURNING for `User` rows (owner columns set by caller).
pub const USER_INSERT: &str = concat!(
    "INSERT INTO \"user\" ",
    "(id, username, display_name, password_hash, bio, verified, yandex_id) ",
    "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, username, display_name, password_hash, ",
    "profile_picture, bio, online, last_seen, created_at, verified, suspended, suspension_reason, ",
    "deleted, deleted_at, yandex_id"
);

/// Username partial (ILIKE) fetch used by user search.
pub const USER_SELECT_LIKE: &str = concat!(
    "SELECT id, username, display_name, password_hash, profile_picture, bio, online, last_seen, ",
    "created_at, verified, suspended, suspension_reason, deleted, deleted_at, yandex_id ",
    "FROM \"user\" WHERE username ILIKE $1 AND id <> $2 ORDER BY username ASC LIMIT 20"
);

/// Full column list for fetching a `Message` row.
pub const MESSAGE_FIELDS: &str = concat!(
    "id, content, timestamp, user_id, is_read, reply_to_id, is_edited "
);

/// SELECT ... FROM message (no WHERE) for pagination.
pub const MESSAGE_SELECT_FROM: &str = concat!(
    "SELECT ",
    "id, content, timestamp, user_id, is_read, reply_to_id, is_edited ",
    "FROM message "
);

/// SELECT ... WHERE id = $1 for a single message.
pub const MESSAGE_SELECT_ID: &str = concat!(
    "SELECT ",
    "id, content, timestamp, user_id, is_read, reply_to_id, is_edited ",
    "FROM message WHERE id = $1"
);

/// SELECT ... AND <clause> (caller appends) — used by pagination to append predicates.
pub fn message_select_and(clause: &str) -> String {
    format!("{}{} {}", MESSAGE_SELECT_FROM, "WHERE ", clause)
}

/// INSERT ... RETURNING for a new public message.
pub const MESSAGE_INSERT: &str = concat!(
    "INSERT INTO message (content, user_id, reply_to_id, timestamp) VALUES ($1,$2,$3, now()) RETURNING ",
    "id, content, timestamp, user_id, is_read, reply_to_id, is_edited "
);

/// SELECT one user by id using the shared column list.
pub const USER_SELECT_BY_ID: &str = concat!(
    "SELECT id, username, display_name, password_hash, profile_picture, bio, online, last_seen, ",
    "created_at, verified, suspended, suspension_reason, deleted, deleted_at, yandex_id ",
    "FROM \"user\" WHERE id = $1 LIMIT 1"
);