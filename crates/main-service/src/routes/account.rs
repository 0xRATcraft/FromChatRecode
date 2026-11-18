//! Account routes, mirroring `routes/account.py`.

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth;
use crate::convert;
use crate::dependencies::{AppState, AuthUser};
use crate::error::{ApiError, ApiResult};
use crate::models::User;
use crate::presence::app_presence;
use crate::utils::get_client_ip;
use crate::verification::OWNER_USER_ID;
use crate::{deleted_user, validation, username};

const FAILED_ATTEMPT_WINDOW_SECONDS: u64 = 300;
const FAILED_ATTEMPT_THRESHOLD: u32 = 5;

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPasswordDerived")]
    current_password_derived: String,
    #[serde(rename = "newPasswordDerived")]
    new_password_derived: String,
    #[serde(rename = "logoutAllExceptCurrent", default)]
    logout_all_except_current: bool,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPasswordRequest {
    #[serde(rename = "passwordDerived")]
    password_derived: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    #[serde(rename = "passwordDerived")]
    password_derived: String,
}

#[derive(Debug, Serialize)]
pub struct StatusOk {
    status: &'static str,
}

fn ok() -> Json<StatusOk> {
    Json(StatusOk { status: "success" })
}

/// In-memory failed-login tracker (mirror of `_failed_login_attempts`).
#[derive(Default)]
pub struct FailedLoginStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>>,
}

impl FailedLoginStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn record(&self, identifier: &str) -> bool {
        let now = std::time::Instant::now();
        let mut g = self.inner.lock().expect("failed login lock");
        let attempts = g.entry(identifier.to_string()).or_default();
        attempts.push_back(now);
        while attempts.front().map(|t| now.duration_since(*t).as_secs() > FAILED_ATTEMPT_WINDOW_SECONDS).unwrap_or(false) {
            attempts.pop_front();
        }
        attempts.len() >= FAILED_ATTEMPT_THRESHOLD as usize
    }
    pub fn reset(&self, identifier: &str) {
        let mut g = self.inner.lock().expect("failed login lock");
        g.remove(identifier);
    }
}

fn is_admin(user: &User) -> bool {
    user.id == OWNER_USER_ID
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/instance_id", get(instance_id_public))
        .route("/check_auth", get(check_auth))
        .route("/check_username", get(check_username))
        .route("/crypto/public-key", get(get_public_key).post(set_public_key))
        .route("/crypto/backup", get(get_backup).post(set_backup))
        .route("/crypto/public-key/of/{user_id}", get(get_public_key_of))
        .route("/users/search", get(search_users))
        .route("/logout", get(logout))
        .route("/change-password", post(change_password))
        .route("/verify-password", post(verify_password_endpoint))
        .route("/delete", post(delete_account))
        .route("/account/delete", post(delete_account))
        .route("/admin/user/{user_id}", delete(delete_user_as_owner))
}

async fn instance_id_public() -> ApiResult<Json<serde_json::Value>> {
    // In-process random fingerprint (persisted generation to DATA_DIR is not portable here).
    let id = Uuid::new_v4().simple().to_string();
    Ok(Json(serde_json::json!({ "instance_id": id })))
}

async fn check_auth() -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({ "authenticated": true })))
}

async fn check_username(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Json<serde_json::Value>> {
    let u = params.get("username").cloned().unwrap_or_default();
    let u = u.trim().to_string();
    if !validation::is_valid_username(&u) {
        return Err(ApiError::bad_request(
            "invalid_username",
            "Username must be 3 to 20 characters and contain only English letters, digits, hyphens, and underscores",
        ));
    }
    let exists = username::username_taken(&state.db, &u, None).await?;
    Ok(Json(serde_json::json!({ "exists": exists })))
}

async fn get_public_key(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let pk: Option<String> =
        sqlx::query_scalar("SELECT public_key_b64 FROM crypto_public_key WHERE user_id=$1")
            .bind(user.user_id())
            .fetch_optional(&state.db)
            .await?;
    Ok(Json(serde_json::json!({ "publicKey": pk })))
}

async fn set_public_key(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> ApiResult<Json<StatusOk>> {
    let pk = payload.get("publicKey").and_then(|v| v.as_str()).unwrap_or("");
    if pk.is_empty() {
        return Err(ApiError::bad_request("public_key_required", "publicKey required"));
    }
    if !(10..=10000).contains(&pk.len()) {
        return Err(ApiError::bad_request("invalid_public_key", "Invalid publicKey format"));
    }
    sqlx::query(
        "INSERT INTO crypto_public_key (user_id, public_key_b64) VALUES ($1,$2) \
         ON CONFLICT (user_id) DO UPDATE SET public_key_b64=EXCLUDED.public_key_b64",
    )
    .bind(user.user_id())
    .bind(pk)
    .execute(&state.db)
    .await?;
    Ok(ok())
}

async fn get_backup(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let blob: Option<String> = sqlx::query_scalar("SELECT blob_json FROM crypto_backup WHERE user_id=$1")
        .bind(user.user_id())
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "blob": blob })))
}

async fn set_backup(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> ApiResult<Json<StatusOk>> {
    let blob = payload.get("blob").and_then(|v| v.as_str()).unwrap_or("");
    if blob.is_empty() {
        return Err(ApiError::bad_request("blob_required", "blob required"));
    }
    if blob.len() > 1_000_000 {
        return Err(ApiError::bad_request(
            "invalid_blob",
            "Invalid blob format or size exceeds 1MB",
        ));
    }
    sqlx::query(
        "INSERT INTO crypto_backup (user_id, blob_json) VALUES ($1,$2) \
         ON CONFLICT (user_id) DO UPDATE SET blob_json=EXCLUDED.blob_json",
    )
    .bind(user.user_id())
    .bind(blob)
    .execute(&state.db)
    .await?;
    Ok(ok())
}

async fn get_public_key_of(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let pk: Option<String> =
        sqlx::query_scalar("SELECT public_key_b64 FROM crypto_public_key WHERE user_id=$1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(Json(serde_json::json!({ "publicKey": pk })))
}

async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    let q = params.get("q").cloned().unwrap_or_default().trim().to_string();
    if q.chars().count() < 2 {
        return Ok(Json(serde_json::json!({ "users": [] })));
    }
    let pattern = format!("%{}%", q);
    let rows: Vec<User> = sqlx::query_as(crate::USER_SELECT_LIKE)
        .bind(&pattern)
        .bind(user.user_id())
        .fetch_all(&state.db)
        .await?;

    let mut users = Vec::new();
    let is_admin = user.user_id() == OWNER_USER_ID;
    for u in rows {
        let redacted = deleted_user::is_deleted_user(&u) || deleted_user::is_suspended_user(&u);
        if !is_admin && redacted {
            continue;
        }
        let converted = convert::convert_user(&state.db, app_presence(), &u, Some(user.user_id())).await?;
        users.push(converted);
    }
    Ok(Json(serde_json::json!({ "users": users })))
}

async fn logout(
    State(state): State<AppState>,
    user: AuthUser,
    headers: axum::http::HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let session_id = &user.claims.session_id;
    sqlx::query("UPDATE device_session SET revoked=TRUE WHERE user_id=$1 AND session_id=$2")
        .bind(user.user_id())
        .bind(session_id)
        .execute(&state.db)
        .await?;
    let _ = get_client_ip(&headers_to_request(&headers));
    Ok(Json(serde_json::json!({ "status": "success", "message": "Logged out successfully" })))
}

fn headers_to_request(headers: &axum::http::HeaderMap) -> axum::http::Request<()> {
    axum::http::Request::builder()
        .uri("/")
        .body(())
        .map(|mut req| {
            *req.headers_mut() = headers.clone();
            req
        })
        .unwrap_or_else(|_| axum::http::Request::default())
}

async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if !auth::verify_password(&req.current_password_derived.trim(), &user.user.password_hash) {
        return Err(ApiError::bad_request("wrong_password", "Текущий пароль неверный"));
    }
    let new_hash = auth::get_password_hash(&req.new_password_derived.trim());
    sqlx::query("UPDATE \"user\" SET password_hash=$1 WHERE id=$2")
        .bind(new_hash)
        .bind(user.user_id())
        .execute(&state.db)
        .await?;

    if req.logout_all_except_current {
        let current = &user.claims.session_id;
        sqlx::query(
            "UPDATE device_session SET revoked=TRUE WHERE user_id=$1 AND session_id <> $2 AND revoked=FALSE",
        )
        .bind(user.user_id())
        .bind(current)
        .execute(&state.db)
        .await?;
    }
    Ok(Json(serde_json::json!({ "status": "success" })))
}

async fn verify_password_endpoint(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<VerifyPasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if !auth::verify_password(&req.password_derived.trim(), &user.user.password_hash) {
        return Err(ApiError::bad_request("wrong_password", "Wrong password"));
    }
    let _ = state;
    Ok(Json(serde_json::json!({ "status": "success" })))
}

async fn delete_account(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<DeleteAccountRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    if is_admin(&user.user) {
        return Err(ApiError::bad_request("cannot_delete_owner", "Cannot delete admin/owner account"));
    }
    if !auth::verify_password(&req.password_derived.trim(), &user.user.password_hash) {
        return Err(ApiError::bad_request("wrong_password", "Wrong password"));
    }
    let id = user.user_id();
    deleted_user::apply_deleted_fields_to_db(&state.db, id).await?;
    state.presence.remove_user(id);
    Ok(Json(serde_json::json!({ "status": "success", "message": "Account deleted successfully" })))
}

async fn delete_user_as_owner(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    user: AuthUser,
) -> ApiResult<Json<serde_json::Value>> {
    if !is_admin(&user.user) {
        return Err(ApiError::forbidden("only_owner", "Only owner can perform this action"));
    }
    if user_id == OWNER_USER_ID {
        return Err(ApiError::bad_request("cannot_delete_owner", "Cannot delete owner account"));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM \"user\" WHERE id=$1)")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    if !exists {
        return Err(ApiError::not_found("user_not_found", "User not found"));
    }
    sqlx::query("DELETE FROM message WHERE user_id=$1").bind(user_id).execute(&state.db).await?;
    sqlx::query("DELETE FROM \"user\" WHERE id=$1").bind(user_id).execute(&state.db).await?;
    Ok(Json(serde_json::json!({ "status": "success", "deleted_user_id": user_id })))
}