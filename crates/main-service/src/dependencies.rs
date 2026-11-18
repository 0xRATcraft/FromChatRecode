//! Axum extractor for authenticated users + app state.

use axum::http::request::Parts;
use sqlx::PgPool;

use crate::auth;
use crate::models::User;

/// Header carrying the user's JWT.
pub const AUTH_HEADER: &str = "Authorization";
/// Incognito header used to suppress presence updates.
pub const INCOGNITO_HEADER: &str = "X-FromChat-Incognito";

/// Application shared state.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub presence: crate::presence::PresenceService,
    pub ws: crate::ws::WsManager,
    pub profanity: crate::profanity::ProfanityConfig,
    pub failed_logins: std::sync::Arc<crate::routes::account::FailedLoginStore>,
    pub dm_rate_limiter: crate::routes::dm::DmRateLimiter,
}

impl AppState {
    pub fn new(db: PgPool, jwt_secret: String) -> Self {
        let presence = crate::presence::PresenceService::new();
        Self {
            db,
            jwt_secret,
            presence: presence.clone(),
            ws: crate::ws::WsManager::new(presence),
            profanity: crate::profanity::ProfanityConfig {
                chat_filter_url: std::env::var("CHAT_FILTER_URL").ok(),
                disabled: crate::config::chat_filter_disabled_from_env(),
            },
            failed_logins: std::sync::Arc::new(crate::routes::account::FailedLoginStore::new()),
            dm_rate_limiter: crate::routes::dm::DmRateLimiter::new(),
        }
    }

    /// Load a user row by id (for WS dispatch that needs the full `User`).
    pub async fn models_user_cache(&self, id: i64) -> Result<User, crate::error::ApiError> {
        sqlx::query_as(crate::USER_SELECT_BY_ID)
            .bind(id)
            .fetch_one(&self.db)
            .await
            .map_err(crate::error::ApiError::from)
    }
}

/// Authenticated user extracted from a Bearer token, re-read from the DB.
pub struct AuthUser {
    pub user: User,
    pub claims: auth::Claims,
    pub incognito: bool,
}

impl AuthUser {
    pub fn user_id(&self) -> i64 {
        self.user.id
    }
    pub fn username(&self) -> &str {
        &self.user.username
    }
}

/// Errors surfaced by the auth extractor.
#[derive(Debug)]
pub enum AuthError {
    Missing,
    Invalid,
    Unauthorized,
    Suspended,
    Deleted,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Missing => write!(f, "Missing authorization header"),
            AuthError::Invalid => write!(f, "Invalid or expired token"),
            AuthError::Unauthorized => write!(f, "Unauthorized"),
            AuthError::Suspended => write!(f, "Account suspended"),
            AuthError::Deleted => write!(f, "Account deleted"),
        }
    }
}

impl std::error::Error for AuthError {}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            AuthError::Missing => (axum::http::StatusCode::UNAUTHORIZED, "missing_token"),
            AuthError::Invalid | AuthError::Unauthorized => {
                (axum::http::StatusCode::UNAUTHORIZED, "invalid_token")
            }
            AuthError::Suspended => (
                axum::http::StatusCode::FORBIDDEN,
                "account_suspended",
            ),
            AuthError::Deleted => (axum::http::StatusCode::GONE, "account_deleted"),
        };
        let body = serde_json::json!({ "error": code, "detail": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}

impl From<AuthError> for axum::http::StatusCode {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Missing | AuthError::Invalid | AuthError::Unauthorized => {
                axum::http::StatusCode::UNAUTHORIZED
            }
            AuthError::Suspended => axum::http::StatusCode::FORBIDDEN,
            AuthError::Deleted => axum::http::StatusCode::GONE,
        }
    }
}

impl axum::extract::FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Missing)?;

        let claims = auth::verify_token(&state.jwt_secret, token).ok_or(AuthError::Invalid)?;

        let incognito = parts
            .headers
            .get(INCOGNITO_HEADER)
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"true"))
            .unwrap_or(false);

        let user: User = sqlx::query_as("SELECT * FROM \"user\" WHERE id = $1")
            .bind(claims.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| AuthError::Unauthorized)?
            .ok_or(AuthError::Unauthorized)?;

        if user.deleted {
            return Err(AuthError::Deleted);
        }
        if user.suspended {
            return Err(AuthError::Suspended);
        }

        Ok(AuthUser { user, claims, incognito })
    }
}