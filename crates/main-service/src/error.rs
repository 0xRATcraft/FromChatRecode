//! App-wide error type for handlers.

use axum::response::{IntoResponse, Response};
use axum::Json;

/// Unified API error; `{ error, detail }` JSON body mirroring the Python app.
#[derive(Debug)]
pub struct ApiError {
    pub status: axum::http::StatusCode,
    pub code: String,
    pub detail: String,
}

impl ApiError {
    pub fn bad_request(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: code.to_string(),
            detail: detail.into(),
        }
    }
    pub fn unauthorized(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: code.to_string(),
            detail: detail.into(),
        }
    }
    pub fn forbidden(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::FORBIDDEN,
            code: code.to_string(),
            detail: detail.into(),
        }
    }
    pub fn not_found(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::NOT_FOUND,
            code: code.to_string(),
            detail: detail.into(),
        }
    }
    pub fn conflict(code: &str, detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::CONFLICT,
            code: code.to_string(),
            detail: detail.into(),
        }
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error".to_string(),
            detail: detail.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.code, "detail": self.detail });
        (self.status, Json(body)).into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ApiError {}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("database error: {}", e);
        Self::internal("database error")
    }
}

pub type ApiResult<T> = Result<T, ApiError>;