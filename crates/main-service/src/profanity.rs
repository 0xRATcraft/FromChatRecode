//! Thin HTTP client for the chat-filter service, mirroring `security/chat_filter.py`.

use axum::http::StatusCode;

/// Configuration for profanity checks.
#[derive(Clone, Debug)]
pub struct ProfanityConfig {
    /// Base URL of the chat-filter service (without trailing slash).
    pub chat_filter_url: Option<String>,
    /// When true the filter is disabled and always allows.
    pub disabled: bool,
}

impl ProfanityConfig {
    pub fn is_enabled(&self) -> bool {
        !self.disabled && self.chat_filter_url.as_deref().map(|u| !u.is_empty()).unwrap_or(false)
    }
}

/// Do an HTTP POST to the chat-filter `/check` endpoint.
/// Mirrors `contains_profanity`:
///  - empty text → false (allowed)
///  - disabled → false (allowed)
///  - enabled + unreachable / 4xx / 5xx → 503 (fail closed)
async fn filter_allows(cfg: &ProfanityConfig, text: &str) -> Result<bool, crate::error::ApiError> {
    if !cfg.is_enabled() {
        return Ok(true);
    }
    let url = format!("{}/check", cfg.chat_filter_url.as_deref().unwrap_or("").trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|_| crate::error::ApiError::internal("content filter unavailable"))?;

    let resp = client
        .post(url)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(_) => {
            return Err(crate::error::ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "content_filter_unavailable".into(),
                detail: "Content filter unavailable".into(),
            })
        }
    };
    if resp.status().is_server_error() || resp.status().is_client_error() {
        return Err(crate::error::ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "content_filter_unavailable".into(),
            detail: "Content filter unavailable".into(),
        });
    }
    let body: serde_json::Value = resp.json().await.map_err(|_| crate::error::ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "content_filter_unavailable".into(),
        detail: "Content filter unavailable".into(),
    })?;
    let allowed = body.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok(allowed)
}

/// Return true if content must be rejected (contains profanity).
pub async fn contains_profanity(cfg: &ProfanityConfig, text: &str) -> Result<bool, crate::error::ApiError> {
    if text.trim().is_empty() {
        return Ok(false);
    }
    let allowed = filter_allows(cfg, text).await?;
    Ok(!allowed)
}