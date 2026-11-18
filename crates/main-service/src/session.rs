//! Device-session creation and helpers, mirroring `_create_device_session` in `auth_steps.py`
//! and the branch in `dependencies.py`.

use axum::http::HeaderMap;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::config::jwt::TOKEN_INACTIVITY_EXPIRE_HOURS;
use crate::error::{ApiError, ApiResult};
use crate::models::User;

/// Session kinds.
pub const SESSION_KIND_STANDARD: &str = "standard";
pub const SESSION_KIND_INCOGNITO: &str = "incognito";

/// Absolute lifetime (hours) for incognito sessions.
pub const INCOGNITO_SESSION_TTL_HOURS: i64 = 12;

/// Client-detected device type (a light reformulation of the ua-parser result).
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub device_type: String,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub browser_name: Option<String>,
    pub browser_version: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
}

/// Parse headers into a coarse device/session classification.
/// We reuse the `woothee` crate (UA parser) for browser/OS detection and
/// approximate mobile/tablet/bot classification like python `user_agents`.
pub fn parse_client_info(headers: &HeaderMap) -> ClientInfo {
    let raw_ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let parsed = woothee::parser::Parser::new().parse(&raw_ua);

    let os_name = parsed.as_ref().map(|p| p.os.to_string());
    let browser_name = parsed
        .as_ref()
        .map(|p| p.name.trim().to_string())
        .filter(|s| !s.is_empty());
    let browser_version = parsed
        .as_ref()
        .map(|p| p.version.trim().to_string())
        .filter(|s| !s.is_empty());

    let lower = raw_ua.to_lowercase();
    let is_mobile = lower.contains("mobile") || lower.contains("iphone") || lower.contains("android") && !lower.contains("tablet");
    let is_tablet = lower.contains("ipad") || lower.contains("tablet");
    let is_bot = lower.contains("bot") || lower.contains("crawler") || lower.contains("spider");

    let device_type = if is_tablet {
        "tablet"
    } else if is_mobile {
        "mobile"
    } else if is_bot {
        "bot"
    } else {
        "desktop"
    }
    .to_string();

    ClientInfo {
        device_type,
        os_name,
        os_version: None,
        browser_name,
        browser_version,
        brand: None,
        model: None,
    }
}

/// True when the client asked for an incognito session via the header.
pub fn request_wants_incognito(headers: &HeaderMap) -> bool {
    headers
        .get(crate::dependencies::INCOGNITO_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| matches!(s.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Create a new device session row and return its session id (mirror of auth_steps).
pub async fn create_device_session(
    db: &sqlx::PgPool,
    user: &User,
    headers: &HeaderMap,
    device_name: Option<&str>,
) -> ApiResult<String> {
    let session_id = Uuid::new_v4().simple().to_string();
    let now = Utc::now();
    let incognito = request_wants_incognito(headers);
    let info = parse_client_info(headers);
    let session_kind = if incognito { SESSION_KIND_INCOGNITO } else { SESSION_KIND_STANDARD };
    let expires_at = if incognito {
        Some(now + Duration::hours(INCOGNITO_SESSION_TTL_HOURS))
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO device_session \
         (user_id, raw_user_agent, device_name, device_type, os_name, os_version, \
          browser_name, browser_version, brand, model, session_id, session_kind, \
          expires_at, created_at, last_seen, revoked) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,FALSE)",
    )
    .bind(user.id)
    .bind(headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
    .bind(device_name.map(|s| s.to_string()))
    .bind(&info.device_type)
    .bind(&info.os_name)
    .bind(&info.os_version)
    .bind(&info.browser_name)
    .bind(&info.browser_version)
    .bind(&info.brand)
    .bind(&info.model)
    .bind(&session_id)
    .bind(session_kind)
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(session_id)
}

/// Validate that a device session for a user is neither revoked nor expired.
/// On success, touches `last_seen` (sliding expiration).
pub async fn touch_and_validate_session(
    db: &sqlx::PgPool,
    user_id: i64,
    session_id: &str,
    allow_suspended: bool,
) -> ApiResult<()> {
    let row: Option<(String, Option<chrono::DateTime<chrono::Utc>>, bool, String)> = sqlx::query_as(
        "SELECT session_kind, expires_at, revoked, (SELECT suspended FROM \"user\" WHERE id = $1) \
         FROM device_session WHERE user_id=$1 AND session_id=$2",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_optional(db)
    .await?;

    let Some((_, expires_at, revoked, suspended)) = row else {
        return Err(ApiError::unauthorized("invalid_session", "Session revoked or not found"));
    };
    if revoked {
        return Err(ApiError::unauthorized("invalid_session", "Session revoked or not found"));
    }
    let now = Utc::now();
    if expires_at.map(|e| e <= now).unwrap_or(false) {
        sqlx::query("UPDATE device_session SET revoked = TRUE WHERE user_id=$1 AND session_id=$2")
            .bind(user_id)
            .bind(session_id)
            .execute(db)
            .await?;
        return Err(ApiError::unauthorized("session_expired", "Session expired"));
    }

    // Suspended gate
    let suspended = suspended == "true";
    if suspended && !allow_suspended {
        return Err(ApiError::forbidden("account_suspended", "Account suspended"));
    }

    // Sliding inactivity expiration
    let threshold = now - Duration::hours(TOKEN_INACTIVITY_EXPIRE_HOURS);
    let last_seen: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_seen FROM device_session WHERE user_id=$1 AND session_id=$2",
    )
    .bind(user_id)
    .bind(session_id)
    .fetch_one(db)
    .await?;
    if last_seen.map(|l| l < threshold).unwrap_or(false) {
        sqlx::query("UPDATE device_session SET revoked = TRUE WHERE user_id=$1 AND session_id=$2")
            .bind(user_id)
            .bind(session_id)
            .execute(db)
            .await?;
        return Err(ApiError::unauthorized("session_expired", "Session expired due to inactivity"));
    }

    sqlx::query("UPDATE device_session SET last_seen = now() WHERE user_id=$1 AND session_id=$2")
        .bind(user_id)
        .bind(session_id)
        .execute(db)
        .await?;
    Ok(())
}