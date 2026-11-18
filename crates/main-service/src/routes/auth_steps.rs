//! Step-based auth endpoints, mirroring `routes/auth_steps.py`.

use axum::extract::{ConnectInfo, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth;
use crate::convert::convert_user;
use crate::dependencies::AppState;
use crate::error::{ApiError, ApiResult};
use crate::models;
use crate::presence::app_presence;
use crate::profanity::ProfanityConfig;
use crate::session;
use crate::username;
use crate::validation;
use crate::verification::{allocate_user_id, OWNER_USERNAME};

#[derive(Debug, Deserialize)]
pub struct UsernameStepRequest {
    username: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordStepRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Yandex OAuth is stubbed in this port; fields remain in the request schema.
pub struct YandexExchangeRequest {
    code: String,
    #[serde(rename = "code_verifier")]
    code_verifier: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Yandex/captcha flows are stubbed in this port; fields remain in the schema.
pub struct RegisterConfirmRequest {
    username: String,
    password: String,
    #[serde(rename = "confirm_password")]
    confirm_password: String,
    #[serde(rename = "display_name")]
    display_name: String,
    bio: Option<String>,
    #[serde(rename = "registration_proof")]
    registration_proof: Option<String>,
    #[serde(rename = "yandex_code")]
    yandex_code: Option<String>,
    #[serde(rename = "code_verifier")]
    code_verifier: Option<String>,
    #[serde(rename = "captcha_token")]
    captcha_token: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/steps/username", post(auth_step_username))
        .route("/auth/steps/password", post(auth_step_password))
        .route("/auth/steps/register/confirm", post(auth_step_register_confirm))
        // Yandex exchange stub (Yandex OAuth not wired in this port).
        .route("/auth/yandex/exchange", post(auth_yandex_exchange))
}

fn profanity(state: &AppState) -> &ProfanityConfig {
    &state.profanity
}

async fn auth_step_username(
    State(state): State<AppState>,
    Json(body): Json<UsernameStepRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let username = body.username.trim().to_string();
    if !validation::is_valid_username(&username) {
        return Err(ApiError::bad_request(
            "invalid_username",
            "Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        ));
    }
    if crate::profanity::contains_profanity(profanity(&state), &username).await? {
        return Err(ApiError::bad_request("profanity", "Имя пользователя содержит запрещённые слова"));
    }
    let exists = username::username_taken(&state.db, &username, None).await?;
    Ok(Json(serde_json::json!({ "ok": true, "exists": exists })))
}

async fn auth_step_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PasswordStepRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let username = body.username.trim().to_string();
    let password = body.password.trim().to_string();

    if crate::profanity::contains_profanity(profanity(&state), &username).await? {
        return Err(ApiError::bad_request("profanity", "Имя пользователя содержит запрещённые слова"));
    }
    if !validation::is_valid_username(&username) {
        return Err(ApiError::bad_request(
            "invalid_username",
            "Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        ));
    }

    let user: Option<models::User> = sqlx::query_as(crate::USER_SELECT)
        .bind(&username)
        .fetch_optional(&state.db)
        .await?;

    let Some(user) = user else {
        return Ok(Json(serde_json::json!({
            "status": "needs_register",
            "yandex_required": false,
            "captcha_required": false,
        })));
    };

    if !auth::verify_password(&password, &user.password_hash) {
        let client_ip = peer.ip().to_string();
        handle_failed_login(&state, &username, Some(&client_ip))?;
    }

    let session_id = session::create_device_session(&state.db, &user, &headers, None).await?;
    let token = auth::create_token(&state.jwt_secret, user.id, &user.username, &session_id);
    let user_payload = convert_user(&state.db, app_presence(), &user, None).await?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Login successful",
        "token": token,
        "session_id": session_id,
        "user": user_payload,
    })))
}

fn handle_failed_login(
    state: &AppState,
    username: &str,
    client_ip: Option<&str>,
) -> ApiResult<()> {
    let identifiers: Vec<String> = std::iter::once(format!("user:{}", username))
        .chain(client_ip.map(|ip| format!("ip:{}", ip)))
        .collect();
    let mut suspicious = false;
    for id in &identifiers {
        if state.failed_logins.record(&id) {
            suspicious = true;
        }
    }
    if suspicious {
        return Err(ApiError {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_attempts".into(),
            detail: "Too many login attempts. Try again in a few minutes.".into(),
        });
    }
    Err(ApiError::unauthorized(
        "invalid_credentials",
        "Неверное имя пользователя или пароль",
    ))
}

async fn auth_yandex_exchange(
    State(_state): State<AppState>,
    Json(_body): Json<YandexExchangeRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    Err(ApiError {
        status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
        code: "yandex_not_configured".into(),
        detail: "Yandex sign-in is not configured on this server.".into(),
    })
}

async fn auth_step_register_confirm(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    ConnectInfo(_peer): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<RegisterConfirmRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let username = body.username.trim().to_string();
    let display_name = body.display_name.trim().to_string();
    let password = body.password.trim().to_string();
    let confirm_password = body.confirm_password.trim().to_string();

    if !validation::is_valid_username(&username) {
        return Err(ApiError::bad_request(
            "invalid_username",
            "Имя пользователя должно быть от 3 до 20 символов и содержать только английские буквы, цифры, дефисы и подчеркивания",
        ));
    }
    if crate::profanity::contains_profanity(profanity(&state), &username).await? {
        return Err(ApiError::bad_request("profanity", "Имя пользователя содержит запрещённые слова"));
    }
    if !validation::is_valid_display_name(&display_name) {
        return Err(ApiError::bad_request(
            "invalid_display_name",
            "Отображаемое имя должно быть от 1 до 64 символов и не может быть пустым",
        ));
    }
    if crate::profanity::contains_profanity(profanity(&state), &display_name).await? {
        return Err(ApiError::bad_request("profanity", "Отображаемое имя содержит запрещённые слова"));
    }
    if !validation::is_valid_password(&password) {
        return Err(ApiError::bad_request(
            "invalid_password",
            "Пароль должен быть от 5 до 50 символов и не содержать пробелов",
        ));
    }
    if password != confirm_password {
        return Err(ApiError::bad_request("password_mismatch", "Пароли не совпадают"));
    }
    if username::username_taken(&state.db, &username, None).await? {
        return Err(ApiError::bad_request("username_taken", "Это имя пользователя уже занято"));
    }

    let bio_text = body
        .bio
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(bio) = &bio_text {
        if bio.chars().count() > 500 {
            return Err(ApiError::bad_request("bio_too_long", "Описание должно быть не длиннее 500 символов"));
        }
        if crate::profanity::contains_profanity(profanity(&state), bio).await? {
            return Err(ApiError::bad_request("profanity", "Описание содержит запрещённые слова"));
        }
    }

    // Owner setup: first account with owner username becomes verified.
    let owner_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM \"user\" WHERE lower(username) = lower($1))")
            .bind(OWNER_USERNAME)
            .fetch_one(&state.db)
            .await?;
    let is_owner = !owner_exists && username.to_lowercase() == OWNER_USERNAME.to_lowercase();

    let new_id = allocate_user_id();
    let password_hash = auth::get_password_hash(&password);

    let user = loop {
        match sqlx::query_as::<_, models::User>(crate::USER_INSERT)
            .bind(new_id)
            .bind(&username)
            .bind(&display_name)
            .bind(&password_hash)
            .bind(&bio_text)
            .bind(is_owner)
            .bind(Option::<String>::None)
            .fetch_one(&state.db)
            .await
        {
            Ok(u) => break u,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => continue,
            Err(sqlx::Error::RowNotFound) => continue,
            Err(e) => return Err(ApiError::from(e)),
        }
    };

    let session_id = session::create_device_session(&state.db, &user, &headers, None).await?;
    let token = auth::create_token(&state.jwt_secret, user.id, &user.username, &session_id);
    let user_payload = convert_user(&state.db, app_presence(), &user, None).await?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Регистрация прошла успешно",
        "token": token,
        "user": user_payload,
    })))
}