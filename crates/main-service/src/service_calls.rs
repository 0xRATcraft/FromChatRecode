//! Inter-service HTTP calls, port of `service_calls.py`.

use serde_json::Value;
use std::time::Duration;

use crate::error::{ApiError, ApiResult};

const MESSAGING_TIMEOUT: Duration = Duration::from_secs(5);
const STORAGE_TIMEOUT: Duration = Duration::from_secs(30);
const STORAGE_TIMEOUT_LONG: Duration = Duration::from_secs(120);

fn messaging_base() -> ApiResult<String> {
    std::env::var("MESSAGING_SERVICE_URL")
        .map(|u| u.trim_end_matches('/').to_string())
        .map_err(|_| ApiError::internal("MESSAGING_SERVICE_URL is not set"))
}

fn storage_base() -> ApiResult<String> {
    std::env::var("FILE_STORAGE_SERVICE_URL")
        .map(|u| u.trim_end_matches('/').to_string())
        .map_err(|_| ApiError::internal("FILE_STORAGE_SERVICE_URL is not set"))
}

fn is_compliance_required() -> bool {
    !matches!(
        crate::config::retention_never_store_compliance(),
        true
    )
}

/// Compliance public key (from env COMPLIANCE_PUBLIC_KEY). Empty when not required.
pub fn compliance_public_key() -> ApiResult<String> {
    if !is_compliance_required() {
        return Ok(String::new());
    }
    let key = std::env::var("COMPLIANCE_PUBLIC_KEY").unwrap_or_default().trim().to_string();
    if key.is_empty() {
        return Err(ApiError::internal(
            "Compliance public key not available - set COMPLIANCE_PUBLIC_KEY environment variable",
        ));
    }
    Ok(key)
}

async fn post_json(url: String, body: &Value, timeout: Duration) -> ApiResult<Value> {
    let client = reqwest::Client::builder().timeout(timeout).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let resp = client.post(url).json(body).send().await.map_err(|e| {
        tracing::warn!("service call failed: {}", e);
        ApiError::internal("service unavailable")
    })?;
    let status = resp.status();
    let j: Value = resp.json().await.map_err(|_| ApiError::internal("bad service response"))?;
    if status.is_client_error() {
        let detail = j.get("detail").and_then(|v| v.as_str()).unwrap_or("service error").to_string();
        return Err(ApiError {
            status,
            code: "service_error".into(),
            detail,
        });
    }
    if status.is_server_error() {
        return Err(ApiError::internal("service error"));
    }
    Ok(j)
}

async fn get_json(url: String, headers: &[(&str, String)], timeout: Duration) -> ApiResult<Value> {
    let client = reqwest::Client::builder().timeout(timeout).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let mut req = client.get(url);
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = req.send().await.map_err(|e| {
        tracing::warn!("service get failed: {}", e);
        ApiError::internal("service unavailable")
    })?;
    let status = resp.status();
    let j: Value = resp.json().await.map_err(|_| ApiError::internal("bad service response"))?;
    if status.is_client_error() || status.is_server_error() {
        return Err(ApiError::internal("service error"));
    }
    Ok(j)
}

/// GET /key/transport/public from messaging service.
pub async fn get_messaging_transport_public_key() -> ApiResult<Value> {
    let url = format!("{}/key/transport/public", messaging_base()?);
    get_json(url, &[], MESSAGING_TIMEOUT).await
}

/// Deliver transport ciphertext to file-storage as a completed resumable upload.
/// Returns the upload_id for messaging to consume.
pub async fn stage_transport_ciphertext_resumable_upload(
    transport_ciphertext: &[u8],
    filename: &str,
    allowed_user_ids: &[i64],
    user_id: i64,
) -> ApiResult<String> {
    let storage = storage_base()?;
    // init
    let init_body = serde_json::json!({
        "filename": filename,
        "total_size": transport_ciphertext.len(),
        "allowed_user_ids": allowed_user_ids,
    });
    let init: Value = post_json(
        format!("{}/uploads/resumable/init", storage),
        &init_body,
        Duration::from_secs(10),
    )
    .await?;
    let upload_id = init
        .get("upload_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("storage init missing upload_id"))?
        .to_string();

    // chunk bytes at offset 0
    let url = format!("{}/uploads/resumable/{}", storage, upload_id);
    let client = reqwest::Client::builder().timeout(STORAGE_TIMEOUT_LONG).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let resp = client
        .patch(&url)
        .body(transport_ciphertext.to_vec())
        .header("X-User-ID", user_id.to_string())
        .header("X-Upload-Offset", "0")
        .send()
        .await
        .map_err(|e| { tracing::warn!("chunk upload failed: {}", e); ApiError::internal("storage unavailable") })?;
    let _ = resp.error_for_status().map_err(|e| ApiError::internal(format!("chunk upload: {}", e)))?;

    // complete
    let complete: Value = post_json(
        format!("{}/uploads/resumable/{}/complete", storage, upload_id),
        &serde_json::json!({"upload_id": upload_id}),
        Duration::from_secs(10),
    )
    .await?;
    let _ = complete;
    Ok(upload_id)
}

/// POST /process to messaging service (envelope encryption, no files).
pub async fn process_message_in_messaging_service(
    client_public_key_b64: &str,
    transport_nonce_b64: &str,
    transport_ciphertext_b64: &str,
    compliance_public_key_b64: &str,
    sender_public_key_b64: &str,
    recipient_public_key_b64: &str,
) -> ApiResult<Value> {
    let body = serde_json::json!({
        "client_public_key_b64": client_public_key_b64,
        "transport_nonce_b64": transport_nonce_b64,
        "transport_ciphertext_b64": transport_ciphertext_b64,
        "compliance_public_key_b64": compliance_public_key_b64,
        "sender_public_key_b64": sender_public_key_b64,
        "recipient_public_key_b64": recipient_public_key_b64,
    });
    let url = format!("{}/process", messaging_base()?);
    post_json(url, &body, MESSAGING_TIMEOUT).await
}

/// POST /process-with-files to messaging service (single MEK for message + files).
pub async fn process_message_with_files_in_messaging_service(
    client_public_key_b64: &str,
    transport_nonce_b64: &str,
    transport_ciphertext_b64: &str,
    compliance_public_key_b64: &str,
    sender_public_key_b64: &str,
    recipient_public_key_b64: &str,
    transport_files: &[Value],
    file_access_user_id: i64,
    recipient_id: i64,
) -> ApiResult<Value> {
    let body = serde_json::json!({
        "client_public_key_b64": client_public_key_b64,
        "transport_nonce_b64": transport_nonce_b64,
        "transport_ciphertext_b64": transport_ciphertext_b64,
        "compliance_public_key_b64": compliance_public_key_b64,
        "sender_public_key_b64": sender_public_key_b64,
        "recipient_public_key_b64": recipient_public_key_b64,
        "files": transport_files,
        "file_access_user_id": file_access_user_id,
        "recipient_id": recipient_id,
    });
    let url = format!("{}/process-with-files", messaging_base()?);
    let client = reqwest::Client::builder().timeout(STORAGE_TIMEOUT_LONG).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let resp = client.post(url).json(&body).send().await.map_err(|e| {
        tracing::warn!("process-with-files failed: {}", e);
        ApiError::internal("messaging service unavailable")
    })?;
    let status = resp.status();
    let j: Value = resp.json().await.map_err(|_| ApiError::internal("bad messaging response"))?;
    if status == reqwest::StatusCode::BAD_REQUEST {
        let detail = j.get("detail").and_then(|v| v.as_str()).unwrap_or("processing failed").to_string();
        return Err(ApiError::bad_request("processing_failed", detail));
    }
    if status.is_server_error() {
        return Err(ApiError::internal("messaging service error"));
    }
    Ok(j)
}

/// DELETE a resumable upload in storage.
pub async fn delete_resumable_upload_in_storage(upload_id: &str, user_id: i64) -> ApiResult<Value> {
    let storage = storage_base()?;
    let url = format!("{}/uploads/resumable/{}", storage, upload_id);
    let client = reqwest::Client::builder().timeout(STORAGE_TIMEOUT).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let resp = client
        .delete(url)
        .header("X-User-ID", user_id.to_string())
        .send()
        .await
        .map_err(|e| { tracing::warn!("delete upload failed: {}", e); ApiError::internal("storage unavailable") })?;
    let status = resp.status();
    let j: Value = resp.json().await.map_err(|_| ApiError::internal("bad storage response"))?;
    if status.is_server_error() {
        return Err(ApiError::internal("storage error"));
    }
    Ok(j)
}

/// GET a resumable upload's status in storage.
pub async fn get_resumable_upload_status_in_storage(upload_id: &str, user_id: i64) -> ApiResult<Value> {
    let storage = storage_base()?;
    let url = format!("{}/uploads/resumable/{}", storage, upload_id);
    get_json(url, &[("X-User-ID", user_id.to_string())], Duration::from_secs(10)).await
}

/// PATCH a resumable upload chunk (JSON base64 body).
pub async fn upload_resumable_chunk_in_storage(upload_id: &str, user_id: i64, offset: i64, data_b64: &str) -> ApiResult<Value> {
    let storage = storage_base()?;
    let url = format!("{}/uploads/resumable/{}", storage, upload_id);
    let body = serde_json::json!({"offset": offset, "data_b64": data_b64});
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|_| ApiError::internal("http client build failed"))?;
    let resp = client.patch(url).json(&body).header("X-User-ID", user_id.to_string()).send().await.map_err(|e| {
        tracing::warn!("chunk upload failed: {}", e);
        ApiError::internal("storage unavailable")
    })?;
    let status = resp.status();
    let j: Value = resp.json().await.map_err(|_| ApiError::internal("bad storage response"))?;
    if status.is_server_error() {
        return Err(ApiError::internal("storage error"));
    }
    Ok(j)
}

/// POST complete for a resumable upload.
pub async fn complete_resumable_upload_in_storage(upload_id: &str, user_id: i64) -> ApiResult<Value> {
    let storage = storage_base()?;
    let url = format!("{}/uploads/resumable/{}/complete", storage, upload_id);
    post_json(url, &serde_json::json!({"upload_id": upload_id}), Duration::from_secs(10)).await
        .map(|v| { let _ = user_id; v })
}

/// POST init for a resumable upload in storage.
pub async fn init_resumable_upload_in_storage(
    filename: &str,
    total_size: i64,
    allowed_user_ids: &[i64],
    chunk_size: Option<i64>,
) -> ApiResult<Value> {
    let storage = storage_base()?;
    let mut body = serde_json::json!({
        "filename": filename,
        "total_size": total_size,
        "allowed_user_ids": allowed_user_ids,
    });
    if let Some(cs) = chunk_size {
        body["chunk_size"] = serde_json::json!(cs);
    }
    let url = format!("{}/uploads/resumable/init", storage);
    post_json(url, &body, Duration::from_secs(10)).await
}