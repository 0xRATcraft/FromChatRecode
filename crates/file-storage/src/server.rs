//! HTTP front of the file storage service, mirroring Python `src/file_storage/main.py`.

use std::sync::Arc;

use axum::extract::multipart::Multipart;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use fc_shared::config::Config;

use crate::storage::{api_error, ApiError, Storage};

#[derive(Clone)]
struct Api {
    storage: Arc<Storage>,
}

/// Reads `X-User-ID` header; 401 when missing.
fn user_id_from_request(req: &Request) -> Result<i64, (StatusCode, Json<ApiError>)> {
    let raw = req
        .headers()
        .get("X-User-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match raw {
        Some(v) => v
            .trim()
            .parse::<i64>()
            .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "Invalid user authentication")),
        None => Err(api_error(StatusCode::UNAUTHORIZED, "Missing user authentication")),
    }
}

/// Read a multipart field value (first value encountered for repeated names).
#[allow(dead_code)]
async fn multipart_field(mp: &mut Multipart, name: &str) -> Option<String> {
    while let Some(field) = mp.next_field().await.ok().flatten() {
        if field.name() == Some(name) {
            if let Ok(text) = field.text().await {
                return Some(text);
            }
        }
    }
    None
}

/// Read the file field bytes from a multipart body.
async fn multipart_file_bytes(mp: &mut Multipart) -> Option<(String, Vec<u8>)> {
    while let Some(field) = mp.next_field().await.ok().flatten() {
        if field.name().is_some() && field.file_name().is_some() {
            let name = field.file_name().unwrap_or("file").to_string();
            if let Ok(data) = field.bytes().await {
                return Some((name, data.to_vec()));
            }
        }
    }
    None
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy", "service": "file_storage"}))
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({"message": "FromChat File Storage Service", "status": "operational"}))
}

/// POST /upload — multipart file upload (`file` field).
async fn upload_file(State(api): State<Api>, mut mp: Multipart) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let (original_name, data) = multipart_file_bytes(&mut mp)
        .await
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "file field required"))?;
    let result = api
        .storage
        .upload_file_bytes(&original_name, &data)
        .map_err(|(s, e)| (s, e))?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "filename": result.file_id,
        "original_name": result.filename,
        "size": result.size,
        "path": format!("/files/{}", result.file_id),
    })))
}

/// Store a base64 file: POST /upload-base64.
#[derive(Deserialize)]
struct UploadBase64Req {
    filename: Option<String>,
    data_b64: String,
    #[allow(dead_code)]
    content_type: Option<String>,
    allowed_user_ids: Option<Vec<i64>>,
}

async fn upload_base64(
    State(api): State<Api>,
    Json(payload): Json<UploadBase64Req>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    match api.storage.upload_base64(
        payload.filename.as_deref().unwrap_or("file"),
        &payload.data_b64,
        payload.allowed_user_ids.unwrap_or_default(),
    ) {
        Ok(r) => Ok(Json(serde_json::json!({
            "file_id": r.file_id,
            "filename": r.filename,
            "size": r.size,
            "path": r.path,
        }))),
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
struct InitResumableReq {
    filename: Option<String>,
    total_size: usize,
    allowed_user_ids: Vec<i64>,
    chunk_size: Option<usize>,
}

async fn init_resumable(
    State(api): State<Api>,
    Json(payload): Json<InitResumableReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    api.storage
        .init_resumable(
            payload.filename.as_deref().unwrap_or("file"),
            payload.total_size,
            payload.allowed_user_ids,
            payload.chunk_size,
        )
        .map(Json)
}

async fn resumable_status(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    api.storage.resumable_status(&upload_id, uid).map(Json)
}

/// PATCH /uploads/resumable/{upload_id}
async fn upload_resumable_chunk(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if content_type == "application/octet-stream" {
        let offset_raw = req
            .headers()
            .get("X-Upload-Offset")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let offset = match offset_raw {
            Some(v) => v.trim().parse::<usize>().map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid X-Upload-Offset"))?,
            None => return Err(api_error(StatusCode::BAD_REQUEST, "X-Upload-Offset header is required")),
        };
        let bytes = axum::body::to_bytes(req.into_body(), 5 * 1024 * 1024 * 1024)
            .await
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to read body"))?;
        return api
            .storage
            .upload_resumable_chunk(&upload_id, uid, offset, &bytes)
            .map(Json);
    }

    // JSON fallback.
    #[derive(Deserialize)]
    struct JsonChunk {
        offset: usize,
        data_b64: String,
    }
    let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to read body"))?;
    let payload: JsonChunk =
        serde_json::from_slice(&bytes).map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid JSON"))?;
    let chunk = B64
        .decode(&payload.data_b64)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid base64"))?;
    api.storage
        .upload_resumable_chunk(&upload_id, uid, payload.offset, &chunk)
        .map(Json)
}

async fn complete_resumable(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    api.storage.complete_resumable(&upload_id, uid).map(Json)
}

async fn resumable_blob_path(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    api.storage.resumable_blob_path(&upload_id, uid).map(Json)
}

async fn resumable_data_b64(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    api.storage.resumable_data_b64(&upload_id, uid).map(Json)
}

async fn delete_resumable(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    api.storage.delete_resumable(&upload_id, uid).map(Json)
}

#[derive(Deserialize)]
struct PromoteReq {
    stored_name: String,
}

async fn promote_resumable(
    State(api): State<Api>,
    Path(upload_id): Path<String>,
    req: Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    let body = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to read body"))?;
    let payload: PromoteReq =
        serde_json::from_slice(&body).map_err(|_| api_error(StatusCode::BAD_REQUEST, "stored_name is required"))?;
    let stored_name = payload.stored_name.trim().to_string();
    if stored_name.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "stored_name is required"));
    }
    api.storage
        .promote_resumable_to_normal(&upload_id, uid, &stored_name)
        .map(Json)
}

/// POST /uploads/files/normal/store — multipart with `stored_name` + `file`.
async fn store_normal_file_multipart(
    State(api): State<Api>,
    mut mp: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // First pass to capture stored_name.
    let mut stored_name: Option<String> = None;
    while let Some(field) = mp.next_field().await.ok().flatten() {
        if field.name() == Some("stored_name") {
            if let Ok(text) = field.text().await {
                stored_name = Some(text.trim().to_string());
            }
            break;
        }
    }
    let stored_name = stored_name.ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "stored_name is required"))?;
    if stored_name.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "stored_name is required"));
    }
    // Read the pending file into a temp path.
    let tmp_dir = api.storage.paths.tmp_dir.clone();
    let tmp_path = tmp_dir.join(format!("normal-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut written: Option<usize> = None;
    while let Some(field) = mp.next_field().await.ok().flatten() {
        if field.file_name().is_some() {
            let data = field
                .bytes()
                .await
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to read file"))?;
            std::fs::write(&tmp_path, data.as_ref())
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to write temp file"))?;
            written = Some(data.len());
            break;
        }
    }
    if written.is_none() {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(api_error(StatusCode::BAD_REQUEST, "file field required"));
    }
    let result = api
        .storage
        .store_normal_file_from_path(&stored_name, &tmp_path)
        .map_err(|(s, e)| (s, e));
    let _ = std::fs::remove_file(&tmp_path);
    result.map(|r| {
        Json(serde_json::json!({
            "stored_name": r.stored_name,
            "size": r.size,
            "path": r.path,
        }))
    })
}

/// Serve a stored file from files_dir.
async fn get_file(
    State(api): State<Api>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if filename.is_empty() || filename.contains('/') || filename.contains('\\') {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid filename"));
    }
    let path = api.storage.paths.files_dir.join(&filename);
    if !path.is_file() {
        return Err(api_error(StatusCode::NOT_FOUND, "File not found"));
    }
    match tokio::fs::read(&path).await {
        Ok(data) => Ok(([(header::CONTENT_TYPE, header::HeaderValue::from_static("application/octet-stream"))], data).into_response()),
        Err(_) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file")),
    }
}

/// GET /uploads/files/normal/{filename}
async fn get_file_normal(
    State(api): State<Api>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let safe = Storage::secure_filename(&filename);
    if safe != filename {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid file name"));
    }
    let path = api.storage.paths.normal_dir.join(&safe);
    if !path.is_file() {
        return Err(api_error(StatusCode::NOT_FOUND, "File not found"));
    }
    match tokio::fs::read(&path).await {
        Ok(data) => Ok(([(header::CONTENT_TYPE, header::HeaderValue::from_static("application/octet-stream"))], data).into_response()),
        Err(_) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file")),
    }
}

async fn get_file_normal_dimensions(
    State(api): State<Api>,
    Path(stored_name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    match api.storage.get_normal_file_dimensions(&stored_name) {
        Some(v) => Ok(Json(v)),
        None => Err(api_error(StatusCode::NOT_FOUND, "File not found")),
    }
}

async fn get_file_thumb(
    State(api): State<Api>,
    Path(filename): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let safe = Storage::secure_filename(&filename);
    if safe != filename {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid file name"));
    }
    let mut path = api.storage.paths.thumbs_dir.join(&safe);
    if !path.is_file() {
        if let Some(stem) = std::path::Path::new(&safe).file_stem().map(|s| s.to_string_lossy().to_string()) {
            let alt = api.storage.paths.thumbs_dir.join(format!("{stem}.jpg"));
            if alt.is_file() {
                path = alt;
            }
        }
    }
    if !path.is_file() {
        return Err(api_error(StatusCode::NOT_FOUND, "Thumbnail not found"));
    }
    match tokio::fs::read(&path).await {
        Ok(data) => Ok(([(header::CONTENT_TYPE, header::HeaderValue::from_static("image/jpeg"))], data).into_response()),
        Err(_) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read thumb")),
    }
}

async fn get_public_thumb_meta(
    State(api): State<Api>,
    Path(stored_name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    match api.storage.get_public_thumb_meta(&stored_name) {
        Some(v) => Ok(Json(v)),
        None => Err(api_error(StatusCode::NOT_FOUND, "Thumbnail meta not found")),
    }
}

/// POST /uploads/files/thumbs/store — multipart thumb + dimensions.
async fn store_public_thumb(
    State(api): State<Api>,
    mut mp: Multipart,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mut stored_name = String::new();
    let mut width: u32 = 1;
    let mut height: u32 = 1;
    let mut file_size: usize = 0;
    let mut jpeg: Vec<u8> = Vec::new();

    while let Some(field) = mp.next_field().await.ok().flatten() {
        let name = field.name().unwrap_or("").to_string();
        if name == "stored_name" {
            stored_name = field.text().await.unwrap_or_default().trim().to_string();
        } else if name == "width" {
            width = field
                .text()
                .await
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(1);
        } else if name == "height" {
            height = field
                .text()
                .await
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(1);
        } else if name == "file_size" {
            file_size = field
                .text()
                .await
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(0);
        } else if field.file_name().is_some() {
            jpeg = field
                .bytes()
                .await
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to read thumb"))?
                .to_vec();
        }
    }

    if stored_name.trim().is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "stored_name is required"));
    }
    api.storage
        .store_public_thumb(stored_name.trim(), &jpeg, width, height, file_size)
        .map(Json)
}

#[derive(Deserialize)]
struct DimsForm {
    stored_name: String,
    width: u32,
    height: u32,
    file_size: usize,
}

async fn store_public_image_dimensions(
    State(api): State<Api>,
    Json(payload): Json<DimsForm>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    api.storage
        .store_public_image_dimensions(&payload.stored_name, payload.width, payload.height, payload.file_size)
        .map(Json)
}

/// GET /uploads/files/encrypted/{filename} — permission-checked.
async fn get_file_encrypted(
    State(api): State<Api>,
    Path(filename): Path<String>,
    req: Request,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let uid = user_id_from_request(&req)?;
    let safe = Storage::secure_filename(&filename);
    if safe != filename {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid file name"));
    }
    let path = api.storage.paths.files_dir.join(&safe);
    if !path.is_file() {
        return Err(api_error(StatusCode::NOT_FOUND, "File not found"));
    }
    if !api.storage.check_file_permissions(&safe, uid) && uid != 1 {
        return Err(api_error(StatusCode::FORBIDDEN, "Access denied to this file"));
    }
    match tokio::fs::read(&path).await {
        Ok(data) => Ok(([(header::CONTENT_TYPE, header::HeaderValue::from_static("application/octet-stream"))], data).into_response()),
        Err(_) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read file")),
    }
}

/// Build the file storage app.
pub fn app(config: Config) -> Router {
    let storage = Arc::new(Storage::new(config.files_dir.clone()));
    let api = Api { storage };
    Router::new()
        .route("/health", get(health))
        .route("/", get(root))
        .route("/upload", post(upload_file))
        .route("/upload-base64", post(upload_base64))
        .route("/uploads/resumable/init", post(init_resumable))
        .route(
            "/uploads/resumable/{upload_id}",
            get(resumable_status).patch(upload_resumable_chunk).delete(delete_resumable),
        )
        .route("/uploads/resumable/{upload_id}/complete", post(complete_resumable))
        .route("/uploads/resumable/{upload_id}/blob-path", get(resumable_blob_path))
        .route("/uploads/resumable/{upload_id}/data-b64", get(resumable_data_b64))
        .route("/uploads/resumable/{upload_id}/promote-normal", post(promote_resumable))
        .route("/uploads/files/normal/store", post(store_normal_file_multipart))
        .route("/uploads/files/normal/{stored_name}/dimensions", get(get_file_normal_dimensions))
        .route("/uploads/files/normal/{filename}", get(get_file_normal))
        .route("/uploads/files/thumbs/meta/{stored_name}", get(get_public_thumb_meta))
        .route("/uploads/files/thumbs/{filename}", get(get_file_thumb))
        .route("/uploads/files/thumbs/store", post(store_public_thumb))
        .route("/uploads/files/thumbs/dimensions", post(store_public_image_dimensions))
        .route("/uploads/files/encrypted/{filename}", get(get_file_encrypted))
        .route("/files/{filename}", get(get_file))
        .with_state(api)
}