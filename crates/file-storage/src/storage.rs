//! File storage backend: streaming/base64 uploads, permissions map,
//! resumable upload sessions, normal/encrypted/thumbnails directories.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;
use uuid::Uuid;

use crate::dimensions;

/// Max upload size (5GB) matching the Python service.
pub const MAX_UPLOAD_SIZE: usize = 5 * 1024 * 1024 * 1024;

/// Storage layout mirroring the Python `BASE_DIR` tree.
pub struct StoragePaths {
    pub base_dir: PathBuf,
    pub files_dir: PathBuf,
    pub normal_dir: PathBuf,
    pub encrypted_dir: PathBuf,
    pub thumbs_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub resumable_meta_dir: PathBuf,
    pub resumable_data_dir: PathBuf,
    pub permissions_file: PathBuf,
}

impl StoragePaths {
    pub fn new(base_dir: PathBuf) -> Self {
        let files_dir = base_dir.join("files");
        Self {
            files_dir: files_dir.clone(),
            normal_dir: base_dir.join("data").join("uploads").join("files").join("normal"),
            encrypted_dir: base_dir.join("data").join("uploads").join("files").join("encrypted"),
            thumbs_dir: base_dir.join("thumbs"),
            tmp_dir: base_dir.join("tmp"),
            resumable_meta_dir: base_dir.join("tmp").join("resumable").join("meta"),
            resumable_data_dir: base_dir.join("tmp").join("resumable").join("data"),
            permissions_file: base_dir.join("permissions.json"),
            base_dir,
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for d in [
            &self.files_dir,
            &self.normal_dir,
            &self.encrypted_dir,
            &self.thumbs_dir,
            &self.tmp_dir,
            &self.resumable_meta_dir,
            &self.resumable_data_dir,
        ] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// JSON error payload (matches FastAPI's `{"detail": ...}`).
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub detail: String,
}

pub fn api_error(status: axum::http::StatusCode, detail: impl Into<String>) -> (axum::http::StatusCode, axum::Json<ApiError>) {
    (status, axum::Json(ApiError { detail: detail.into() }))
}

/// Shared storage state.
pub struct Storage {
    pub paths: StoragePaths,
    /// filename → allowed_user_ids for encrypted files.
    permissions: Mutex<HashMap<String, Vec<i64>>>,
}

impl Storage {
    pub fn new(base_dir: PathBuf) -> Self {
        let paths = StoragePaths::new(base_dir);
        paths.ensure_dirs().ok();
        let perms = Self::load_permissions(&paths.permissions_file);
        Self {
            paths,
            permissions: Mutex::new(perms),
        }
    }

    fn load_permissions(file: &Path) -> HashMap<String, Vec<i64>> {
        match std::fs::read_to_string(file) {
            Ok(text) => serde_json::from_str::<HashMap<String, Vec<i64>>>(&text).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_permissions(&self) {
        let perms = self.permissions.lock().expect("perm lock");
        if let Ok(text) = serde_json::to_string_pretty(&*perms) {
            let _ = std::fs::write(&self.paths.permissions_file, text);
        }
    }

    pub fn store_file_permissions(&self, file_id: &str, allowed: Vec<i64>) {
        self.permissions.lock().expect("perm lock").insert(file_id.to_string(), allowed);
        self.save_permissions();
    }

    pub fn check_file_permissions(&self, file_id: &str, user_id: i64) -> bool {
        let perms = self.permissions.lock().expect("perm lock");
        perms.get(file_id).map(|v| v.contains(&user_id)).unwrap_or(false)
    }

    pub fn secure_filename(name: &str) -> String {
        Path::new(name)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string())
    }

    fn stored_name(&self, original_name: &str) -> String {
        let uid = Uuid::new_v4().simple().to_string();
        format!("{uid}_{}", Self::secure_filename(original_name))
    }

    /// Stream a byte buffer to a destination. Returns bytes written.
    pub fn write_secure(&self, dest: &Path, data: &[u8]) -> std::io::Result<usize> {
        std::fs::write(dest, data)?;
        let _ = set_secure_perms(dest);
        Ok(data.len())
    }

    pub fn resumable_meta_path(&self, upload_id: &str) -> PathBuf {
        self.paths.resumable_meta_dir.join(format!("{upload_id}.json"))
    }
    pub fn resumable_data_path(&self, upload_id: &str) -> PathBuf {
        self.paths.resumable_data_dir.join(format!("{upload_id}.bin"))
    }

    pub fn read_resumable_meta(&self, upload_id: &str) -> Result<ResumableMeta, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let path = self.resumable_meta_path(upload_id);
        if !path.exists() {
            return Err(api_error(axum::http::StatusCode::NOT_FOUND, "Upload session not found"));
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<ResumableMeta>(&text)
                .map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to read upload session")),
            Err(_) => Err(api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to read upload session")),
        }
    }

    pub fn write_resumable_meta(&self, upload_id: &str, data: &ResumableMeta) {
        let path = self.resumable_meta_path(upload_id);
        if let Ok(text) = serde_json::to_string(data) {
            let _ = std::fs::write(path, text);
        }
    }

    pub fn assert_resumable_access(&self, meta: &ResumableMeta, user_id: i64) -> Result<(), (axum::http::StatusCode, axum::Json<ApiError>)> {
        if user_id == 1 {
            return Ok(());
        }
        if meta.allowed_user_ids.contains(&user_id) {
            return Ok(());
        }
        Err(api_error(axum::http::StatusCode::FORBIDDEN, "Access denied to this upload"))
    }

    /// Basic upload: store an in-memory file into files_dir.
    pub fn upload_file_bytes(&self, original_name: &str, data: &[u8]) -> Result<UploadResult, (axum::http::StatusCode, axum::Json<ApiError>)> {
        if data.len() > MAX_UPLOAD_SIZE {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "File exceeds maximum allowed size"));
        }
        let original_name = Self::secure_filename(original_name);
        let stored_name = self.stored_name(&original_name);
        let dest = self.paths.files_dir.join(&stored_name);
        let size = self
            .write_secure(&dest, data)
            .map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to store file"))?;
        Ok(UploadResult {
            file_id: stored_name.clone(),
            filename: original_name,
            size,
            path: format!("/uploads/files/encrypted/{stored_name}"),
        })
    }

    /// Base64 upload variant.
    pub fn upload_base64(&self, filename: &str, data_b64: &str, allowed_user_ids: Vec<i64>) -> Result<UploadResult, (axum::http::StatusCode, axum::Json<ApiError>)> {
        if data_b64.is_empty() {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "data_b64 is required"));
        }
        let data = B64
            .decode(data_b64)
            .map_err(|_| api_error(axum::http::StatusCode::BAD_REQUEST, "Invalid base64"))?;
        let result = self.upload_file_bytes(filename, &data)?;
        self.store_file_permissions(&result.file_id, allowed_user_ids);
        Ok(result)
    }

    pub fn init_resumable(
        &self,
        filename: &str,
        total_size: usize,
        allowed_user_ids: Vec<i64>,
        chunk_size: Option<usize>,
    ) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let chunk_size = chunk_size.filter(|c| *c > 0).unwrap_or(262_144);
        if total_size == 0 {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "total_size must be > 0"));
        }
        if total_size > MAX_UPLOAD_SIZE {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "File exceeds maximum allowed size"));
        }
        if allowed_user_ids.is_empty() {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "allowed_user_ids is required"));
        }
        let upload_id = Uuid::new_v4().simple().to_string();
        let meta = ResumableMeta {
            upload_id: upload_id.clone(),
            filename: Self::secure_filename(filename),
            total_size,
            offset: 0,
            complete: false,
            chunk_size,
            allowed_user_ids,
            created_at: fc_shared::utils::now_secs(),
            updated_at: fc_shared::utils::now_secs(),
        };
        self.write_resumable_meta(&upload_id, &meta);
        let _ = std::fs::write(self.resumable_data_path(&upload_id), []);
        Ok(serde_json::json!({
            "upload_id": upload_id,
            "chunk_size": chunk_size,
            "offset": 0,
        }))
    }

    pub fn resumable_status(&self, upload_id: &str, user_id: i64) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        Ok(serde_json::json!({
            "upload_id": upload_id,
            "filename": meta.filename,
            "total_size": meta.total_size,
            "offset": meta.offset,
            "complete": meta.complete,
        }))
    }

    pub fn upload_resumable_chunk(
        &self,
        upload_id: &str,
        user_id: i64,
        offset: usize,
        chunk: &[u8],
    ) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let mut meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        if meta.complete {
            return Err(api_error(axum::http::StatusCode::CONFLICT, "Upload already completed"));
        }
        if chunk.is_empty() {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "empty chunk"));
        }
        if offset != meta.offset {
            return Err(api_error(
                axum::http::StatusCode::CONFLICT,
                format!("Offset mismatch. expected={} got={offset}", meta.offset),
            ));
        }
        let new_offset = meta.offset + chunk.len();
        if new_offset > meta.total_size {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Chunk exceeds total_size"));
        }
        let data_path = self.resumable_data_path(upload_id);
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).create(true).open(&data_path)
            .map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to write chunk"))?;
        f.write_all(chunk).map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to write chunk"))?;
        meta.offset = new_offset;
        meta.updated_at = fc_shared::utils::now_secs();
        self.write_resumable_meta(upload_id, &meta);
        Ok(serde_json::json!({ "offset_received": new_offset }))
    }

    pub fn complete_resumable(&self, upload_id: &str, user_id: i64) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let mut meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        if meta.offset != meta.total_size {
            return Err(api_error(
                axum::http::StatusCode::CONFLICT,
                format!("Upload incomplete. offset={} total={}", meta.offset, meta.total_size),
            ));
        }
        meta.complete = true;
        meta.updated_at = fc_shared::utils::now_secs();
        self.write_resumable_meta(upload_id, &meta);
        Ok(serde_json::json!({ "file_id": upload_id, "upload_id": upload_id }))
    }

    pub fn resumable_blob_path(&self, upload_id: &str, user_id: i64) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        if !meta.complete {
            return Err(api_error(axum::http::StatusCode::CONFLICT, "Upload not completed"));
        }
        let data_path = self.resumable_data_path(upload_id);
        if !data_path.exists() {
            return Err(api_error(axum::http::StatusCode::NOT_FOUND, "Upload payload not found"));
        }
        Ok(serde_json::json!({
            "upload_id": upload_id,
            "filename": meta.filename,
            "file_size": meta.total_size,
            "encrypted_file_path": data_path.to_string_lossy().to_string(),
        }))
    }

    pub fn resumable_data_b64(&self, upload_id: &str, user_id: i64) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        if !meta.complete {
            return Err(api_error(axum::http::StatusCode::CONFLICT, "Upload not completed"));
        }
        let data_path = self.resumable_data_path(upload_id);
        if !data_path.exists() {
            return Err(api_error(axum::http::StatusCode::NOT_FOUND, "Upload payload not found"));
        }
        let payload = std::fs::read(&data_path)
            .map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to read payload"))?;
        Ok(serde_json::json!({
            "upload_id": upload_id,
            "filename": meta.filename,
            "file_size": payload.len(),
            "encrypted_file_data_b64": B64.encode(payload),
        }))
    }

    pub fn delete_resumable(&self, upload_id: &str, user_id: i64) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        let _ = std::fs::remove_file(self.resumable_meta_path(upload_id));
        let _ = std::fs::remove_file(self.resumable_data_path(upload_id));
        Ok(serde_json::json!({ "status": "deleted", "upload_id": upload_id }))
    }

    /// Store a plain public-chat attachment into normal_dir with a fixed name.
    pub fn store_normal_file_from_path(
        &self,
        stored_name: &str,
        source_path: &Path,
    ) -> Result<NormalFileResult, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let safe_name = Self::secure_filename(stored_name);
        if stored_name != safe_name {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Invalid stored name"));
        }
        if !source_path.is_file() {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "source_path is not a file"));
        }
        let dest = self.paths.normal_dir.join(&safe_name);
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::copy(source_path, &dest)
            .map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to store file"))?;
        let _ = set_secure_perms(&dest);
        let size = std::fs::metadata(&dest).map(|m| m.len() as usize).unwrap_or(0);
        Ok(NormalFileResult {
            stored_name: safe_name.clone(),
            size,
            path: format!("/uploads/files/normal/{safe_name}"),
        })
    }

    /// Copy a completed resumable upload into normal storage (promote).
    pub fn promote_resumable_to_normal(
        &self,
        upload_id: &str,
        user_id: i64,
        stored_name: &str,
    ) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let meta = self.read_resumable_meta(upload_id)?;
        self.assert_resumable_access(&meta, user_id)?;
        if !meta.complete {
            return Err(api_error(axum::http::StatusCode::CONFLICT, "Upload not completed"));
        }
        let data_path = self.resumable_data_path(upload_id);
        if !data_path.is_file() {
            return Err(api_error(axum::http::StatusCode::NOT_FOUND, "Upload payload not found"));
        }
        let stored = self.store_normal_file_from_path(stored_name, &data_path)?;
        Ok(serde_json::json!({
            "upload_id": upload_id,
            "filename": meta.filename,
            "file_size": stored.size,
            "stored_name": stored.stored_name,
            "path": stored.path,
        }))
    }

    pub fn thumb_jpeg_path(&self, stored_name: &str) -> PathBuf {
        let stem = Path::new(stored_name).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        self.paths.thumbs_dir.join(format!("{stem}.jpg"))
    }
    pub fn thumb_meta_path(&self, stored_name: &str) -> PathBuf {
        let stem = Path::new(stored_name).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        self.paths.thumbs_dir.join(format!("{stem}.json"))
    }

    pub fn store_public_thumb(
        &self,
        stored_name: &str,
        jpeg: &[u8],
        width: u32,
        height: u32,
        file_size: usize,
    ) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let safe = Self::secure_filename(stored_name);
        if safe != stored_name {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Invalid stored name"));
        }
        if jpeg.is_empty() {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Empty thumbnail"));
        }
        let path = self.thumb_jpeg_path(&safe);
        std::fs::write(&path, jpeg).map_err(|_| api_error(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to store thumb"))?;
        let _ = set_secure_perms(&path);
        let meta = serde_json::json!({
            "stored_name": safe,
            "width": width,
            "height": height,
            "file_size": file_size,
            "thumb_path": format!("/uploads/files/thumbs/{}", path.file_name().unwrap_or_default().to_string_lossy()),
        });
        let mp = self.thumb_meta_path(&safe);
        let _ = std::fs::write(&mp, meta.to_string());
        Ok(meta)
    }

    pub fn store_public_image_dimensions(
        &self,
        stored_name: &str,
        width: u32,
        height: u32,
        file_size: usize,
    ) -> Result<serde_json::Value, (axum::http::StatusCode, axum::Json<ApiError>)> {
        let safe = Self::secure_filename(stored_name);
        if safe != stored_name {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Invalid stored name"));
        }
        if width == 0 || height == 0 {
            return Err(api_error(axum::http::StatusCode::BAD_REQUEST, "Invalid image dimensions"));
        }
        let meta = serde_json::json!({
            "stored_name": safe,
            "width": width,
            "height": height,
            "file_size": file_size,
            "thumb_path": "",
        });
        let mp = self.thumb_meta_path(&safe);
        let _ = std::fs::write(&mp, meta.to_string());
        Ok(meta)
    }

    /// Load thumbnail meta with fallback to reading the normal file.
    pub fn get_public_thumb_meta(&self, stored_name: &str) -> Option<serde_json::Value> {
        let safe = Self::secure_filename(stored_name);
        if safe != stored_name {
            return None;
        }
        let thumb_path = self.thumb_jpeg_path(&safe);
        let meta_path = self.thumb_meta_path(&safe);

        let mut width: u32 = 1;
        let mut height: u32 = 1;
        let mut file_size: usize = 0;
        let has_meta = meta_path.is_file();
        if has_meta {
            if let Ok(text) = std::fs::read_to_string(&meta_path) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    width = v.get("width").and_then(|x| x.as_u64()).unwrap_or(1) as u32;
                    height = v.get("height").and_then(|x| x.as_u64()).unwrap_or(1) as u32;
                    file_size = v.get("file_size").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                }
            }
        }

        // Fallback: read dimensions from the stored normal file.
        let normal_path = self.paths.normal_dir.join(&safe);
        if (dimensions::is_placeholder_dimensions(width, height) || file_size == 0) && normal_path.is_file() {
            if let Ok(size) = std::fs::metadata(&normal_path) {
                if file_size == 0 {
                    file_size = size.len() as usize;
                }
            }
            if dimensions::is_placeholder_dimensions(width, height) {
                if let Some((w, h)) = dimensions::read_image_dimensions(&normal_path) {
                    width = w;
                    height = h;
                }
            }
        }

        if !has_meta && dimensions::is_placeholder_dimensions(width, height) && !thumb_path.is_file() {
            return None;
        }

        let thumbnail_b64 = if thumb_path.is_file() {
            std::fs::read(&thumb_path)
                .map(|j| B64.encode(j))
                .unwrap_or_default()
        } else {
            String::new()
        };

        Some(serde_json::json!({
            "stored_name": safe,
            "width": width,
            "height": height,
            "file_size": file_size,
            "thumbnail_b64": thumbnail_b64,
            "thumb_path": if thumb_path.is_file() {
                format!("/uploads/files/thumbs/{}", thumb_path.file_name().unwrap_or_default().to_string_lossy())
            } else { String::new() },
        }))
    }

    pub fn get_normal_file_dimensions(&self, stored_name: &str) -> Option<serde_json::Value> {
        let path = self.get_normal_file_path(stored_name)?;
        let size = std::fs::metadata(&path).map(|m| m.len() as usize).unwrap_or(0);
        let safe = Self::secure_filename(stored_name);
        let (w, h) = dimensions::read_image_dimensions(&path).unwrap_or((1, 1));
        Some(serde_json::json!({
            "stored_name": safe,
            "width": w,
            "height": h,
            "file_size": size,
        }))
    }

    pub fn get_normal_file_path(&self, stored_name: &str) -> Option<PathBuf> {
        let safe = Self::secure_filename(stored_name);
        let path = self.paths.normal_dir.join(safe);
        path.is_file().then_some(path)
    }
}

/// Set non-executable owner rw perms (0o600) — best-effort on Windows/Linux.
#[allow(unused_variables)]
pub fn set_secure_perms(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadResult {
    pub file_id: String,
    pub filename: String,
    pub size: usize,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NormalFileResult {
    pub stored_name: String,
    pub size: usize,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ResumableMeta {
    pub upload_id: String,
    pub filename: String,
    pub total_size: usize,
    pub offset: usize,
    pub complete: bool,
    pub chunk_size: usize,
    pub allowed_user_ids: Vec<i64>,
    pub created_at: u64,
    pub updated_at: u64,
}