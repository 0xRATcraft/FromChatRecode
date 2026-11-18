//! Small helpers mirroring `utils.py`: client IP extraction.

use axum::http::Request;

/// Extract client IP honoring x-real-ip, then x-forwarded-for, then socket peer.
pub fn get_client_ip<B>(request: &Request<B>) -> Option<String> {
    let headers = request.headers();
    if let Some(v) = headers.get("x-real-ip") {
        let c = v.to_str().unwrap_or("").trim().to_string();
        if !c.is_empty() {
            return Some(c);
        }
    }
    if let Some(v) = headers.get("x-forwarded-for") {
        if let Ok(s) = v.to_str() {
            let first = s.split(',').next().unwrap_or("").trim().to_string();
            if !first.is_empty() {
                return Some(first);
            }
        }
    }
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
}

/// Normalize an ISO timestamp for API responses.
pub fn iso(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.to_rfc3339()
}