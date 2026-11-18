//! Middleware: CORS and a simple in-memory per-IP rate limiter
//! mirroring the Python `rate_limit.py` behaviour.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

/// Per-IP token-bucket-ish limiter. On exhaust 429 is returned.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    max: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max,
            window,
        }
    }

    /// Returns true if the request should be allowed (under the limit).
    pub fn allow(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else { return true };
        let now = Instant::now();
        let mut g = self.inner.lock().expect("rate limiter lock");
        let entries = g.entry(ip).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        if entries.len() < self.max {
            entries.push(now);
            true
        } else {
            false
        }
    }
}

/// Axum middleware layer applying a shared rate limiter, defaulting the IP via x-forwarded-for / x-real-ip.
pub async fn rate_limit_mw(
    state: axum::extract::State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_ip(&req);
    if state.allow(ip) {
        next.run(req).await
    } else {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "error": "rate_limited", "detail": "Too many requests" }).to_string(),
            ))
            .expect("build 429 response")
    }
}

pub(crate) fn extract_ip<B>(request: &Request<B>) -> Option<IpAddr> {
    let headers = request.headers();
    for h in ["x-real-ip", "x-forwarded-for"] {
        if let Some(v) = headers.get(h) {
            let s = v.to_str().unwrap_or("");
            let first = s.split(',').next().unwrap_or("").trim();
            if let Ok(ip) = first.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}