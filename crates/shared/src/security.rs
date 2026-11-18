//! Lightweight application security helpers shared across services.
//! Real JWT/bcrypt lives in the main-service crate; this module provides
//! glue types and IP handling.

use std::net::IpAddr;

/// Extract the client IP, honoring the same proxy headers as the Python code:
/// `x-real-ip`, then the first entry of `x-forwarded-for`, then the socket peer.
pub fn client_ip(
    headers: &http_headers::Headers,
    peer: Option<IpAddr>,
) -> Option<String> {
    if let Some(v) = headers.get("x-real-ip") {
        let c = String::from_utf8_lossy(v).trim().to_string();
        if !c.is_empty() {
            return Some(c);
        }
    }
    if let Some(v) = headers.get("x-forwarded-for") {
        let s = String::from_utf8_lossy(v);
        let first = s.split(',').next().unwrap_or("").trim().to_string();
        if !first.is_empty() {
            return Some(first);
        }
    }
    peer.map(|p| p.to_string())
}

pub mod http_headers {
    use std::collections::HashMap;
    /// Minimal case-insensitive header map extracted from an axum request.
    #[derive(Debug, Default, Clone)]
    pub struct Headers {
        map: HashMap<String, Vec<u8>>,
    }
    impl Headers {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn from_iter<I: IntoIterator<Item = (String, Vec<u8>)>>(iter: I) -> Self {
            let mut map = HashMap::new();
            for (k, v) in iter {
                map.insert(k.to_ascii_lowercase(), v);
            }
            Self { map }
        }
        pub fn get(&self, key: &str) -> Option<&[u8]> {
            self.map.get(&key.to_ascii_lowercase()).map(|v| v.as_slice())
        }
    }
}