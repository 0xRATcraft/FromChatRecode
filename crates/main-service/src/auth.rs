//! JWT + bcrypt authentication helpers.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Hours after which a token hard-expires (safety net).
const MAX_TOKEN_LIFETIME_HOURS: i64 = 365 * 24;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub user_id: i64,
    pub username: String,
    pub session_id: String,
    pub exp: usize,
}

/// Create a JWT with the configured secret (HS256), mirroring `create_token`.
pub fn create_token(secret: &str, user_id: i64, username: &str, session_id: &str) -> String {
    let exp = chrono::Utc::now().timestamp() + MAX_TOKEN_LIFETIME_HOURS * 3600;
    let claims = Claims {
        user_id,
        username: username.to_string(),
        session_id: session_id.to_string(),
        exp: exp as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("encode JWT")
}

/// Verify a JWT and return its claims, or None on any error.
pub fn verify_token(secret: &str, token: &str) -> Option<Claims> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.leeway = 0;
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
        .ok()
        .map(|d| d.claims)
}

/// bcrypt password hashing.
pub fn get_password_hash(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("bcrypt hash")
}

/// Verify a password against a stored bcrypt hash.
pub fn verify_password(password: &str, hashed: &str) -> bool {
    bcrypt::verify(password, hashed).unwrap_or(false)
}