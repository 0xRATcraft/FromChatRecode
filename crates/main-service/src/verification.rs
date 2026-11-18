//! Username allocation, attempt tracking, and verification-status computation.
//! Mirrors `username.py`, `verification_service.py`, and the failed-login counter in `account.py`.

use rand::Rng;

use crate::models::User;
use crate::similarity::is_user_similar_to_verified;
pub use crate::similarity::VerifiedUserData;

/// Fixed owner (owner) username.
pub const OWNER_USERNAME: &str = "denis0001-dev";

/// The owner is always allocated user id 1.
pub const OWNER_USER_ID: i64 = 1;

/// Allocate a new user id, mirroring `allocate_user_id`:
/// id 1 is reserved for the owner; subsequent ids are random in [2, i32::MAX).
pub fn allocate_user_id() -> i64 {
    rand::thread_rng().gen_range(2..=(i32::MAX as i64))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    Verified,
    Warning,
    Blocked,
    None,
}

impl VerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Verified => "verified",
            VerificationStatus::Warning => "warning",
            VerificationStatus::Blocked => "blocked",
            VerificationStatus::None => "none",
        }
    }
}

/// Verified, non-deleted, non-suspended users for similarity computation.
pub fn get_verified_users_data(users: &[User]) -> Vec<VerifiedUserData> {
    users
        .iter()
        .filter(|u| u.verified && !u.deleted && !u.suspended)
        .map(|u| VerifiedUserData {
            username: u.username.clone(),
            display_name: u.display_name.clone(),
        })
        .collect()
}

/// Compute a user's verification status for the API payload.
pub fn compute_verification_status(user: &User, verified_users: &[VerifiedUserData]) -> VerificationStatus {
    if user.deleted {
        return VerificationStatus::None;
    }
    if user.suspended {
        return VerificationStatus::Blocked;
    }
    if user.verified {
        return VerificationStatus::Verified;
    }
    let (is_similar, _) = is_user_similar_to_verified(&user.username, &user.display_name, verified_users);
    if is_similar {
        VerificationStatus::Warning
    } else {
        VerificationStatus::None
    }
}

/// A simple in-memory attempt counter keyed by (identifier, purpose)
/// mirroring the failed-login windowing in `account.py`.
#[derive(Default)]
pub struct AttemptStore {
    inner: std::sync::Mutex<std::collections::HashMap<(String, String), (u32, std::time::Instant)>>,
}

impl AttemptStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment and return the attempts for (key, purpose) in a small window.
    /// Returns true when the configured max is exceeded within the window seconds.
    pub fn check_and_increment(&self, key: &str, purpose: &str, max: u32, window_secs: u64) -> bool {
        let mut g = self.inner.lock().expect("attempt store lock");
        let now = std::time::Instant::now();
        let entry = g
            .entry((key.to_string(), purpose.to_string()))
            .or_insert((0, now));
        if now.duration_since(entry.1).as_secs() > window_secs {
            entry.1 = now;
            entry.0 = 0;
        }
        entry.0 += 1;
        entry.0 > max
    }

    pub fn reset(&self, key: &str, purpose: &str) {
        let mut g = self.inner.lock().expect("attempt store lock");
        g.remove(&(key.to_string(), purpose.to_string()));
    }
}