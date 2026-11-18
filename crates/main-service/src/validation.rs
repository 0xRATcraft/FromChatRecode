//! Input validation helpers mirroring `validation.py`.

use regex::Regex;

/// Username: 3–20 chars, English letters/digits/dash/underscore only.
pub fn is_valid_username(username: &str) -> bool {
    if username.len() < 3 || username.len() > 20 {
        return false;
    }
    let re = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    re.is_match(username)
}

/// Display name: 1–64 chars and not blank.
pub fn is_valid_display_name(display_name: &str) -> bool {
    if display_name.len() < 1 || display_name.len() > 64 {
        return false;
    }
    !display_name.trim().is_empty()
}

/// Password: 5–50 chars and no whitespace / invisible separators.
pub fn is_valid_password(password: &str) -> bool {
    if password.len() < 5 || password.len() > 50 {
        return false;
    }
    let re = Regex::new(r"[\s\u{180e}\u{200b}-\u{200d}\u{2060}\u{feff}]").unwrap();
    !re.is_match(password)
}