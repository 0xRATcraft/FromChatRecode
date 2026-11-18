//! Similarity detection for usernames and display names, mirroring `similarity.py`:
//! Levenshtein distance <= 2 or visual (homoglyph) equality.

/// Levenshtein distance between two strings (Py implementation port).
pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    if s1.len() < s2.len() {
        return levenshtein_distance(s2, s1);
    }
    if s2.is_empty() {
        return s1.len();
    }
    let s1: Vec<char> = s1.chars().collect();
    let s2: Vec<char> = s2.chars().collect();
    let mut previous_row: Vec<usize> = (0..=s2.len()).collect();
    for (i, c1) in s1.iter().enumerate() {
        let mut current_row = vec![i + 1];
        for (j, c2) in s2.iter().enumerate() {
            let insertions = previous_row[j + 1] + 1;
            let deletions = current_row[j] + 1;
            let substitutions = previous_row[j] + usize::from(c1 != c2);
            current_row.push(insertions.min(deletions).min(substitutions));
        }
        previous_row = current_row;
    }
    previous_row[s2.len()]
}

/// Homoglyph neighbours (as in `similarity.py`).
fn homoglyph_neighbours(ch: char) -> &'static [char] {
    match ch {
        '0' => &['O', 'o', 'Q'],
        'O' => &['0', 'o', 'Q'],
        'o' => &['0', 'O', 'Q'],
        '1' => &['l', 'I', '|'],
        'l' => &['1', 'I', '|'],
        'I' => &['1', 'l', '|'],
        '5' => &['S', 's'],
        'S' => &['5', 's'],
        's' => &['5', 'S'],
        '6' => &['G', 'g'],
        'G' => &['6', 'g'],
        'g' => &['6', 'G'],
        '8' => &['B', 'b'],
        'B' => &['8', 'b'],
        'b' => &['8', 'B'],
        '9' => &['g', 'q'],
        'q' => &['9', 'g'],
        '2' => &['Z', 'z'],
        'Z' => &['2', 'z'],
        'z' => &['2', 'Z'],
        '3' => &['E'],
        'E' => &['3'],
        '4' => &['A'],
        'A' => &['4'],
        '7' => &['T', 't'],
        'T' => &['7', 't'],
        't' => &['7', 'T'],
        _ => &[],
    }
}

fn are_homoglyphs_keyed(c1: char, c2: char) -> bool {
    if c1 == c2 {
        return true;
    }
    let n1 = homoglyph_neighbours(c1);
    if n1.contains(&c2) {
        return true;
    }
    let n2 = homoglyph_neighbours(c2);
    if n2.contains(&c1) {
        return true;
    }
    false
}

/// Visual similarity: equal length and every char pair equal or homoglyph.
pub fn check_visual_similarity(s1: &str, s2: &str) -> bool {
    if s1.chars().count() != s2.chars().count() {
        return false;
    }
    for (c1, c2) in s1.chars().zip(s2.chars()) {
        if !are_homoglyphs_keyed(c1, c2) {
            return false;
        }
    }
    true
}

/// Usernames similar if equal-length visual match (edit distance handled below).
fn similar_by_visual(a: &str, b: &str) -> bool {
    check_visual_similarity(a, b)
}

fn check_username_similarity(u1: &str, u2: &str) -> bool {
    if u1 == u2 {
        return false;
    }
    if levenshtein_distance(&u1.to_lowercase(), &u2.to_lowercase()) <= 2 {
        return true;
    }
    similar_by_visual(u1, u2)
}

fn check_display_name_similarity(d1: &str, d2: &str) -> bool {
    if d1 == d2 {
        return false;
    }
    if levenshtein_distance(&d1.to_lowercase(), &d2.to_lowercase()) <= 2 {
        return true;
    }
    similar_by_visual(d1, d2)
}

/// A verified user's minimal data.
pub struct VerifiedUserData {
    pub username: String,
    pub display_name: String,
}

/// Return (is_similar, similar_to_username).
pub fn is_user_similar_to_verified(
    user_username: &str,
    user_display_name: &str,
    verified_users: &[VerifiedUserData],
) -> (bool, String) {
    for v in verified_users {
        if check_username_similarity(user_username, &v.username) {
            return (true, v.username.clone());
        }
        if check_display_name_similarity(user_display_name, &v.display_name) {
            return (true, v.username.clone());
        }
    }
    (false, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lev_simple() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("", "xyz"), 3);
    }

    #[test]
    fn visual_homoglyphs() {
        assert!(check_visual_similarity("denis", "denis"));
        assert!(check_visual_similarity("l0gin", "l0gin"));
        assert!(check_visual_similarity("oOne", "O0ne")); // o/O/0, n, e homoglyph-tolerant
        assert!(!check_visual_similarity("aaaa", "aabz"));
    }
}