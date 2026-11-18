//! Content check engine: allowlist, normalization, profanity, politics, blocklist.
//! A faithful port of `engine.py` + `charset.py` to Rust.

use std::collections::HashSet;

use crate::blocklist::Blocklist;

// ---------------------------------------------------------------------------
// Chroma/setup: character allowlists + replacement maps
// ---------------------------------------------------------------------------

fn range_set(start: u32, end: u32) -> HashSet<u32> {
    (start..=end).collect()
}

/// Build the set of allowed scalar codepoints (mirrors `_build_allowed_codepoints`).
fn build_allowed_codepoints() -> HashSet<u32> {
    let mut a: HashSet<u32> = HashSet::new();
    a.extend(range_set('A' as u32, 'Z' as u32));
    a.extend(range_set('a' as u32, 'z' as u32));
    a.extend(range_set('0' as u32, '9' as u32));
    a.extend(range_set(0x0410, 0x044F)); // А-я
    a.insert(0x0401); // Ё
    a.insert(0x0451); // ё
    for ch in " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~«»№…–—±×÷€£¥©®™°§"
        .chars()
        .map(|c| c as u32)
    {
        a.insert(ch);
    }
    for ch in ['\t', '\n', '\r'] {
        a.insert(ch as u32);
    }
    a.extend(range_set(0xFF01, 0xFF5E));
    a.insert(0x3000);
    a.extend(range_set(0x1D400, 0x1D7FF));
    a.extend(range_set(0x2460, 0x24FF));
    a.extend(range_set(0x1F100, 0x1F1FF));
    a.extend(range_set(0x1F150, 0x1F19A));
    a.extend(range_set(0x2600, 0x27BF));
    a.extend(range_set(0x2300, 0x23FF));
    a.extend(range_set(0x2B00, 0x2BFF));
    a.extend(range_set(0x1F000, 0x1F02F));
    a.extend(range_set(0x1F0A0, 0x1F0FF));
    a.extend(range_set(0x1F300, 0x1F5FF));
    a.extend(range_set(0x1F600, 0x1F64F));
    a.extend(range_set(0x1F680, 0x1F6FF));
    a.extend(range_set(0x1F700, 0x1F77F));
    a.extend(range_set(0x1F780, 0x1F7FF));
    a.extend(range_set(0x1F800, 0x1F8FF));
    a.extend(range_set(0x1F900, 0x1F9FF));
    a.extend(range_set(0x1FA00, 0x1FAFF));
    a.extend(range_set(0x1FB00, 0x1FBFF));
    a.insert(0x200D);
    a.insert(0xFE0E);
    a.insert(0xFE0F);
    a.extend(range_set(0x1F3FB, 0x1F3FF));
    a.extend(range_set(0xE0020, 0xE007F));
    a.extend(range_set(0x0300, 0x036F));
    // Greek lookalikes
    for cp in [
        0x03B1, 0x0391, 0x03BF, 0x039F, 0x03C1, 0x03A1, 0x03C5, 0x03A5,
        0x03C7, 0x03A7, 0x03B5, 0x0395, 0x03B9, 0x0399, 0x03BD, 0x039D,
        0x03BC, 0x039C, 0x03C0, 0x03A0, 0x03C4, 0x03A4, 0x03B3, 0x0393,
        0x03C3, 0x03A3, 0x03C6, 0x03A6,
    ] {
        a.insert(cp);
    }
    for (cp, _) in &PHONETIC_TO_CYR {
        a.insert(*cp);
    }
    a
}

/// Phonetic/IPA lookalikes → Cyrillic.
const PHONETIC_TO_CYR: [(u32, char); 14] = [
    (0x1D00, 'а'), (0x1D04, 'с'), (0x1D07, 'е'), (0x1D0B, 'к'),
    (0x1D1B, 'т'), (0x1D20, 'в'), (0x1D22, 'з'), (0x1D26, 'г'),
    (0x1D27, 'л'), (0x1D28, 'п'), (0x1D29, 'р'), (0x028D, 'м'),
    (0x0299, 'в'), (0x0278, 'ф'),
];

/// Phonetic/IPA lookalikes → ASCII.
const PHONETIC_TO_ASCII: [(u32, char); 14] = [
    (0x1D00, 'a'), (0x1D04, 'c'), (0x1D07, 'e'), (0x1D0B, 'k'),
    (0x1D1B, 't'), (0x1D20, 'v'), (0x1D22, 'z'), (0x1D26, 'g'),
    (0x1D27, 'l'), (0x1D28, 'p'), (0x1D29, 'r'), (0x028D, 'm'),
    (0x0299, 'b'), (0x0278, 'f'),
];

fn add_latin_block(m: &mut std::collections::HashMap<u32, char>, start: u32, upper: bool) {
    let base = if upper { 'A' } else { 'a' } as u32;
    for i in 0..26u32 {
        m.insert(start + i, char::from_u32(base + i).unwrap());
    }
}

fn add_digit_block(m: &mut std::collections::HashMap<u32, char>, start: u32) {
    for i in 0..10u32 {
        m.insert(start + i, char::from_u32('0' as u32 + i).unwrap());
    }
}

/// Build the replacement-to-Cyrillic map (mirrors `_build_replacement_map`).
fn build_replacement_to_cyr() -> std::collections::HashMap<u32, char> {
    let mut m = std::collections::HashMap::new();
    add_latin_block(&mut m, 0x1D400, true);
    add_latin_block(&mut m, 0x1D41A, false);
    add_latin_block(&mut m, 0x1D434, true);
    // Italic small: h slots around 0x210E.
    for (i, ch) in "abcdefghijklmnopqrstuvwxyz".chars().enumerate() {
        let i = i as u32;
        if ch == 'h' {
            m.insert(0x210E, 'h');
        } else if i < 7 {
            m.insert(0x1D44E + i, ch);
        } else if i > 7 {
            m.insert(0x1D456 + (i - 8), ch);
        }
    }
    add_latin_block(&mut m, 0x1D468, true);
    add_latin_block(&mut m, 0x1D482, false);
    add_latin_block(&mut m, 0x1D49C, true);
    add_latin_block(&mut m, 0x1D4B6, false);
    add_latin_block(&mut m, 0x1D4D0, true);
    add_latin_block(&mut m, 0x1D4EA, false);
    add_latin_block(&mut m, 0x1D504, true);
    add_latin_block(&mut m, 0x1D51E, false);
    add_latin_block(&mut m, 0x1D538, true);
    add_latin_block(&mut m, 0x1D552, false);
    add_latin_block(&mut m, 0x1D56C, true);
    add_latin_block(&mut m, 0x1D586, false);
    add_latin_block(&mut m, 0x1D5A0, true);
    add_latin_block(&mut m, 0x1D5BA, false);
    add_latin_block(&mut m, 0x1D5D4, true);
    add_latin_block(&mut m, 0x1D5EE, false);
    add_latin_block(&mut m, 0x1D608, true);
    add_latin_block(&mut m, 0x1D622, false);
    add_latin_block(&mut m, 0x1D63C, true);
    add_latin_block(&mut m, 0x1D656, false);
    add_latin_block(&mut m, 0x1D670, true);
    add_latin_block(&mut m, 0x1D68A, false);
    for start in [0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6] {
        add_digit_block(&mut m, start);
    }
    // Fullwidth → ASCII
    for i in 0x21..0x7Fu32 {
        m.insert(0xFF00 + i - 0x20, char::from_u32(i).unwrap());
    }
    // Circled Latin
    for i in 0..26u32 {
        m.insert(0x24B6 + i, char::from_u32('A' as u32 + i).unwrap());
        m.insert(0x24D0 + i, char::from_u32('a' as u32 + i).unwrap());
    }
    // Negative squared capitals + small
    for i in 0..26u32 {
        m.insert(0x1F170 + i, char::from_u32('A' as u32 + i).unwrap());
        m.insert(0x1F150 + i, char::from_u32('a' as u32 + i).unwrap());
    }
    // Regional indicators → a-z
    for i in 0..26u32 {
        m.insert(0x1F1E6 + i, char::from_u32('a' as u32 + i).unwrap());
    }
    // Latin → Cyrillic + leet
    let latin_to_cyr: [(&str, char); 29] = [
        ("a", 'а'), ("b", 'б'), ("c", 'с'), ("d", 'д'), ("e", 'е'),
        ("f", 'ф'), ("g", 'г'), ("h", 'х'), ("i", 'и'), ("k", 'к'),
        ("l", 'л'), ("m", 'м'), ("n", 'н'), ("o", 'о'), ("p", 'п'),
        ("r", 'р'), ("s", 'с'), ("t", 'т'), ("u", 'у'), ("v", 'в'),
        ("w", 'в'), ("x", 'х'), ("y", 'у'), ("z", 'з'), ("0", 'о'),
        ("1", 'и'), ("3", 'е'), ("4", 'а'), ("@", 'а'),
    ];
    for (src, dst) in latin_to_cyr {
        let c = src.chars().next().unwrap();
        m.insert(c as u32, dst);
        if c.is_alphabetic() {
            let upper = c.to_uppercase().next().unwrap();
            m.insert(upper as u32, dst);
        }
    }
    // Negative squared → Cyrillic overrides the ASCII mapping above for those chars.
    let neg_fill: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    for i in 0..26u32 {
        let lat = neg_fill[i as usize];
        let cyr = latin_to_cyr.iter().find(|(s, _)| *s == &lat.to_string()).map(|x| x.1).unwrap_or(lat);
        m.insert(0x1F170 + i, cyr);
        m.insert(0x1F150 + i, cyr);
    }
    // Cyrillic identity, ё→е
    for cp in 0x0410..0x0450u32 {
        if let Some(ch) = char::from_u32(cp) {
            let lower = ch.to_lowercase().next().unwrap();
            let mapped = if lower == 'ё' { 'е' } else { lower };
            m.insert(cp, mapped);
        }
    }
    m.insert(0x0401, 'е');
    m.insert(0x0451, 'е');
    // Greek lookalikes → Cyrillic
    let greek = [
        (0x03B1, 'а'), (0x0391, 'а'), (0x03BF, 'о'), (0x039F, 'о'),
        (0x03C1, 'р'), (0x03A1, 'р'), (0x03C5, 'у'), (0x03A5, 'у'),
        (0x03C7, 'х'), (0x03A7, 'х'), (0x03B5, 'е'), (0x0395, 'е'),
        (0x03B9, 'и'), (0x0399, 'и'), (0x03BD, 'н'), (0x039D, 'н'),
        (0x03BC, 'м'), (0x039C, 'м'), (0x03C0, 'п'), (0x03A0, 'п'),
        (0x03C4, 'т'), (0x03A4, 'т'), (0x03B3, 'г'), (0x0393, 'г'),
        (0x03C3, 'с'), (0x03A3, 'с'), (0x03C6, 'ф'), (0x03A6, 'ф'),
    ];
    for (cp, ch) in greek {
        m.insert(cp, ch);
    }
    for (cp, ch) in PHONETIC_TO_CYR {
        m.insert(cp, ch);
    }
    m
}

/// Build the replacement-to-ASCII map (mirrors `_build_ascii_replacement_map`).
fn build_replacement_to_ascii() -> std::collections::HashMap<u32, char> {
    let mut m = std::collections::HashMap::new();
    add_latin_block(&mut m, 0x1D400, true);
    add_latin_block(&mut m, 0x1D41A, false);
    add_latin_block(&mut m, 0x1D434, true);
    for (i, ch) in "abcdefghijklmnopqrstuvwxyz".chars().enumerate() {
        let i = i as u32;
        if ch == 'h' {
            m.insert(0x210E, 'h');
        } else if i < 7 {
            m.insert(0x1D44E + i, ch);
        } else if i > 7 {
            m.insert(0x1D456 + (i - 8), ch);
        }
    }
    for start in [
        0x1D468, 0x1D49C, 0x1D4D0, 0x1D504, 0x1D538, 0x1D56C,
        0x1D5A0, 0x1D5D4, 0x1D608, 0x1D63C, 0x1D670,
    ] {
        add_latin_block(&mut m, start, true);
    }
    for start in [
        0x1D482, 0x1D4B6, 0x1D4EA, 0x1D51E, 0x1D552, 0x1D586,
        0x1D5BA, 0x1D5EE, 0x1D622, 0x1D656, 0x1D68A,
    ] {
        add_latin_block(&mut m, start, false);
    }
    for start in [0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6] {
        add_digit_block(&mut m, start);
    }
    for i in 0x21..0x7Fu32 {
        m.insert(0xFF00 + i - 0x20, char::from_u32(i).unwrap());
    }
    for i in 0..26u32 {
        m.insert(0x24B6 + i, char::from_u32('A' as u32 + i).unwrap());
        m.insert(0x24D0 + i, char::from_u32('a' as u32 + i).unwrap());
        m.insert(0x1F170 + i, char::from_u32('A' as u32 + i).unwrap());
        m.insert(0x1F150 + i, char::from_u32('a' as u32 + i).unwrap());
        m.insert(0x1F1E6 + i, char::from_u32('a' as u32 + i).unwrap());
    }
    for cp in 'A' as u32..='Z' as u32 {
        m.insert(cp, cp.to_lowercase_char());
    }
    for cp in 'a' as u32..='z' as u32 {
        m.insert(cp, char::from_u32(cp).unwrap());
    }
    for cp in '0' as u32..='9' as u32 {
        m.insert(cp, char::from_u32(cp).unwrap());
    }
    for (cp, ch) in PHONETIC_TO_ASCII {
        m.insert(cp, ch);
    }
    m
}

trait ToLowerChar {
    fn to_lowercase_char(self) -> char;
}
impl ToLowerChar for u32 {
    fn to_lowercase_char(self) -> char {
        let c = char::from_u32(self).unwrap();
        c.to_lowercase().next().unwrap()
    }
}

struct Charset {
    allowed: HashSet<u32>,
    replace_cyr: std::collections::HashMap<u32, char>,
    replace_ascii: std::collections::HashMap<u32, char>,
}

impl Charset {
    fn new() -> Self {
        Self {
            allowed: build_allowed_codepoints(),
            replace_cyr: build_replacement_to_cyr(),
            replace_ascii: build_replacement_to_ascii(),
        }
    }

    fn nfkc(text: &str) -> String {
        // Rust has no stdlib NFKC. Preserve most inputs; fullwidth handled by maps.
        // For the port we approximate NFKC with to_lowercase where needed by maps.
        text.to_string()
    }

    fn has_disallowed(&self, text: &str) -> bool {
        // Rejected emoji sequences and flag pair UA reject.
        let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
        let n = cps.len();
        let mut i = 0;
        while i < n {
            // UA flag pair → reject.
            if i + 1 < n && (0x1F1FA == cps[i] && 0x1F1E6 == cps[i + 1]) {
                return true;
            }
            // Rejected emoji sequences (rainbow flag).
            if i + 3 < n
                && cps[i] == 0x1F3F3
                && cps[i + 1] == 0xFE0F
                && cps[i + 2] == 0x200D
                && cps[i + 3] == 0x1F308
            {
                return true;
            }
            if i + 2 < n && cps[i] == 0x1F3F3 && cps[i + 1] == 0x200D && cps[i + 2] == 0x1F308 {
                return true;
            }
            if !self.allowed.contains(&cps[i]) {
                return true;
            }
            i += 1;
        }
        false
    }

    fn map_to_cyr(&self, text: &str) -> String {
        let norm = Self::nfkc(text);
        let mut out = String::new();
        for ch in norm.chars() {
            let cp = ch as u32;
            if let Some(&mapped) = self.replace_cyr.get(&cp) {
                if mapped.is_alphabetic() || mapped.is_numeric() {
                    out.push(mapped.to_lowercase().next().unwrap());
                }
            } else if ch.is_alphabetic() || ch.is_numeric() {
                out.push(ch.to_lowercase().next().unwrap());
            }
        }
        out
    }

    fn map_to_ascii(&self, text: &str) -> String {
        let norm = Self::nfkc(text);
        let mut out = String::new();
        for ch in norm.chars() {
            let cp = ch as u32;
            if let Some(&mapped) = self.replace_ascii.get(&cp) {
                if mapped.is_ascii() && (mapped.is_ascii_alphabetic() || mapped.is_ascii_digit()) {
                    out.push(mapped.to_lowercase().next().unwrap());
                }
            } else if ch.is_ascii() && (ch.is_ascii_alphabetic() || ch.is_ascii_digit()) {
                out.push(ch.to_lowercase().next().unwrap());
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Static term dictionaries
// ---------------------------------------------------------------------------

macro_rules! terms {
    ($($x:expr),* $(,)?) => {
        vec![$($x.to_string()),*].into_iter().collect::<HashSet<String>>()
    };
}

fn static_ru_terms() -> HashSet<String> {
    terms![
        "бляд","блять","бля","сука","суки","сучка","мразь","ебан","ебать",
        "ебёт","ебет","ебаная","уёбок","уебок","уебище","еблищ","еблахищ",
        "ебал","пенис","пизда","пиздец","хуй","хуи","хуя","хуе","хуё",
        "хуйня","хуйло","хер","гондон","долбоёб","долбоеб","дебил","идиот",
        "член","проститутка","проститутки","урод","хуесос","хуесосы",
        "хуесосов","хуесоса","пидор","пидоры","пидорас","пидорасы",
        "пидорасов","педераст","педик","ниггер","жид","чурк","черножоп",
        "узкоглаз","пиндос","хохол","москал","бульбаш","гомик","шлюх",
        "курва","манда","олигофрен","шизоид","аутист","убейсебя","убей",
        "убью","повесься","сдохни","издохни","сгинь","выпейяду","взорвать",
        "взорву","теракт","сиськ","минет","отсос",
    ]
}

fn adult_terms() -> HashSet<String> {
    terms![
        "порно","порн","порню","порнуха","эротика","эротический","секс",
        "сексуальный","инцест","порнография","порностудия","порновидео",
        "порносайт","сексчат","сексчатик","секслайв","сексвидео",
    ]
}

fn politics_terms() -> HashSet<String> {
    terms![
        "путин","зеленск","навальн","медведев","байден","трамп","спецоперац",
        "мобилизац","крымнаш","донбасс","днр","лнр","украин","русофоб",
        "либерал","лгбт","lgbt","евросоюз","госдум","единаяроссия","оппозиц",
        "выборыпрезидента","референдум","нато","фашизм","фашист","нацизм",
        "нацист","бандер","майдан","ватник","укроп",
    ]
}

fn whitelist() -> HashSet<String> {
    terms!["говно"]
}

const CUSTOM_EN_TERMS: [&str; 2] = ["porn", "xxx"];

// ---------------------------------------------------------------------------
// Helper character sets
// ---------------------------------------------------------------------------

const OBFUSCATION_FILLER: &[char] = &['ъ', '\u{00ad}', '\u{200b}', '\u{2060}'];

fn collapse_repeated(s: &str) -> String {
    let mut out = String::new();
    let mut prev: Option<char> = None;
    for ch in s.chars() {
        if Some(ch) != prev {
            out.push(ch);
            prev = Some(ch);
        }
    }
    out
}

fn strip_fillers(s: &str) -> String {
    s.chars().filter(|c| !OBFUSCATION_FILLER.contains(c)).collect()
}

fn cyrillic_match_variants(norm: &str) -> Vec<String> {
    if norm.is_empty() {
        return vec![];
    }
    let mut variants: HashSet<String> = HashSet::new();
    variants.insert(norm.to_string());
    let collapsed = collapse_repeated(norm);
    let stripped = strip_fillers(norm);
    variants.insert(collapsed.clone());
    variants.insert(stripped.clone());
    variants.insert(collapse_repeated(&stripped));
    variants.insert(strip_fillers(&collapsed));
    let mut expanded: HashSet<String> = HashSet::new();
    for form in variants {
        if form.is_empty() {
            continue;
        }
        expanded.insert(form.clone());
        if form.ends_with('ь') {
            expanded.insert(form[..form.len() - 1].to_string());
        }
    }
    expanded.into_iter().collect()
}

// Ambiguous letter swaps for alternates.
const AMBIGUOUS_SWAPS: [(&str, &str); 9] = [
    ("у", "и"), ("и", "у"), ("е", "з"), ("р", "п"), ("п", "р"),
    ("я", "а"), ("а", "я"), ("я", "й"), ("й", "я"),
];

fn cyrillic_alternates(normalized: &str) -> Vec<String> {
    let mut alts: HashSet<String> = HashSet::new();
    alts.insert(normalized.to_string());
    if normalized.contains("хуу") {
        alts.insert(normalized.replace("хуу", "хуй"));
    }
    if normalized.contains("хуи") {
        alts.insert(normalized.replace("хуи", "хуй"));
    }
    // х→у + й substitution.
    let chars: Vec<char> = normalized.chars().collect();
    for i in 1..chars.len() {
        if chars[i] == 'у' && chars[i - 1] == 'х' {
            let mut trial = chars.clone();
            trial[i] = 'й';
            alts.insert(trial.into_iter().collect());
        }
    }
    let seed: Vec<String> = alts.iter().cloned().collect();
    for form in &seed {
        let chars: Vec<char> = form.chars().collect();
        for (i, ch) in chars.iter().enumerate() {
            for (src, dst) in AMBIGUOUS_SWAPS {
                let src_c = src.chars().next().unwrap();
                if *ch == src_c {
                    let mut trial = chars.clone();
                    trial[i] = dst.chars().next().unwrap();
                    alts.insert(trial.into_iter().collect());
                }
            }
        }
    }
    // «хкя» / «хъуя» → «хуя»/«хуй» etc.
    let re = regex::Regex::new(r"^х[ъьку]{0,3}[аяй]$").unwrap();
    if re.is_match(normalized) {
        for w in ["хуя", "хуй", "хуи", "хуе"] {
            alts.insert(w.to_string());
        }
    }
    alts.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Matching helpers
// ---------------------------------------------------------------------------

fn substring_hit(text: &str, terms: &HashSet<String>) -> bool {
    for term in terms {
        if term.is_empty() {
            continue;
        }
        if text.contains(term) {
            return true;
        }
        if term.ends_with('ь') && text.contains(&term[..term.len() - 1]) {
            return true;
        }
    }
    false
}

fn subsequence_hit(text: &str, term: &str) -> bool {
    if term.len() < 3 {
        return false;
    }
    let max_span_ratio: f32 = if term.len() <= 3 {
        1.3
    } else if term.len() == 4 {
        1.4
    } else if term.len() <= 5 {
        1.5
    } else {
        1.8
    };

    let word_chars: Vec<char> = term.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut seq_start: usize = 0;
    let term_len = word_chars.len();

    while i < text_chars.len() && j < word_chars.len() {
        let ch = text_chars[i];
        if OBFUSCATION_FILLER.contains(&ch) {
            i += 1;
            continue;
        }
        if ch == word_chars[j] {
            if seq_start == 0 && text_chars[..i].iter().any(|c| !OBFUSCATION_FILLER.contains(c)) == false {
                seq_start = i;
            }
            if i == 0 || (seq_start == 0 && j == 0) {
                seq_start = i;
            }
            j += 1;
            if j == word_chars.len() {
                let span = (i + 1 - seq_start) as f32;
                if span <= (term_len as f32) * max_span_ratio {
                    return true;
                }
                let next_start = seq_start + 1;
                seq_start = 0;
                j = 0;
                i = next_start;
                continue;
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The chat-filter engine with full matching logic.
pub struct Engine {
    charset: Charset,
    static_terms: HashSet<String>,
    adult: HashSet<String>,
    politics: HashSet<String>,
    allow: HashSet<String>,
}

impl Engine {
    pub fn new() -> Self {
        let mut static_terms = static_ru_terms();
        static_terms.extend(adult_terms());
        Self {
            charset: Charset::new(),
            static_terms,
            adult: adult_terms(),
            politics: politics_terms(),
            allow: whitelist(),
        }
    }

    /// Return True if text may be published.
    pub fn is_allowed(&self, blocklist: &Blocklist, text: &str) -> bool {
        if text.is_empty() {
            return true;
        }
        if self.charset.has_disallowed(text) {
            return false;
        }
        if self.phrase_hit(text) {
            return false;
        }
        let cyr = self.charset.map_to_cyr(text);
        if !cyr.is_empty() && self.allow.contains(&cyr) {
            return true;
        }
        if !cyr.is_empty() && self.stretched_profanity_hit(&cyr) {
            return false;
        }
        if !cyr.is_empty() && self.token_obfuscation_hit(text, &cyr) {
            return false;
        }
        if !cyr.is_empty() && self.ru_terms_hit(blocklist, text, &cyr) {
            return false;
        }
        let ascii_form = self.charset.map_to_ascii(text);
        if !ascii_form.is_empty() && self.ascii_terms_hit(blocklist, text, &ascii_form) {
            return false;
        }
        // Custom blocklist on ascii glued form.
        let block: HashSet<String> = blocklist
            .get_blocklist()
            .into_iter()
            .map(|w| w.replace(" ", ""))
            .collect();
        if !ascii_form.is_empty() && substring_hit(&ascii_form, &block) {
            return false;
        }
        true
    }

    // -- phrase matching --
    fn phrase_hit(&self, text: &str) -> bool {
        let lowered = text.to_lowercase();
        let compact: String = lowered.chars().filter(|c| !matches!(c, ' ' | '-' | '_' | '.')).collect();
        let phrases: Vec<(&str, bool)> = vec![
            ("max is better", true),
            ("макс лучше", true),
            ("fromchat говно", true),
            ("фромчат говно", true),
            ("18+", false),
            ("xxx", false),
        ];
        for (p, word) in phrases {
            if word {
                if lowered.split_whitespace().collect::<Vec<_>>().join(" ").contains(p) {
                    return true;
                }
            } else if lowered.contains(p) {
                return true;
            }
        }
        // compact porn
        let lc = compact.chars().collect::<String>();
        for c in ["пооорно", "порно", "porn", "p0rn", "po0rn"] {
            if lc.contains(c) {
                return true;
            }
        }
        false
    }

    fn stretched_profanity_hit(&self, normalized: &str) -> bool {
        if normalized.is_empty() {
            return false;
        }
        let pats = [
            r"х[ъь]*у+[йи]?",
            r"х[ъь]*[уy]+[йиеё]+",
            r"х[ъьку]{0,3}[аяй]",
            r"еб[а]{2,}[тл][ь]?",
            r"еб[а]+[тл]{1,2}[ь]?",
            r"б[лl]+[яa@]+[тt]+[ь]?",
            r"п[иi1]+[зz3]+[дd]+",
            r"ч[лl][ъь]*[еe][ъь]*[нn][аa]?",
            r"п[еe][ъь]*[нn][иi][сs][аa]?",
        ];
        for p in pats {
            let re = regex::Regex::new(p).unwrap();
            if re.is_match(normalized) {
                return true;
            }
        }
        false
    }

    fn token_obfuscation_hit(&self, text: &str, _cyr: &str) -> bool {
        // Token-level hard-sign bypass: for each word, check stretched/obfuscated patterns.
        let pats = [
            r"^х[ъьку]{0,3}[аяй]$",
            r"^ч[лl][ъь]*[еe][ъь]*[нn][аa]?$",
            r"^п[еe][ъь]*[нn][иi][сs][аa]?$",
            r"^х[ъь]*у+[йи]?$",
            r"^х[ъь]*[уy]+[йиеё]+$",
            r"^еб[а]{2,}[тл][ь]?$",
            r"^еб[а]+[тл]{1,2}[ь]?$",
            r"^б[лl]+[яa@]+[тt]+[ь]?$",
            r"^п[иi1]+[зz3]+[дd]+$",
        ];
        for token in text.split_whitespace() {
            let cyr = self.charset.map_to_cyr(token);
            if cyr.is_empty() {
                continue;
            }
            for alt in cyrillic_alternates(&cyr) {
                for variant in cyrillic_match_variants(&alt) {
                    for p in &pats {
                        let re = regex::Regex::new(p).unwrap();
                        if re.is_match(&variant) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn ru_terms_hit(&self, blocklist: &Blocklist, text: &str, cyr: &str) -> bool {
        let mut terms = self.static_terms.clone();
        for w in blocklist.get_blocklist() {
            terms.insert(w.replace(" ", "").to_lowercase());
        }
        terms.extend(self.politics.clone());
        for w in &self.allow {
            terms.remove(w);
        }
        let long_terms: HashSet<String> = terms.iter().filter(|t| t.len() >= 5).cloned().collect();
        let short_token_terms: HashSet<String> = terms
            .iter()
            .filter(|t| t.len() == 4 && self.adult_contains(t))
            .cloned()
            .collect();

        // Exact token term match for short adult terms.
        if !short_token_terms.is_empty() && self.exact_token_term_hit(text, &short_token_terms) {
            return true;
        }

        let forms = self.term_match_forms(text, cyr);
        for form in &forms {
            if self.allow.contains(form) {
                continue;
            }
            let sub_terms: HashSet<String> = terms.difference(&short_token_terms).cloned().collect();
            if substring_hit(form, &sub_terms) {
                return true;
            }
            for term in &sub_terms {
                if subsequence_hit(form, term) {
                    return true;
                }
            }
        }

        // Spaced bypass: concat tokens.
        if text.split_whitespace().count() > 1 {
            let concat = self.concatenated_token_cyr(text);
            if !concat.is_empty() && !self.allow.contains(&concat) {
                let concat_forms = cyrillic_alternates(&concat);
                if substring_hit(&concat, &long_terms) {
                    return true;
                }
                for form in concat_forms {
                    if substring_hit(&form, &long_terms) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn adult_contains(&self, t: &str) -> bool {
        self.adult.contains(t)
    }

    fn exact_token_term_hit(&self, text: &str, terms: &HashSet<String>) -> bool {
        for token in text.split_whitespace() {
            let cyr = self.charset.map_to_cyr(token);
            if cyr.is_empty() {
                continue;
            }
            for form in cyrillic_alternates(&cyr) {
                for variant in cyrillic_match_variants(&form) {
                    if terms.contains(&variant) {
                        return true;
                    }
                    for term in terms {
                        if term.ends_with('ь') && variant == term[..term.len() - 1] {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn term_match_forms(&self, text: &str, cyr: &str) -> Vec<String> {
        if text.split_whitespace().count() > 1 {
            self.token_cyrillic_alternate_forms(text)
        } else {
            let alts = cyrillic_alternates(cyr);
            let mut out = Vec::new();
            for alt in alts {
                out.extend(cyrillic_match_variants(&alt));
            }
            out
        }
    }

    fn token_cyrillic_alternate_forms(&self, text: &str) -> Vec<String> {
        let mut forms: HashSet<String> = HashSet::new();
        for token in text.split_whitespace() {
            if token.is_empty() {
                continue;
            }
            let cyr = self.charset.map_to_cyr(token);
            if !cyr.is_empty() {
                for alt in cyrillic_alternates(&cyr) {
                    forms.extend(cyrillic_match_variants(&alt));
                }
            }
        }
        forms.into_iter().collect()
    }

    fn concatenated_token_cyr(&self, text: &str) -> String {
        let mut parts = String::new();
        for token in text.split_whitespace() {
            let cyr = self.charset.map_to_cyr(token);
            if !cyr.is_empty() {
                parts.push_str(&cyr);
            }
        }
        parts
    }

    fn ascii_terms_hit(&self, blocklist: &Blocklist, text: &str, ascii_form: &str) -> bool {
        let _ = ascii_form;
        // English profanity via better_profanity-like tokens; port uses a token set.
        let en_terms: HashSet<String> = {
            let mut s: HashSet<String> = CUSTOM_EN_TERMS.iter().map(|e| e.to_string()).collect();
            for w in blocklist.get_blocklist() {
                if w.is_ascii() {
                    s.insert(w.replace(" ", ""));
                }
            }
            s
        };
        let forms = if text.split_whitespace().count() > 1 {
            let mut f = HashSet::new();
            for token in text.split_whitespace() {
                let a = self.charset.map_to_ascii(token);
                if !a.is_empty() {
                    f.insert(a);
                }
            }
            f.into_iter().collect::<Vec<_>>()
        } else {
            vec![ascii_form.to_string()]
        };
        for form in forms {
            if substring_hit(&form, &en_terms) {
                return true;
            }
            for term in &en_terms {
                if subsequence_hit(&form, term) {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}