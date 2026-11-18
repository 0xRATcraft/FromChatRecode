//! Minimal image dimension readers (PNG / JPEG / GIF / WebP) used for
//! public-chat thumbnails. Mirrors the behaviour of the Python
//! `public_image_dimensions` helper without decoding full images.

/// Returns (width, height) or None when dimensions are unknown / placeholder.
pub fn read_image_dimensions(path: &std::path::Path) -> Option<(u32, u32)> {
    let data = std::fs::read(path).ok()?;
    read_image_dimensions_from_bytes(&data)
}

/// `[1,1]` is treated as "placeholder" (unknown) throughout the project.
pub fn is_placeholder_dimensions(width: u32, height: u32) -> bool {
    width <= 1 && height <= 1
}

/// Guess dimensions from the leading bytes of a common image format.
pub fn read_image_dimensions_from_bytes(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() >= 8 && data[..8] == *b"\x89PNG\r\n\x1a\n" {
        return png_dimensions(data);
    }
    if data.len() >= 3 && data[..3] == *b"GIF" {
        return gif_dimensions(data);
    }
    if data.len() >= 2 && data[..2] == *b"\xff\xd8" {
        return jpeg_dimensions(data);
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return webp_dimensions(data);
    }
    None
}

fn png_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    // IHDR chunk starts at byte 16: width (4) + height (4) big-endian.
    if data.len() < 24 {
        return None;
    }
    let w = u32::from_be_bytes(data[16..20].try_into().ok()?);
    let h = u32::from_be_bytes(data[20..24].try_into().ok()?);
    Some((w, h))
}

fn gif_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 10 {
        return None;
    }
    let w = u16::from_le_bytes([data[6], data[7]]) as u32;
    let h = u16::from_le_bytes([data[8], data[9]]) as u32;
    Some((w, h))
}

fn jpeg_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    // Walk SOF0..SOF15 markers.
    let mut i = 2usize;
    while i + 9 < data.len() {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        if marker == 0xD8 || marker == 0xD9 {
            i += 2;
            continue;
        }
        if marker == 0x01 {
            // standalone marker
            i += 2;
            continue;
        }
        if (0xD0..=0xD7).contains(&marker) {
            // restart markers have no length
            i += 2;
            continue;
        }
        if i + 4 > data.len() {
            return None;
        }
        let seg_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        // SOF markers (baseline / progressive / lossless / differential).
        if (0xC0..=0xCF).contains(&marker)
            && !(0xC4 == marker || 0xC8 == marker || 0xCC == marker)
        {
            if i + 9 > data.len() {
                return None;
            }
            let h = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
            let w = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
            return Some((w, h));
        }
        i += 2 + seg_len;
    }
    None
}

fn webp_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    // VP8X / VP8L / VP8 chunk locate.
    let mut i = 12usize; // after "RIFF"...."WEBP"
    while i + 8 <= data.len()
    {
        let chunk = &data[i..i + 4];
        let size = u32::from_le_bytes(data[i + 4..i + 8].try_into().ok()?) as usize;
        match chunk {
            b"VP8X" => {
                if i + 14 > data.len() {
                    return None;
                }
                let w = 1 + u24_le(&data[i + 12..i + 15]);
                let h = 1 + u24_le(&data[i + 15..i + 18]);
                return Some((w, h));
            }
            b"VP8 " => {
                if i + 14 > data.len() {
                    return None;
                }
                let w = u16::from_le_bytes([data[i + 12], data[i + 13]]) & 0x3FFF;
                let h = u16::from_le_bytes([data[i + 14], data[i + 15]]) & 0x3FFF;
                return Some((w as u32, h as u32));
            }
            b"VP8L" => {
                if i + 13 > data.len() {
                    return None;
                }
                let b = data[i + 9];
                let w = (1 + u16_le(&[data[i+9] & 0x3F, data[i+10] >> 2])) as u32;
                let h = (1 + u16_le(&[(data[i+10] & 0x03) << 6, data[i+11] & 0x3F])) as u32;
                let _ = b;
                return Some((w, h));
            }
            _ => {}
        }
        i += 8 + size + (size % 2);
    }
    None
}

fn u24_le(b: &[u8]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn u16_le(b: &[u8]) -> u16 {
    (b[0] as u16) | ((b[1] as u16) << 8)
}