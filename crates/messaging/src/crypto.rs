//! Envelope encryption pipeline for the messaging service.
//!
//! Mirrors the Python `src/messaging/encryption.py` and `processor.py`:
//! transport decryption (X25519 + XSalsa20-Poly1305 NaCl box),
//! MEK generation/encryption via AES-256-GCM and HKDF-SHA256 wrap-key
//! derivation for sender/recipient/compliance.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Nonce size used by NaCl `crypto_box` transport encryption (XSalsa20-Poly1305).
pub const TRANSPORT_NONCE_SIZE: usize = 24;
/// AES-GCM nonce size for content encryption.
pub const MEK_NONCE_SIZE: usize = 12;
/// Message Encryption Key size in bytes.
pub const MEK_SIZE: usize = 32;
/// AES-GCM tag size appended to on-disk file ciphertext.
pub const GCM_TAG_SIZE: usize = 16;

/// Streaming AES-256-GCM transport format magic bytes.
pub const FCAE_MAGIC: [u8; 4] = *b"FCAE";
pub const FCAE_VERSION: u8 = 1;
pub const FCAE_FRAME_LENGTH_BYTES: usize = 4;
pub const TRANSPORT_FILE_KEY_CONTEXT: &str = "fromchat_transport_file_v1";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("transport decrypt failed: {0}")]
    Transport(String),
    #[error("base64 decode failed: {0}")]
    B64(String),
    #[error("invalid key: {0}")]
    Key(String),
    #[error("AES-GCM operation failed")]
    Aead,
    #[error("unsupported format: {0}")]
    Format(String),
}

/// Copy a byte slice into a fixed 32-byte array or fail.
fn to_array32(raw: &[u8]) -> Result<[u8; 32], CryptoError> {
    if raw.len() != 32 {
        return Err(CryptoError::Key("expected 32 bytes".into()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(raw);
    Ok(buf)
}

/// Generate a random Message Encryption Key (32 bytes).
pub fn generate_mek() -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; MEK_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random nonce.
pub fn generate_nonce(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut n = vec![0u8; size];
    OsRng.fill_bytes(&mut n);
    n
}

/// Derive a key from a shared secret via HKDF-SHA256 with a zero salt,
/// matching the Python `derive_key_from_shared_secret`.
pub fn derive_key_from_shared_secret(shared: &[u8], context: &str, key_size: usize) -> Vec<u8> {
    let salt = [0u8; 16];
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = vec![0u8; key_size];
    hk.expand(context.as_bytes(), &mut okm)
        .expect("HKDF expand into fixed buffer");
    okm
}

/// Wrap a MEK using a KEK with AES-256-GCM; returns base64(nonce || ciphertext).
pub fn wrap_mek(mek: &[u8], wrap_key: &[u8]) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(wrap_key).map_err(|_| CryptoError::Key("wrap key".into()))?;
    let nonce = generate_nonce(MEK_NONCE_SIZE);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), mek)
        .map_err(|_| CryptoError::Aead)?;
    let mut wrapped = Vec::with_capacity(nonce.len() + ciphertext.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ciphertext);
    Ok(B64.encode(wrapped))
}

/// Unwrap a MEK from base64(nonce || ciphertext).
pub fn unwrap_mek(wrapped_b64: &str, wrap_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let wrapped = B64
        .decode(wrapped_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    if wrapped.len() < MEK_NONCE_SIZE {
        return Err(CryptoError::Key("wrapped too short".into()));
    }
    let (nonce, ciphertext) = wrapped.split_at(MEK_NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(wrap_key).map_err(|_| CryptoError::Key("wrap key".into()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Aead)
}

/// AES-256-GCM encrypt a message; returns (nonce_b64, ciphertext_b64).
pub fn encrypt_message(plaintext: &[u8], mek: &[u8]) -> Result<(String, String), CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(mek).map_err(|_| CryptoError::Key("mek".into()))?;
    let nonce = generate_nonce(MEK_NONCE_SIZE);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Aead)?;
    Ok((B64.encode(&nonce), B64.encode(&ciphertext)))
}

/// X25519 shared secret between a static secret and a peer raw public key.
fn x25519_shared(our: &StaticSecret, peer_raw: &[u8]) -> Result<[u8; 32], CryptoError> {
    let peer = PublicKey::from(to_array32(peer_raw)?);
    Ok(our.diffie_hellman(&peer).to_bytes())
}

/// In-memory ephemeral transport key state (never persisted).
pub struct EphemeralKey {
    private_bytes: Vec<u8>,
    public_key_b64: String,
    key_id_ms: u128,
    created_at_secs: u64,
}

impl EphemeralKey {
    pub fn private_bytes(&self) -> &[u8] {
        &self.private_bytes
    }
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }
    pub fn key_id_ms(&self) -> u128 {
        self.key_id_ms
    }
    pub fn created_at_secs(&self) -> u64 {
        self.created_at_secs
    }
}

/// Generate a fresh ephemeral X25519 keypair.
pub fn generate_ephemeral_keypair() -> EphemeralKey {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);
    EphemeralKey {
        private_bytes: secret.to_bytes().to_vec(),
        public_key_b64: B64.encode(public.as_bytes()),
        key_id_ms: fc_shared::utils::now_millis(),
        created_at_secs: fc_shared::utils::now_secs(),
    }
}

fn static_secret_from(raw: &[u8]) -> Result<StaticSecret, CryptoError> {
    Ok(StaticSecret::from(to_array32(raw)?))
}

/// NaCl `crypto_box_open_easy` (X25519 + XSalsa20-Poly1305) transport decryption.
pub fn decrypt_transport_message(
    client_public_key_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
    ephemeral_private_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let client = B64
        .decode(client_public_key_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    let nonce = B64
        .decode(nonce_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    salsa_box_open(&client, &nonce, &ciphertext, ephemeral_private_bytes)
}

/// Open a NaCl `crypto_box` ciphertext using the server ephemeral secret and
/// the client public key (XSalsa20-Poly1305, matching tweetnacl.box).
fn salsa_box_open(
    client_public: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ephemeral_private_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let peer = crypto_box::PublicKey::from(to_array32(client_public)?);
    let secret = crypto_box::SecretKey::from(to_array32(ephemeral_private_bytes)?);
    let salsa = crypto_box::SalsaBox::new(&peer, &secret);
    let nonce = crypto_box::Nonce::from_slice(nonce);
    salsa
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Transport("decryption failed".into()))
}

/// Derive the server-side AES key for the streaming FCAE transport format.
/// Uses the NaCl `crypto_box_beforenm` shared secret (raw X25519) then HKDF.
fn derive_transport_file_aes_key(
    client_public_b64: &str,
    ephemeral_private_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let client = B64
        .decode(client_public_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    let priv_key = static_secret_from(ephemeral_private_bytes)?;
    let shared = x25519_shared(&priv_key, &client)?;
    Ok(derive_key_from_shared_secret(&shared, TRANSPORT_FILE_KEY_CONTEXT, MEK_SIZE))
}

/// Read one FCAE frame from a byte slice cursor.
fn read_fcae_frame(data: &[u8], pos: &mut usize) -> Result<Option<(Vec<u8>, Vec<u8>)>, CryptoError> {
    if *pos >= data.len() {
        return Ok(None);
    }
    if data.len() - *pos < FCAE_FRAME_LENGTH_BYTES {
        return Err(CryptoError::Format("truncated FCAE frame length".into()));
    }
    let frame_len = u32::from_be_bytes(
        data[*pos..*pos + FCAE_FRAME_LENGTH_BYTES].try_into().unwrap(),
    ) as usize;
    *pos += FCAE_FRAME_LENGTH_BYTES;
    if frame_len <= MEK_NONCE_SIZE {
        return Err(CryptoError::Format("invalid FCAE frame length".into()));
    }
    if data.len() - *pos < frame_len {
        return Err(CryptoError::Format("truncated FCAE frame".into()));
    }
    let frame = &data[*pos..*pos + frame_len];
    *pos += frame_len;
    let (iv, ciphertext) = frame.split_at(MEK_NONCE_SIZE);
    Ok(Some((iv.to_vec(), ciphertext.to_vec())))
}

/// Decrypt a streaming FCAE transport blob (chunked AES-256-GCM frames).
pub fn decrypt_fcae_transport_stream(
    client_public_key_b64: &str,
    blob: &[u8],
    ephemeral_private_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !blob.starts_with(&FCAE_MAGIC) {
        return Err(CryptoError::Format("not an FCAE blob".into()));
    }
    if blob.len() < FCAE_MAGIC.len() + 1 {
        return Err(CryptoError::Format("FCAE blob too short".into()));
    }
    if blob[4] != FCAE_VERSION {
        return Err(CryptoError::Format("unsupported FCAE version".into()));
    }
    let aes_key = derive_transport_file_aes_key(client_public_key_b64, ephemeral_private_bytes)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::Key("aes key".into()))?;
    let mut out = Vec::new();
    let mut pos = FCAE_MAGIC.len() + 1;
    while let Some((iv, ciphertext)) = read_fcae_frame(blob, &mut pos)? {
        let plain = cipher
            .decrypt(Nonce::from_slice(&iv), ciphertext.as_slice())
            .map_err(|_| CryptoError::Aead)?;
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

/// Decrypt a transport-encrypted binary blob (`nonce || ciphertext` or FCAE).
pub fn decrypt_transport_blob(
    client_public_key_b64: &str,
    encrypted_blob: &[u8],
    ephemeral_private_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if encrypted_blob.starts_with(&FCAE_MAGIC) {
        return decrypt_fcae_transport_stream(
            client_public_key_b64,
            encrypted_blob,
            ephemeral_private_bytes,
        );
    }
    if encrypted_blob.len() < TRANSPORT_NONCE_SIZE + 16 {
        return Err(CryptoError::Transport("blob too short".into()));
    }
    let (nonce, ciphertext) = encrypted_blob.split_at(TRANSPORT_NONCE_SIZE);
    let client = B64
        .decode(client_public_key_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    salsa_box_open(&client, nonce, ciphertext, ephemeral_private_bytes)
}

fn wrap_mek_for(public_key_b64: &str, mek: &[u8], context: &str) -> Result<String, CryptoError> {
    let key_bytes = B64
        .decode(public_key_b64)
        .map_err(|e| CryptoError::B64(e.to_string()))?;
    let wrap_key = derive_key_from_shared_secret(&key_bytes, context, MEK_SIZE);
    wrap_mek(mek, &wrap_key)
}

/// Process an encrypted message through the envelope encryption pipeline.
/// Mirrors Python `process_encrypted_message`. Returns a JSON-serialisable value.
pub fn process_encrypted_message(
    client_public_key_b64: &str,
    transport_nonce_b64: &str,
    transport_ciphertext_b64: &str,
    compliance_public_key_b64: &str,
    sender_public_key_b64: &str,
    recipient_public_key_b64: &str,
    ephemeral_private_bytes: &[u8],
    store_compliance: bool,
) -> Result<serde_json::Value, CryptoError> {
    let plaintext = decrypt_transport_message(
        client_public_key_b64,
        transport_nonce_b64,
        transport_ciphertext_b64,
        ephemeral_private_bytes,
    )?;

    let mek = generate_mek();
    let (content_nonce, ciphertext) = encrypt_message(&plaintext, &mek)?;

    let sender_wrapped = wrap_mek_for(sender_public_key_b64, &mek, "sender_wrap_key")?;
    let recipient_wrapped = wrap_mek_for(recipient_public_key_b64, &mek, "recipient_wrap_key")?;

    let compliance_wrapped = if store_compliance {
        if compliance_public_key_b64.trim().is_empty() {
            return Err(CryptoError::Key("compliance public key required".into()));
        }
        Some(wrap_mek_for(compliance_public_key_b64.trim(), &mek, "compliance_wrap_key")?)
    } else {
        None
    };

    Ok(serde_json::json!({
        "nonce": content_nonce,
        "ciphertext": ciphertext,
        "compliance_wrapped_mek": compliance_wrapped,
        "sender_wrapped_mek": sender_wrapped,
        "recipient_wrapped_mek": recipient_wrapped,
    }))
}