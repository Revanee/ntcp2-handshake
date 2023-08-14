use chacha20poly1305::{
    aead::{Aead, AeadInPlace, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

/// 32 byte cipher key, as generated from KDF
pub type K = [u8; 32];

// Counter-based nonce, 12 bytes.
// Starts at 0 and incremented for each message.
// First four bytes are always zero.
// Last eight bytes are the counter, little-endian encoded.
// Maximum value is 2**64 - 2.
// Connection must be dropped and restarted after
// it reaches that value.
// The value 2**64 - 1 must never be sent.
pub type Nonce = [u8; 12];

/// Associated data
pub enum AD {
    /// In handshake phase:
    /// Associated data, 32 bytes.
    /// The SHA256 hash of all preceding data.
    Handshake([u8; 32]),
    /// In data phase:
    /// Zero bytes
    Data,
}

impl From<[u8; 32]> for AD {
    fn from(hash: [u8; 32]) -> Self {
        AD::Handshake(hash)
    }
}

const EMPTY_SLICE: [u8; 0] = [];

impl AsRef<[u8]> for AD {
    fn as_ref(&self) -> &[u8] {
        match self {
            AD::Handshake(h) => h,
            AD::Data => &EMPTY_SLICE,
        }
    }
}

/// Plaintext data, 0 or more bytes
type Data = [u8];

/// Length of (encrypted data + MAC) to follow, 16 - 65535
/// Obfuscation using SipHash (see below)
/// Not used in message 1 or 2, or message 3 part 1, where the length is fixed
/// Not used in message 3 part 1, as the length is specified in message 1
type ObfsLen = u16;

/// encrypted data :: Same size as plaintext data, 0 - 65519 bytes
type EncryptedData = [u8];

/// MAC :: Poly1305 message authentication code, 16 bytes
type MAC = [u8; 16];

/// ChaCha20/Poly1305 encryption
///
/// # Arguments
///
/// * `k` - 32 byte cipher key, as generated from KDF
/// * `nonce` - Counter-based nonce, 12 bytes.
/// Starts at 0 and incremented for each message.
/// First four bytes are always zero.
/// Last eight bytes are the counter, little-endian encoded.
/// Maximum value is `2**64 - 2`.
/// Connection must be dropped and restarted after
/// it reaches that value.
/// The value `2**64 - 1` must never be sent.
/// * `ad` - In handshake phase:
/// Associated data, 32 bytes.
/// The SHA256 hash of all preceding data.
/// In data phase:
/// Zero bytes
/// * `data` - Plaintext data, 0 or more bytes
pub fn encrypt(
    k: &K,
    nonce: &Nonce,
    ad: &AD,
    data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = k;
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce;
    let payload = aead::Payload {
        msg: data,
        aad: ad.as_ref(),
    };
    let ciphertext = cipher.encrypt(nonce.as_slice().into(), payload)?;
    Ok(ciphertext)
}

fn decrypt(k: &K, nonce: &Nonce, ad: &AD, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = k;
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce;
    let payload = aead::Payload {
        msg: data,
        aad: ad.as_ref(),
    };
    let plaintext = cipher.decrypt(nonce.as_slice().into(), payload)?;
    Ok(plaintext)
}
