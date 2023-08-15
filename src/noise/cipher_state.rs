use std::marker::PhantomData;

use super::suite::NoiseSuite;

/// A CipherState object contains k and n variables,
/// which it uses to encrypt and decrypt ciphertexts.
/// During the handshake phase each party has a single CipherState,
/// but during the transport phase each party has two CipherState objects:
/// one for sending, and one for receiving.
#[derive(Debug, Default, Clone, Copy)]
pub struct CipherState<S: NoiseSuite> {
    /// A cipher key of 32 bytes (which may be empty).
    /// Empty is a special value which indicates k has not yet been initialized.
    k: Option<[u8; 32]>,

    /// An 8-byte (64-bit) unsigned integer nonce.
    n: u64,

    _phantom: PhantomData<S>,
}

impl<S: NoiseSuite> CipherState<S> {
    /// InitializeKey(key): Sets k = key. Sets n = 0.
    pub fn initialize_key(&mut self, key: Option<[u8; 32]>) {
        self.k = key;
        self.n = 0;
    }

    /// HasKey(): Returns true if k is non-empty, false otherwise.
    pub fn hash_key(&self) -> bool {
        self.k.is_some()
    }

    /// SetNonce(nonce): Sets n = nonce.
    /// This function is used for handling out-of-order transport messages,
    /// as described in Section 11.4.
    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    /// EncryptWithAd(ad, plaintext):
    /// If k is non-empty returns ENCRYPT(k, n++, ad, plaintext).
    /// Otherwise returns plaintext.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self.k {
            Some(k) => {
                self.n += 1;
                S::encrypt(k, self.n, ad, plaintext)
            }
            None => plaintext.into(),
        }
    }

    /// DecryptWithAd(ad, ciphertext):
    /// If k is non-empty returns DECRYPT(k, n++, ad, ciphertext).
    /// Otherwise returns ciphertext.
    /// If an authentication failure occurs in DECRYPT()
    /// then n is not incremented and an error is signaled to the caller.
    pub fn decrypt_with_ad(&self, ad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        todo!()
    }

    /// Rekey(): Sets k = REKEY(k).
    pub fn rekey(&mut self) {
        todo!()
    }
}
