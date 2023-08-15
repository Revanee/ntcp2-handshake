use super::{cipher_state::CipherState, hkdf};
use crate::noise::{hash, HASHLEN};

/// A SymmetricState object contains a CipherState plus ck and h variables.
/// It is so-named because it encapsulates all the "symmetric crypto" used by Noise.
/// During the handshake phase each party has a single SymmetricState,
/// which can be deleted once the handshake is finished.
#[derive(Debug, Default, Clone, Copy)]
pub struct SymmetricState {
    /// Chaining key of [HASHLEN] bytes
    ck: [u8; HASHLEN],
    /// Hash output of [HASHLEN] bytes
    h: [u8; HASHLEN],

    /// CipherState object
    cipher_state: CipherState,
}

impl SymmetricState {
    /// InitializeSymmetric(protocol_name):
    /// Takes an arbitrary-length protocol_name byte sequence (see Section 8).
    /// Executes the following steps:
    /// * If protocol_name is less than or equal to HASHLEN bytes in length,
    /// sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
    /// Otherwise sets h = HASH(protocol_name).
    /// * Sets ck = h.
    /// * Calls InitializeKey(empty).
    pub fn initialize_symmetric(&mut self, protocol_name: &[u8]) {
        if protocol_name.len() <= HASHLEN {
            self.h = protocol_name
                .iter()
                .chain(std::iter::repeat(&0))
                .take(HASHLEN)
                .copied()
                .collect::<Vec<u8>>()
                .try_into()
                .expect("protocol_name length is more than HASHLEN");
        } else {
            self.h = hash(protocol_name);
        }

        self.ck = self.h;

        self.cipher_state.initialize_key(None);
    }

    /// MixKey(input_key_material): Executes the following steps:
    /// * Sets ck, temp_k = HKDF(ck, input_key_material, 2).
    /// * If HASHLEN is 64, then truncates temp_k to 32 bytes.
    /// * Calls InitializeKey(temp_k).
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, temp_k, _) = hkdf(self.ck, input_key_material, 2);
        self.ck = ck;

        if HASHLEN == 64 {
            unimplemented!()
        }

        self.cipher_state.initialize_key(Some(temp_k));
    }

    /// MixHash(data): Sets h = HASH(h || data).
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash([self.h.as_slice(), data].concat().as_slice());
    }

    // MixKeyAndHash(input_key_material): This function is used for handling pre-shared symmetric keys, as described in Section 9. It executes the following steps:
    // * Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    // * Calls MixHash(temp_h).
    // * If HASHLEN is 64, then truncates temp_k to 32 bytes.
    // * Calls InitializeKey(temp_k).
    pub fn mix_key_and_hash(&self, input_key_material: &[u8]) {
        todo!()
    }

    /// GetHandshakeHash(): Returns h. This function should only be called at the end of a handshake, i.e. after the Split() function has been called. This function is used for channel binding, as described in Section 11.2
    pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
        todo!()
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext),
    /// calls MixHash(ciphertext), and returns ciphertext.
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self
            .cipher_state
            .encrypt_with_ad(self.h.as_slice(), plaintext);
        self.mix_hash(ciphertext.as_slice());
        ciphertext
    }

    /// DecryptAndHash(ciphertext): Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
    pub fn decrypt_and_hash(&self, ciphertext: &[u8]) -> Vec<u8> {
        todo!()
    }

    /// Split(): Returns a pair of CipherState objects for encrypting transport messages. Executes the following steps, where zerolen is a zero-length byte sequence:
    /// * Sets temp_k1, temp_k2 = HKDF(ck, zerolen, 2).
    /// * If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
    /// * Creates two new CipherState objects c1 and c2.
    /// * Calls c1.InitializeKey(temp_k1) and c2.InitializeKey(temp_k2).
    /// * Returns the pair (c1, c2).
    pub fn split(&self) -> (CipherState, CipherState) {
        todo!()
    }
}
