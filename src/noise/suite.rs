use super::{Key, KeyPair};

/// A constant specifying the size in bytes of the hash output. Must be 32 or 64.
pub const HASHLEN: usize = 32;

/// A constant specifying the size in bytes of public keys and DH outputs.
/// For security reasons, DHLEN must be 32 or greater.
pub const DHLEN: usize = 32;

pub trait NoiseSuite {
    /// Generates a new Diffie-Hellman key pair.
    /// A DH key pair consists of public_key and private_key elements.
    /// A public_key represents an encoding of a DH public key into a byte sequence of length DHLEN.
    /// The public_key encoding details are specific to each set of DH functions.
    fn generate_keypair() -> KeyPair;

    /// Performs a Diffie-Hellman calculation between the private key in key_pair and the public_key
    /// and returns an output sequence of bytes of length DHLEN.
    /// For security, the Gap-DH problem based on this function must be unsolvable
    /// by any practical cryptanalytic adversary [2].
    /// The public_key either encodes some value which is a generator in a large prime-order group
    /// (which value may have multiple equivalent encodings), or is an invalid value.
    /// Implementations must handle invalid public keys either by returning some output
    /// which is purely a function of the public key and does not depend on the private key,
    /// or by signaling an error to the caller.
    /// The DH function may define more specific rules for handling invalid values.
    fn dh(key_pair: KeyPair, public_key: Key) -> Key;

    /// Encrypts plaintext using the cipher key k of 32 bytes and an 8-byte unsigned integer nonce n
    /// which must be unique for the key k. Returns the ciphertext.
    /// Encryption must be done with an "AEAD" encryption mode with the associated data ad
    /// (using the terminology from [1]) and returns a ciphertext that is the same size
    /// as the plaintext plus 16 bytes for authentication data.
    /// The entire ciphertext must be indistinguishable from random if the key is secret
    /// (note that this is an additional requirement that isn't necessarily met by all AEAD schemes).
    fn encrypt(k: Key, n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8>;

    /// Hashes some arbitrary-length data with a collision-resistant
    /// cryptographic hash function and returns an output of HASHLEN bytes.
    fn hash(data: &[u8]) -> [u8; HASHLEN];

    /// Applies HMAC from [3] using the HASH() function. This function is only called as part of HKDF(), below.
    fn hmac_hash(key: Key, data: &[u8]) -> [u8; HASHLEN];

    /// Takes a chaining_key byte sequence of length HASHLEN,
    /// and an input_key_material byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes.
    /// Returns a pair or triple of byte sequences each of length HASHLEN, depending on whether num_outputs is two or three:
    /// Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
    /// Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
    /// Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
    /// If num_outputs == 2 then returns the pair (output1, output2).
    /// Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
    /// Returns the triple (output1, output2, output3).
    fn hkdf(
        chaining_key: [u8; HASHLEN],
        input_key_material: &[u8],
        num_outputs: usize,
    ) -> ([u8; HASHLEN], [u8; HASHLEN], Option<[u8; HASHLEN]>);
}

#[derive(Clone, Copy, Default)]
pub struct Ntcp2NoiseSuite;

impl NoiseSuite for Ntcp2NoiseSuite {
    fn generate_keypair() -> KeyPair {
        let private = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&private);
        KeyPair::new(public.to_bytes(), private.to_bytes())
    }

    fn dh(key_pair: KeyPair, public_key: Key) -> Key {
        let private = x25519_dalek::StaticSecret::from(key_pair.private);
        let public = x25519_dalek::PublicKey::from(public_key);
        let shared_secret = private.diffie_hellman(&public);
        shared_secret.to_bytes()
    }

    fn encrypt(k: Key, n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use aead::{Aead, KeyInit};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&k.into());
        let payload = aead::Payload {
            msg: plaintext,
            aad: ad,
        };

        let nonce_bytes = [&[0u8; 4], n.to_le_bytes().as_slice()].concat();
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        cipher.encrypt(nonce, payload).expect("failed to encrypt")
    }

    fn hash(data: &[u8]) -> [u8; HASHLEN] {
        /// NTCP2 uses SHA256
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hmac_hash(key: Key, data: &[u8]) -> [u8; HASHLEN] {
        use hmac::Mac;

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn hkdf(
        chaining_key: [u8; HASHLEN],
        input_key_material: &[u8],
        num_outputs: usize,
    ) -> ([u8; HASHLEN], [u8; HASHLEN], Option<[u8; HASHLEN]>) {
        let temp_key = Self::hmac_hash(chaining_key, input_key_material);
        let output1 = Self::hmac_hash(temp_key, &[1u8]);
        let output2 = Self::hmac_hash(temp_key, [output1.as_slice(), &[2u8]].concat().as_slice());
        if num_outputs == 2 {
            return (output1, output2, None);
        }
        let output3 = Self::hmac_hash(temp_key, [output2.as_slice(), &[3u8]].concat().as_slice());
        (output1, output2, Some(output3))
    }
}
