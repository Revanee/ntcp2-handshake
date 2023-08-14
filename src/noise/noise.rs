use sha2::{Digest, Sha256};

use super::symmetric_state::SymmetricState;

struct DhKeypair {
    public: [u8; 32],
    private: [u8; 32],
}

/// A HandshakeState object contains a SymmetricState plus DH variables (s, e, rs, re)
/// and a variable representing the handshake pattern.
/// During the handshake phase each party has a single HandshakeState,
/// which can be deleted once the handshake is finished.
struct HandshakeState {
    rs: [u8; 32],
    symmetric_state: SymmetricState,
}

impl HandshakeState {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// MixHash(data)
    /// || below means append
    /// h = SHA256(h || data);
    fn mix_hash(&mut self, data: &[u8]) {
        self.symmetric_state.mix_hash(data);
    }

    // pub fn alice_e_precalc(&mut self, peer_static_key: [u8; 32]) {
    //     // This is the "e" message pattern:

    //     // Define protocol_name.
    //     // Set protocol_name = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"
    //     //  (48 bytes, US-ASCII encoded, no NULL termination).
    //     let protocol_name = crate::NTCP2_NOISE_ID.as_bytes();

    //     // Define Hash h = 32 bytes
    //     self.h = self.sha256(protocol_name);

    //     // Define ck = 32 byte chaining key. Copy the h data to ck.
    //     // Set ck = h
    //     self.ck = self.h;

    //     // Define rs = Bob's 32-byte static key as published in the RouterInfo
    //     self.rs = peer_static_key;

    //     // MixHash(null prologue)
    //     let h = self.sha256(&self.h);

    //     // up until here, can all be precalculated by Alice for all outgoing connections
    // }

    // fn alice_e(&mut self, e: DhKeypair) {
    //     // Alice must validate that Bob's static key is a valid point on the curve here.
    //     // Note: not implemented

    //     // Bob static key
    //     // MixHash(rs)
    //     // || below means append
    //     // h = SHA256(h || rs);
    //     self.mix_hash(&self.rs);

    //     // up until here, can all be precalculated by Bob for all incoming connections

    //     // This is the "e" message pattern:

    //     // Alice generates her ephemeral DH key pair e.
    //     // Note: Arg `e` is the ephemeral DK key for Alice

    //     // Alice ephemeral key X
    //     // MixHash(e.pubkey)
    //     // || below means append
    //     // h = SHA256(h || e.pubkey);
    //     self.mix_hash(&e.public);

    //     // h is used as the associated data for the AEAD in message 1
    //     // Retain the Hash h for the message 2 KDF

    //     // End of "e" message pattern.
    // }

    // fn remaining_stuff_todo() {
    //     // This is the "es" message pattern:

    //     // // DH(e, rs) == DH(s, re)
    //     // Define input_key_material = 32 byte DH result of Alice's ephemeral key and Bob's static key
    //     // Set input_key_material = X25519 DH result

    //     // // MixKey(DH())

    //     // Define temp_key = 32 bytes
    //     // Define HMAC-SHA256(key, data) as in [RFC-2104]_
    //     // // Generate a temp key from the chaining key and DH result
    //     // // ck is the chaining key, defined above
    //     // temp_key = HMAC-SHA256(ck, input_key_material)
    //     // // overwrite the DH result in memory, no longer needed
    //     // input_key_material = (all zeros)

    //     // // Output 1
    //     // // Set a new chaining key from the temp key
    //     // // byte() below means a single byte
    //     // ck =       HMAC-SHA256(temp_key, byte(0x01)).

    //     // // Output 2
    //     // // Generate the cipher key k
    //     // Define k = 32 bytes
    //     // // || below means append
    //     // // byte() below means a single byte
    //     // k =        HMAC-SHA256(temp_key, ck || byte(0x02)).
    //     // // overwrite the temp_key in memory, no longer needed
    //     // temp_key = (all zeros)

    //     // // retain the chaining key ck for message 2 KDF

    //     // End of "es" message pattern.
    // }
}
