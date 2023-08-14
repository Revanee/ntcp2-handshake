use super::symmetric_state::SymmetricState;

/// A HandshakeState object contains a SymmetricState plus DH variables (s, e, rs, re) and a variable representing the handshake pattern. During the handshake phase each party has a single HandshakeState, which can be deleted once the handshake is finished.
/// A HandshakeState also has variables to track its role, and the remaining portion of the handshake pattern.
#[derive(Debug, Default, Clone)]
pub struct HandshakeState {
    /// s: The local static key pair
    s: Option<[u8; 32]>,
    /// e: The local ephemeral key pair
    e: Option<[u8; 32]>,
    /// rs: The remote party's static public key
    rs: Option<[u8; 32]>,
    /// re: The remote party's ephemeral public key
    re: Option<[u8; 32]>,

    /// initiator: A boolean indicating the initiator or responder role.
    initiator: bool,
    /// message_patterns: A sequence of message patterns. Each message pattern is a sequence of tokens from the set ("e", "s", "ee", "es", "se", "ss"). (An additional "psk" token is introduced in Section 9, but we defer its explanation until then.)
    message_patterns: Vec<Vec<String>>,

    /// SymmetricState object.
    symmetric_state: SymmetricState,
}

impl HandshakeState {
    /// Initialize(handshake_pattern, initiator, prologue, s, e, rs, re): Takes a valid handshake_pattern (see Section 7) and an initiator boolean specifying this party's role as either initiator or responder.
    /// Takes a prologue byte sequence which may be zero-length, or which may contain context information that both parties want to confirm is identical (see Section 6).
    /// Takes a set of DH key pairs (s, e) and public keys (rs, re) for initializing local variables, any of which may be empty. Public keys are only passed in if the handshake_pattern uses pre-messages (see Section 7). The ephemeral values (e, re) are typically left empty, since they are created and exchanged during the handshake; but there are exceptions (see Section 10).
    /// Performs the following steps:
    /// Derives a protocol_name byte sequence by combining the names for the handshake pattern and crypto functions, as specified in Section 8. Calls InitializeSymmetric(protocol_name).
    /// Calls MixHash(prologue).
    /// Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
    /// Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and responder have pre-messages, the initiator's public keys are hashed first. If multiple public keys are listed in either party's pre-message, the public keys are hashed in the order that they are listed.
    /// Sets message_patterns to the message patterns from handshake_pattern.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        &self,
        message_patterns: Vec<Vec<String>>,
        initiator: bool,
        prologue: &[u8],
        s: Option<[u8; 32]>,
        e: Option<[u8; 32]>,
        rs: Option<[u8; 32]>,
        re: Option<[u8; 32]>,
    ) {
        todo!()
    }

    // WriteMessage(payload, message_buffer): Takes a payload byte sequence which may be zero-length, and a message_buffer to write the output into. Performs the following steps, aborting if any EncryptAndHash() call returns an error:
    // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
    // For "e": Sets e (which must be empty) to GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key).
    // For "s": Appends EncryptAndHash(s.public_key) to the buffer.
    // For "ee": Calls MixKey(DH(e, re)).
    // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
    // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
    // For "ss": Calls MixKey(DH(s, rs)).
    // Appends EncryptAndHash(payload) to the buffer.
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    pub fn write_message(&self) {
        todo!()
    }

    // ReadMessage(message, payload_buffer): Takes a byte sequence containing a Noise handshake message, and a payload_buffer to write the message's plaintext payload into. Performs the following steps, aborting if any DecryptAndHash() call returns an error:
    // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
    // For "e": Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
    // For "s": Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
    // For "ee": Calls MixKey(DH(e, re)).
    // For "es": Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
    // For "se": Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
    // For "ss": Calls MixKey(DH(s, rs)).
    // Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
    // If there are no more message patterns returns two new CipherState objects by calling Split().
    pub fn read_message(&self) {
        todo!()
    }
}
