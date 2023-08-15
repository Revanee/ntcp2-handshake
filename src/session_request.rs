//! XK(s, rs):           Authentication   Confidentiality
//!  -> e, es                  0                2
//!
//!  Authentication: None (0).
//!  This payload may have been sent by any party, including an active attacker.
//!
//!  Confidentiality: 2.
//!  Encryption to a known recipient, forward secrecy for sender compromise
//!  only, vulnerable to replay.  This payload is encrypted based only on DHs
//!  involving the recipient's static key pair.  If the recipient's static
//!  private key is compromised, even at a later date, this payload can be
//!  decrypted.  This message can also be replayed, since there's no ephemeral
//!  contribution from the recipient.
//!
//!  "e": Alice generates a new ephemeral key pair and stores it in the e
//!       variable, writes the ephemeral public key as cleartext into the
//!       message buffer, and hashes the public key along with the old h to
//!       derive a new h.
//!
//!  "es": A DH is performed between the Alice's ephemeral key pair and the
//!        Bob's static key pair.  The result is hashed along with the old ck to
//!        derive a new ck and k, and n is set to zero.

fn _session_request() -> Vec<u8> {
    todo!();
    // let peer_router_ident_b64 = "LxOEhFCbJRYIX81sNWnpj0HBQo8k8gaA96VQJeRfaS4=";
    // let peer_router_ident =
    //     base64::decode(peer_router_ident_b64).expect("failed to decode peer ident from base64");
    // // This is optimistic. PublicKeyLength could be different that 256 bytes, based on the Certificate
    // let _peer_public_key: [u8; 32] = peer_router_ident[0..32]
    //     .try_into()
    //     .expect("failed to convert peer ident to public key");

    // let (hash, keypair) = e();
    // let options = Options::new();
    // let padding: Vec<u8> = vec![];
    // let unencrypted_data =
    //     UnencryptedSessionRequest::new(keypair.public.to_bytes(), options, &padding);
    // let counter: u64 = 0;
    // let nonce_pre_padding = [0u8; 4];
    // let nonce: [u8; 12] = nonce_pre_padding
    //     .into_iter()
    //     .chain(counter.to_le_bytes().into_iter())
    //     .collect::<Vec<u8>>()
    //     .try_into()
    //     .expect("failed to calculate nonce bytes");
    // let ad = crate::kdf::sha256(&[]);
    // let session_request = unencrypted_data.encrypt(keypair.public.as_bytes(), &nonce, &ad.into());
    // session_request.to_bytes()
}
