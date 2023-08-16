//! The establishment sequence is as follows:
//!
//! Alice                           Bob
//!
//! SessionRequest ------------------->
//! <------------------- SessionCreated
//! SessionConfirmed ----------------->
//!
//! Using Noise terminology, the establishment and data sequence is as follows: (Payload Security Properties)
//!
//! XK(s, rs):           Authentication   Confidentiality
//! <- s
//! ...
//! -> e, es                  0                2
//! <- e, ee                  2                1
//! -> s, se                  2                5
//! <-                        2                5
//!
//! Some notations:
//!
//! - RH_A = Router Hash for Alice (32 bytes)
//! - RH_B = Router Hash for Bob (32 bytes)
//!

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use base64::Engine;

use self::session_request::{Options, UnencryptedSessionRequest};

pub mod session_created;
pub mod session_request;

pub const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

pub fn initiator_handshake(
    peer_public_key: [u8; 32],
    peer_router_hash: [u8; 32],
    peer_iv: [u8; 16],
    peer_stream: &mut TcpStream,
) {
    // Initialize NOISE
    let mut noise = crate::noise::handshake_state::HandshakeState::<
        crate::noise::suite::Ntcp2NoiseSuite,
    >::new(peer_router_hash, peer_iv);
    let handshake_pattern = crate::noise::handshake_state::ntcp2_handshake_pattern();
    noise.initialize(
        handshake_pattern,
        true,
        &[],
        None,
        None,
        Some(peer_public_key),
        None,
    );

    // Send SessionRequest
    {
        let padding_length = 0;
        let session_request_constant_length = crate::ntcp2::session_request::SessionRequest::len();
        let options = Options::new(2, 0, 0, 0);

        let mut message_buffer = vec![0u8; session_request_constant_length + padding_length];
        noise.write_message(options.as_bytes(), &mut message_buffer);
        // TODO: Padding with random data
        noise.set_h2(vec![]);

        println!("Sending SessionRequest: {}", options);
        send(peer_stream, &message_buffer);
    }

    // Receive SessionCreated
    {
        let session_created_frame_len = crate::ntcp2::session_created::SessionCreated::len();
        let session_created_frame = recv(peer_stream, session_created_frame_len)
            .expect("failed to receive session created");
        println!("Received session_created: {:?}", session_created_frame);

        let mut message_buffer = vec![0u8; 16];
        noise.read_message(&session_created_frame, &mut message_buffer);

        println!("Received noise message: {:?}", message_buffer);
        let session_created_options =
            crate::ntcp2::session_created::Options::try_from(message_buffer.as_slice()).unwrap();

        println!(
            "Received SessionCreated options: {}",
            session_created_options
        );

        let session_created_padding_len = 0;
        let session_created_padding_frame =
            recv(peer_stream, session_created_padding_len).expect("failed to receive padding");
        println!(
            "Received session_created_padding: {:?}",
            session_created_padding_frame
        );
    }
    // let mut message_buffer = [u8; 48];
    // noise.read_message(&response, &mut message_buffer);
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    println!("Receiving message of length: {}", len);
    let mut msg = vec![0u8; len];
    stream
        .read_exact(&mut msg[..])
        .unwrap_or_else(|_| panic!("failed to read message of size {}", len));
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    stream.write_all(buf).unwrap();
}

#[test]
fn test_initiator_handshake() {
    println!("Establishing TCP connection...");
    let mut stream = TcpStream::connect("127.0.0.1:12346").unwrap();
    println!("Connected to TCP");

    let peer_public_key_b64: &str = "BCfyQoO3xK1nCkWwjYDgrVRjg7Kwtk5yCsli2lOyAhY=";
    let peer_router_hash_b64: &str = "Bunc8ECK24KZ0FxfLV0/bLTmxaJZeuTXWbSe/8d6AyU=";
    let peer_iv_b64: &str = "+A4iwdmSHvcbwjtqCsXUXQ==";

    let b64 = base64::engine::general_purpose::STANDARD;

    let peer_public_key = b64.decode(peer_public_key_b64).unwrap().try_into().unwrap();
    let peer_router_hash = b64
        .decode(peer_router_hash_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let peer_iv = b64.decode(peer_iv_b64).unwrap().try_into().unwrap();

    initiator_handshake(peer_public_key, peer_router_hash, peer_iv, &mut stream);
}
