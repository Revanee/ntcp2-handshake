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

pub mod session_confirmed;
pub mod session_created;
pub mod session_request;

pub const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

pub fn initiator_handshake(
    own_public_key: [u8; 32],
    own_private_key: [u8; 32],
    peer_public_key: [u8; 32],
    peer_router_hash: [u8; 32],
    peer_iv: [u8; 16],
    peer_stream: &mut TcpStream,
    router_identity: &[u8],
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
        Some(crate::noise::KeyPair {
            public: own_public_key,
            private: own_private_key,
        }),
        None,
        Some(peer_public_key),
        None,
    );

    // Send SessionRequest
    {
        // TODO: Random padding
        let padding = [1, 2, 3];

        let session_request_constant_length = crate::ntcp2::session_request::SessionRequest::len();
        let options = Options::new(2, padding.len() as u16, 0, 0);

        let mut message_buffer = vec![0u8; session_request_constant_length];
        noise.write_message(options.as_bytes(), &mut message_buffer);
        message_buffer.extend_from_slice(&padding);
        noise.set_h2(padding.into());

        println!("Sending SessionRequest: {}", options);
        send(peer_stream, &message_buffer);
    }

    // Receive SessionCreated
    {
        let session_created_frame_len = crate::ntcp2::session_created::SessionCreated::len();
        let session_created_frame = recv(peer_stream, session_created_frame_len)
            .expect("failed to receive session created");

        let mut message_buffer = vec![0u8; 16];
        noise.read_message(&session_created_frame, &mut message_buffer);

        let session_created_options =
            crate::ntcp2::session_created::Options::try_from(message_buffer.as_slice()).unwrap();

        println!(
            "Received SessionCreated options: {}",
            session_created_options
        );

        let session_created_padding_len = session_created_options.pad_len() as usize;
        let session_created_padding_frame =
            recv(peer_stream, session_created_padding_len).expect("failed to receive padding");
        println!(
            "Received session_created_padding: {:?}",
            session_created_padding_frame
        );
        noise.set_h3(session_created_padding_frame);
    }

    // Send SessionConfirmed
    {
        const NTCP2_MTU: usize = 65535;
        let mut message_buffer = vec![0u8; NTCP2_MTU];
        // TODO: Write router identity
        noise.write_message(&[], &mut message_buffer);
        send(peer_stream, &message_buffer);
    }
}

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    println!("Receiving message of length {}...", len);
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
    const TEST_ROUTER_IDENTITY: &str =
        "OjlrJgYiBXkPlLR9UkCoIdGJY8DcftjwCmL3PWiIdWhF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHixeT6yvbOQ77PWve7h3vOyebYGVEYZ6wwbfKnVw/hk45BQAEAAcABAAAAYnpCqoMAg4AAAAAAAAAAAVOVENQMgBABGNhcHM9ATQ7AXM9LFdZQnA2OEdocUVOV2s3TX44Tk41THMxVUU1c0J5Sn5ZaDhaVzB6M3AwUVE9OwF2PQEyOw8AAAAAAAAAAARTU1UyAXwEY2Fwcz0BNDsBaT0sfm5KblRCSHVyZmhuZzBBdTdoM0QwUHNDVjNtRXdvajIxM3huOFVZekF4TT07BWlleHAwPQoxNjkxODM2NzIyOwVpZXhwMT0KMTY5MTgzNjcwNzsFaWV4cDI9CjE2OTE4MzY3MDc7A2loMD0sYmxIby0wZHhGMllSb05LQW90SVdGeHltRjczV0h5dUdZbXBVUnc4WTF5MD07A2loMT0sfmF1MmplNGxFbmtFZnJCdGhJeWljT2d1Y2ZYSmVEa2p4WEJGY1IxMkI3Yz07A2loMj0sZU83T2Y2QlRqcjBGM3czbnVWbThxUkUyMDVqfmVFZzllcGRvNXVFVWFMWT07BWl0YWcwPQo0MDAzNDU1MDk4OwVpdGFnMT0KMzkyMzMwMDEyODsFaXRhZzI9CjIyODgxNTE2MjU7AXM9LExZbVBGTmxRNH5nOGtpdjZ5OE9MR1ZXd2VWNndvMU1pamsxWmpjNk1hazg9OwF2PQEyOwAALARjYXBzPQJMVTsFbmV0SWQ9ATI7DnJvdXRlci52ZXJzaW9uPQYwLjkuNTk75wElj2dF2Qhokil5YH4t768xImr9e49BY8n040W4HAhc2SjzfCqRv6GYThkGOlkjEa6NDcTo04DLpQlB2Xf4BA==";

    let router_identity = base64::decode(TEST_ROUTER_IDENTITY).unwrap();

    print!("Establishing TCP connection...");
    let mut stream = TcpStream::connect("127.0.0.1:12346").unwrap();
    println!(" Connected to TCP");

    let public_key_b64: &str = "Am5NvNyBzK+hqYpbz6Q7CiVg8MU3xWdwwMIHRNiGDhQ=";
    let private_key_b64: &str = "iFA0BLrP8+nyN+dwVsJuFWsk18EOMI3l5ZO9ftqjFXg=";

    let peer_public_key_b64: &str = "BCfyQoO3xK1nCkWwjYDgrVRjg7Kwtk5yCsli2lOyAhY=";
    let peer_router_hash_b64: &str = "Bunc8ECK24KZ0FxfLV0/bLTmxaJZeuTXWbSe/8d6AyU=";
    let peer_iv_b64: &str = "+A4iwdmSHvcbwjtqCsXUXQ==";

    let b64 = base64::engine::general_purpose::STANDARD;

    let public_key = b64.decode(public_key_b64).unwrap().try_into().unwrap();
    let private_key = b64.decode(private_key_b64).unwrap().try_into().unwrap();

    let peer_public_key = b64.decode(peer_public_key_b64).unwrap().try_into().unwrap();
    let peer_router_hash = b64
        .decode(peer_router_hash_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let peer_iv = b64.decode(peer_iv_b64).unwrap().try_into().unwrap();

    initiator_handshake(
        public_key,
        private_key,
        peer_public_key,
        peer_router_hash,
        peer_iv,
        &mut stream,
        &router_identity,
    );
}
