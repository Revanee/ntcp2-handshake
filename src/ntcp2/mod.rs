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

use rand::RngCore;

use self::session_request::SessionRequest;

pub mod session_created;
pub mod session_request;

pub const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
const SESSION_CREATED_FRAME_LEN: usize = 64;
const SESSION_REQUEST_FRAME_LEN: usize = 64;

pub fn initiator_handshake(
    own_public_key: [u8; 32],
    own_private_key: [u8; 32],
    peer_public_key: [u8; 32],
    peer_router_hash: [u8; 32],
    peer_iv: [u8; 16],
    peer_stream: &mut TcpStream,
    router_info: &[u8],
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
        let mut rng = rand::rngs::OsRng::new().expect("failed to initialize RNG");
        let padding_len: u8 = rng.next_u32() as u8;
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill_bytes(&mut padding);

        let options =
            SessionRequest::new(2, padding.len() as u16, router_info.len() as u16 + 16, 0);

        let mut message_buffer = vec![0u8; SESSION_REQUEST_FRAME_LEN];
        noise.write_message(options.as_bytes(), &mut message_buffer);
        message_buffer.extend_from_slice(&padding);
        noise.set_h2(padding);

        println!("Sending SessionRequest: {}", options);
        send(peer_stream, &message_buffer);
    }

    // Receive SessionCreated
    {
        let session_created_frame = recv(peer_stream, SESSION_CREATED_FRAME_LEN)
            .expect("failed to receive session created");

        let mut message_buffer = vec![0u8; 16];
        noise.read_message(&session_created_frame, &mut message_buffer);

        let session_created_options =
            crate::ntcp2::session_created::SessionCreated::try_from(message_buffer.as_slice())
                .unwrap();

        println!("Received SessionCreated: {}", session_created_options);

        let session_created_padding_len = session_created_options.pad_len() as usize;
        let session_created_padding_frame =
            recv(peer_stream, session_created_padding_len).expect("failed to receive padding");
        println!(
            "Received SessionCreated padding: {:?}",
            session_created_padding_frame
        );
        noise.set_h3(session_created_padding_frame);
    }

    // Send SessionConfirmed
    {
        println!("Sending SessionConfirmed: {:?}", router_info);
        const NTCP2_MTU: usize = 65535;
        let mut message_buffer = vec![0u8; NTCP2_MTU];
        noise.write_message(router_info, &mut message_buffer);
        send(peer_stream, &message_buffer);
    }

    println!("Handshake complete!");
}

fn recv(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    println!("Receiving message of length {}...", len);
    let mut msg = vec![0u8; len];
    stream
        .read_exact(&mut msg[..])
        .unwrap_or_else(|_| panic!("failed to read message of size {}", len));
    Ok(msg)
}

fn send(stream: &mut TcpStream, buf: &[u8]) {
    stream.write_all(buf).unwrap();
}
