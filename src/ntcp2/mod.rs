use std::{
    io::{Read, Write},
    net::TcpStream,
};

use self::session_request::{Options, UnencryptedSessionRequest};

pub mod session_created;
pub mod session_request;

pub const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

fn initiator_handshake(peer_router_hash: [u8; 32], peer_iv: [u8; 16], peer_stream: &mut TcpStream) {
    let options = Options::new(2, 0, 0, 0);
    let mut noise = crate::noise::handshake_state::HandshakeState::<
        crate::noise::suite::Ntcp2NoiseSuite,
    >::new(peer_router_hash, peer_iv);

    let padding_length = 0;
    let mut message_buffer = vec![0u8; 64 + padding_length];

    noise.write_message(options.as_bytes(), &mut message_buffer);

    send(peer_stream, &message_buffer);

    let response = recv(peer_stream, 64).expect("failed to receive response");

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
