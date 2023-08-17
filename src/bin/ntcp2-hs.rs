use std::net::TcpStream;

use base64::Engine;
use clap::{command, Parser, Subcommand};
use ntcp2_hs::{noise::suite::NoiseSuite, ntcp2::initiator_handshake};

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to an I2P Router using NTCP2
    Connect {
        /// The I2P Router's hostname
        host: String,
        /// The I2P Router's port
        port: u16,

        /// Peer's public key in b64
        peer_public_key: String,

        /// Peer's router hash in b64
        peer_router_hash: String,

        /// Peer's IV in b64
        peer_iv: String,
    },
    /// Listen for incoming NTCP2 connections
    Listen {},
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Connect {
            host,
            port,
            peer_public_key,
            peer_router_hash,
            peer_iv,
        } => {
            let b64 = base64::engine::general_purpose::STANDARD;
            let peer_public_key = b64
                .decode(peer_public_key)
                .expect("Failed to decode public key");
            let peer_router_hash = b64
                .decode(peer_router_hash)
                .expect("Failed to decode router hash");
            let peer_iv = b64.decode(peer_iv).expect("Failed to decode IV");

            let keypair = ntcp2_hs::noise::suite::Ntcp2NoiseSuite::generate_keypair();
            println!("Generated public key: {}", hex::encode(keypair.public));
            println!("Connecting to {}:{}", host, port);
            let mut peer_stream = TcpStream::connect(format!("{}:{}", host, port))
                .expect("Failed to connect to peer");

            initiator_handshake(
                keypair.public,
                keypair.private,
                peer_public_key.try_into().expect("Invalid peer public key"),
                peer_router_hash
                    .try_into()
                    .expect("Invalid peer router hash"),
                peer_iv.try_into().expect("Invalid peer IV"),
                &mut peer_stream,
                &[1, 3, 3, 7],
            );
        }
        Commands::Listen {} => unimplemented!(),
    }
}
