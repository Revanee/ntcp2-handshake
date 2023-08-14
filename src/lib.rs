mod crypto;
mod noise;
mod ntcp2;
mod session_request;

use sha2::Digest;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

const NTCP2_MAX_BYTES: u32 = 65537;
const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
static SECRET: &[u8] = b"i don't care for fidget spinners";
const SESSION_REQUEST_CT_LEN: usize = 64;

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
fn recv(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut msg_len_buf = [0u8; 2];
    stream
        .read_exact(&mut msg_len_buf)
        .expect("failed to reat first 2 bytes");
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    println!("Receiving message of length: {}", msg_len);
    let mut msg = vec![0u8; msg_len];
    stream
        .read_exact(&mut msg[..])
        .unwrap_or_else(|_| panic!("failed to read message of size {}", msg_len));
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
fn send(stream: &mut TcpStream, buf: &[u8]) {
    stream.write_all(buf).unwrap();
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddrV6, TcpStream},
        sync::Arc,
    };

    use base64::Engine;
    use i2p_snow::{resolvers::CryptoResolver, Builder as NoiseBuilder};
    use rand::{rngs::OsRng, Rng};

    use crate::{
        noise::{
            cipher_state::CipherState,
            handshake_state::{self, HandshakeState},
            symmetric_state::SymmetricState,
        },
        recv, send, session_request, NTCP2_NOISE_ID, SESSION_REQUEST_CT_LEN,
    };

    #[derive(Clone)]
    struct TestRng {
        bytes: Vec<u8>,
    }

    impl rand::CryptoRng for TestRng {}
    impl rand::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = self.bytes.iter().cycle();
            dest.fill_with(|| *i.next().unwrap());
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            unimplemented!()
        }
    }

    impl i2p_snow::types::Random for TestRng {}

    #[derive(Clone)]
    struct TestCryptoResolver<RNG: i2p_snow::types::Random> {
        rng: Option<RNG>,
        resolver: Arc<i2p_snow::resolvers::DefaultResolver>,
    }

    impl<RNG: i2p_snow::types::Random + Clone + 'static> CryptoResolver for TestCryptoResolver<RNG> {
        fn resolve_rng(&self) -> Option<Box<dyn i2p_snow::types::Random>> {
            self.rng
                .clone()
                .map(|rng| Box::new(rng) as Box<dyn i2p_snow::types::Random>)
        }

        fn resolve_dh(
            &self,
            choice: &i2p_snow::params::DHChoice,
        ) -> Option<Box<dyn i2p_snow::types::Dh>> {
            self.resolver.resolve_dh(choice)
        }

        fn resolve_hash(
            &self,
            choice: &i2p_snow::params::HashChoice,
        ) -> Option<Box<dyn i2p_snow::types::Hash>> {
            self.resolver.resolve_hash(choice)
        }

        fn resolve_cipher(
            &self,
            choice: &i2p_snow::params::CipherChoice,
        ) -> Option<Box<dyn i2p_snow::types::Cipher>> {
            self.resolver.resolve_cipher(choice)
        }

        fn resolve_obfusc(
            &self,
            choice: &i2p_snow::params::ObfuscChoice,
        ) -> Option<Box<dyn i2p_snow::types::Obfusc + Send>> {
            self.resolver.resolve_obfusc(choice)
        }
    }

    const CACHED_RANDOM_B64: &str = "TmEa/nf0gEVf8RDCuUL91Q==";
    // const EXPECTED_MESSAGE_B64: &str = "Q0E7XMvZdAH5Vf2iZt/2znRTtOPbtRvvIQR/qQqlSQqcnSuF+L0IYfiZMhnKusSds3PXf9HUNTfFTJA7HSLhsgAAAAAAAAAAAAAAAAAAAAA=";
    const EXPECTED_MESSAGE_B64: &str = "Q0E7XMvZdAH5Vf2iZt/2znRTtOPbtRvvIQR/qQqlSQqcnSuF+L0IYfiZMhnKusSds3PXf9HUNTfFTJA7HSLhsk5hGv539IBFX/EQwrlC/dU=";

    const PUBLIC_KEY_B64: &str = "Am5NvNyBzK+hqYpbz6Q7CiVg8MU3xWdwwMIHRNiGDhQ=";
    const PRIVATE_KEY_B64: &str = "iFA0BLrP8+nyN+dwVsJuFWsk18EOMI3l5ZO9ftqjFXg=";

    const PEER_PUBLIC_KEY_B64: &str = "BCfyQoO3xK1nCkWwjYDgrVRjg7Kwtk5yCsli2lOyAhY=";
    const PEER_ROUTER_HASH_B64: &str = "Bunc8ECK24KZ0FxfLV0/bLTmxaJZeuTXWbSe/8d6AyU=";
    const PEER_IV_B64: &str = "+A4iwdmSHvcbwjtqCsXUXQ==";

    const SESSION_REQUEST_OPTIONS_B64: &str = "AAIAEACAAAAAAAAAAAAAAA==";

    const TEST_OPTIONS: crate::ntcp2::Options = crate::ntcp2::Options {
        id: 0,
        ver: 2,
        pad_len: [0, 16],
        m3p2_len: [0, 128],
        rsvd: [0, 0],
        tsa: [0, 0, 0, 0],
        reserved: [0, 0, 0, 0],
    };

    struct TestData {
        public_key: [u8; 32],
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        peer_router_hash: [u8; 32],
        peer_iv: [u8; 16],
        cached_random: [u8; 16],
        session_request_options: [u8; 16],
        expected_message: Vec<u8>,
    }

    fn get_test_data() -> TestData {
        let b64 = base64::engine::general_purpose::STANDARD;
        TestData {
            public_key: b64.decode(PUBLIC_KEY_B64).unwrap().try_into().unwrap(),
            private_key: b64.decode(PRIVATE_KEY_B64).unwrap().try_into().unwrap(),
            peer_public_key: b64.decode(PEER_PUBLIC_KEY_B64).unwrap().try_into().unwrap(),
            peer_router_hash: b64
                .decode(PEER_ROUTER_HASH_B64)
                .unwrap()
                .try_into()
                .unwrap(),
            peer_iv: b64.decode(PEER_IV_B64).unwrap().try_into().unwrap(),
            cached_random: b64.decode(CACHED_RANDOM_B64).unwrap().try_into().unwrap(),
            session_request_options: b64
                .decode(SESSION_REQUEST_OPTIONS_B64)
                .unwrap()
                .try_into()
                .unwrap(),
            expected_message: b64.decode(EXPECTED_MESSAGE_B64).unwrap(),
        }
    }

    #[test]
    fn cached_session_request_message_same_as_i2p_noise() {
        let test_data = get_test_data();

        let mut noise_session = i2p_snow::Builder::with_resolver(
            NTCP2_NOISE_ID.parse().unwrap(),
            Box::new(TestCryptoResolver::<TestRng> {
                rng: Some(TestRng {
                    bytes: test_data.cached_random.to_vec(),
                }),
                resolver: Arc::new(i2p_snow::resolvers::DefaultResolver::default()),
            }),
        )
        .local_private_key(&test_data.private_key)
        .remote_public_key(&test_data.peer_public_key)
        .aesobfse(&test_data.peer_router_hash, &test_data.peer_iv)
        .enable_ask()
        .build_initiator()
        .unwrap();

        let padlen: usize = 16;
        let mut buf = vec![0u8; SESSION_REQUEST_CT_LEN + padlen];
        noise_session
            .write_message(&test_data.session_request_options, &mut buf)
            .unwrap();
        // rng.fill(&mut buf[SESSION_REQUEST_CT_LEN..]);
        buf[SESSION_REQUEST_CT_LEN..].copy_from_slice(&test_data.cached_random);

        noise_session
            .set_h_data(2, &buf[SESSION_REQUEST_CT_LEN..])
            .unwrap();

        assert_eq!(buf, test_data.expected_message);

        // // Connect to our server, which is hopefully listening.
        // println!("Establishing TCP connection...");
        // // let mut stream = TcpStream::connect("149.62.244.210:12345").unwrap();
        // // let mut stream = TcpStream::connect("localhost:54321").unwrap();
        // let mut stream = TcpStream::connect("127.0.0.1:12346").unwrap();
        // println!("Connected to TCP");

        // println!("Sending message...");
        // send(&mut stream, &buf);
        // println!("Waiting for response...");
        // let response = recv(&mut stream).expect("failed to receive message");
        // println!("Got response: {:?}", response);
        // noise_session
        //     .read_message(&response, &mut buf)
        //     .expect("failed to read message");
        // println!("Read response: {:?}", &buf);
    }

    #[test]
    fn options_encoding_and_decoding() {
        let expected_options_bytes = get_test_data().session_request_options;
        let expectes_options = crate::ntcp2::Options::from(expected_options_bytes);

        assert_eq!(
            expectes_options.to_bytes(),
            expected_options_bytes,
            "Options bytes should be the same as parsed bytes"
        );

        assert_eq!(
            TEST_OPTIONS.to_bytes(),
            expected_options_bytes,
            "Test Options bytes should be the same as cached Options bytes"
        );
    }

    #[test]
    fn unencrypted_session_request_encoding_and_decoding() {
        let test_data = get_test_data();
        let ephemeral_key = test_data.public_key;
        let options = TEST_OPTIONS;
        let padding = [0u8; 16];

        let unencrypted_session_request = crate::ntcp2::UnencryptedSessionRequest {
            x: ephemeral_key,
            options,
            padding: &padding,
        };

        let encrypted_session_reqeust = unencrypted_session_request.encrypt(
            &test_data.peer_router_hash,
            &[0u8; 12],
            &crate::crypto::AD::Handshake(sha256(&[0u8])),
        );
        println!("Encrypted SessionRequest: {:?}", encrypted_session_reqeust);

        let expected_session_reqeust =
            crate::ntcp2::SessionRequest::try_from(test_data.expected_message.as_slice()).unwrap();

        println!("Expected SessionRequest: {:?}", expected_session_reqeust);
        let unencrypted_expected_session_request = expected_session_reqeust.decrypt();
        println!(
            "Expected Unencrypted SessionRequest: {:?}",
            unencrypted_expected_session_request,
        );

        // assert_eq!(
        //     expectes_options.to_bytes(),
        //     expected_options_bytes,
        //     "Options bytes should be the same as parsed bytes"
        // );

        // assert_eq!(
        //     TEST_OPTIONS.to_bytes(),
        //     expected_options_bytes,
        //     "Test Options bytes should be the same as cached Options bytes"
        // );
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn test_create_noise() {
        let test_data = get_test_data();
        let ephemeral_key = test_data.public_key;
        let options = TEST_OPTIONS;
        let padding = [0u8; 16];

        let session_request = crate::ntcp2::UnencryptedSessionRequest {
            x: ephemeral_key,
            options,
            padding: &padding,
        };

        let cipher_state = CipherState::default();
        let symmetric_state = SymmetricState::default();
        let handshake_state = HandshakeState::default();

        let hanshake_patterns = vec![
            vec!["s".to_owned()],
            vec!["e".to_owned(), "es".to_owned()],
            vec!["e".to_owned(), "ee".to_owned()],
            vec!["s".to_owned(), "se".to_owned()],
        ];

        handshake_state.initialize(hanshake_patterns, true, &[], None, None, None, None);
        handshake_state.write_message();
    }
}
