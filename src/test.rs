
use std::sync::Arc;

use base64::Engine;
use i2p_snow::resolvers::CryptoResolver;

use crate::{
    noise::{
        suite::{NoiseSuite, Ntcp2NoiseSuite, HASHLEN},
        Key, KeyPair,
    },
    ntcp2::NTCP2_NOISE_ID,
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

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
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

#[derive(Clone, Copy, Default)]
struct Ntcp2NoiseSuiteFixedRandom;

impl NoiseSuite for Ntcp2NoiseSuiteFixedRandom {
    fn generate_keypair() -> KeyPair {
        KeyPair::new(
            [
                183, 157, 198, 149, 201, 249, 184, 58, 103, 173, 204, 130, 201, 98, 39, 104, 44, 7,
                10, 125, 221, 214, 115, 254, 192, 182, 73, 229, 216, 53, 125, 50,
            ],
            [
                78, 97, 26, 254, 119, 244, 128, 69, 95, 241, 16, 194, 185, 66, 253, 213, 78, 97,
                26, 254, 119, 244, 128, 69, 95, 241, 16, 194, 185, 66, 253, 213,
            ],
        )
    }

    fn dh(key_pair: KeyPair, public_key: Key) -> Key {
        Ntcp2NoiseSuite::dh(key_pair, public_key)
    }

    fn encrypt(k: Key, n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        Ntcp2NoiseSuite::encrypt(k, n, ad, plaintext)
    }

    fn hash(data: &[u8]) -> [u8; HASHLEN] {
        Ntcp2NoiseSuite::hash(data)
    }

    fn hmac_hash(key: Key, data: &[u8]) -> [u8; HASHLEN] {
        Ntcp2NoiseSuite::hmac_hash(key, data)
    }

    fn hkdf(
        chaining_key: [u8; HASHLEN],
        input_key_material: &[u8],
        num_outputs: usize,
    ) -> ([u8; HASHLEN], [u8; HASHLEN], Option<[u8; HASHLEN]>) {
        Ntcp2NoiseSuite::hkdf(chaining_key, input_key_material, num_outputs)
    }

    fn decrypt(k: Key, n: u64, ad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        Ntcp2NoiseSuite::decrypt(k, n, ad, ciphertext)
    }
}

const CACHED_RANDOM_B64: &str = "TmEa/nf0gEVf8RDCuUL91Q==";

const PUBLIC_KEY_B64: &str = "Am5NvNyBzK+hqYpbz6Q7CiVg8MU3xWdwwMIHRNiGDhQ=";
const PRIVATE_KEY_B64: &str = "iFA0BLrP8+nyN+dwVsJuFWsk18EOMI3l5ZO9ftqjFXg=";

const PEER_PUBLIC_KEY_B64: &str = "N0CG8qhchDbeq9vK5Vqg0w201g7lKicXiEPaKHsvzW4=";
const PEER_ROUTER_HASH_B64: &str = "xWvwRP2XVfKJdjISqVVZman8TIWEBBedC6z5koNj67A=";
const PEER_IV_B64: &str = "pRAL/JsEpz3VR+kM0bDO+Q==";

const SESSION_REQUEST_OPTIONS_B64: &str = "AAIAEACAAAAAAAAAAAAAAA==";

const TEST_ROUTER_IDENTITY: &str =
        "OjlrJgYiBXkPlLR9UkCoIdGJY8DcftjwCmL3PWiIdWhF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHixeT6yvbOQ77PWve7h3vOyebYGVEYZ6wwbfKnVw/hk45BQAEAAcABAAAAYnpCqoMAg4AAAAAAAAAAAVOVENQMgBABGNhcHM9ATQ7AXM9LFdZQnA2OEdocUVOV2s3TX44Tk41THMxVUU1c0J5Sn5ZaDhaVzB6M3AwUVE9OwF2PQEyOw8AAAAAAAAAAARTU1UyAXwEY2Fwcz0BNDsBaT0sfm5KblRCSHVyZmhuZzBBdTdoM0QwUHNDVjNtRXdvajIxM3huOFVZekF4TT07BWlleHAwPQoxNjkxODM2NzIyOwVpZXhwMT0KMTY5MTgzNjcwNzsFaWV4cDI9CjE2OTE4MzY3MDc7A2loMD0sYmxIby0wZHhGMllSb05LQW90SVdGeHltRjczV0h5dUdZbXBVUnc4WTF5MD07A2loMT0sfmF1MmplNGxFbmtFZnJCdGhJeWljT2d1Y2ZYSmVEa2p4WEJGY1IxMkI3Yz07A2loMj0sZU83T2Y2QlRqcjBGM3czbnVWbThxUkUyMDVqfmVFZzllcGRvNXVFVWFMWT07BWl0YWcwPQo0MDAzNDU1MDk4OwVpdGFnMT0KMzkyMzMwMDEyODsFaXRhZzI9CjIyODgxNTE2MjU7AXM9LExZbVBGTmxRNH5nOGtpdjZ5OE9MR1ZXd2VWNndvMU1pamsxWmpjNk1hazg9OwF2PQEyOwAALARjYXBzPQJMVTsFbmV0SWQ9ATI7DnJvdXRlci52ZXJzaW9uPQYwLjkuNTk75wElj2dF2Qhokil5YH4t768xImr9e49BY8n040W4HAhc2SjzfCqRv6GYThkGOlkjEa6NDcTo04DLpQlB2Xf4BA==";

fn test_options() -> crate::ntcp2::session_request::SessionRequest {
    crate::ntcp2::session_request::SessionRequest::new(0, 16, 128, 0)
}

struct TestData {
    public_key: [u8; 32],
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    peer_router_hash: [u8; 32],
    peer_iv: [u8; 16],
    cached_random: [u8; 16],
    session_request_options: [u8; 16],
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
    }
}

#[test]
fn options_encoding_and_decoding() {
    let expected_options_bytes = get_test_data().session_request_options;
    let expectes_options =
        crate::ntcp2::session_request::SessionRequest::from(expected_options_bytes);

    assert_eq!(
        expectes_options.to_bytes(),
        expected_options_bytes,
        "Options bytes should be the same as parsed bytes"
    );

    assert_eq!(
        test_options().to_bytes(),
        expected_options_bytes,
        "Test Options bytes should be the same as cached Options bytes"
    );
}

#[test]
fn test_noise_reference() {
    let b64 = base64::engine::general_purpose::STANDARD;

    let test_data = get_test_data();
    // Initialize NOISE
    let mut noise = crate::noise::handshake_state::HandshakeState::<
        crate::noise::suite::Ntcp2NoiseSuite,
    >::new(test_data.peer_router_hash, test_data.peer_iv);
    let handshake_pattern = crate::noise::handshake_state::ntcp2_handshake_pattern();
    noise.initialize(
        handshake_pattern,
        true,
        &[],
        Some(KeyPair::new(test_data.public_key, test_data.private_key)),
        Some(KeyPair::new(test_data.public_key, test_data.private_key)),
        Some(test_data.peer_public_key),
        None,
    );

    let mut reference_noise = i2p_snow::Builder::with_resolver(
        NTCP2_NOISE_ID.parse().unwrap(),
        Box::new(TestCryptoResolver::<TestRng> {
            rng: Some(TestRng {
                bytes: test_data.cached_random.to_vec(),
            }),
            resolver: Arc::new(i2p_snow::resolvers::DefaultResolver::default()),
        }),
    )
    .fixed_ephemeral_key_for_testing_only(&test_data.private_key)
    .local_private_key(&test_data.private_key)
    .remote_public_key(&test_data.peer_public_key)
    .aesobfse(&test_data.peer_router_hash, &test_data.peer_iv)
    .enable_ask()
    .build_initiator()
    .unwrap();

    // Send SessionRequest
    {
        let router_info = b64.decode(TEST_ROUTER_IDENTITY).unwrap();
        let padding = [5, 4, 3, 2, 1];
        let options = crate::ntcp2::session_request::SessionRequest::new(
            2,
            padding.len() as u16,
            router_info.len() as u16 + 16,
            0,
        );

        let mut message_buffer = vec![0u8; 64];
        noise.write_message(options.as_bytes(), &mut message_buffer);
        noise.set_h2(padding.into());

        let mut reference_message_buffer = vec![0u8; 64];
        reference_noise
            .write_message(options.as_bytes(), &mut reference_message_buffer)
            .expect("failed to write message");
        reference_noise
            .set_h_data(2, &padding)
            .expect("failed to set h data");

        assert_eq!(message_buffer, reference_message_buffer);
    }

    // Receive SessionCreated
    {
        let session_created_frame = [
            9, 21, 248, 108, 231, 226, 229, 39, 177, 136, 12, 137, 91, 195, 81, 104, 111, 168, 69,
            146, 162, 246, 191, 62, 207, 189, 246, 251, 195, 73, 69, 14, 53, 101, 145, 14, 175, 74,
            94, 37, 165, 129, 139, 24, 126, 251, 12, 71, 148, 250, 192, 87, 126, 168, 159, 121,
            123, 198, 117, 113, 172, 156, 232, 103,
        ];
        println!("Received session_created: {:?}", session_created_frame);

        const SESSION_CREATED_LEN: usize = 16;

        let mut reference_message_buffer = vec![0u8; SESSION_CREATED_LEN];
        reference_noise
            .read_message(&session_created_frame, &mut reference_message_buffer)
            .expect("failed to read message");

        println!(
            "Received reference noise message: {:?}",
            reference_message_buffer
        );

        let mut message_buffer = [0u8; SESSION_CREATED_LEN];
        noise.read_message(&session_created_frame, &mut message_buffer);

        assert_eq!(&message_buffer, reference_message_buffer.as_slice());

        println!("Received noise message: {:?}", message_buffer);
        let session_created_options =
            crate::ntcp2::session_created::SessionCreated::from(message_buffer);

        println!(
            "Received SessionCreated options: {}",
            session_created_options
        );

        let session_created_padding_frame =
            [154, 187, 178, 193, 153, 125, 133, 181, 157, 232, 4, 252, 48];
        println!(
            "Received session_created_padding: {:?}",
            session_created_padding_frame
        );

        reference_noise
            .set_h_data(3, &session_created_padding_frame)
            .unwrap();
        noise.set_h3(session_created_padding_frame.into());
    }

    // Send SessionConfirmed
    {
        let router_info = b64.decode(TEST_ROUTER_IDENTITY).unwrap();

        const NTCP2_MTU: usize = 65535;
        let mut reference_message_buffer = vec![0u8; NTCP2_MTU];
        let len = reference_noise
            .write_message(&router_info, &mut reference_message_buffer)
            .unwrap();
        println!("Reference NOISE wrote SessionConfirmed of length {}", len);

        let mut message_buffer = vec![0u8; NTCP2_MTU];
        noise.write_message(&router_info, &mut message_buffer);

        assert_eq!(message_buffer, reference_message_buffer);
    }
}
