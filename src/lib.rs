pub mod noise;
pub mod ntcp2;

#[cfg(test)]
mod tests {
    use std::{net::TcpStream, sync::Arc};

    use base64::Engine;
    use i2p_snow::resolvers::CryptoResolver;

    use crate::{
        noise::{
            handshake_state::HandshakeState,
            suite::{NoiseSuite, Ntcp2NoiseSuite, HASHLEN},
            Key, KeyPair,
        },
        ntcp2::NTCP2_NOISE_ID,
    };
    use std::io::Read;
    use std::io::Write;

    const SESSION_REQUEST_CT_LEN: usize = 64;

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
            // let b64 = base64::engine::general_purpose::STANDARD;
            // let public = b64.decode(PUBLIC_KEY_B64).unwrap().try_into().unwrap();
            // let private = b64.decode(PRIVATE_KEY_B64).unwrap().try_into().unwrap();
            KeyPair::new(
                [
                    183, 157, 198, 149, 201, 249, 184, 58, 103, 173, 204, 130, 201, 98, 39, 104,
                    44, 7, 10, 125, 221, 214, 115, 254, 192, 182, 73, 229, 216, 53, 125, 50,
                ],
                [
                    78, 97, 26, 254, 119, 244, 128, 69, 95, 241, 16, 194, 185, 66, 253, 213, 78,
                    97, 26, 254, 119, 244, 128, 69, 95, 241, 16, 194, 185, 66, 253, 213,
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
    // const EXPECTED_MESSAGE_B64: &str = "Q0E7XMvZdAH5Vf2iZt/2znRTtOPbtRvvIQR/qQqlSQqcnSuF+L0IYfiZMhnKusSds3PXf9HUNTfFTJA7HSLhsgAAAAAAAAAAAAAAAAAAAAA=";
    const EXPECTED_MESSAGE_B64: &str = "Q0E7XMvZdAH5Vf2iZt/2znRTtOPbtRvvIQR/qQqlSQqcnSuF+L0IYfiZMhnKusSds3PXf9HUNTfFTJA7HSLhsk5hGv539IBFX/EQwrlC/dU=";

    const PUBLIC_KEY_B64: &str = "Am5NvNyBzK+hqYpbz6Q7CiVg8MU3xWdwwMIHRNiGDhQ=";
    const PRIVATE_KEY_B64: &str = "iFA0BLrP8+nyN+dwVsJuFWsk18EOMI3l5ZO9ftqjFXg=";

    const PEER_PUBLIC_KEY_B64: &str = "BCfyQoO3xK1nCkWwjYDgrVRjg7Kwtk5yCsli2lOyAhY=";
    const PEER_ROUTER_HASH_B64: &str = "Bunc8ECK24KZ0FxfLV0/bLTmxaJZeuTXWbSe/8d6AyU=";
    const PEER_IV_B64: &str = "+A4iwdmSHvcbwjtqCsXUXQ==";

    const SESSION_REQUEST_OPTIONS_B64: &str = "AAIAEACAAAAAAAAAAAAAAA==";

    const TEST_ROUTER_IDENTITY: &str =
        "OjlrJgYiBXkPlLR9UkCoIdGJY8DcftjwCmL3PWiIdWhF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHi0XrrDDycEkvw+Tjj5j6lQaQ6/+hlqw9356NGWGT2ceLReusMPJwSS/D5OOPmPqVBpDr/6GWrD3fno0ZYZPZx4tF66ww8nBJL8Pk44+Y+pUGkOv/oZasPd+ejRlhk9nHixeT6yvbOQ77PWve7h3vOyebYGVEYZ6wwbfKnVw/hk45BQAEAAcABAAAAYnpCqoMAg4AAAAAAAAAAAVOVENQMgBABGNhcHM9ATQ7AXM9LFdZQnA2OEdocUVOV2s3TX44Tk41THMxVUU1c0J5Sn5ZaDhaVzB6M3AwUVE9OwF2PQEyOw8AAAAAAAAAAARTU1UyAXwEY2Fwcz0BNDsBaT0sfm5KblRCSHVyZmhuZzBBdTdoM0QwUHNDVjNtRXdvajIxM3huOFVZekF4TT07BWlleHAwPQoxNjkxODM2NzIyOwVpZXhwMT0KMTY5MTgzNjcwNzsFaWV4cDI9CjE2OTE4MzY3MDc7A2loMD0sYmxIby0wZHhGMllSb05LQW90SVdGeHltRjczV0h5dUdZbXBVUnc4WTF5MD07A2loMT0sfmF1MmplNGxFbmtFZnJCdGhJeWljT2d1Y2ZYSmVEa2p4WEJGY1IxMkI3Yz07A2loMj0sZU83T2Y2QlRqcjBGM3czbnVWbThxUkUyMDVqfmVFZzllcGRvNXVFVWFMWT07BWl0YWcwPQo0MDAzNDU1MDk4OwVpdGFnMT0KMzkyMzMwMDEyODsFaXRhZzI9CjIyODgxNTE2MjU7AXM9LExZbVBGTmxRNH5nOGtpdjZ5OE9MR1ZXd2VWNndvMU1pamsxWmpjNk1hazg9OwF2PQEyOwAALARjYXBzPQJMVTsFbmV0SWQ9ATI7DnJvdXRlci52ZXJzaW9uPQYwLjkuNTk75wElj2dF2Qhokil5YH4t768xImr9e49BY8n040W4HAhc2SjzfCqRv6GYThkGOlkjEa6NDcTo04DLpQlB2Xf4BA==";

    fn test_options() -> crate::ntcp2::session_request::Options {
        crate::ntcp2::session_request::Options::new(0, 16, 128, 0)
    }

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
        // let response = recv(&mut stream, 64).expect("failed to receive message");
        // println!("Got response: {:?}", response);
        // noise_session
        //     .read_message(&response, &mut buf)
        //     .expect("failed to read message");
        // println!("Read response: {:?}", &buf);
    }

    #[test]
    fn options_encoding_and_decoding() {
        let expected_options_bytes = get_test_data().session_request_options;
        let expectes_options = crate::ntcp2::session_request::Options::from(expected_options_bytes);

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
    fn test_create_noise() {
        let test_data = get_test_data();
        // let ephemeral_key = test_data.public_key;
        let options = test_options();
        // let padding = [0u8; 16];

        // let session_request = crate::ntcp2::UnencryptedSessionRequest {
        //     x: ephemeral_key,
        //     options,
        //     padding: &padding,
        // };

        let mut handshake_state =
            HandshakeState::<Ntcp2NoiseSuite>::new(test_data.peer_router_hash, test_data.peer_iv);

        handshake_state.initialize(
            crate::noise::handshake_state::ntcp2_handshake_pattern(),
            true,
            &[],
            None,
            Some(KeyPair::new(test_data.public_key, test_data.private_key)),
            Some(test_data.peer_public_key),
            None,
        );

        let padlen: usize = 16;
        let mut buf = vec![0u8; SESSION_REQUEST_CT_LEN + padlen];
        handshake_state.write_message(&options.to_bytes(), &mut buf);
        buf[SESSION_REQUEST_CT_LEN..].copy_from_slice(&test_data.cached_random[..padlen]);

        println!("SessionRequest encrypted:\t\t {:?}", &buf);
        println!(
            "SessionRequest encrypted expected:\t {:?}",
            &test_data.expected_message
        );

        // Connect to our server, which is hopefully listening.
        println!("Establishing TCP connection...");
        // let mut stream = TcpStream::connect("149.62.244.210:12345").unwrap();
        // let mut stream = TcpStream::connect("localhost:54321").unwrap();
        let mut stream = TcpStream::connect("127.0.0.1:12346").unwrap();
        println!("Connected to TCP");

        println!("Sending message...");
        send(&mut stream, &buf);
        println!("Waiting for response...");
        let resp_pad_len = 0;
        let response =
            recv(&mut stream, 32 + 32 + resp_pad_len).expect("failed to receive message");
        println!("Got response: {:?}", response);
    }

    #[test]
    fn test_noise_reference() {
        // Connect to our server, which is hopefully listening.
        println!("Establishing TCP connection...");
        // let mut stream = TcpStream::connect("149.62.244.210:12345").unwrap();
        // let mut stream = TcpStream::connect("localhost:54321").unwrap();
        let mut peer_stream = TcpStream::connect("127.0.0.1:12346").unwrap();
        println!("Connected to TCP");

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
            let router_info = base64::decode(TEST_ROUTER_IDENTITY).unwrap();
            let padding = [5, 4, 3, 2, 1];
            let options = crate::ntcp2::session_request::Options::new(
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

            send(&mut peer_stream, &message_buffer);
            send(&mut peer_stream, &padding);
        }

        // Receive SessionCreated
        {
            const SESSION_CREATED_FRAME_LEN: usize = 64;
            let session_created_frame = recv(&mut peer_stream, SESSION_CREATED_FRAME_LEN)
                .expect("failed to receive session created");
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
                crate::ntcp2::session_created::Options::from(message_buffer);

            println!(
                "Received SessionCreated options: {}",
                session_created_options
            );

            let session_created_padding_len = session_created_options.pad_len() as usize;
            let session_created_padding_frame = recv(&mut peer_stream, session_created_padding_len)
                .expect("failed to receive padding");
            println!(
                "Received session_created_padding: {:?}",
                session_created_padding_frame
            );

            reference_noise
                .set_h_data(3, &session_created_padding_frame)
                .unwrap();
            noise.set_h3(session_created_padding_frame);
        }

        // Send SessionConfirmed
        {
            let router_info = base64::decode(TEST_ROUTER_IDENTITY).unwrap();

            const NTCP2_MTU: usize = 65535;
            let mut reference_message_buffer = vec![0u8; NTCP2_MTU];
            let len = reference_noise
                .write_message(&router_info, &mut reference_message_buffer)
                .unwrap();
            println!("Reference NOISE wrote SessionConfirmed of length {}", len);

            let mut message_buffer = vec![0u8; NTCP2_MTU];
            // TODO: Write router info
            noise.write_message(&router_info, &mut message_buffer);

            assert_eq!(message_buffer, reference_message_buffer);

            send(&mut peer_stream, &message_buffer);
        }
    }
}
