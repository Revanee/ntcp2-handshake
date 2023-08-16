use self::suite::DHLEN;

pub mod cipher_state;
pub mod handshake_state;
pub mod suite;
pub mod symmetric_state;

#[derive(Debug, Clone, Copy)]
pub struct KeyPair {
    pub public: Key,
    pub private: Key,
}

impl KeyPair {
    pub fn new(public: Key, private: Key) -> Self {
        Self { public, private }
    }
}

pub type Key = [u8; DHLEN];

#[derive(Debug, Clone, Copy)]
pub struct Aes256Obfuscator {
    /// The key used for AES-256. In NTCP2 it's the peer router hash.
    key: [u8; 32],
    /// The initialization vector used for AES-256. In NTCP2 it's the peer IV.
    iv: [u8; 16],
}

impl Aes256Obfuscator {
    pub fn obfuscate(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut cipher = crypto::aes::cbc_encryptor(
            crypto::aes::KeySize::KeySize256,
            &self.key,
            &self.iv,
            crypto::blockmodes::NoPadding,
        );
        let mut input = crypto::buffer::RefReadBuffer::new(plaintext);
        let mut output = crypto::buffer::RefWriteBuffer::new(out);
        cipher
            .encrypt(&mut input, &mut output, true)
            .expect("failed to encrypt");
        self.iv.copy_from_slice(&out[out.len() - 16..]);
        out.len()
    }

    fn deobfuscate(&mut self, obfusctext: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        let mut cipher = crypto::aes::cbc_decryptor(
            crypto::aes::KeySize::KeySize256,
            &self.key,
            &self.iv,
            crypto::blockmodes::NoPadding,
        );
        let mut input = crypto::buffer::RefReadBuffer::new(obfusctext);
        let mut output = crypto::buffer::RefWriteBuffer::new(out);
        match cipher.decrypt(&mut input, &mut output, true) {
            Ok(_) => {
                self.iv
                    .copy_from_slice(&obfusctext[obfusctext.len() - 16..]);
                Ok(obfusctext.len())
            }
            Err(_) => Err(()),
        }
    }
}
