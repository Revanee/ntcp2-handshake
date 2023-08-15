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

use std::array::TryFromSliceError;

pub const NTCP2_NOISE_ID: &str = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";

/// Session Request
/// +----+----+----+----+----+----+----+----+
/// |                                       |
/// +        obfuscated with RH_B           +
/// |       AES-CBC-256 encrypted X         |
/// +             (32 bytes)                +
/// |                                       |
/// +                                       +
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// |                                       |
/// +                                       +
/// |   ChaChaPoly frame                    |
/// +             (32 bytes)                +
/// |   k defined in KDF for message 1      |
/// +   n = 0                               +
/// |   see KDF for associated data         |
/// +----+----+----+----+----+----+----+----+
/// |     unencrypted authenticated         |
/// ~         padding (optional)            ~
/// |     length defined in options block   |
/// +----+----+----+----+----+----+----+----+
#[derive(Debug)]
pub struct SessionRequest<'a> {
    /// 32 bytes, AES-256-CBC encrypted X25519 ephemeral key, little endian
    /// key: RH_B
    /// iv: As published in Bobs network database entry
    x: [u8; 32],

    /// ChaChaPoly frame (32 bytes)
    /// k defined in KDF for message 1
    /// n = 0                         
    /// see KDF for associated data   
    _chachapoly_frame: [u8; 32],

    /// Random data, 0 or more bytes.
    /// Total message length must be 65535 bytes or less.
    /// Total message length must be 287 bytes or less if
    /// Bob is publishing his address as NTCP
    /// (see Version Detection section below).
    /// Alice and Bob will use the padding data in the KDF for message 2.
    /// It is authenticated so that any tampering will cause the
    /// next message to fail.
    padding: &'a [u8],
}

impl SessionRequest<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.padding.len());
        buf.extend_from_slice(&self.x);
        // TODO: Figure out how to get the ChaChaPoly frame
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(self.padding);
        buf
    }

    pub fn decrypt(&self) -> UnencryptedSessionRequest {
        todo!()
    }
}

impl<'a> TryFrom<&'a [u8]> for SessionRequest<'a> {
    type Error = TryFromSliceError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            x: bytes[0..32].try_into()?,
            _chachapoly_frame: bytes[32..64].try_into()?,
            padding: &bytes[64..],
        })
    }
}

/// Unencrypted Data
/// Poly1305 authentication tag not shown
/// +----+----+----+----+----+----+----+----+
/// |                                       |
/// +                                       +
/// |                   X                   |
/// +              (32 bytes)               +
/// |                                       |
/// +                                       +
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// |               options                 |
/// +              (16 bytes)               +
/// |                                       |
/// +----+----+----+----+----+----+----+----+
/// |     unencrypted authenticated         |
/// +         padding (optional)            +
/// |     length defined in options block   |
/// ~               .   .   .               ~
/// |                                       |
/// +----+----+----+----+----+----+----+----+
#[derive(Debug)]
pub struct UnencryptedSessionRequest<'a> {
    /// 32 bytes, X25519 ephemeral key, little endian
    pub x: [u8; 32],

    /// options block, 16 bytes, see below
    pub options: Options,

    /// Random data, 0 or more bytes.
    /// Total message length must be 65535 bytes or less.
    /// Total message length must be 287 bytes or less if
    /// Bob is publishing his address as "NTCP"
    /// (see Version Detection section below)
    /// Alice and Bob will use the padding data in the KDF for message 2.
    /// It is authenticated so that any tampering will cause the
    /// next message to fail.
    pub padding: &'a [u8],
}

impl<'a> UnencryptedSessionRequest<'a> {
    pub fn new(key: [u8; 32], options: Options, padding: &'a [u8]) -> Self {
        Self {
            x: key,
            options,
            padding,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.x.as_slice(), &self.options.to_bytes(), self.padding].concat()
    }
}

/// Options block
/// All fields are big-endian
/// +----+----+----+----+----+----+----+----+
/// | id | ver|  padLen | m3p2len | Rsvd(0) |
/// +----+----+----+----+----+----+----+----+
/// |        tsA        |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
#[derive(Debug)]
pub struct Options {
    /// 1 byte, the network ID (currently 2, except for test networks)
    /// As of 0.9.42. See proposal 147.
    pub id: u8,

    /// 1 byte, protocol version (currently 2)
    pub ver: u8,

    /// 2 bytes, length of the padding, 0 or more
    /// Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
    /// (Distribution is implementation-dependent)
    pub pad_len: [u8; 2],

    /// 2 bytes, length of the the second AEAD frame in SessionConfirmed
    /// (message 3 part 2) See notes below
    pub m3p2_len: [u8; 2],

    /// 2 bytes, set to 0 for compatibility with future options
    pub rsvd: [u8; 2],

    /// 4 bytes, Unix timestamp, unsigned seconds.
    /// Wraps around in 2106
    pub tsa: [u8; 4],

    /// 4 bytes, set to 0 for compatibility with future options
    pub reserved: [u8; 4],
}

impl Options {
    pub fn new() -> Self {
        let router_info_len: u16 = 1337;
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("failed to read the time")
            .as_secs();
        let pad_len = [0u8; 2];
        let m3p2_len = router_info_len.to_be_bytes();
        let tsa: [u8; 4] = match seconds.to_be_bytes() {
            [.., a, b, c, d] => [a, b, c, d],
        };
        let reserved = [0u8; 4];
        Self {
            id: 2,
            ver: 2,
            pad_len,
            m3p2_len,
            rsvd: [0, 0],
            tsa,
            reserved,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        [
            self.id,
            self.ver,
            self.pad_len[0],
            self.pad_len[1],
            self.m3p2_len[0],
            self.m3p2_len[1],
            self.rsvd[0],
            self.rsvd[1],
            self.tsa[0],
            self.tsa[1],
            self.tsa[2],
            self.tsa[3],
            self.reserved[0],
            self.reserved[1],
            self.reserved[2],
            self.reserved[3],
        ]
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; 16]> for Options {
    fn from(bytes: [u8; 16]) -> Self {
        let mut pad_len = [0u8; 2];
        pad_len.copy_from_slice(&bytes[2..4]);
        let mut m3p2_len = [0u8; 2];
        m3p2_len.copy_from_slice(&bytes[4..6]);
        let mut rsvd = [0u8; 2];
        rsvd.copy_from_slice(&bytes[6..8]);
        let mut tsa = [0u8; 4];
        tsa.copy_from_slice(&bytes[8..12]);
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&bytes[12..16]);
        Self {
            id: bytes[0],
            ver: bytes[1],
            pad_len,
            m3p2_len,
            rsvd,
            tsa,
            reserved,
        }
    }
}
