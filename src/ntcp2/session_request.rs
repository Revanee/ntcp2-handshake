use std::{array::TryFromSliceError, fmt::Display};

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
#[derive(Debug, Clone)]
pub struct SessionRequest {
    buf: Vec<u8>,
}

impl SessionRequest {
    pub const fn len() -> usize {
        64
    }

    /// 32 bytes, AES-256-CBC encrypted X25519 ephemeral key, little endian
    /// key: RH_B
    /// iv: As published in Bobs network database entry
    pub fn x(&self) -> [u8; 32] {
        self.buf[0..32].try_into().expect("failed to get x")
    }

    /// ChaChaPoly frame (32 bytes)
    /// k defined in KDF for message 1
    /// n = 0                         
    /// see KDF for associated data   
    pub fn chachapoly_frame(&self) -> [u8; 32] {
        self.buf[32..64]
            .try_into()
            .expect("failed to get chachapoly_frame")
    }

    /// Random data, 0 or more bytes.
    /// Total message length must be 65535 bytes or less.
    /// Total message length must be 287 bytes or less if
    /// Bob is publishing his address as NTCP
    /// (see Version Detection section below).
    /// Alice and Bob will use the padding data in the KDF for message 2.
    /// It is authenticated so that any tampering will cause the
    /// next message to fail.
    pub fn padding(&self) -> &[u8] {
        self.buf[64..].as_ref()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl TryFrom<&[u8]> for SessionRequest {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let x = bytes[0..32].try_into()?;
        let chachapoly_frame = bytes[32..64].try_into()?;
        let padding = &bytes[64..];
        Ok(Self {
            buf: [x, chachapoly_frame, padding].concat(),
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
#[derive(Debug, Clone)]
pub struct UnencryptedSessionRequest {
    buf: Vec<u8>,
    pad_len: usize,
}

impl UnencryptedSessionRequest {
    /// 32 bytes, X25519 ephemeral key, little endian
    pub fn x(&self) -> [u8; 32] {
        self.buf[0..32].try_into().expect("failed to get x")
    }

    /// options block, 16 bytes, see below
    pub fn options(&self) -> Options {
        Options::try_from(&self.buf[32..48]).expect("failed to get options")
    }

    /// Random data, 0 or more bytes.
    /// Total message length must be 65535 bytes or less.
    /// Total message length must be 287 bytes or less if
    /// Bob is publishing his address as "NTCP"
    /// (see Version Detection section below)
    /// Alice and Bob will use the padding data in the KDF for message 2.
    /// It is authenticated so that any tampering will cause the
    /// next message to fail.
    pub fn padding(&self) -> &[u8] {
        self.buf[48..(48 + self.pad_len)].as_ref()
    }
}

impl UnencryptedSessionRequest {
    pub fn new(key: [u8; 32], options: Options, padding: &[u8]) -> Self {
        Self {
            buf: [key.as_slice(), options.to_bytes().as_slice(), padding].concat(),
            pad_len: padding.len(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

/// Options block
/// All fields are big-endian
/// +----+----+----+----+----+----+----+----+
/// | id | ver|  padLen | m3p2len | Rsvd(0) |
/// +----+----+----+----+----+----+----+----+
/// |        tsA        |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
#[derive(Debug, Clone, Copy)]
pub struct Options([u8; 16]);

impl Options {
    pub fn new(network_id: u8, pad_len: u16, m3p2_len: u16, tsa: u32) -> Self {
        let rsvd = [0u8; 2];
        let reserved = [0u8; 4];
        let ver: u8 = 2;
        Self(
            [
                network_id.to_be_bytes().as_slice(),
                ver.to_be_bytes().as_slice(),
                pad_len.to_be_bytes().as_slice(),
                m3p2_len.to_be_bytes().as_slice(),
                rsvd.as_slice(),
                tsa.to_be_bytes().as_slice(),
                reserved.as_slice(),
            ]
            .concat()
            .try_into()
            .expect("failed to construct options"),
        )
    }

    /// 1 byte, the network ID (currently 2, except for test networks)
    /// As of 0.9.42. See proposal 147.
    pub fn id(&self) -> u8 {
        self.0[0]
    }

    /// 1 byte, protocol version (currently 2)
    pub fn ver(&self) -> u8 {
        self.0[1]
    }

    /// 2 bytes, length of the padding, 0 or more
    /// Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
    /// (Distribution is implementation-dependent)
    pub fn pad_len(&self) -> [u8; 2] {
        self.0[2..4].try_into().expect("failed to get pad_len")
    }

    /// 2 bytes, length of the the second AEAD frame in SessionConfirmed
    /// (message 3 part 2) See notes below
    pub fn m3p2_len(&self) -> [u8; 2] {
        self.0[4..6].try_into().expect("failed to get m3p2_len")
    }

    /// 2 bytes, set to 0 for compatibility with future options
    pub fn rsvd(&self) -> [u8; 2] {
        self.0[6..8].try_into().expect("failed to get rsvd")
    }

    /// 4 bytes, Unix timestamp, unsigned seconds.
    /// Wraps around in 2106
    pub fn tsa(&self) -> [u8; 4] {
        self.0[8..12].try_into().expect("failed to get tsa")
    }

    /// 4 bytes, set to 0 for compatibility with future options
    pub fn reserved(&self) -> [u8; 4] {
        self.0[12..16].try_into().expect("failed to get reserved")
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Default for Options {
    fn default() -> Self {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("failed to read the time")
            .as_secs();
        Self::new(2, 0, 0, seconds as u32)
    }
}

impl From<[u8; 16]> for Options {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for Options {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(bytes.try_into()?))
    }
}

impl Display for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Options (id: {}, pad_len: {}, m3p2_len: {}, tsa: {}",
            self.id(),
            u16::from_be_bytes(self.pad_len()),
            u16::from_be_bytes(self.m3p2_len()),
            u32::from_be_bytes(self.tsa()),
        ))?;

        Ok(())
    }
}
