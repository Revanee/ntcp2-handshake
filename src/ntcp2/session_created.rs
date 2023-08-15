use std::array::TryFromSliceError;

/// +----+----+----+----+----+----+----+----+
/// |                                       |
/// +                                       +
/// |                  Y                    |
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
pub struct SessionCreated {
    buf: Vec<u8>,
}

impl SessionCreated {
    /// 32 bytes, X25519 ephemeral key, little endian
    pub fn y(&self) -> [u8; 32] {
        self.buf[0..32].try_into().expect("failed to get y")
    }

    /// options block, 16 bytes, see below
    pub fn options(&self) -> [u8; 16] {
        self.buf[32..48].try_into().expect("failed to get options")
    }

    /// Random data, 0 or more bytes.
    /// Total message length must be 65535 bytes or less.
    /// Alice and Bob will use the padding data in the KDF for message 3 part 1.
    /// It is authenticated so that any tampering will cause the
    /// next message to fail.
    pub fn padding(&self) -> &[u8] {
        &self.buf[48..]
    }
}

/// +----+----+----+----+----+----+----+----+
/// | Rsvd(0) | padLen  |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
/// |        tsB        |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
pub struct Options([u8; 16]);

impl Options {
    /// Reserved :: 10 bytes total, set to 0 for compatibility with future options
    pub fn reserved(&self) -> [u8; 10] {
        self.0[0..10].try_into().expect("failed to get reserved")
    }
    /// 2 bytes, big endian, length of the padding, 0 or more
    /// Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
    /// (Distribution is implementation-dependent)
    pub fn pad_len(&self) -> u16 {
        u16::from_be_bytes(self.0[10..12].try_into().expect("failed to get pad_len"))
    }

    /// 4 bytes, big endian, Unix timestamp, unsigned seconds.
    /// Wraps around in 2106
    pub fn ts_b(&self) -> u32 {
        u32::from_be_bytes(self.0[12..16].try_into().expect("failed to get ts_b"))
    }
}

impl From<[u8; 16]> for Options {
    fn from(buf: [u8; 16]) -> Self {
        Self(buf)
    }
}

impl TryFrom<&[u8]> for Options {
    type Error = TryFromSliceError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(buf.try_into()?))
    }
}
