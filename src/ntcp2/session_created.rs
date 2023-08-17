use std::{array::TryFromSliceError, fmt::Display};

/// +----+----+----+----+----+----+----+----+
/// | Rsvd(0) | padLen  |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
/// |        tsB        |   Reserved (0)    |
/// +----+----+----+----+----+----+----+----+
pub struct SessionCreated([u8; 16]);

impl SessionCreated {
    /// Reserved :: 10 bytes total, set to 0 for compatibility with future options
    pub fn reserved(&self) -> [u8; 10] {
        [&self.0[0..2], &self.0[4..8], &self.0[12..16]]
            .concat()
            .try_into()
            .expect("failed to get reserved")
    }
    /// 2 bytes, big endian, length of the padding, 0 or more
    /// Min/max guidelines TBD. Random size from 0 to 31 bytes minimum?
    /// (Distribution is implementation-dependent)
    pub fn pad_len(&self) -> u16 {
        u16::from_be_bytes(self.0[2..4].try_into().expect("failed to get pad_len"))
    }

    /// 4 bytes, big endian, Unix timestamp, unsigned seconds.
    /// Wraps around in 2106
    pub fn ts_b(&self) -> u32 {
        u32::from_be_bytes(self.0[8..12].try_into().expect("failed to get ts_b"))
    }
}

impl From<[u8; 16]> for SessionCreated {
    fn from(buf: [u8; 16]) -> Self {
        Self(buf)
    }
}

impl TryFrom<&[u8]> for SessionCreated {
    type Error = TryFromSliceError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(buf.try_into()?))
    }
}

impl Display for SessionCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            format!(
                "SessionCreated (pad_len: {}, ts_b: {})",
                self.pad_len(),
                self.ts_b()
            )
            .as_str(),
        )?;

        Ok(())
    }
}
