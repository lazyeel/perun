// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The 347-byte Start input (SPIM), measured on the Android oracle.
//!
//! `ADIProvisioningStart` consumes exactly 347 bytes; every other length is
//! rejected with `-45033` (`invalidDataBody`). The measured anatomy is:
//!
//! ```text
//! offset  size  field
//! 0x000   264   server payload (opaque)
//! 0x108   4     Body B length, BE u32 = 52
//! 0x10c   4     Body B version, BE u32
//! 0x110   52    Body B
//! 0x144   20    integrity tag
//! 0x158   3     ignored padding
//! ```
//!
//! Start rejects a single-bit change anywhere in `[0x000..0x144)`, but it
//! accepts arbitrary changes in the last three bytes and still emits a
//! bit-identical CPIM. The tag is not identity-bound, and no standard hash of
//! the prefix, of the Body B, or of their concatenations reproduces it. The
//! type therefore validates the structure and preserves the tag opaquely; it
//! does not recompute it.

/// Total length of the SPIM, fixed by the native reader.
pub const SPIM_LEN: usize = 347;

/// Length of the opaque server-issued prefix.
pub const PAYLOAD_LEN: usize = 264;

/// Offset of the Body B length word.
pub const LENGTH_OFFSET: usize = 264;

/// Offset of the Body B version word.
pub const VERSION_OFFSET: usize = 268;

/// Offset of the Body B bytes.
pub const BODY_B_OFFSET: usize = 272;

/// Length of the Body B section.
pub const BODY_B_LEN: usize = 52;

/// Offset of the 20-byte integrity tag.
pub const TAG_OFFSET: usize = 324;

/// Length of the integrity tag.
pub const TAG_LEN: usize = 20;

/// Offset of the three ignored padding bytes.
pub const PADDING_OFFSET: usize = 344;

/// Length of the ignored padding.
pub const PADDING_LEN: usize = 3;

const _: () = assert!(BODY_B_OFFSET + BODY_B_LEN == TAG_OFFSET);
const _: () = assert!(TAG_OFFSET + TAG_LEN == PADDING_OFFSET);
const _: () = assert!(PADDING_OFFSET + PADDING_LEN == SPIM_LEN);

/// A structurally valid 347-byte Start input.
#[derive(Clone, PartialEq, Eq)]
pub struct Spim([u8; SPIM_LEN]);

impl Spim {
    /// Parse a SPIM, checking the exact length and the Body B length word.
    pub fn parse(bytes: &[u8]) -> Result<Self, SpimError> {
        if bytes.len() != SPIM_LEN {
            return Err(SpimError::BadLength { len: bytes.len() });
        }
        let declared = u32::from_be_bytes([
            bytes[LENGTH_OFFSET],
            bytes[LENGTH_OFFSET + 1],
            bytes[LENGTH_OFFSET + 2],
            bytes[LENGTH_OFFSET + 3],
        ]);
        if declared as usize != BODY_B_LEN {
            return Err(SpimError::BadBodyBLength { declared });
        }
        let mut out = [0u8; SPIM_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The raw 347 bytes.
    pub const fn as_bytes(&self) -> &[u8; SPIM_LEN] {
        &self.0
    }

    /// The server-issued prefix (`0..264`).
    pub fn payload(&self) -> &[u8] {
        &self.0[..PAYLOAD_LEN]
    }

    /// The Body B section (`272..324`).
    pub fn body_b(&self) -> &[u8] {
        &self.0[BODY_B_OFFSET..TAG_OFFSET]
    }

    /// Body B length read from the header (always [`BODY_B_LEN`] after parsing).
    pub fn body_b_len(&self) -> u32 {
        u32::from_be_bytes(
            self.0[LENGTH_OFFSET..LENGTH_OFFSET + 4]
                .try_into()
                .expect("length offset"),
        )
    }

    /// Body B version read from the header.
    pub fn body_b_version(&self) -> u32 {
        u32::from_be_bytes(
            self.0[VERSION_OFFSET..VERSION_OFFSET + 4]
                .try_into()
                .expect("version offset"),
        )
    }

    /// The opaque 20-byte integrity tag.
    pub fn tag(&self) -> &[u8] {
        &self.0[TAG_OFFSET..PADDING_OFFSET]
    }

    /// The three padding bytes the native reader ignores.
    pub fn padding(&self) -> &[u8] {
        &self.0[PADDING_OFFSET..]
    }

    /// The exact bytes.
    pub fn to_bytes(&self) -> [u8; SPIM_LEN] {
        self.0
    }
}

impl std::fmt::Debug for Spim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spim")
            .field("payload_len", &PAYLOAD_LEN)
            .field("body_b_len", &BODY_B_LEN)
            .field("body_b_version", &self.body_b_version())
            .finish_non_exhaustive()
    }
}

/// A malformed SPIM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpimError {
    /// The input is not exactly [`SPIM_LEN`] bytes.
    BadLength {
        /// Observed length.
        len: usize,
    },
    /// The Body B length word is not [`BODY_B_LEN`].
    BadBodyBLength {
        /// Declared Body B length.
        declared: u32,
    },
}

impl std::fmt::Display for SpimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength { len } => write!(f, "SPIM must be {SPIM_LEN} bytes, got {len}"),
            Self::BadBodyBLength { declared } => write!(
                f,
                "SPIM Body B length {declared:#x} differs from {BODY_B_LEN:#x}"
            ),
        }
    }
}

impl std::error::Error for SpimError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; SPIM_LEN] {
        let mut out = [0u8; SPIM_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(31).wrapping_add(5);
        }
        out[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&(BODY_B_LEN as u32).to_be_bytes());
        out[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&4u32.to_be_bytes());
        out
    }

    #[test]
    fn anatomy_is_the_measured_one() {
        assert_eq!(PAYLOAD_LEN, 264);
        assert_eq!(BODY_B_OFFSET, 272);
        assert_eq!(BODY_B_LEN, 52);
        assert_eq!(TAG_OFFSET, 324);
        assert_eq!(TAG_LEN, 20);
        assert_eq!(PADDING_OFFSET, 344);
        assert_eq!(PADDING_LEN, 3);
        assert_eq!(SPIM_LEN, 347);
    }

    #[test]
    fn parse_round_trips_the_bytes() {
        let raw = sample();
        let spim = Spim::parse(&raw).expect("valid");
        assert_eq!(spim.payload(), &raw[..PAYLOAD_LEN]);
        assert_eq!(spim.body_b_len(), BODY_B_LEN as u32);
        assert_eq!(spim.body_b_version(), 4);
        assert_eq!(spim.body_b(), &raw[BODY_B_OFFSET..TAG_OFFSET]);
        assert_eq!(spim.tag(), &raw[TAG_OFFSET..PADDING_OFFSET]);
        assert_eq!(spim.padding(), &raw[PADDING_OFFSET..]);
        assert_eq!(spim.to_bytes(), raw);
    }

    #[test]
    fn length_must_be_exact() {
        for len in [0, 346, 348, 411] {
            assert_eq!(
                Spim::parse(&vec![0u8; len]).unwrap_err(),
                SpimError::BadLength { len }
            );
        }
    }

    #[test]
    fn body_b_length_word_is_checked() {
        let mut raw = sample();
        raw[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&51u32.to_be_bytes());
        assert_eq!(
            Spim::parse(&raw).unwrap_err(),
            SpimError::BadBodyBLength { declared: 51 }
        );
    }

    #[test]
    fn tag_and_padding_are_preserved_opaquely() {
        let mut raw = sample();
        raw[TAG_OFFSET..PADDING_OFFSET].fill(0xEE);
        raw[PADDING_OFFSET..].fill(0xFF);
        let spim = Spim::parse(&raw).expect("valid");
        assert!(spim.tag().iter().all(|&byte| byte == 0xEE));
        assert!(spim.padding().iter().all(|&byte| byte == 0xFF));
        assert_eq!(spim.to_bytes(), raw);
    }
}
