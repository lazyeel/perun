// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The 16-byte ADI device identity, the `adi_identifier` file.
//!
//! The native harness stores it as raw bytes, but the ADI API also accepts
//! the 32-character hex form. This module keeps the two representations
//! strict and names the rule the state container depends on: only the first
//! eight bytes are bound ([`Identity::bound`]); the last eight are accepted
//! and ignored by the native reader.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

/// Length of the raw device identity.
pub const IDENTITY_LEN: usize = 16;

/// Number of leading identity bytes the provisioning state is bound to.
pub const IDENTITY_BIND_LEN: usize = 8;

/// A 16-byte ADI device identity.
///
/// `Debug` is redacted so an identity cannot leak into a log or an error
/// report by accident. Use [`Identity::to_hex`] only at a local harness
/// boundary.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity([u8; IDENTITY_LEN]);

impl Identity {
    /// Wrap exactly [`IDENTITY_LEN`] bytes.
    pub const fn from_bytes(bytes: [u8; IDENTITY_LEN]) -> Self {
        Self(bytes)
    }

    /// Read the 16 raw bytes from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, IdentityError> {
        let bytes: [u8; IDENTITY_LEN] = bytes
            .try_into()
            .map_err(|_| IdentityError::BadLength { len: bytes.len() })?;
        Ok(Self(bytes))
    }

    /// Parse the 32-character lowercase or uppercase hex form.
    ///
    /// `0x` prefixes, dashes, spaces and newlines are rejected: an identity
    /// in a log must be unambiguous.
    pub fn from_hex(text: &str) -> Result<Self, IdentityError> {
        let bytes = text.as_bytes();
        if bytes.len() != IDENTITY_LEN * 2 {
            return Err(IdentityError::BadLength { len: bytes.len() });
        }
        let mut out = [0u8; IDENTITY_LEN];
        for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            let high = hex_nibble(pair[0]).ok_or(IdentityError::BadHex { index: index * 2 })?;
            let low = hex_nibble(pair[1]).ok_or(IdentityError::BadHex {
                index: index * 2 + 1,
            })?;
            out[index] = (high << 4) | low;
        }
        Ok(Self(out))
    }

    /// The 16 bytes as stored in `adi_identifier`.
    pub const fn as_bytes(&self) -> &[u8; IDENTITY_LEN] {
        &self.0
    }

    /// The first eight bytes, the identity half the native state checks.
    pub fn bound(&self) -> &[u8; IDENTITY_BIND_LEN] {
        self.0[..IDENTITY_BIND_LEN]
            .try_into()
            .expect("bound identity length")
    }

    /// Lowercase 32-character hex.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(IDENTITY_LEN * 2);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }

    /// Read raw bytes from `path`.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let bytes = std::fs::read(path.as_ref()).map_err(IdentityError::Io)?;
        Self::from_slice(&bytes)
    }

    /// Write raw bytes to `path` with mode `0600` on Unix.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(IdentityError::Io)?;
        file.write_all(&self.0).map_err(IdentityError::Io)?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(IdentityError::Io)?;
        }
        Ok(())
    }

    /// Read 16 fresh bytes from `/dev/urandom`.
    pub fn random() -> Result<Self, IdentityError> {
        let mut bytes = [0u8; IDENTITY_LEN];
        let mut source = std::fs::File::open("/dev/urandom").map_err(IdentityError::Io)?;
        source.read_exact(&mut bytes).map_err(IdentityError::Io)?;
        if bytes.iter().all(|&byte| byte == bytes[0]) {
            return Err(IdentityError::NotRandom);
        }
        Ok(Self(bytes))
    }

    /// Whether the whole identity is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&byte| byte == 0)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity(<redacted>)")
    }
}

/// A malformed identity or an identity file error.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
    /// The input is not exactly [`IDENTITY_LEN`] bytes or 32 hex characters.
    BadLength { len: usize },
    /// The hex character at `index` is not `[0-9a-fA-F]`.
    BadHex { index: usize },
    /// The file could not be read or written.
    Io(std::io::Error),
    /// `/dev/urandom` returned the same byte sixteen times.
    NotRandom,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { len } => {
                write!(
                    f,
                    "identity must be 16 bytes or 32 hex characters, got {len}"
                )
            }
            Self::BadHex { index } => write!(f, "invalid hex digit at index {index}"),
            Self::Io(error) => write!(f, "i/o: {error}"),
            Self::NotRandom => f.write_str("the random source returned a constant identity"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes() -> [u8; IDENTITY_LEN] {
        let mut out = [0u8; IDENTITY_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(0x2a);
        }
        out
    }

    #[test]
    fn hex_round_trips() {
        let identity = Identity::from_bytes(bytes());
        let hex = identity.to_hex();
        assert_eq!(hex.len(), IDENTITY_LEN * 2);
        assert_eq!(Identity::from_hex(&hex).unwrap(), identity);
        assert_eq!(Identity::from_hex(&hex.to_uppercase()).unwrap(), identity);
    }

    #[test]
    fn slice_round_trips_and_checks_length() {
        let identity = Identity::from_bytes(bytes());
        assert_eq!(Identity::from_slice(identity.as_bytes()).unwrap(), identity);

        let short = [0u8; IDENTITY_LEN - 1];
        assert!(matches!(
            Identity::from_slice(&short),
            Err(IdentityError::BadLength { len: 15 })
        ));
    }

    #[test]
    fn malformed_hex_is_rejected_at_the_exact_index() {
        let hex = Identity::from_bytes(bytes()).to_hex();
        for &bad in b"x \n" {
            let mut text = hex.clone().into_bytes();
            text[10] = bad;
            let text = String::from_utf8(text).unwrap();
            assert!(matches!(
                Identity::from_hex(&text),
                Err(IdentityError::BadHex { index: 10 })
            ));
        }
        assert!(matches!(
            Identity::from_hex("abc"),
            Err(IdentityError::BadLength { len: 3 })
        ));
    }

    #[test]
    fn bound_is_the_first_half() {
        let identity = Identity::from_bytes(bytes());
        assert_eq!(identity.bound(), &bytes()[..IDENTITY_BIND_LEN]);

        let mut other = bytes();
        other[IDENTITY_BIND_LEN] ^= 1;
        assert_eq!(identity.bound(), Identity::from_bytes(other).bound());
    }

    #[test]
    fn zero_is_detected() {
        assert!(Identity::from_bytes([0u8; IDENTITY_LEN]).is_zero());
        assert!(!Identity::from_bytes(bytes()).is_zero());
    }

    #[test]
    fn debug_is_redacted() {
        let text = format!("{:?}", Identity::from_bytes(bytes()));
        assert_eq!(text, "Identity(<redacted>)");
    }
}
