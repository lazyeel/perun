// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The provisioning state: Perun's own versioned container, plus a
//! lossless codec for Apple's `adi.pb`.
//!
//! # Why an own container
//!
//! The Android oracle persists the end of provisioning as a single
//! `adi-data/adi.pb` file. Its measured layout is a big-endian
//! `version`/`n` header, an `n`-byte blob and a fixed 580-byte tail. The
//! native reader authenticates every byte of that file, but the tail's
//! structure is not lifted and cannot be regenerated from the identity
//! alone. The campaign plan therefore gives the final engine its own
//! versioned format and keeps the Apple file only as an interop codec
//! (`research-runs/plan-autonomous-anisette-2026-11-16.md`, section 4).
//!
//! # Container v1
//!
//! ```text
//! offset  size  field
//! 0x00    8     magic "PERUNST\0"
//! 0x08    4     format version, BE u32, currently 1
//! 0x0c    4     flags, BE u32, must be zero
//! 0x10    4     body length, BE u32
//! 0x14    32    HMAC-SHA-256 tag over bytes 0x00..0x14 and the body
//! 0x34    ...   body
//! ```
//!
//! # Body
//!
//! The body is a canonical TLV stream: a one-byte tag, a two-byte
//! big-endian length and the value. Tags must appear in strictly
//! ascending order, at most once, and all mandatory tags must be
//! present. There is no padding and no trailing data.
//!
//! ```text
//! tag  field           length
//! 1    identity        8
//! 2    session         4
//! 3    provisioned_at  8
//! 4    cpim            276
//! 5    ptm             487
//! 6    tk              16
//! 7    spim            variable, optional
//! ```
//!
//! # Identity binding
//!
//! The record is bound to the first eight bytes of the 16-byte
//! `adi_identifier`, which is what the native engine checks: mutating a
//! byte in `adi_identifier[0..8]` makes the native reader reject the
//! state with `-45061`, while mutating `adi_identifier[8..16]` leaves it
//! accepted. The tag key is derived from those same eight bytes, so a
//! state presented with a different device identity fails both the
//! explicit comparison and the tag check.
//!
//! The derivation is public: the tag detects corruption and accidental
//! cross-device copies, not a local attacker who knows the identity and
//! can re-seal the record. Confidentiality is not provided; the CPIM,
//! PTM and TK are stored in the clear.
//!
//! # Apple codec
//!
//! [`AppleState`] parses and re-encodes the native file without
//! interpreting the blob or the tail. It is deliberately structural:
//! every version is preserved so a capture round-trips byte for byte,
//! while [`AppleState::is_native_supported`] reports whether the native
//! Android reader would accept that version.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::identity::Identity;
use crate::sha256;

/// Magic of the Perun state container.
pub const MAGIC: &[u8; 8] = b"PERUNST\0";

/// Version of the Perun state container written by this module.
pub const FORMAT_VERSION: u32 = 1;

/// Length of the fixed container header, including the tag.
pub const HEADER_LEN: usize = HEADER_PREFIX_LEN + TAG_LEN;

/// Length of the container header before the tag.
pub const HEADER_PREFIX_LEN: usize = 8 + 4 + 4 + 4;

/// Length of the HMAC-SHA-256 tag.
pub const TAG_LEN: usize = 32;

/// Number of `adi_identifier` bytes the state is bound to.
pub const IDENTITY_BIND_LEN: usize = crate::identity::IDENTITY_BIND_LEN;

/// Length of the full `adi_identifier` file.
pub const IDENTIFIER_LEN: usize = crate::identity::IDENTITY_LEN;

/// Length of the CPIM section.
pub const CPIM_LEN: usize = 276;

/// Length of the PTM section.
pub const PTM_LEN: usize = 487;

/// Length of the transaction key.
pub const TK_LEN: usize = 16;

/// Apple container version accepted by the native Android reader.
pub const APPLE_VERSION: u32 = 1;

/// Apple container header: two big-endian `u32` values.
pub const APPLE_HEADER_LEN: usize = 8;

/// Fixed Apple container tail.
pub const APPLE_TAIL_LEN: usize = 580;

const KEY_CONTEXT: &[u8] = b"perun-adi state key v1";

/// A provisioning record, independent of any on-disk container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningRecord {
    /// First eight bytes of the device's 16-byte `adi_identifier`.
    pub identity: [u8; IDENTITY_BIND_LEN],
    /// 32-bit session value passed to `ProvisioningEnd`.
    pub session: u32,
    /// Unix seconds at which provisioning completed.
    pub provisioned_at: u64,
    /// 276-byte CPIM produced locally during provisioning.
    pub cpim: [u8; CPIM_LEN],
    /// 487-byte PTM returned by `finishMachineProvisioning`.
    pub ptm: [u8; PTM_LEN],
    /// 16-byte transaction key returned by `finishMachineProvisioning`.
    pub tk: [u8; TK_LEN],
    /// Optional SPIM returned by `startMachineProvisioning`.
    pub spim: Option<Vec<u8>>,
}

impl ProvisioningRecord {
    fn encode_body(&self) -> Result<Vec<u8>, StateError> {
        let spim_len = self.spim.as_ref().map_or(0, Vec::len);
        let mut body = Vec::with_capacity(
            7 * 3 + IDENTITY_BIND_LEN + 4 + 8 + CPIM_LEN + PTM_LEN + TK_LEN + spim_len,
        );
        put(&mut body, Tag::Identity, &self.identity);
        put(&mut body, Tag::Session, &self.session.to_be_bytes());
        put(
            &mut body,
            Tag::ProvisionedAt,
            &self.provisioned_at.to_be_bytes(),
        );
        put(&mut body, Tag::Cpim, &self.cpim);
        put(&mut body, Tag::Ptm, &self.ptm);
        put(&mut body, Tag::Tk, &self.tk);
        if let Some(spim) = &self.spim {
            if spim.is_empty() || spim.len() > usize::from(u16::MAX) {
                return Err(StateError::FieldLength {
                    tag: Tag::Spim.byte(),
                    len: spim.len(),
                });
            }
            put(&mut body, Tag::Spim, spim);
        }
        Ok(body)
    }

    fn decode_body(body: &[u8]) -> Result<Self, StateError> {
        let mut identity = None;
        let mut session = None;
        let mut provisioned_at = None;
        let mut cpim = None;
        let mut ptm = None;
        let mut tk = None;
        let mut spim = None;

        let mut seen = 0u8;
        let mut last = None;
        let mut rest = body;

        while !rest.is_empty() {
            if rest.len() < 3 {
                return Err(StateError::TruncatedField);
            }
            let tag_byte = rest[0];
            let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
            let Some(tag) = Tag::from_byte(tag_byte) else {
                return Err(StateError::UnknownField(tag_byte));
            };
            if len > rest.len() - 3 {
                return Err(StateError::TruncatedField);
            }
            let value = &rest[3..3 + len];
            rest = &rest[3 + len..];

            let bit = 1u8 << tag_byte;
            if seen & bit != 0 {
                return Err(StateError::DuplicateField(tag_byte));
            }
            if let Some(previous) = last {
                if tag <= previous {
                    return Err(StateError::FieldOrder(tag_byte));
                }
            }
            seen |= bit;
            last = Some(tag);

            match tag {
                Tag::Identity => identity = Some(fixed::<IDENTITY_BIND_LEN>(value, tag)?),
                Tag::Session => session = Some(u32::from_be_bytes(fixed::<4>(value, tag)?)),
                Tag::ProvisionedAt => {
                    provisioned_at = Some(u64::from_be_bytes(fixed::<8>(value, tag)?));
                }
                Tag::Cpim => cpim = Some(fixed::<CPIM_LEN>(value, tag)?),
                Tag::Ptm => ptm = Some(fixed::<PTM_LEN>(value, tag)?),
                Tag::Tk => tk = Some(fixed::<TK_LEN>(value, tag)?),
                Tag::Spim => {
                    if value.is_empty() {
                        return Err(StateError::FieldLength {
                            tag: tag_byte,
                            len: 0,
                        });
                    }
                    spim = Some(value.to_vec());
                }
            }
        }

        Ok(Self {
            identity: identity.ok_or(StateError::MissingField(Tag::Identity.byte()))?,
            session: session.ok_or(StateError::MissingField(Tag::Session.byte()))?,
            provisioned_at: provisioned_at
                .ok_or(StateError::MissingField(Tag::ProvisionedAt.byte()))?,
            cpim: cpim.ok_or(StateError::MissingField(Tag::Cpim.byte()))?,
            ptm: ptm.ok_or(StateError::MissingField(Tag::Ptm.byte()))?,
            tk: tk.ok_or(StateError::MissingField(Tag::Tk.byte()))?,
            spim,
        })
    }
}

/// Seal a provisioning record into a v1 container.
pub fn seal(record: &ProvisioningRecord) -> Result<Vec<u8>, StateError> {
    let body = record.encode_body()?;
    Ok(seal_body(&body, &record.identity))
}

/// Open a v1 container and verify it belongs to `identifier`.
///
/// Only the first eight bytes of `identifier` participate in the binding;
/// the remaining eight are accepted but ignored, matching the native
/// engine's measured behaviour.
///
/// The body is parsed strictly before the tag is checked so that an
/// identity mismatch is reported as such rather than as a generic tag
/// failure. No record is returned until the tag has been verified.
pub fn open(bytes: &[u8], identifier: &Identity) -> Result<ProvisioningRecord, StateError> {
    open_bound(bytes, identifier.bound())
}

/// Read and open a state file.
pub fn load(
    path: impl AsRef<Path>,
    identifier: &Identity,
) -> Result<ProvisioningRecord, StateIoError> {
    let bytes = std::fs::read(path.as_ref())?;
    Ok(open(&bytes, identifier)?)
}

/// Seal a record and write it as one state file.
///
/// The file is opened without `O_TRUNC`, truncated to the final container
/// size, and overwritten with one buffer, matching the native writer's
/// measured `open` -> `ftruncate` -> `write` -> `close` sequence. Parent
/// directories are not created, and there is no temporary file or rename.
pub fn store(path: impl AsRef<Path>, record: &ProvisioningRecord) -> Result<(), StateIoError> {
    let bytes = seal(record)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.as_ref())?;
    file.set_len(bytes.len() as u64)?;
    file.write_all(&bytes)?;
    Ok(())
}

/// Apple's `adi.pb` container, preserved without interpreting its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleState {
    version: u32,
    blob: Vec<u8>,
    tail: [u8; APPLE_TAIL_LEN],
}

impl AppleState {
    /// Build a version-1 Apple container from a blob and a tail.
    pub fn new(blob: Vec<u8>, tail: [u8; APPLE_TAIL_LEN]) -> Result<Self, StateError> {
        if u32::try_from(blob.len()).is_err() {
            return Err(StateError::AppleBlobTooLong(blob.len()));
        }
        Ok(Self {
            version: APPLE_VERSION,
            blob,
            tail,
        })
    }

    /// Parse a file as `version`, `n`, `n` blob bytes and a 580-byte tail.
    ///
    /// This is a structural codec: it preserves the version so captures
    /// round-trip byte for byte. The native Android reader rejects any
    /// version other than 1; use [`Self::is_native_supported`] to check.
    pub fn parse(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() < APPLE_HEADER_LEN + APPLE_TAIL_LEN {
            return Err(StateError::Truncated);
        }
        let version = be_u32(bytes, 0);
        let declared = be_u32(bytes, 4);
        let blob_len =
            usize::try_from(declared).map_err(|_| StateError::AppleLengthMismatch { declared })?;
        let total = APPLE_HEADER_LEN
            .checked_add(blob_len)
            .and_then(|value| value.checked_add(APPLE_TAIL_LEN))
            .ok_or(StateError::AppleLengthMismatch { declared })?;
        if total != bytes.len() {
            return Err(StateError::AppleLengthMismatch { declared });
        }

        let blob = bytes[APPLE_HEADER_LEN..APPLE_HEADER_LEN + blob_len].to_vec();
        let mut tail = [0u8; APPLE_TAIL_LEN];
        tail.copy_from_slice(&bytes[APPLE_HEADER_LEN + blob_len..]);
        Ok(Self {
            version,
            blob,
            tail,
        })
    }

    /// Encode the container back to its file form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(APPLE_HEADER_LEN + self.blob.len() + APPLE_TAIL_LEN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.blob);
        out.extend_from_slice(&self.tail);
        out
    }

    /// Whether the native Android reader accepts this container version.
    pub fn is_native_supported(&self) -> bool {
        self.version == APPLE_VERSION
    }

    /// Container version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Variable-length blob between the header and the tail.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// Fixed 580-byte tail, preserved opaquely.
    pub fn tail(&self) -> &[u8; APPLE_TAIL_LEN] {
        &self.tail
    }
}

/// A malformed state container or an identity mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// Input ended before the fixed header could be read.
    Truncated,
    /// The `PERUNST\0` magic is missing.
    BadMagic,
    /// Container version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u32),
    /// Reserved flags are non-zero.
    UnsupportedFlags(u32),
    /// The declared body length does not match the remaining input.
    LengthMismatch,
    /// A TLV header or value runs past the end of the body.
    TruncatedField,
    /// The TLV tag is not defined for version 1.
    UnknownField(u8),
    /// The TLV tag appeared more than once.
    DuplicateField(u8),
    /// The TLV tags are not in strictly ascending order.
    FieldOrder(u8),
    /// The field value has the wrong length.
    FieldLength {
        /// Tag byte of the offending field.
        tag: u8,
        /// Observed value length.
        len: usize,
    },
    /// A mandatory field is absent.
    MissingField(u8),
    /// The record belongs to a different device identity.
    IdentityMismatch,
    /// The integrity tag does not match.
    BadTag,
    /// An Apple blob does not fit the container's `u32` length field.
    AppleBlobTooLong(usize),
    /// The Apple `n` value does not describe the file size.
    AppleLengthMismatch {
        /// `n` read from the Apple header.
        declared: u32,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("state is shorter than the fixed header"),
            Self::BadMagic => f.write_str("bad PERUNST magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported state version {version}")
            }
            Self::UnsupportedFlags(flags) => {
                write!(f, "unsupported state flags {flags:#010x}")
            }
            Self::LengthMismatch => {
                f.write_str("declared body length does not match the file size")
            }
            Self::TruncatedField => f.write_str("truncated state field"),
            Self::UnknownField(tag) => write!(f, "unknown state field tag {tag}"),
            Self::DuplicateField(tag) => write!(f, "duplicate state field tag {tag}"),
            Self::FieldOrder(tag) => {
                write!(f, "state field tag {tag} is out of canonical order")
            }
            Self::FieldLength { tag, len } => {
                write!(f, "state field {tag} has unsupported length {len}")
            }
            Self::MissingField(tag) => write!(f, "missing state field tag {tag}"),
            Self::IdentityMismatch => f.write_str("state belongs to a different identity"),
            Self::BadTag => f.write_str("state integrity tag mismatch"),
            Self::AppleBlobTooLong(len) => {
                write!(f, "Apple blob length {len} does not fit in u32")
            }
            Self::AppleLengthMismatch { declared } => {
                write!(
                    f,
                    "Apple container declares n={declared}, which does not match the file size"
                )
            }
        }
    }
}

impl std::error::Error for StateError {}

/// A state error together with an I/O error from [`load`] or [`store`].
#[derive(Debug)]
#[non_exhaustive]
pub enum StateIoError {
    /// The container was read but rejected.
    State(StateError),
    /// The file could not be read or written.
    Io(std::io::Error),
}

impl fmt::Display for StateIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(f, "state: {error}"),
            Self::Io(error) => write!(f, "i/o: {error}"),
        }
    }
}

impl std::error::Error for StateIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<StateError> for StateIoError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<std::io::Error> for StateIoError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// TLV tags of the canonical body, in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Tag {
    Identity = 1,
    Session = 2,
    ProvisionedAt = 3,
    Cpim = 4,
    Ptm = 5,
    Tk = 6,
    Spim = 7,
}

impl Tag {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Identity,
            2 => Self::Session,
            3 => Self::ProvisionedAt,
            4 => Self::Cpim,
            5 => Self::Ptm,
            6 => Self::Tk,
            7 => Self::Spim,
            _ => return None,
        })
    }

    fn byte(self) -> u8 {
        self as u8
    }
}

fn open_bound(
    bytes: &[u8],
    identity: &[u8; IDENTITY_BIND_LEN],
) -> Result<ProvisioningRecord, StateError> {
    let header = bytes.get(..HEADER_LEN).ok_or(StateError::Truncated)?;
    if header[..MAGIC.len()] != *MAGIC {
        return Err(StateError::BadMagic);
    }

    let version = be_u32(header, 8);
    if version != FORMAT_VERSION {
        return Err(StateError::UnsupportedVersion(version));
    }
    let flags = be_u32(header, 12);
    if flags != 0 {
        return Err(StateError::UnsupportedFlags(flags));
    }

    let body = &bytes[HEADER_LEN..];
    if be_u32(header, 16) as usize != body.len() {
        return Err(StateError::LengthMismatch);
    }

    let record = ProvisioningRecord::decode_body(body)?;
    if &record.identity != identity {
        return Err(StateError::IdentityMismatch);
    }

    let expected = sha256::hmac(&derive_key(identity), &[&header[..HEADER_PREFIX_LEN], body]);
    if !sha256::ct_eq(&expected, &header[HEADER_PREFIX_LEN..]) {
        return Err(StateError::BadTag);
    }

    Ok(record)
}

fn seal_body(body: &[u8], identity: &[u8; IDENTITY_BIND_LEN]) -> Vec<u8> {
    let mut header = [0u8; HEADER_PREFIX_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[12..16].copy_from_slice(&0u32.to_be_bytes());
    let body_len = u32::try_from(body.len()).expect("state body is bounded by its u16 fields");
    header[16..20].copy_from_slice(&body_len.to_be_bytes());

    let tag = sha256::hmac(&derive_key(identity), &[&header, body]);

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&tag);
    out.extend_from_slice(body);
    out
}

fn derive_key(identity: &[u8; IDENTITY_BIND_LEN]) -> [u8; 32] {
    sha256::hmac(KEY_CONTEXT, &[&identity[..]])
}

fn put(out: &mut Vec<u8>, tag: Tag, value: &[u8]) {
    out.push(tag.byte());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn fixed<const N: usize>(value: &[u8], tag: Tag) -> Result<[u8; N], StateError> {
    if value.len() != N {
        return Err(StateError::FieldLength {
            tag: tag.byte(),
            len: value.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    Ok(out)
}

fn be_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const IDENTITY: [u8; IDENTITY_BIND_LEN] = [0x8e, 0x3c, 0x51, 0xa7, 0x02, 0xd4, 0x6b, 0xf9];

    fn pattern<const N: usize>(seed: u8) -> [u8; N] {
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(seed);
        }
        out
    }

    fn record() -> ProvisioningRecord {
        ProvisioningRecord {
            identity: IDENTITY,
            session: 0x2101_68c6,
            provisioned_at: 1_763_000_000,
            cpim: pattern(0x11),
            ptm: pattern(0x22),
            tk: pattern(0x33),
            spim: Some(pattern::<347>(0x44).to_vec()),
        }
    }

    fn identifier() -> Identity {
        let mut out = [0u8; IDENTIFIER_LEN];
        out[..IDENTITY_BIND_LEN].copy_from_slice(&IDENTITY);
        out[IDENTITY_BIND_LEN..].copy_from_slice(&pattern::<8>(0x99));
        Identity::from_bytes(out)
    }

    fn apple_tail() -> [u8; APPLE_TAIL_LEN] {
        pattern(0x5a)
    }

    fn apple_bytes(version: u32, blob: &[u8], tail: &[u8; APPLE_TAIL_LEN]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        out.extend_from_slice(blob);
        out.extend_from_slice(tail);
        out
    }

    fn canonical_body(record: &ProvisioningRecord) -> Vec<u8> {
        let mut body = Vec::new();
        put(&mut body, Tag::Identity, &record.identity);
        put(&mut body, Tag::Session, &record.session.to_be_bytes());
        put(
            &mut body,
            Tag::ProvisionedAt,
            &record.provisioned_at.to_be_bytes(),
        );
        put(&mut body, Tag::Cpim, &record.cpim);
        put(&mut body, Tag::Ptm, &record.ptm);
        put(&mut body, Tag::Tk, &record.tk);
        if let Some(spim) = &record.spim {
            put(&mut body, Tag::Spim, spim);
        }
        body
    }

    #[test]
    fn container_round_trips_with_and_without_spim() {
        let record = record();
        let sealed = seal(&record).unwrap();
        assert_eq!(open(&sealed, &identifier()).unwrap(), record);

        let mut without_spim = record;
        without_spim.spim = None;
        let sealed = seal(&without_spim).unwrap();
        assert_eq!(open(&sealed, &identifier()).unwrap(), without_spim);
    }

    #[test]
    fn header_is_canonical() {
        let sealed = seal(&record()).unwrap();
        assert_eq!(&sealed[..MAGIC.len()], &MAGIC[..]);
        assert_eq!(be_u32(&sealed, 8), FORMAT_VERSION);
        assert_eq!(be_u32(&sealed, 12), 0);
        assert_eq!(
            be_u32(&sealed, 16) as usize,
            sealed.len() - HEADER_LEN,
            "body length covers exactly the TLV body"
        );
    }

    #[test]
    fn only_the_first_eight_identity_bytes_are_bound() {
        let sealed = seal(&record()).unwrap();

        let mut other_last_half = *identifier().as_bytes();
        other_last_half[IDENTITY_BIND_LEN..].fill(0xa5);
        assert_eq!(
            open(&sealed, &Identity::from_bytes(other_last_half)).unwrap(),
            record()
        );

        for index in 0..IDENTITY_BIND_LEN {
            let mut other_first_half = *identifier().as_bytes();
            other_first_half[index] ^= 0x01;
            assert_eq!(
                open(&sealed, &Identity::from_bytes(other_first_half)).unwrap_err(),
                StateError::IdentityMismatch,
                "identity byte {index}"
            );
        }
    }

    #[test]
    fn every_byte_is_authenticated() {
        let sealed = seal(&record()).unwrap();
        for (index, _) in sealed.iter().enumerate() {
            let mut corrupted = sealed.clone();
            corrupted[index] ^= 0x01;
            assert!(
                open(&corrupted, &identifier()).is_err(),
                "byte {index} was accepted after mutation"
            );
        }
    }

    #[test]
    fn body_content_mutation_is_a_bad_tag() {
        let sealed = seal(&record()).unwrap();
        let mut corrupted = sealed.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x80;
        assert_eq!(
            open(&corrupted, &identifier()).unwrap_err(),
            StateError::BadTag
        );
    }

    #[test]
    fn tag_mutation_is_rejected() {
        let sealed = seal(&record()).unwrap();
        let mut corrupted = sealed.clone();
        corrupted[HEADER_PREFIX_LEN] ^= 0x80;
        assert_eq!(
            open(&corrupted, &identifier()).unwrap_err(),
            StateError::BadTag
        );
    }

    #[test]
    fn every_truncation_is_rejected() {
        let sealed = seal(&record()).unwrap();
        for len in 0..sealed.len() {
            assert!(
                open(&sealed[..len], &identifier()).is_err(),
                "truncation at {len}"
            );
        }

        let mut extended = sealed.clone();
        extended.push(0);
        assert_eq!(
            open(&extended, &identifier()).unwrap_err(),
            StateError::LengthMismatch
        );
    }

    #[test]
    fn non_canonical_order_is_rejected() {
        let record = record();
        let mut body = Vec::new();
        put(&mut body, Tag::Session, &record.session.to_be_bytes());
        put(&mut body, Tag::Identity, &record.identity);
        put(
            &mut body,
            Tag::ProvisionedAt,
            &record.provisioned_at.to_be_bytes(),
        );
        put(&mut body, Tag::Cpim, &record.cpim);
        put(&mut body, Tag::Ptm, &record.ptm);
        put(&mut body, Tag::Tk, &record.tk);
        let sealed = seal_body(&body, &record.identity);
        assert_eq!(
            open(&sealed, &identifier()).unwrap_err(),
            StateError::FieldOrder(Tag::Identity.byte())
        );
    }

    #[test]
    fn duplicate_field_is_rejected() {
        let record = record();
        let mut body = canonical_body(&record);
        put(&mut body, Tag::Identity, &record.identity);
        let sealed = seal_body(&body, &record.identity);
        assert_eq!(
            open(&sealed, &identifier()).unwrap_err(),
            StateError::DuplicateField(Tag::Identity.byte())
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let record = record();
        let mut body = canonical_body(&record);
        body.extend_from_slice(&[9, 0, 0]);
        let sealed = seal_body(&body, &record.identity);
        assert_eq!(
            open(&sealed, &identifier()).unwrap_err(),
            StateError::UnknownField(9)
        );
    }

    #[test]
    fn wrong_field_length_is_rejected() {
        let record = record();
        let mut body = Vec::new();
        put(&mut body, Tag::Identity, &record.identity[..7]);
        put(&mut body, Tag::Session, &record.session.to_be_bytes());
        put(
            &mut body,
            Tag::ProvisionedAt,
            &record.provisioned_at.to_be_bytes(),
        );
        put(&mut body, Tag::Cpim, &record.cpim);
        put(&mut body, Tag::Ptm, &record.ptm);
        put(&mut body, Tag::Tk, &record.tk);
        let sealed = seal_body(&body, &record.identity);
        assert_eq!(
            open(&sealed, &identifier()).unwrap_err(),
            StateError::FieldLength {
                tag: Tag::Identity.byte(),
                len: 7
            }
        );
    }

    #[test]
    fn missing_field_is_rejected() {
        let record = record();
        let mut body = Vec::new();
        put(&mut body, Tag::Identity, &record.identity);
        put(&mut body, Tag::Session, &record.session.to_be_bytes());
        put(
            &mut body,
            Tag::ProvisionedAt,
            &record.provisioned_at.to_be_bytes(),
        );
        put(&mut body, Tag::Cpim, &record.cpim);
        put(&mut body, Tag::Ptm, &record.ptm);
        let sealed = seal_body(&body, &record.identity);
        assert_eq!(
            open(&sealed, &identifier()).unwrap_err(),
            StateError::MissingField(Tag::Tk.byte())
        );
    }

    #[test]
    fn empty_spim_is_rejected_at_seal() {
        let mut record = record();
        record.spim = Some(Vec::new());
        assert_eq!(
            seal(&record).unwrap_err(),
            StateError::FieldLength {
                tag: Tag::Spim.byte(),
                len: 0
            }
        );
    }

    #[test]
    fn apple_container_round_trips() {
        let blob = pattern::<29>(0x77).to_vec();
        let tail = apple_tail();
        let bytes = apple_bytes(APPLE_VERSION, &blob, &tail);
        let state = AppleState::parse(&bytes).unwrap();
        assert_eq!(state.version(), APPLE_VERSION);
        assert_eq!(state.blob(), blob.as_slice());
        assert_eq!(state.tail(), &tail);
        assert!(state.is_native_supported());
        assert_eq!(state.encode(), bytes);
    }

    #[test]
    fn apple_zero_length_blob_round_trips() {
        let tail = apple_tail();
        let bytes = apple_bytes(APPLE_VERSION, &[], &tail);
        let state = AppleState::parse(&bytes).unwrap();
        assert!(state.blob().is_empty());
        assert_eq!(state.encode(), bytes);
    }

    #[test]
    fn apple_version_is_preserved_but_flagged() {
        let tail = apple_tail();
        let bytes = apple_bytes(2, b"x", &tail);
        let state = AppleState::parse(&bytes).unwrap();
        assert_eq!(state.version(), 2);
        assert!(!state.is_native_supported());
        assert_eq!(state.encode(), bytes);
    }

    #[test]
    fn apple_length_mismatch_is_rejected() {
        let tail = apple_tail();
        let mut bytes = apple_bytes(APPLE_VERSION, b"abc", &tail);
        bytes.push(0);
        assert_eq!(
            AppleState::parse(&bytes).unwrap_err(),
            StateError::AppleLengthMismatch { declared: 3 }
        );

        let short = &bytes[..APPLE_HEADER_LEN + APPLE_TAIL_LEN - 1];
        assert_eq!(AppleState::parse(short).unwrap_err(), StateError::Truncated);

        let mut huge = Vec::new();
        huge.extend_from_slice(&APPLE_VERSION.to_be_bytes());
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        huge.extend_from_slice(&tail);
        assert_eq!(
            AppleState::parse(&huge).unwrap_err(),
            StateError::AppleLengthMismatch { declared: u32::MAX }
        );
    }

    #[test]
    fn apple_new_sets_the_version() {
        let state = AppleState::new(b"blob".to_vec(), apple_tail()).unwrap();
        assert_eq!(state.version(), APPLE_VERSION);
        let bytes = state.encode();
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 4);
    }

    #[test]
    #[ignore = "requires PERUN_APPLE_STATE=/path/to/adi.pb from a local capture"]
    fn apple_capture_round_trips() {
        let path = std::env::var("PERUN_APPLE_STATE").expect("set PERUN_APPLE_STATE");
        let bytes = std::fs::read(path).expect("read the Apple state capture");
        let state = AppleState::parse(&bytes).expect("parse the Apple state capture");
        assert_eq!(state.encode(), bytes, "the capture must round-trip exactly");
        assert_eq!(state.tail().len(), APPLE_TAIL_LEN);
        assert_eq!(
            bytes.len(),
            APPLE_HEADER_LEN + state.blob().len() + APPLE_TAIL_LEN
        );
    }

    static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let index = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("perun-adi-state-{}-{index}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn store_and_load_round_trip() {
        let dir = temp_dir();
        let path = dir.join("adi-state.bin");
        let record = record();
        store(&path, &record).unwrap();
        assert_eq!(load(&path, &identifier()).unwrap(), record);
        assert_eq!(std::fs::read(&path).unwrap(), seal(&record).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_truncates_a_longer_file() {
        let dir = temp_dir();
        let path = dir.join("adi-state.bin");
        std::fs::write(&path, vec![0xaa; 4096]).unwrap();
        store(&path, &record()).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), seal(&record()).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn load_rejects_a_different_identity() {
        let dir = temp_dir();
        let path = dir.join("adi-state.bin");
        store(&path, &record()).unwrap();

        let mut other = *identifier().as_bytes();
        other[0] ^= 0x01;
        assert!(matches!(
            load(&path, &Identity::from_bytes(other)),
            Err(StateIoError::State(StateError::IdentityMismatch))
        ));

        let mut other_last_half = *identifier().as_bytes();
        other_last_half[IDENTITY_BIND_LEN..].fill(0x5a);
        assert_eq!(
            load(&path, &Identity::from_bytes(other_last_half)).unwrap(),
            record()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
