// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The 276-byte CPIM anatomy, from the reference dump.
//!
//! `cpim276.bin` is the cold-canon CPIM the Configuration body
//! wrote on the successful Android call-6 run (2026-10-11): the
//! `out` pointer at ctx+0x80 carried it, the length at ctx+0x50
//! was 0x114 = 276. Its byte structure, measured by the audit of
//! 2026-10-23:
//!
//! ```text
//! [0x000..0x004)  version          = 5            (BE)
//! [0x004..0x014)  session block    = 16 bytes     (three BE words + marker 0x15098a76)
//! [0x014..0x018)  body A length    = 0xa0 (160)   (BE)
//! [0x018..0x0b8)  body A           = 160 bytes    (the crypto body)
//! [0x0b8..0x0d8)  body A digest    = 32 bytes     (SHA-256-shaped)
//! [0x0d8..0x0dc)  body B length    = 0x34 (52)    (BE)
//! [0x0dc..0x0e0)  body B version   = 4            (BE)
//! [0x0e0..0x114)  body B           = 52 bytes     (the tail section)
//! ```
//!
//! The arithmetic closes exactly: 0xe0 + 0x34 == 0x114 (276).
//! Which parts our transpiled fold forms: the word channels write
//! the packet (the fold's output surface), and the CPIM sections
//! derive from the session state the fold consumes -- body A is
//! the crypto body the fold feeds, the digest covers it, body B
//! carries the section metadata. The validator below pins the
//! reference shape so the generator's output can be compared
//! against it byte for byte when the session fold lands.

/// The parsed sections of a CPIM blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpimLayout {
    pub version: u32,
    pub session: [u8; 16],
    pub body_a: Vec<u8>,
    pub body_a_digest: Vec<u8>,
    pub body_b: Vec<u8>,
    pub body_b_version: u32,
}

impl CpimLayout {
    /// The reference's total size (0x114).
    pub const REFERENCE_LEN: usize = 276;

    /// Parse a 276-byte CPIM by its own length fields; an error
    /// means the blob does not carry the reference shape.
    pub fn parse(blob: &[u8]) -> Result<Self, String> {
        if blob.len() < 0x18 {
            return Err(format!("too short: {}", blob.len()));
        }
        let be32 = |off: usize| -> Result<u32, String> {
            let s = blob.get(off..off + 4).ok_or("eof")?;
            Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        };
        let version = be32(0x00)?;
        let mut session = [0u8; 16];
        session.copy_from_slice(blob.get(0x04..0x14).ok_or("eof")?);
        let len_a = be32(0x14)? as usize;
        if len_a != 160 {
            return Err(format!("body A length {len_a:#x} != 0xa0"));
        }
        let a = blob
            .get(0x18..0x18 + len_a)
            .ok_or("body A truncated")?
            .to_vec();
        let d_start = 0x18 + len_a;
        let digest = blob
            .get(d_start..d_start + 32)
            .ok_or("digest truncated")?
            .to_vec();
        let len_b = be32(d_start + 32)? as usize;
        let bver = be32(d_start + 36)?;
        let b = blob.get(d_start + 40..).ok_or("body B truncated")?.to_vec();
        if b.len() != len_b {
            return Err(format!("body B len {} != declared {len_b:#x}", b.len()));
        }
        if d_start + 40 + len_b != blob.len() {
            return Err(format!(
                "sections end at {:#x}, blob is {:#x}",
                d_start + 40 + len_b,
                blob.len()
            ));
        }
        Ok(Self {
            version,
            session,
            body_a: a,
            body_a_digest: digest,
            body_b: b,
            body_b_version: bver,
        })
    }

    /// Serialize the layout back -- the generator's output shape.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::REFERENCE_LEN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&(self.body_a.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body_a);
        out.extend_from_slice(&self.body_a_digest);
        out.extend_from_slice(&(self.body_b.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body_b_version.to_be_bytes());
        out.extend_from_slice(&self.body_b);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference cold-canon dump: parse, round-trip, pin every
    /// section length. The bytes travel as an env-gated path (the
    /// dump lives outside the repo).
    #[test]
    fn reference_cpim_parses_and_roundtrips() {
        let Some(path) = std::env::var_os("PERUN_CPIM_REF") else {
            eprintln!("PERUN_CPIM_REF unset -- skipping the reference test");
            return;
        };
        let blob = std::fs::read(path).expect("read reference");
        assert_eq!(blob.len(), 276, "the reference is 0x114 bytes");
        let l = CpimLayout::parse(&blob).expect("reference must parse");
        assert_eq!(l.version, 5);
        assert_eq!(l.body_a.len(), 160);
        assert_eq!(l.body_a_digest.len(), 32);
        assert_eq!(l.body_b.len(), 52);
        assert_eq!(l.body_b_version, 4);
        // The round-trip is byte-exact: the parse is reversible.
        assert_eq!(l.to_bytes(), blob);
    }
}
