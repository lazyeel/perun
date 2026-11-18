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
//! [0x004..0x014)  session block    = 16 bytes     (sample-specific layout; not a fixed marker)
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

    /// The SPIM offset of the serialized Body B section.
    ///
    /// Measured across the local corpus: `SPIM[264..268]` is the Body B
    /// length (52), `SPIM[268..272]` its version word, and `SPIM[272..324)`
    /// its 52 bytes. The first 264 bytes are the server-issued prefix.
    pub const SPIM_BODY_B_OFFSET: usize = 264;

    /// Body B length in both the SPIM tail and the CPIM container.
    pub const BODY_B_LEN: usize = 52;

    /// Assemble a CPIM around the SPIM the session started from.
    ///
    /// `session`, `body_a` and `body_a_digest` are the Rust End fold's
    /// outputs. The Body B section is taken verbatim from the SPIM tail:
    /// across every local SPIM/CPIM pair (different identities, sessions
    /// and ASLR layouts) `CPIM[0xd8..0x114] == SPIM[264..324]` held without
    /// exception, so it is an input of the pair, not an End-derived value.
    /// Passing a different Body B would break the native reader.
    pub fn from_spim_tail(
        spim: &[u8],
        session: [u8; 16],
        body_a: [u8; 160],
        body_a_digest: [u8; 32],
    ) -> Result<Self, String> {
        if spim.len() != 347 {
            return Err(format!("SPIM must be 347 bytes, got {}", spim.len()));
        }
        let tail = &spim[Self::SPIM_BODY_B_OFFSET..];
        let body_b_len = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
        let body_b_version = u32::from_be_bytes([tail[4], tail[5], tail[6], tail[7]]);
        if body_b_len as usize != Self::BODY_B_LEN {
            return Err(format!(
                "SPIM Body B length {body_b_len:#x} differs from {:#x}",
                Self::BODY_B_LEN
            ));
        }
        Ok(Self {
            version: 5,
            session,
            body_a: body_a.to_vec(),
            body_a_digest: body_a_digest.to_vec(),
            body_b: tail[8..8 + Self::BODY_B_LEN].to_vec(),
            body_b_version,
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

    /// The SPIM tail is copied into the CPIM verbatim: build the layout
    /// from synthetic sections, splice the SPIM tail, and read it back.
    #[test]
    fn spim_tail_splices_body_b() {
        let mut spim = vec![0u8; 347];
        for (index, byte) in spim.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
        }
        spim[264..268].copy_from_slice(&(CpimLayout::BODY_B_LEN as u32).to_be_bytes());
        spim[268..272].copy_from_slice(&4u32.to_be_bytes());

        let body_b = &spim[CpimLayout::SPIM_BODY_B_OFFSET + 8
            ..CpimLayout::SPIM_BODY_B_OFFSET + 8 + CpimLayout::BODY_B_LEN];
        let layout =
            CpimLayout::from_spim_tail(&spim, [0x22; 16], [0x33; 160], [0x44; 32]).expect("valid");
        assert_eq!(layout.body_b, body_b);
        assert_eq!(layout.body_b_version, 4);
        assert_eq!(layout.version, 5);

        let encoded = layout.to_bytes();
        assert_eq!(encoded.len(), CpimLayout::REFERENCE_LEN);
        assert_eq!(
            &encoded[0xd8..0xdc],
            &(CpimLayout::BODY_B_LEN as u32).to_be_bytes()
        );
        assert_eq!(&encoded[0xdc..0xe0], &4u32.to_be_bytes());
        assert_eq!(&encoded[0xe0..0x114], body_b);
        assert_eq!(CpimLayout::parse(&encoded).unwrap(), layout);
    }

    #[test]
    fn spim_tail_rejects_a_wrong_length_or_declared_body_b() {
        let spim = [0u8; 347];
        assert!(
            CpimLayout::from_spim_tail(&spim[..346], [0; 16], [0; 160], [0; 32]).is_err(),
            "a short SPIM has no Body B tail"
        );

        let mut wrong = [0u8; 347];
        wrong[264..268].copy_from_slice(&51u32.to_be_bytes());
        assert!(
            CpimLayout::from_spim_tail(&wrong, [0; 16], [0; 160], [0; 32])
                .unwrap_err()
                .contains("Body B length")
        );
    }

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
