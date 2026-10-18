// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The white-box word channel: the Configuration verdict word's four
//! byte mixers, reconstructed as pure Rust from the write-only
//! watchpoint session (ww1.log) and the collapsed disassembly slice.
//!
//! The last mile of the Configuration call (0xcfe0b46a) computes the
//! word it stores into pkt[4..8] as four independent byte channels.
//! Each channel reads ONE byte of the DLL's own image through a
//! planter row pointer plus a fold-computed session index, then mixes
//! the byte through a collapsed MBA chain:
//!
//! ```text
//! pkt+4 = G4(image[base4 + idx4])   idx4 = (r9d >> 24) ^ 0x72
//! pkt+5 = image[base5 + MBA5(a)] ^ 0x13, a = [rsp+0x140] ^ 0xe5
//! pkt+6 = (G6(image[base6 + MBA6(r13b)]) ^ r13d ^ 0x4b) ^ 0x26 (low byte)
//! pkt+7 = image[base7 + MBA7(r9b)] ^ 0x64
//! ```
//!
//! with the measured bases (image RVAs, the planter rows minus their
//! read constants): base4 = 0x162cb0, base5 = 0x14b830,
//! base6 = 0x183cf0, base7 = 0x159270.
//!
//! G4 is a byte bijection whose unique preimages are 0x01 <- 0x69
//! and 0x00 <- 0xda: the SUCCESS WORD 00 00 00 01 therefore requires
//! every channel to land on its own success byte of the image, which
//! is a property of the fold-computed indices -- not of anything the
//! caller puts in the packet.

/// The collapsed pkt+4 mixer: a 256-entry byte bijection.
///
/// Verified against the ww1.log session: G4(0x8a) = 0x90 -- the first
/// byte of the digest word 9058b9ad our failing session published.
#[inline]
pub fn g4(x: u8) -> u8 {
    let dl = x ^ 0x23;
    let cl = (dl.wrapping_mul(0x4f)).wrapping_sub(dl.wrapping_mul(0x9e) & 0xae);
    let cl = cl.wrapping_add(0x57);
    let al = ((cl >> 1) & 0x62) ^ 0x5f;
    let dl2 = ((cl & 0xc0) ^ 0x40).wrapping_add(al);
    let al2 = dl2.wrapping_add(0x83);
    let cl2 = cl ^ 0xe2;
    let al3 = al2 & cl2;
    let bl = al3 ^ 0xbf;
    let al5 = ((al3 << 1) & 0x44).wrapping_add(bl);
    let al7 = (al5 << 2).wrapping_sub(al5 << 1);
    let cl3 = cl2.wrapping_add(dl2).wrapping_add(0x83);
    let dl3 = cl3 ^ 0x6f;
    let cl5 = ((cl3 << 1) & 0xde).wrapping_add(dl3);
    let al8 = (al7.wrapping_add(0x81)) ^ 0x80;
    cl5.wrapping_add(0x10).wrapping_sub(al8)
}

/// The pkt+5 index mixer (collapsed from the lea/neg/lea/xor chain).
#[inline]
pub fn mba5(a: u8) -> u32 {
    let neg = (((a as u32) << 1) & 0x11e).wrapping_neg();
    (0x1a82438f_u32).wrapping_add(a as u32).wrapping_add(neg) ^ 0x1a824375
}

/// The pkt+7 index mixer.
#[inline]
pub fn mba7(r9b: u8) -> u32 {
    let a = (r9b ^ 0xfb) as u32;
    let neg = ((a << 1) & 0x1c4).wrapping_neg();
    (0x466749e2_u32).wrapping_add(a).wrapping_add(neg) ^ 0x46674951
}

/// The pkt+6 index mixer (over r13b).
#[inline]
pub fn mba6(r13b: u8) -> u32 {
    let a = (r13b ^ 0xe1) as u32;
    let neg = ((a << 1) & 0x1ac).wrapping_neg();
    (0x7b531dd6_u32).wrapping_add(a).wrapping_add(neg) ^ 0x7b531d2e
}

/// The pkt+6 byte mixer after the image read (the edi chain).
#[inline]
pub fn g6(x: u8) -> u32 {
    let edi = x.wrapping_add(0xda) ^ 0xe1;
    let al = (edi << 1) & 0x46;
    let edi = edi.wrapping_sub(al).wrapping_add(0x23) ^ 0x23;
    let neg = (((edi << 1) as u32) & 0x30).wrapping_neg();
    0x98_u32.wrapping_add(edi as u32).wrapping_add(neg)
}

/// The measured channel bases (image RVAs).
pub const BASE4: u32 = 0x162cb0;
pub const BASE5: u32 = 0x14b830;
pub const BASE6: u32 = 0x183cf0;
pub const BASE7: u32 = 0x159270;

/// The fold inputs the word channels consume (the measured session
/// values from ww1.log -- the failing Configuration run that
/// published the digest word 9058b9ad).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordInputs {
    /// r9d on entry to the +4 channel (after the fold cycles).
    pub r9d: u32,
    /// the [rsp+0x140] byte AFTER its `xor 0xe5` (the mixer's input).
    pub frame140: u8,
    /// r13b (the +6 channel's seed).
    pub r13b: u8,
    /// r13d (folded into the +6 channel's output).
    pub r13d: u32,
    /// r9b (the +7 channel's seed).
    pub r9b: u8,
}

/// The inputs measured off the ww1.log failing session.
pub const WW1_INPUTS: WordInputs = WordInputs {
    r9d: 0x73dc77fa,
    frame140: 0x39,
    r13b: 0x77,
    r13d: 0x73dc77,
    r9b: 0xfa,
};

/// Read a byte of the image by RVA (the caller supplies the mapping;
/// the parity harness uses the PE section table, a live guest could
/// use its own mapping of the loaded image).
pub trait ImageByRva {
    fn byte_at_rva(&self, rva: u32) -> u8;
}

/// Evaluate the four channels with the collapsed mixers.
///
/// Returns the word pkt[4..8] as `[b4, b5, b6, b7]` -- the exact bytes
/// the Configuration body stores, in store order.
pub fn word_channels(inp: &WordInputs, image: &dyn ImageByRva) -> [u8; 4] {
    let idx4 = (inp.r9d >> 24) ^ 0x72;
    let b4 = image.byte_at_rva(BASE4.wrapping_add(idx4));
    let out4 = g4(b4);

    let b5 = image.byte_at_rva(BASE5.wrapping_add(mba5(inp.frame140)));
    let out5 = b5 ^ 0x13;

    let b6 = image.byte_at_rva(BASE6.wrapping_add(mba6(inp.r13b)));
    let out6 = ((g6(b6) ^ inp.r13d ^ 0x4b) as u8) ^ 0x26;

    let b7 = image.byte_at_rva(BASE7.wrapping_add(mba7(inp.r9b)));
    let out7 = b7 ^ 0x64;

    [out4, out5, out6, out7]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flat image view: RVAs map onto the file through a fixed
    /// section table (mirrors the measured DLL layout).
    struct FlatImage<'a> {
        data: &'a [u8],
    }

    impl ImageByRva for FlatImage<'_> {
        fn byte_at_rva(&self, rva: u32) -> u8 {
            // .text: vsize 0x140b70, vrva 0x1000, raw 0x400.
            let off = if (0x1000..0x141c00).contains(&rva) {
                rva - 0x1000 + 0x400
            } else if (0x142000..0x19ce00).contains(&rva) {
                rva - 0x142000 + 0x141000
            } else {
                panic!("rva {rva:#x} outside the mapped sections");
            };
            self.data[off as usize]
        }
    }

    /// The parity test against the ww1.log session: the transpiled
    /// channels must reproduce the digest word 9058b9ad byte for byte.
    ///
    /// The DLL is supplied through PERUN_COREADI_DLL (never a repo
    /// path); the test is skipped when the variable is unset.
    #[test]
    fn ww1_parity_word_digest() {
        let Some(path) = std::env::var_os("PERUN_COREADI_DLL") else {
            eprintln!("PERUN_COREADI_DLL unset -- skipping the parity test");
            return;
        };
        let dll = std::fs::read(path).expect("read the DLL");
        let img = FlatImage { data: &dll };
        let word = word_channels(&WW1_INPUTS, &img);
        assert_eq!(word, [0x90, 0x58, 0xb9, 0xad]);
    }

    /// G4 must be a bijection with the measured preimages.
    #[test]
    fn g4_is_a_bijection_with_success_preimage() {
        let mut seen = [false; 256];
        for x in 0u16..256 {
            let y = g4(x as u8) as usize;
            assert!(!seen[y], "G4 collision at {x:#x}");
            seen[y] = true;
        }
        assert_eq!(g4(0x69), 0x01, "the success byte's unique preimage");
        assert_eq!(g4(0xda), 0x00, "the zero byte's unique preimage");
        assert_eq!(g4(0x8a), 0x90, "the ww1 digest byte");
    }

    /// The collapsed index mixers must match the measured offsets.
    #[test]
    fn index_mixers_match_the_measured_offsets() {
        assert_eq!(mba5(0x39), 0xc3);
        assert_eq!(mba7(0xfa), 0xb2);
        assert_eq!(mba6(0x77), 0x6e);
        assert_eq!(g6(0x00), 0xa3);
    }
}
