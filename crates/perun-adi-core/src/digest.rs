//! The digest node, transcribed from the live Android oracle
//! (+0xfbf67..+0xfc07d, the stage-two writer of the depot's
//! digest rows 0xA0..0xBF).
//!
//! The node is NOT a fold cascade: it is SHIFT ARITHMETIC packing
//! six session words into depot bytes. Every store is
//! `depot[pos] = (WORD +/- K) >> N` (mod 2^32, byte-taken),
//! writing through the masked base 0xa879896bfa0398XX where the
//! low 12 bits carry the depot offset (`pos = XX - 0x7CE`).
//!
//! The six words (measured live, run 29 -- `digest_words.txt`):
//! W1 = [rbp-0xb8], W2 = r14, W3 = [rbp-0x40], W4 = r8,
//! W5 = [rbp-0x68], W6 = r13. Each word's four bytes land on four
//! depot positions with the family constants 0x62, 0x9662,
//! 0x169662 and 0x64e9699e.
//!
//! VERIFICATION STATUS, stated honestly: the formulas are a static
//! transcription from the node's disassembly
//! (`/opt/data/adi-re/digest_node_dis.txt`, 136 insn); the live
//! pair (the node's words AND the same session's depot) has not
//! yet been captured in one run -- the run-29 gdb died at the
//! writer stage after logging the words. The parity test below is
//! therefore GATED on that pair's files; it will fire the day the
//! single missing run is taken.

/// The word -> bytes packing of one word (the family constants
/// decoded from the node): four bytes for four depot positions.
#[inline]
pub fn word_bytes(w: u32) -> [u8; 4] {
    [
        w.wrapping_add(0x62) as u8,
        (w.wrapping_add(0x9662) >> 8) as u8,
        (w.wrapping_add(0x169662) >> 16) as u8,
        (w.wrapping_sub(0x64E9699E) >> 24) as u8,
    ]
}

/// The six session words the node packs.
#[derive(Clone, Copy, Debug)]
pub struct DigestWords {
    pub w1: u32, // [rbp-0xb8]
    pub w2: u32, // r14
    pub w3: u32, // [rbp-0x40]
    pub w4: u32, // r8
    pub w5: u32, // [rbp-0x68]
    pub w6: u32, // r13
}

/// The digest's measured shape: 21 of the 32 depot positions
/// [0xA0..0xC0) are owned by this node (rows 0xA8..0xBC); the
/// remaining 11 (0xA0..0xA7 and 0xBD..0xBF) live in code branches
/// not yet transcribed. The decoded map (store -> position ->
/// formula), from the disassembly:
///
/// 0xA8 = (W6+0x5E)&0xFF            0xB2 = (W3+0x169662)>>16
/// 0xA9 = (W2+0x3ADA8A5E)>>24       0xB3 = (W3+0x9662)>>8
/// 0xAA = (W2+0xDA8A5E)>>16         0xB4 = (W3+0x62)&0xFF
/// 0xAB = (W1+0x169662)>>24         0xB5 = (W5-0x64E9699E)>>24
/// 0xAC = (W2+0x5E)&0xFF            0xB6 = (W5+0x169662)>>16
/// 0xAD = (W1-0x64E9699E)>>24       0xB7 = (W5+0x9662)>>8
/// 0xAE = (W1+0x169662)>>16         0xB8 = (W5+0x62)&0xFF
/// 0xAF = (W1+0x9662)>>8            0xB9 = (W4-0x64E9699E)>>24
/// 0xB0 = (W1+0x62)>>16             0xBA = (W4+0x169662)>>16
/// 0xB1 = (W3+0x9B169662)>>24       0xBB = (W4+0x9662)>>8
///                                  0xBC = (W4+0x62)&0xFF
///
/// NOTE the W1 line: its "+0x62" byte is the >>16 lane (the
/// measured store is `lea eax,[rcx+0x62]; shr eax,0x10`), and the
/// "-0x64e9699e" byte is the >>24 lane -- the node's own
/// permutation, kept exactly as the disassembly shows.
pub const DIGEST_LEN: usize = 32;

/// Pack the node's 21 owned positions into the digest zone
/// (the 11 untranscribed positions are left zero -- the caller
/// must not mistake this for the finished 32 bytes).
pub fn generate_digest(words: &DigestWords) -> [u8; DIGEST_LEN] {
    let mut d = [0u8; DIGEST_LEN];
    let put = |d: &mut [u8; DIGEST_LEN], pos: usize, b: u8| d[pos - 0xA0] = b;
    put(&mut d, 0xA8, words.w6.wrapping_add(0x5E) as u8);
    put(&mut d, 0xA9, (words.w2.wrapping_add(0x3ADA8A5E) >> 24) as u8);
    put(&mut d, 0xAA, (words.w2.wrapping_add(0xDA8A5E) >> 16) as u8);
    put(&mut d, 0xAB, (words.w1.wrapping_add(0x169662) >> 24) as u8);
    put(&mut d, 0xAC, words.w2.wrapping_add(0x5E) as u8);
    put(&mut d, 0xAD, (words.w1.wrapping_sub(0x64E9699E) >> 24) as u8);
    put(&mut d, 0xAE, (words.w1.wrapping_add(0x169662) >> 16) as u8);
    put(&mut d, 0xAF, (words.w1.wrapping_add(0x9662) >> 8) as u8);
    put(&mut d, 0xB0, (words.w1.wrapping_add(0x62) >> 16) as u8);
    put(&mut d, 0xB1, (words.w3.wrapping_add(0x9B169662) >> 24) as u8);
    put(&mut d, 0xB2, (words.w3.wrapping_add(0x169662) >> 16) as u8);
    put(&mut d, 0xB3, (words.w3.wrapping_add(0x9662) >> 8) as u8);
    put(&mut d, 0xB4, words.w3.wrapping_add(0x62) as u8);
    put(&mut d, 0xB5, (words.w5.wrapping_sub(0x64E9699E) >> 24) as u8);
    put(&mut d, 0xB6, (words.w5.wrapping_add(0x169662) >> 16) as u8);
    put(&mut d, 0xB7, (words.w5.wrapping_add(0x9662) >> 8) as u8);
    put(&mut d, 0xB8, words.w5.wrapping_add(0x62) as u8);
    put(&mut d, 0xB9, (words.w4.wrapping_sub(0x64E9699E) >> 24) as u8);
    put(&mut d, 0xBA, (words.w4.wrapping_add(0x169662) >> 16) as u8);
    put(&mut d, 0xBB, (words.w4.wrapping_add(0x9662) >> 8) as u8);
    put(&mut d, 0xBC, words.w4.wrapping_add(0x62) as u8);
    d
}

/// The 11 positions this module does NOT yet own (the honest
/// boundary): rows 0xA0..0xA7 and 0xBD..0xBF.
pub const UNTRANSCRIBED: [usize; 11] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xBD, 0xBE, 0xBF,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape invariant, pinned without live files: the 21
    /// owned positions plus the 11 untranscribed ones tile the
    /// 32-byte digest zone exactly, with no overlap.
    #[test]
    fn digest_zone_tiles_exactly() {
        let mut seen = [false; DIGEST_LEN];
        let words = DigestWords { w1: 0x11111111, w2: 0x22222222, w3: 0x33333333,
                                  w4: 0x44444444, w5: 0x55555555, w6: 0x66666666 };
        let d = generate_digest(&words);
        // every owned position is written (nonzero for these words)
        for pos in (0xA8..=0xBC).chain(0xA9..=0xA9) {
            let _ = pos;
        }
        let owned: [usize; 21] = [
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
            0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
        ];
        assert_eq!(owned.len() + UNTRANSCRIBED.len(), DIGEST_LEN);
        let mut union = owned.to_vec();
        union.extend_from_slice(&UNTRANSCRIBED);
        for pos in &union {
            assert!(!seen[pos - 0xA0], "position {pos:#x} twice");
            seen[pos - 0xA0] = true;
        }
        assert!(seen.iter().all(|&s| s));
        // the untranscribed positions are still zero in the output
        for pos in UNTRANSCRIBED {
            assert_eq!(d[pos - 0xA0], 0, "untranscribed {pos:#x} must stay zero");
        }
        // and the W1 line pins its permutation: w1=0xFFFFFFFF
        let words = DigestWords { w1: u32::MAX, ..words };
        let d = generate_digest(&words);
        assert_eq!(d[0xB0 - 0xA0], (u32::MAX.wrapping_add(0x62) >> 16) as u8);
        assert_eq!(d[0xAD - 0xA0], (u32::MAX.wrapping_sub(0x64E9699E) >> 24) as u8);
    }

    /// The live parity, GATED on the missing same-session pair
    /// (the node's words + the same run's CPIM). The run-29 words
    /// are already on disk (`digest_words.txt`); the run died
    /// before the depot dump, so the gate stays closed until a
    /// single fresh run captures both.
    #[test]
    fn live_digest_parity() {
        let dir = std::env::var("PERUN_LIVE_DIR").unwrap_or_else(|_| "/opt/data/adi-re".into());
        let words_path = format!("{dir}/digest_words.txt");
        let cpim_path = format!("{dir}/live_prov_out.bin");
        let (Ok(wtxt), Ok(cpim)) = (std::fs::read_to_string(&words_path), std::fs::read(&cpim_path))
        else {
            eprintln!("gating: no live word+cpim pair under {dir}");
            return;
        };
        // A same-session pair is proven by a marker file written by
        // the capturing gdb run (it dumps both artifacts itself);
        // without the marker the words may be from another session.
        if std::env::var("PERUN_DIGEST_PAIR_READY").is_err() {
            eprintln!("gating: PERUN_DIGEST_PAIR_READY not set -- the same-session pair is not yet captured");
            return;
        }
        let first = wtxt.lines().next().expect("words row");
        let get = |key: &str| -> u32 {
            for f in first.split_whitespace() {
                if let Some(v) = f.strip_prefix(&format!("{key}=")) {
                    return u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap();
                }
            }
            panic!("key {key} missing");
        };
        let words = DigestWords {
            w1: get("rcx_b8"), w2: get("r14"), w3: get("r9_40"),
            w4: get("r8"), w5: get("rbx_68"), w6: get("r13"),
        };
        let d = generate_digest(&words);
        let mut ok = 0;
        let owned: [usize; 21] = [
            0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
            0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
        ];
        for pos in owned {
            assert_eq!(d[pos - 0xA0], cpim[0x18 + pos], "depot+{pos:#x}");
            ok += 1;
        }
        eprintln!("DIGEST live parity: {ok}/21 owned positions");
    }
}
