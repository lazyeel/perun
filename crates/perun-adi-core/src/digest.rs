//! The digest node, transcribed from the live Android oracle
//! (+0xfbdf0..+0xfc110: the digest prologue and the stage-two node
//! writing depot rows 0xA0..0xBF). Measured live across two runs
//! (31/32) and closed to ALL EIGHT blocks in one run (`pair32.py`:
//! three hardware watchpoints over the depot windows 0xA0/0xA8/0xB0,
//! the eight channel words logged at every store, plus the same
//! run's CPIM).
//!
//! THE MEASURED LAW: the digest zone depot[0xA0..0xC0) is the
//! BIG-ENDIAN layout of EIGHT 32-bit sums, four bytes per block:
//!
//!   depot[0xA0+4i .. 0xA3+4i] = MSB..LSB of S_i,  S_i = w_i + K_i
//!
//! with TWO constants only, split by half:
//!   the low half (0xA0..0xAC, written by the prologue):  K = 0x3ADA8A5E
//!   the high half (0xB0..0xBC, written by the node):     K = 0x9B169662
//! and the channel words, named by their live carrier registers:
//!   0xA0: rcx (prologue-phase)   0xB0: [rbp-0xb8]
//!   0xA4: rdx                    0xB4: [rbp-0x40]
//!   0xA8: r13                    0xB8: [rbp-0x68]
//!   0xAC: r14                    0xBC: r8
//!
//! The constants pair by two's complement: -0x64E9699E ==
//! +0x9B169662 (mod 2^32); the families {0x9662, 0x169662,
//! 0x9B169662} / {0x5E, 0xDA8A5E, 0x3ADA8A5E} are one base
//! constant under three top-byte variants -- the earlier
//! per-byte shift formulas were these same sums read lane by
//! lane, and the masked-base arithmetic 0xa879896bfa0398XX with
//! `pos = XX - 0x7CE` still holds for the store addresses.
//!
//! The words are PHASE-LIVE: registers evolve across the node's
//! stores (r13 walked three values, r14 two, rcx and rdx a dozen
//! in the measured run). The parity test therefore resolves each
//! block from the word AT ITS OWN STORE -- every candidate hit on
//! the tape is tried, and the block must come out of a measured
//! register value, never a derived constant.

/// The digest zone length in depot coordinates: depot[0xA0..0xC0).
pub const DIGEST_LEN: usize = 32;
/// First depot position of the zone.
pub const DIGEST_ZONE: usize = 0xA0;
/// The prologue-half constant (blocks 0xA0, 0xA4, 0xA8, 0xAC).
pub const K_LOW: u32 = 0x3ADA8A5E;
/// The node-half constant (blocks 0xB0, 0xB4, 0xB8, 0xBC).
/// Its two's-complement twin is -0x64E9699E.
pub const K_HIGH: u32 = 0x9B169662;

/// The eight channel words, one per block, each named by its
/// live carrier register (the value at the block's own store).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DigestInputs {
    pub a0: u32, // rcx, prologue phase
    pub a4: u32, // rdx
    pub a8: u32, // r13
    pub ac: u32, // r14
    pub b0: u32, // [rbp-0xb8]
    pub b4: u32, // [rbp-0x40]
    pub b8: u32, // [rbp-0x68]
    pub bc: u32, // r8
}

impl DigestInputs {
    /// The block -> sum map, in depot order.
    pub fn sums(&self) -> [u32; 8] {
        [
            self.a0.wrapping_add(K_LOW),
            self.a4.wrapping_add(K_LOW),
            self.a8.wrapping_add(K_LOW),
            self.ac.wrapping_add(K_LOW),
            self.b0.wrapping_add(K_HIGH),
            self.b4.wrapping_add(K_HIGH),
            self.b8.wrapping_add(K_HIGH),
            self.bc.wrapping_add(K_HIGH),
        ]
    }
}

/// Generate the full 32-byte digest zone: the big-endian layout of
/// the eight sums (MSB first at each block's first byte).
pub fn generate_digest(inp: &DigestInputs) -> [u8; DIGEST_LEN] {
    let mut d = [0u8; DIGEST_LEN];
    for (i, &s) in inp.sums().iter().enumerate() {
        let base = 4 * i;
        d[base] = (s >> 24) as u8;
        d[base + 1] = (s >> 16) as u8;
        d[base + 2] = (s >> 8) as u8;
        d[base + 3] = s as u8;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The endianness and split-constant invariants, pinned
    /// without any live files.
    #[test]
    fn digest_layout_is_big_endian_two_constants() {
        let inp = DigestInputs {
            a0: 0x01020304, a4: 0x11111111, a8: 0x12121212, ac: 0x13131313,
            b0: 0x14141414, b4: 0x15151515, b8: 0x16161616, bc: 0x17171717,
        };
        let d = generate_digest(&inp);
        // block 0xA0: the low half constant
        let s = 0x01020304u32.wrapping_add(K_LOW);
        assert_eq!(&d[0..4], &[(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8, s as u8]);
        // block 0xBC: the high half constant, MSB first
        let s = 0x17171717u32.wrapping_add(K_HIGH);
        assert_eq!(&d[0x1C..0x20], &[(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8, s as u8]);
        // the constants' two's-complement twin
        assert_eq!(K_HIGH.wrapping_add(0x64E9699E), 0);
        // eight sums, four bytes each, tile the zone exactly
        assert_eq!(inp.sums().len() * 4, DIGEST_LEN);
    }

    /// The live parity, gated on the pair marker: every one of the
    /// eight blocks must resolve from a MEASURED word on the tape
    /// (the register value at a store hit), against the same
    /// session's CPIM. 32/32 bytes.
    #[test]
    fn live_digest_parity() {
        let dir = std::env::var("PERUN_LIVE_DIR")
            .unwrap_or_else(|_| "/opt/data/adi-re".into());
        let tape = format!("{dir}/pair_wp_words.txt");
        let cpim_path = format!("{dir}/live_prov_out.bin");
        let (Ok(ttxt), Ok(cpim)) = (std::fs::read_to_string(&tape), std::fs::read(&cpim_path))
        else {
            eprintln!("gating: no live word-tape + cpim under {dir}");
            return;
        };
        if std::env::var("PERUN_DIGEST_PAIR_READY").is_err() {
            eprintln!("gating: PERUN_DIGEST_PAIR_READY not set");
            return;
        }
        assert!(cpim.len() >= 0xD8, "the live CPIM is at least 276 bytes");
        // parse the tape rows: channel words per hit
        let mut rows: Vec<Vec<(String, u32)>> = Vec::new();
        let mut saw_writer = false;
        for line in ttxt.lines() {
            if line.starts_with("WRITER-START") {
                saw_writer = true;
            } else if line.starts_with("hit") {
                let mut fields = Vec::new();
                for f in line.split_whitespace() {
                    if let Some((k, v)) = f.split_once('=') {
                        if let Ok(x) = u32::from_str_radix(v.trim_start_matches("0x"), 16) {
                            fields.push((k.to_string(), x));
                        }
                    }
                }
                rows.push(fields);
            }
        }
        assert!(saw_writer, "tape has no WRITER-START marker");
        assert!(!rows.is_empty(), "tape has no hit rows");
        // the block map: (depot block, channel key, constant)
        const CANON: [(usize, &str, u32); 8] = [
            (0xA0, "RCX", K_LOW), (0xA4, "W8", K_LOW),
            (0xA8, "W6", K_LOW), (0xAC, "W2", K_LOW),
            (0xB0, "W1", K_HIGH), (0xB4, "W3", K_HIGH),
            (0xB8, "W5", K_HIGH), (0xBC, "W4", K_HIGH),
        ];
        let get = |cpim: &[u8], pos: usize| cpim[0x18 + pos];
        let mut words = DigestInputs::default();
        let mut resolved = 0;
        for (block, key, k) in CANON {
            // the block's four live bytes, MSB first
            let mut s_live = 0u32;
            for b in 0..4 {
                s_live = (s_live << 8) | get(&cpim, block + b) as u32;
            }
            // resolve the word from a measured hit
            let mut word = None;
            'hits: for row in &rows {
                for (kk, vv) in row {
                    if kk == key && vv.wrapping_add(k) == s_live {
                        word = Some(*vv);
                        break 'hits;
                    }
                }
            }
            let w = word.unwrap_or_else(|| {
                panic!("block {block:#x}: no measured word on the tape sums to {s_live:08x}")
            });
            match block {
                0xA0 => words.a0 = w,
                0xA4 => words.a4 = w,
                0xA8 => words.a8 = w,
                0xAC => words.ac = w,
                0xB0 => words.b0 = w,
                0xB4 => words.b4 = w,
                0xB8 => words.b8 = w,
                _ => words.bc = w,
            }
            resolved += 4;
        }
        // the full 32-byte zone, one generation, one comparison
        let d = generate_digest(&words);
        for (i, &b) in d.iter().enumerate() {
            let pos = DIGEST_ZONE + i;
            assert_eq!(b, get(&cpim, pos), "depot+{pos:#x}");
        }
        eprintln!("DIGEST live parity: {resolved}/32 bytes, all eight blocks resolved from measured words");
    }
}
