//! The digest node, transcribed from the live Android oracle
//! (+0xfbdf0..+0xfc110: the digest prologue and the stage-two node
//! writing depot rows 0xA0..0xBF). Measured live across two runs
//! (31/32) and closed to ALL EIGHT blocks in one run (`pair37.py`:
//! three hardware watchpoints over 8-byte depot spans at 0xA0/0xA8/0xB0;
//! each stop records the eight carrier-register words, a post-write
//! instruction pointer, and the run's CPIM/depot slice).
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
//! The words are PHASE-LIVE: registers evolve across the node's stores.
//! The production loader in `body_a` therefore uses eight named store-time
//! RIP/register pairs, not a snapshot whose value happens to match a CPIM sum.
//! The reference CPIM is only an external test oracle, including in the
//! ignored live parity test.

/// The digest zone length in depot coordinates: depot[0xA0..0xC0).
pub const DIGEST_LEN: usize = 32;
/// First depot position of the zone.
pub const DIGEST_ZONE: usize = 0xA0;
/// The prologue-half constant (blocks 0xA0, 0xA4, 0xA8, 0xAC).
pub const K_LOW: u32 = 0x3ADA8A5E;
/// The node-half constant (blocks 0xB0, 0xB4, 0xB8, 0xBC).
/// Its two's-complement twin is -0x64E9699E.
pub const K_HIGH: u32 = 0x9B169662;

/// The eight channel words, one per block, each named by its measured
/// carrier register. Production constructs them from named store-time events.
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
            a0: 0x01020304,
            a4: 0x11111111,
            a8: 0x12121212,
            ac: 0x13131313,
            b0: 0x14141414,
            b4: 0x15151515,
            b8: 0x16161616,
            bc: 0x17171717,
        };
        let d = generate_digest(&inp);
        // block 0xA0: the low half constant
        let s = 0x01020304u32.wrapping_add(K_LOW);
        assert_eq!(
            &d[0..4],
            &[(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8, s as u8]
        );
        // block 0xBC: the high half constant, MSB first
        let s = 0x17171717u32.wrapping_add(K_HIGH);
        assert_eq!(
            &d[0x1C..0x20],
            &[(s >> 24) as u8, (s >> 16) as u8, (s >> 8) as u8, s as u8]
        );
        // the constants' two's-complement twin
        assert_eq!(K_HIGH.wrapping_add(0x64E9699E), 0);
        // eight sums, four bytes each, tile the zone exactly
        assert_eq!(inp.sums().len() * 4, DIGEST_LEN);
    }

    /// Live parity against the same-session CPIM/depot pair, using the
    /// production store-time producer rather than answer-side selection.
    #[test]
    #[ignore = "requires same-session digest word tape, depot slice and CPIM; set PERUN_DIGEST_PAIR_READY=1"]
    fn live_digest_parity() {
        assert_eq!(
            std::env::var("PERUN_DIGEST_PAIR_READY")
                .as_deref()
                .unwrap_or(""),
            "1",
            "set PERUN_DIGEST_PAIR_READY=1 only for a complete same-session digest pair"
        );
        let dir = std::env::var("PERUN_LIVE_DIR").unwrap_or_else(|_| "/opt/data/adi-re".into());
        let tape = format!("{dir}/pair_wp_words.txt");
        let cpim_path = format!("{dir}/live_prov_out.bin");
        let ttxt =
            std::fs::read_to_string(&tape).expect("same-session digest word tape is required");
        let cpim = std::fs::read(&cpim_path).expect("same-session live CPIM is required");
        assert_eq!(cpim.len(), 0x114, "the live CPIM is 276 bytes");
        assert!(!ttxt.is_empty(), "tape has no hit rows");
        // SAME-SESSION PROOF, mechanical: the run's depot slice (dumped by
        // the writer of the same gdb session) must equal the CPIM's
        // depot window -- if the two disagree the artifacts are from
        // different runs and the parity must not fire.
        if let Ok(dump) = std::fs::read(format!("{dir}/pair_depot.bin")) {
            assert!(
                dump.len() >= 0xC0,
                "the paired depot dump must contain 0xC0 bytes"
            );
            assert_eq!(
                &dump[..0xC0],
                &cpim[0x18..0x18 + 0xC0],
                "the depot slice and the CPIM must be one session"
            );
        } else {
            panic!("no writer depot slice -- the pair is incomplete");
        }
        let d =
            crate::body_a::generate_digest_from_tapes(&dir).expect("store-time digest producer");
        for (i, &b) in d.iter().enumerate() {
            assert_eq!(
                b,
                cpim[0x18 + DIGEST_ZONE + i],
                "depot+{:#x}",
                DIGEST_ZONE + i
            );
        }
        eprintln!("DIGEST live parity: 32/32 bytes from store-time producers");
    }
}
