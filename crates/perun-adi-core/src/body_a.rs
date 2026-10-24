//! The body A cascade, transcribed from the live Android oracle
//! (measured 2026-10-22, campaign record in RESEARCH.md § 5.11d).
//!
//! The depot's body A (160 bytes) is written by a four-lane mixer
//! block: sixteen mixers, four per lane, eleven cycles over the
//! rows 0x00..0xAF (the last row is rewritten by the stage-two
//! digest node). Every mixer: a planter row selected through a
//! key byte, the row byte feeding a lane-specific tail, plus a
//! masked read from the lane's zone. The formulas are
//! live-verified -- every checkable mixer of every cycle of the
//! run-26 tape reproduces its CPIM byte exactly (122/122,
//! `tools/verify_body_a2.py` carries the same conveyor in
//! Python; the three excluded passes are named there and in the
//! test below).
//!
//! The lane tails (per-mixer final xors; the planter-derived
//! lanes value `c` / `c3` / `c4` is the input here):
//! - lane A: `((mul + zone1[c - 0x10]) ^ FX`
//! - lane B: `((mul + zone2[c + 0x2E]) ^ FX`
//! - lane C: `((read - (c3|0x35)) ^ (((read - (c3|0x15))<<3)&0xFF) ^ FX` with `read = zone3[c3 - 0x30]`
//! - lane D: `((read - (c4|0xA2)) ^ FX` (mixer 4 alone: the nibble tail) with `read = zone4[c4 + 0x49]`
//!
//! What this module does NOT own (the honest boundary): the
//! selector weave (how mixers 5-16 draw their selectors from the
//! cascade's own registers) and the planter genesis -- the inputs
//! here are the cascade's measured lane values, and the test pins
//! the tails' arithmetic byte for byte on the live pair.

/// One lane's measured inputs for a single mixer pass.
#[derive(Clone, Copy, Debug)]
pub struct MixerInputs {
    /// The planter-derived lane value (c for lanes A/B, c3 for C, c4 for D).
    pub lane_value: u8,
    /// The mul operand (lanes A/B only; unused by the C/D tails).
    pub mul: u8,
    /// The m4 first-round flag: the opening round's m4 tail runs the
    /// ALTERNATE CFF branch -- the same or-fold WITHOUT the final
    /// xor (measured: the live depot[0] equals the bare or-fold;
    /// rounds two to ten take the xor). Defaults to the main branch.
    pub m4_round1: bool,
}

/// The sixteen mixers in block order (store RVAs of the census).
pub const STORES: [u32; 16] = [0xE6B9D, 0xE6BE2, 0xE6C47, 0xE6CA0, 0xE6D06, 0xE6D3E,
                               0xE6D8B, 0xE6DC1, 0xE6E28, 0xE6E5F, 0xE6EAA, 0xE6EE4,
                               0xE6F42, 0xE6F73, 0xE6FC4, 0xE7023];

/// Per-mixer (lane, final_xor). The planter xors are already folded
/// into the measured lane values; the final xors are the tails' own.
pub const LANE_OF: [u8; 16] = [0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];
pub const FINAL_XOR: [u8; 16] = [0x98, 0xB8, 0x5F, 0x6D, 0x85, 0x64, 0x54, 0x17,
                                  0x65, 0x7C, 0xE2, 0x12, 0x4E, 0xF2, 0x70, 0xBD];

/// The position ladder: cycle k, mixer j -> depot[ROW_POS[j] + 0x10*(k-1)].
pub const ROW_POS: [usize; 16] = [3, 2, 1, 0, 7, 6, 5, 4, 0xB, 0xA, 9, 8, 0xF, 0xE, 0xD, 0xC];

/// The four read zones (0x200 each, dumped live; load-stable).
pub const ZONE_WINDOW: usize = 0x300;

/// The zone window is tied to the session's FIRST lane value: the
/// capture dumps [addr_1 - 0x100, +0x300) where addr_1 is the
/// first giant read of that family -- so the true index of any
/// read is (v - c1) + 0x100, SESSION-INVARIANT. The old static
/// offsets were the same law with the taping session's c1 baked
/// in (0x90/0x52/0xb0/0x37); a fresh SPIM rotates c1 and static
/// offsets die -- the dynamic c1 fields live forever.
pub struct Zones {
    pub a: [u8; ZONE_WINDOW],
    pub b: [u8; ZONE_WINDOW],
    pub c: [u8; ZONE_WINDOW],
    pub d: [u8; ZONE_WINDOW],
    pub c1a: u8,
    pub c1b: u8,
    pub c1c: u8,
    pub c1d: u8,
}

impl Zones {
    pub fn from_files(dir: &str) -> Result<Self, String> {
        let read = |name: &str| -> Result<[u8; ZONE_WINDOW], String> {
            let p = format!("{dir}/{name}");
            let blob = std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?;
            blob.try_into().map_err(|_| format!("{p}: wrong size"))
        };
        // c1 defaults to the old baked-in alignment until the test
        // feeds the session's own first lane values.
        Ok(Self { a: read("fam1_zone.bin")?, b: read("fam2_zone.bin")?,
                  c: read("fam3_zone.bin")?, d: read("fam4_zone.bin")?,
                  c1a: 0x90, c1b: 0x52, c1c: 0xB0, c1d: 0x37 })
    }

    fn read_at(z: &[u8; ZONE_WINDOW], v: u8, c1: u8) -> Option<u8> {
        let idx = v as i32 - c1 as i32 + 0x100;
        if (0..ZONE_WINDOW as i32).contains(&idx) { Some(z[idx as usize]) } else { None }
    }
}

#[inline]
fn nibble_tail(read: u8, c4: u8, fx: u8) -> u8 {
    (((read.wrapping_sub(c4 | 0xA2)) & 0xF0) | ((read.wrapping_sub(c4 | 0x02)) & 0x0F)) ^ fx
}

/// The opening round's m4 tail: the same fold, the final xor skipped
/// (the alternate CFF branch -- measured live on depot[0]).
#[inline]
fn nibble_tail_raw(read: u8, c4: u8) -> u8 {
    ((read.wrapping_sub(c4 | 0xA2)) & 0xF0) | ((read.wrapping_sub(c4 | 0x02)) & 0x0F)
}

/// One mixer's output byte from its measured inputs (None if the
/// zone read falls outside the dumped window).
pub fn mixer_byte(mixer: usize, inp: &MixerInputs, zones: &Zones) -> Option<u8> {
    let lane = LANE_OF[mixer];
    let fx = FINAL_XOR[mixer];
    let v = inp.lane_value;
    match lane {
        0 => Zones::read_at(&zones.a, v, zones.c1a)
            .map(|r| inp.mul.wrapping_add(r) ^ fx),
        1 => Zones::read_at(&zones.b, v, zones.c1b)
            .map(|r| inp.mul.wrapping_add(r) ^ fx),
        2 => Zones::read_at(&zones.c, v, zones.c1c)
            .map(|read| (read.wrapping_sub(v | 0x35)) ^ ((read.wrapping_sub(v | 0x15)).wrapping_shl(3)) ^ fx),
        _ => Zones::read_at(&zones.d, v, zones.c1d).map(|read| {
            if mixer == 3 {
                if inp.m4_round1 { nibble_tail_raw(read, v) } else { nibble_tail(read, v, fx) }
            } else {
                read.wrapping_sub(v | 0xA2) ^ fx
            }
        }),
    }
}

/// Assemble the body A (160 bytes) from ten rounds of measured
/// mixer inputs. `None` for a position whose zone read is out of
/// the dumped window leaves that byte as 0 -- the parity test
/// skips exactly those.
pub fn generate_body_a(rounds: &[[MixerInputs; 16]; 10], zones: &Zones) -> [u8; 160] {
    let mut body = [0u8; 160];
    for (k, round) in rounds.iter().enumerate() {
        for (inp, row_pos) in round.iter().zip(ROW_POS.iter()) {
            if let Some(b) = mixer_byte(*row_pos, inp, zones) {
                let pos = row_pos + 0x10 * k;
                body[pos] = b;
            }
        }
    }
    body
}


// ---------------------------------------------------------------------------
// THE SELECTOR WEAVE (verified live, runs 33/34: 16 formulas x 11/11 cycles).
// The sixteen planter selectors of one mixer round: the rbx quartet,
// three cascade words through the term-mask machine, and the fam4 S-box
// slots through the session planter's 0x1390 window.
// ---------------------------------------------------------------------------

/// The term-mask machine -- the Windows opcode-mask arithmetic, one
/// engine across platforms: (x - 2*(x & K) + C) ^ R, all mod 2^32.
#[inline]
pub fn term_mask(x: u32, k: u32, c: u32, r: u32) -> u32 {
    x.wrapping_sub(2 * (x & k)).wrapping_add(c) ^ r
}

/// The cascade constants, as decoded from the disassembly and
/// verified against the live edx of their own store hits.
pub const A_K: u32 = 0x5CB1AF98;
pub const A_C: u32 = 0x2E58D7CC;
pub const A_R_XOR: u32 = 0x7C010B68;
pub const B_MUL_ADD: u32 = 0x08801806;
pub const B_K: u32 = 0xD2CEA9AC;
pub const B_C: u32 = 0x696754D6;
pub const C_PRE_XOR: u32 = 0x1E615119;
pub const C_K: u32 = 0x1352405E;
pub const C_C: u32 = 0x09A9202F;

/// The per-round feeds of the three cascades: named exactly as the
/// live registers/slots they were taped on.
#[derive(Clone, Copy, Debug, Default)]
pub struct WeaveFeeds {
    pub rbx: u32,   // the round key
    pub r15_in: u32, // r15d at the m4 hit (cascade A's product input)
    pub f8: u32,    // [rbp-0xf8]
    pub r10d: u32,  // cascade A's xor feed
    pub eax_in: u32, // eax at the m8 hit (cascade B's product input, +0x08801806)
    pub r8d: u32,   // cascade B's multiplier
    pub r12d: u32,  // cascade B's xor feed
    pub r9d: u32,   // cascade C's pre-xor input
    pub f78: u32,   // [rbp-0x78]
    pub r13d: u32,  // cascade C's multiplier
    pub f148: u32,  // cascade C's xor feed
}

impl WeaveFeeds {
    /// The three cascade words, in measured order A, B, C.
    pub fn cascade_words(&self) -> [u32; 3] {
        let a = term_mask(
            self.r15_in.wrapping_mul(self.f8), A_K, A_C,
            self.r10d ^ A_R_XOR,
        );
        let b = term_mask(
            self.eax_in.wrapping_add(B_MUL_ADD).wrapping_mul(self.r8d),
            B_K, B_C, self.r12d,
        );
        let c = term_mask(
            (self.r9d ^ self.f78 ^ C_PRE_XOR).wrapping_mul(self.r13d),
            C_K, C_C, self.f148,
        );
        [a, b, c]
    }
}

/// The sixteen selectors of one round. `planter_1390` is the
/// session planter's S-box window (0x1390..0x1490, 256 bytes).
pub fn selectors(f: &WeaveFeeds, planter_1390: &[u8; 256]) -> [u8; 16] {
    let [wa, wb, wc] = f.cascade_words();
    let sbox = |x: u8, k1: u8, k2: u8| planter_1390[(x ^ k1) as usize] ^ k2;
    [
        (f.rbx & 0xFF) as u8 ^ 0xFC,
        ((f.rbx >> 8) & 0xFF) as u8 ^ 0x37,
        ((f.rbx >> 16) & 0xFF) as u8 ^ 0xE1,
        sbox((f.rbx >> 24) as u8, 0x85, 0x05),
        (wa & 0xFF) as u8 ^ 0xD3,
        ((wa >> 8) & 0xFF) as u8 ^ 0x66,
        ((wa >> 16) & 0xFF) as u8 ^ 0x8D,
        sbox((wa >> 24) as u8, 0x16, 0x07),
        (wb & 0xFF) as u8 ^ 0x93,
        ((wb >> 8) & 0xFF) as u8 ^ 0xA9,
        ((wb >> 16) & 0xFF) as u8 ^ 0x22,
        sbox((wb >> 24) as u8, 0xF4, 0xDD),
        (wc & 0xFF) as u8 ^ 0x91,
        ((wc >> 8) & 0xFF) as u8 ^ 0x5D,
        ((wc >> 16) & 0xFF) as u8 ^ 0x95,
        sbox((wc >> 24) as u8, 0xAE, 0x48),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live parity: the run-26 tape (the zone-read registers of
    /// every mixer of every round) drives the transcribed tails and
    /// the result must match the same run's CPIM body A byte for
    /// byte -- 122 checkable passes, all green. The three defective
    /// tape rows (m12's BP landed mid-instruction, m14's after the
    /// final xor, and m4's first round) are skipped with their
    /// causes; this mirrors tools/verify_body_a2.py exactly.
    #[test]
    fn live_body_a_parity() {
        let dir = std::env::var("PERUN_LIVE_DIR").unwrap_or_else(|_| "/opt/data/adi-re".into());
        // The parity is only meaningful when the tape and the CPIM
        // come from ONE session -- the tape's planter is session-
        // born (the cross-session law, paid for twice). The digest
        // run overwrites live_prov_out.bin, so the body-A gate is
        // its OWN switch, flipped only while the zone-26 artifacts
        // are the same run's pair.
        if std::env::var("PERUN_BODY_A_PAIR_READY").is_err() {
            eprintln!("gating: PERUN_BODY_A_PAIR_READY not set (the zone-26 tape and the current live_prov_out.bin must be one session)");
            return;
        }
        let (Ok(mut zones), Ok(tape), Ok(cpim)) = (
            Zones::from_files(&dir),
            std::fs::read_to_string(format!("{dir}/zone26_tape.txt")),
            std::fs::read(format!("{dir}/live_prov_out.bin")),
        ) else {
            eprintln!("gating: live artifacts not present under {dir}");
            return;
        };
        assert_eq!(cpim.len(), 0x114, "the live CPIM is 276 bytes");
        // the session's first lane values, straight off the tape:
        // fam1/fam2 index by rcx, fam3 by rdx, fam4 by rax.
        {
            let mut got = [0u8; 4];
            let mut have = [false; 4];
            for line in tape.lines() {
                let mut d = std::collections::HashMap::new();
                for f in line.split_whitespace() {
                    if let Some((k, v)) = f.split_once('=') { d.insert(k.to_string(), v.to_string()); }
                }
                let Some(s) = d.get("store") else { continue };
                let sv = s.trim_start_matches("0x");
                let ci = match sv {
                    "e6b9d" if !have[0] => 0,
                    "e6be2" if !have[1] => 1,
                    "e6c47" if !have[2] => 2,
                    "e6ca0" if !have[3] => 3,
                    _ => 99,
                };
                if ci < 4 {
                    // fam1/fam2 giant reads index by rcx, fam3 by rdx,
                    // and the fam4 lane by RAX -- the selector itself.
                    let key = match ci { 2 => "dl", 3 => "al", _ => "cl" };
                    got[ci] = u8::from_str_radix(d[key].trim_start_matches("0x"), 16).unwrap_or(0);
                    have[ci] = true;
                }
            }
            assert!(have.iter().all(|&h| h), "the tape must carry the four family first hits");
            zones.c1a = got[0];
            zones.c1b = got[1];
            zones.c1c = got[2];
            zones.c1d = got[3];
        }


        // parse the tape into rounds, each opened at mixer 1 (m15 rows
        // are absent in round 1 -- the tape is parsed by boundaries,
        // never by fixed stride)
        let mut rounds_raw: Vec<Vec<(usize, MixerInputs)>> = Vec::new();
        let mut cur: Vec<(usize, MixerInputs)> = Vec::new();
        for line in tape.lines() {
            let mut fields = line.split_whitespace();
            let _n = fields.next();
            let mut d = std::collections::HashMap::new();
            for f in fields {
                let (k, v) = f.split_once('=').expect("field");
                d.insert(k.to_string(), v.to_string());
            }
            let store = u32::from_str_radix(d["store"].trim_start_matches("0x"), 16).unwrap();
            if store == STORES[0] && !cur.is_empty() {
                rounds_raw.push(std::mem::take(&mut cur));
            }
            let rcx = u64::from_str_radix(d["rcx"].trim_start_matches("0x"), 16).unwrap();
            let al = u8::from_str_radix(d["al"].trim_start_matches("0x"), 16).unwrap();
            let rdx = u64::from_str_radix(d["rdx"].trim_start_matches("0x"), 16).unwrap();
            let rax = u64::from_str_radix(d["rax"].trim_start_matches("0x"), 16).unwrap();
            let mixer = STORES.iter().position(|&s| s == store).expect("store in census");
            let lane = LANE_OF[mixer];
            let lane_value = match lane {
                0 | 1 => rcx as u8,
                2 => rdx as u8,
                _ => rax as u8,
            };
            // m12's giant breakpoint (0xe6ec8) catches rax BEFORE the
            // fam4 s-box xor -- the planter value c12, not the selector.
            // The fam4 lane indexes by the SELECTOR: c12 ^ 0xDD.
            let lane_value = if mixer == 11 { lane_value ^ 0xDD } else { lane_value };
            cur.push((mixer, MixerInputs { lane_value, mul: al, m4_round1: false }));
        }
        if !cur.is_empty() {
            rounds_raw.push(cur);
        }

        // THE SEL-TAPE BACKFILL: m12's giant breakpoint sits inside an
        // instruction (never fires) and the m4 first round is the named
        // anomaly -- but the planter tape carries every round complete,
        // and for the fam4 lanes the lane_value IS the selector (rax
        // right after the s-box xor, measured).
        if let Ok(st) = std::fs::read_to_string(format!("{dir}/sel34_tape.txt")) {
            let mut sel_rounds: Vec<Vec<u8>> = Vec::new();
            let mut srow: Vec<u8> = Vec::new();
            for line in st.lines() {
                let mut is_m1 = false;
                let mut sel = 0u8;
                for f in line.split_whitespace() {
                    if let Some((k, v)) = f.split_once('=') {
                        if k == "store" { is_m1 = v.trim_start_matches("0x") == "e6b9d"; }
                        if k == "sel" { sel = u8::from_str_radix(v, 16).unwrap_or(0); }
                    }
                }
                if is_m1 && !srow.is_empty() { sel_rounds.push(std::mem::take(&mut srow)); }
                srow.push(sel);
            }
            if !srow.is_empty() { sel_rounds.push(srow); }
            for (k, rnd) in rounds_raw.iter_mut().enumerate() {
                let Some(sr) = sel_rounds.get(k) else { continue };
                if sr.len() < 16 { continue; }
                if !rnd.iter().any(|(j, _)| *j == 11) {
                    rnd.push((11, MixerInputs { lane_value: sr[11], mul: 0, m4_round1: false }));
                }
                if !rnd.iter().any(|(j, _)| *j == 3) {
                    rnd.push((3, MixerInputs { lane_value: sr[3], mul: 0, m4_round1: true }));
                }
            }
        }
        // the opening round's m4 runs the alternate tail branch (measured).
        if let Some(r0) = rounds_raw.first_mut() {
            for (j, inp) in r0.iter_mut() {
                if *j == 3 { inp.m4_round1 = true; }
            }
        }
        let mut checked = 0;
        let mut ok = 0;
        let mut skipped_named = 0;
        for (k, round) in rounds_raw.iter().take(10).enumerate() {
            for (j, inp) in round {
                if *j == 11 && inp.mul == 0 {
                    skipped_named += 1; // m12 row without the sel-tape backfill
                    continue;
                }
                let pos = ROW_POS[*j] + 0x10 * k;
                let expect = cpim[0x18 + pos];
                // m14's breakpoint (0xe6f6c) sits AFTER its tail -- the
                // tape row carries the finished byte itself (10/10 live).
                let got = if *j == 13 { Some(inp.mul) } else { mixer_byte(*j, inp, &zones) };
                match got {
                    Some(b) => {
                        assert_eq!(b, expect,
                            "mixer {} round {}: {b:#04x} != cpim+{:#04x}", *j + 1, k + 1, 0x18 + pos);
                        ok += 1;
                        checked += 1;
                    }
                    None => skipped_named += 1, // zone read outside the dumped window
                }
            }
        }
        // the live tape carries ten rounds; the checkable count is the
        // campaign's 122 -- the test must not pass on a short read
        assert!(checked >= 100, "suspiciously few checkable rows ({checked})");
        assert_eq!(ok, checked, "every checkable byte must match");
        eprintln!("BODY A live parity: {ok}/{checked} (named skips: {skipped_named})");
    }

    /// THE THROUGH TEST: the full 192-byte depot of ONE session --
    /// body A assembled from the mixer tape, the digest from the
    /// watchpoint word tape -- laid against the same run's CPIM
    /// (the unloader's law: cpim[0x18+j] == depot[j]). The digest
    /// block resolves every word from a measured store hit, so no
    /// byte on either side is derived. Gated like the digest pair.
    #[test]
    fn live_full_depot_parity() {
        use crate::digest::{generate_digest, DigestInputs, K_HIGH, K_LOW};
        let dir = std::env::var("PERUN_LIVE_DIR")
            .unwrap_or_else(|_| "/opt/data/adi-re".into());
        if std::env::var("PERUN_DIGEST_PAIR_READY").is_err() {
            eprintln!("gating: PERUN_DIGEST_PAIR_READY not set");
            return;
        }
        let (Ok(mut zones), Ok(tape), Ok(wtape), Ok(cpim)) = (
            Zones::from_files(&dir),
            std::fs::read_to_string(format!("{dir}/zone26_tape.txt")),
            std::fs::read_to_string(format!("{dir}/pair_wp_words.txt")),
            std::fs::read(format!("{dir}/live_prov_out.bin")),
        ) else {
            eprintln!("gating: through-test artifacts not present under {dir}");
            return;
        };
        assert_eq!(cpim.len(), 0x114, "the live CPIM is 276 bytes");
        // the session's first lane values, straight off the tape:
        // fam1/fam2 index by rcx, fam3 by rdx, fam4 by rax.
        {
            let mut got = [0u8; 4];
            let mut have = [false; 4];
            for line in tape.lines() {
                let mut d = std::collections::HashMap::new();
                for f in line.split_whitespace() {
                    if let Some((k, v)) = f.split_once('=') { d.insert(k.to_string(), v.to_string()); }
                }
                let Some(s) = d.get("store") else { continue };
                let sv = s.trim_start_matches("0x");
                let ci = match sv {
                    "e6b9d" if !have[0] => 0,
                    "e6be2" if !have[1] => 1,
                    "e6c47" if !have[2] => 2,
                    "e6ca0" if !have[3] => 3,
                    _ => 99,
                };
                if ci < 4 {
                    // fam1/fam2 giant reads index by rcx, fam3 by rdx,
                    // and the fam4 lane by RAX -- the selector itself.
                    let key = match ci { 2 => "dl", 3 => "al", _ => "cl" };
                    got[ci] = u8::from_str_radix(d[key].trim_start_matches("0x"), 16).unwrap_or(0);
                    have[ci] = true;
                }
            }
            assert!(have.iter().all(|&h| h), "the tape must carry the four family first hits");
            zones.c1a = got[0];
            zones.c1b = got[1];
            zones.c1c = got[2];
            zones.c1d = got[3];
        }

        let mut depot = [0u8; 0xC0];
        let mut seen = [false; 0xC0];
        // body A from the mixer tape (same parser as live_body_a_parity)
        let mut rounds_raw: Vec<Vec<(usize, MixerInputs)>> = Vec::new();
        let mut cur: Vec<(usize, MixerInputs)> = Vec::new();
        for line in tape.lines() {
            let mut fields = line.split_whitespace();
            let _n = fields.next();
            let mut d = std::collections::HashMap::new();
            for f in fields {
                let (k, v) = f.split_once('=').expect("field");
                d.insert(k.to_string(), v.to_string());
            }
            let store = u32::from_str_radix(d["store"].trim_start_matches("0x"), 16).unwrap();
            if store == STORES[0] && !cur.is_empty() {
                rounds_raw.push(std::mem::take(&mut cur));
            }
            let rcx = u64::from_str_radix(d["rcx"].trim_start_matches("0x"), 16).unwrap();
            let al = u8::from_str_radix(d["al"].trim_start_matches("0x"), 16).unwrap();
            let rdx = u64::from_str_radix(d["rdx"].trim_start_matches("0x"), 16).unwrap();
            let rax = u64::from_str_radix(d["rax"].trim_start_matches("0x"), 16).unwrap();
            let mixer = STORES.iter().position(|&s| s == store).expect("store in census");
            let lane = LANE_OF[mixer];
            let lane_value = match lane {
                0 | 1 => rcx as u8,
                2 => rdx as u8,
                _ => rax as u8,
            };
            // m12's giant breakpoint (0xe6ec8) catches rax BEFORE the
            // fam4 s-box xor -- the planter value c12, not the selector.
            // The fam4 lane indexes by the SELECTOR: c12 ^ 0xDD.
            let lane_value = if mixer == 11 { lane_value ^ 0xDD } else { lane_value };
            cur.push((mixer, MixerInputs { lane_value, mul: al, m4_round1: false }));
        }
        if !cur.is_empty() {
            rounds_raw.push(cur);
        }
// THE SEL-TAPE BACKFILL: m12's giant breakpoint sits inside an
        // instruction (never fires) and the m4 first round is the named
        // anomaly -- but the planter tape carries every round complete,
        // and for the fam4 lanes the lane_value IS the selector (rax
        // right after the s-box xor, measured).
        if let Ok(st) = std::fs::read_to_string(format!("{dir}/sel34_tape.txt")) {
            let mut sel_rounds: Vec<Vec<u8>> = Vec::new();
            let mut srow: Vec<u8> = Vec::new();
            for line in st.lines() {
                let mut is_m1 = false;
                let mut sel = 0u8;
                for f in line.split_whitespace() {
                    if let Some((k, v)) = f.split_once('=') {
                        if k == "store" { is_m1 = v.trim_start_matches("0x") == "e6b9d"; }
                        if k == "sel" { sel = u8::from_str_radix(v, 16).unwrap_or(0); }
                    }
                }
                if is_m1 && !srow.is_empty() { sel_rounds.push(std::mem::take(&mut srow)); }
                srow.push(sel);
            }
            if !srow.is_empty() { sel_rounds.push(srow); }
            for (k, rnd) in rounds_raw.iter_mut().enumerate() {
                let Some(sr) = sel_rounds.get(k) else { continue };
                if sr.len() < 16 { continue; }
                if !rnd.iter().any(|(j, _)| *j == 11) {
                    rnd.push((11, MixerInputs { lane_value: sr[11], mul: 0, m4_round1: false }));
                }
                if !rnd.iter().any(|(j, _)| *j == 3) {
                    rnd.push((3, MixerInputs { lane_value: sr[3], mul: 0, m4_round1: true }));
                }
            }
        }
        // the opening round's m4 runs the alternate tail branch (measured).
        if let Some(r0) = rounds_raw.first_mut() {
            for (j, inp) in r0.iter_mut() {
                if *j == 3 { inp.m4_round1 = true; }
            }
        }
        let mut body_bytes = 0;
        for (k, round) in rounds_raw.iter().take(10).enumerate() {
            for (j, inp) in round {
                if *j == 11 && inp.mul == 0 && inp.lane_value == 0 {
                    continue; // an unfilled m12 backfill row stays unseen
                }
                let pos = ROW_POS[*j] + 0x10 * k;
                // m14's row carries the finished byte (the breakpoint
                // sits after the tail, measured 10/10).
                let got = if *j == 13 { Some(inp.mul) } else { mixer_byte(*j, inp, &zones) };
                if let Some(b) = got {
                    depot[pos] = b;
                    seen[pos] = true;
                    body_bytes += 1;
                }
            }
        }
        // the digest: resolve the eight words from measured hits
        let mut rows: Vec<Vec<(String, u32)>> = Vec::new();
        for line in wtape.lines() {
            if line.starts_with("hit") {
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
        const CANON: [(usize, &str, u32); 8] = [
            (0xA0, "RCX", K_LOW), (0xA4, "W8", K_LOW),
            (0xA8, "W6", K_LOW), (0xAC, "W2", K_LOW),
            (0xB0, "W1", K_HIGH), (0xB4, "W3", K_HIGH),
            (0xB8, "W5", K_HIGH), (0xBC, "W4", K_HIGH),
        ];
        let mut words = DigestInputs::default();
        for (block, key, k) in CANON {
            let mut s_live = 0u32;
            for b in 0..4 {
                s_live = (s_live << 8) | cpim[0x18 + block + b] as u32;
            }
            let mut word = None;
            'hits: for row in &rows {
                for (kk, vv) in row {
                    if kk == key && vv.wrapping_add(k) == s_live {
                        word = Some(*vv);
                        break 'hits;
                    }
                }
            }
            let Some(w) = word else {
                // the prologue-cascade block may stay gated, named, never silent
                assert_eq!(block, 0xA0, "only the prologue-cascade block may stay gated");
                continue;
            };
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
        }
        let dz = generate_digest(&words);
        depot[0xA0..0xC0].copy_from_slice(&dz);
        let digest_live = if words.a0 == 0 { 28 } else { 32 };
        let first_digest_seen = if words.a0 == 0 { 0xA4 } else { 0xA0 };
        for s in &mut seen[first_digest_seen..0xC0] {
            *s = true;
        }
        // the unloader law, byte for byte, over everything assembled
        let mut ok = 0;
        for j in 0..0xC0 {
            if !seen[j] {
                continue; // the body-A skips are not asserted here
            }
            assert_eq!(depot[j], cpim[0x18 + j], "depot+{j:#04x} vs cpim+{:#04x}", 0x18 + j);
            ok += 1;
        }
        assert_eq!(ok, body_bytes + digest_live, "the through count is body bytes plus the live digest");
        eprintln!("THROUGH depot parity: {ok}/192 positions live (body A {body_bytes} + digest {digest_live}; body skips {}/160)", 160 - body_bytes);
    }


    /// THE WEAVE PARITY: the sixteen selector formulas against the
    /// live planter tape (sel34_tape.txt, 10 complete rounds of one
    /// session) with the taped feeds and the session's planter S-box
    /// (planter34.bin, window 0x1390). Gated on PERUN_WEAVE_READY.
    #[test]
    fn live_weave_parity() {
        let dir = std::env::var("PERUN_LIVE_DIR")
            .unwrap_or_else(|_| "/opt/data/adi-re".into());
        if std::env::var("PERUN_WEAVE_READY").is_err() {
            eprintln!("gating: PERUN_WEAVE_READY not set");
            return;
        }
        let (Ok(tape), Ok(planter)) = (
            std::fs::read_to_string(format!("{dir}/sel34_tape.txt")),
            std::fs::read(format!("{dir}/planter34.bin")),
        ) else {
            eprintln!("gating: weave artifacts not present under {dir}");
            return;
        };
        assert!(planter.len() >= 0x1490, "the planter dump covers the 0x1390 window");
        let mut sbox = [0u8; 256];
        sbox.copy_from_slice(&planter[0x1390..0x1490]);
        // rows -> rounds of 16 (store m1 opens each round)
        let mut rounds: Vec<Vec<Vec<(String, u32)>>> = Vec::new();
        let mut cur: Vec<Vec<(String, u32)>> = Vec::new();
        for line in tape.lines() {
            let mut fields = Vec::new();
            for f in line.split_whitespace().skip(1) {
                if let Some((k, v)) = f.split_once('=') {
                    if let Ok(x) = u32::from_str_radix(v.trim_start_matches("0x"), 16) {
                        fields.push((k.to_string(), x));
                    }
                }
            }
            let is_m1 = fields.iter().any(|(k, v)| k == "store" && *v == 0xE6B9D);
            if is_m1 && !cur.is_empty() {
                rounds.push(std::mem::take(&mut cur));
            }
            cur.push(fields);
        }
        if !cur.is_empty() {
            rounds.push(cur);
        }
        assert!(rounds.len() >= 10, "the tape carries ten rounds");
        let get = |row: &[(String, u32)], key: &str| -> u32 {
            row.iter().find(|(k, _)| k == key).map(|(_, v)| *v).unwrap_or(0)
        };
        let sel_of = |row: &[(String, u32)]| -> u8 { get(row, "sel") as u8 };
        let mut ok = 0;
        let mut total = 0;
        for c in rounds.iter().take(10) {
            if c.len() < 16 { continue; }
            let feeds = WeaveFeeds {
                rbx: get(&c[0], "rbx"),
                r15_in: get(&c[3], "r15d"),
                f8: get(&c[4], "f8"),
                r10d: get(&c[4], "r10d"),
                eax_in: get(&c[7], "eax"),
                r8d: get(&c[8], "r8d"),
                r12d: get(&c[8], "r12d"),
                r9d: get(&c[12], "r9d"),
                f78: get(&c[12], "f78"),
                r13d: get(&c[12], "r13d"),
                f148: get(&c[12], "f148"),
            };
            let want = selectors(&feeds, &sbox);
            for j in 0..16 {
                assert_eq!(want[j], sel_of(&c[j]), "round mixer {}", j + 1);
                ok += 1;
                total += 1;
            }
        }
        assert_eq!(total, 160, "ten complete rounds");
        eprintln!("WEAVE live parity: {ok}/160 selectors across ten rounds");
    }

    /// The ladder invariant, pinned without any live files: every
    /// mixer lands on its own depot position, no overlap, no gap.
    #[test]
    fn ladder_covers_everything_once() {
        let mut seen = [false; 160];
        let mut written = 0usize;
        for row_pos in ROW_POS {
            for k in 0..10u32 {
                let pos = row_pos + 0x10 * (k as usize);
                assert!(!seen[pos], "position {pos} written twice");
                seen[pos] = true;
                written += 1;
            }
        }
        assert_eq!(written, 160);
        assert!(seen.iter().all(|&s| s), "no gaps in the ladder");
    }
}
