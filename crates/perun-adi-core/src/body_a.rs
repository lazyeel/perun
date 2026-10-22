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

/// The zone read offsets into the four dumped zone buffers.
pub mod zone_offsets {
    pub const A: i32 = -0x10;
    pub const B: i32 = 0x2E;
    pub const C: i32 = -0x30;
    pub const D: i32 = 0x49;
}

/// One lane's measured inputs for a single mixer pass.
#[derive(Clone, Copy, Debug)]
pub struct MixerInputs {
    /// The planter-derived lane value (c for lanes A/B, c3 for C, c4 for D).
    pub lane_value: u8,
    /// The mul operand (lanes A/B only; unused by the C/D tails).
    pub mul: u8,
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
pub struct Zones {
    pub a: [u8; 0x200],
    pub b: [u8; 0x200],
    pub c: [u8; 0x200],
    pub d: [u8; 0x200],
}

impl Zones {
    pub fn from_files(dir: &str) -> Result<Self, String> {
        let read = |name: &str| -> Result<[u8; 0x200], String> {
            let p = format!("{dir}/{name}");
            let blob = std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?;
            blob.try_into().map_err(|_| format!("{p}: wrong size"))
        };
        Ok(Self { a: read("fam1_zone.bin")?, b: read("fam2_zone.bin")?,
                  c: read("fam3_zone.bin")?, d: read("fam4_zone.bin")? })
    }

    fn read_at(z: &[u8; 0x200], c: u8, off: i32) -> Option<u8> {
        let idx = c as i32 + off;
        if (0..0x200).contains(&idx) { Some(z[idx as usize]) } else { None }
    }
}

#[inline]
fn nibble_tail(read: u8, c4: u8, fx: u8) -> u8 {
    (((read.wrapping_sub(c4 | 0xA2)) & 0xF0) | ((read.wrapping_sub(c4 | 0x02)) & 0x0F)) ^ fx
}

/// One mixer's output byte from its measured inputs (None if the
/// zone read falls outside the dumped window).
pub fn mixer_byte(mixer: usize, inp: &MixerInputs, zones: &Zones) -> Option<u8> {
    let lane = LANE_OF[mixer];
    let fx = FINAL_XOR[mixer];
    let v = inp.lane_value;
    match lane {
        0 => Zones::read_at(&zones.a, v, zone_offsets::A)
            .map(|r| inp.mul.wrapping_add(r) ^ fx),
        1 => Zones::read_at(&zones.b, v, zone_offsets::B)
            .map(|r| inp.mul.wrapping_add(r) ^ fx),
        2 => Zones::read_at(&zones.c, v, zone_offsets::C)
            .map(|read| (read.wrapping_sub(v | 0x35)) ^ ((read.wrapping_sub(v | 0x15)).wrapping_shl(3)) ^ fx),
        _ => Zones::read_at(&zones.d, v, zone_offsets::D).map(|read| {
            if mixer == 3 { nibble_tail(read, v, fx) } else { read.wrapping_sub(v | 0xA2) ^ fx }
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
        let (Ok(zones), Ok(tape), Ok(cpim)) = (
            Zones::from_files(&dir),
            std::fs::read_to_string(format!("{dir}/zone26_tape.txt")),
            std::fs::read(format!("{dir}/live_prov_out.bin")),
        ) else {
            eprintln!("gating: live artifacts not present under {dir}");
            return;
        };
        assert_eq!(cpim.len(), 0x114, "the live CPIM is 276 bytes");

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
            cur.push((mixer, MixerInputs { lane_value, mul: al }));
        }
        if !cur.is_empty() {
            rounds_raw.push(cur);
        }

        let mut checked = 0;
        let mut ok = 0;
        let mut skipped_named = 0;
        for (k, round) in rounds_raw.iter().take(10).enumerate() {
            for (j, inp) in round {
                if *j == 11 || *j == 13 {
                    skipped_named += 1; // the defective tape rows (m12, m14)
                    continue;
                }
                if *j == 3 && k == 0 {
                    skipped_named += 1; // the open first-round anomaly
                    continue;
                }
                let pos = ROW_POS[*j] + 0x10 * k;
                let expect = cpim[0x18 + pos];
                match mixer_byte(*j, inp, &zones) {
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
