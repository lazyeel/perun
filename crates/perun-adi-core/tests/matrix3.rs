// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! matrix3 — the transcribed Body-A + digest differential oracle, and the
//! public Start-state parity grid.
//!
//! Part A (private corpus, gated): directories under `PERUN_MATRIX3_DIR`
//! holding `live_prov_out.bin` (0x114 reference CPIM) and `pair_depot.bin`
//! (≥0xC0 depot slice), plus the same-session tapes the transcriber needs
//! (`zone26_tape.txt`, `sel34_tape.txt`, `pair_wp_words.txt`). For each
//! case the Rust transcription (`generate_body_from_tapes`) is the
//! differential oracle against the reference CPIM's depot window
//! `cpim[0x18..0x18+0xC0]`: every transcribed byte of body A [0..0xA0)
//! and the digest [0xA0..0xC0) must be equal.
//!
//! Part B (public Start-state parity, the 5-state grid, no gating): the
//! native Apple states of `cases/{tM,tI,tE1794862200,tE1794863400,tE1794865200}`:
//!
//!   - the native state round-trips byte-exact through the Apple codec
//!     (the Rust "Start" rebuild side of the parity);
//!   - Start and OTP snapshots are byte-identical -- Start never mutates
//!     the persisted state (the observable native law);
//!   - the native MID artifacts anchor the law `MID = f(state)`: one
//!     value across the whole grid, 60 bytes each.
//!
//! The 5 OTP payloads are distinct by design (the law is
//! `OTP = f(state, CLOCK_REALTIME)`); the numeric OTP law itself is the
//! native `qi864985u0` lift, still pending.

use perun_adi_core::body_a::generate_body_from_tapes;
use perun_adi_core::state::AppleState;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const GRID: [&str; 5] = ["tM", "tI", "tE1794862200", "tE1794863400", "tE1794865200"];

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn corpus_dirs() -> Vec<PathBuf> {
    let Some(root) = std::env::var_os("PERUN_MATRIX3_DIR") else {
        eprintln!("PERUN_MATRIX3_DIR unset -- part A (transcribed-depot oracle) skipped");
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("read PERUN_MATRIX3_DIR")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.join("cap").join("live_prov_out.bin").exists()
                && path.join("cap").join("pair_depot.bin").exists()
        })
        .collect();
    dirs.sort();
    dirs
}

/// Part A: transcribed depot [0x00..0xC0) vs the reference CPIM depot.
/// Returns (cases checked, body-A bytes exact, digest bytes exact).
fn part_a() -> (usize, usize, usize) {
    let mut checked = 0usize;
    let mut body_a_exact = 0usize;
    let mut digest_exact = 0usize;
    for dir in corpus_dirs() {
        let cpim = read(&dir.join("cap").join("live_prov_out.bin"));
        assert_eq!(
            cpim.len(),
            0x114,
            "{}: reference CPIM must be 0x114",
            dir.display()
        );
        let pair = read(&dir.join("cap").join("pair_depot.bin"));
        assert!(
            pair[..0xC0] == cpim[0x18..0x18 + 0xC0],
            "{}: pair depot is not the CPIM's own depot window",
            dir.display()
        );
        let (depot, body_bytes) =
            generate_body_from_tapes(&dir.to_string_lossy()).expect("transcribe the depot");
        assert_eq!(
            body_bytes,
            160,
            "{}: body-A must cover 160/160",
            dir.display()
        );
        let mismatches = depot[..0xC0]
            .iter()
            .zip(cpim[0x18..0x18 + 0xC0].iter())
            .filter(|(a, b)| a != b)
            .count();
        if mismatches != 0 {
            panic!(
                "{}: transcribed depot differs at {mismatches} byte(s)",
                dir.display()
            );
        }
        body_a_exact += depot[..0xA0]
            .iter()
            .zip(cpim[0x18..0x18 + 0xA0].iter())
            .filter(|(a, b)| a == b)
            .count();
        digest_exact += depot[0xA0..0xC0]
            .iter()
            .zip(cpim[0xB8..0xD8].iter())
            .filter(|(a, b)| a == b)
            .count();
        eprintln!(
            "matrix3[{}]: transcribed body-A [0..0xa0) + digest [0xa0..0xc0) == oracle depot (160+32)",
            dir.display()
        );
        checked += 1;
    }
    (checked, body_a_exact, digest_exact)
}

/// Part B: the public Start-state parity grid over the five native cases.
fn part_b() {
    let root = std::env::var("PERUN_GRID_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/admin/rig/cases"));
    let mut mids = HashSet::new();
    let mut payloads = HashSet::new();
    for name in GRID {
        let dir = root.join(name).join("cap");
        let before_start = read(&dir.join("adi-state-before-start.bin"));
        let before_otp = read(&dir.join("adi-state-before-otp.bin"));
        assert_eq!(
            before_start, before_otp,
            "{name}: Start must not mutate the persisted state"
        );
        let state = AppleState::parse(&before_otp)
            .unwrap_or_else(|error| panic!("{name}: native state must parse: {error}"));
        assert_eq!(
            state.encode(),
            before_otp,
            "{name}: the Apple codec must round-trip byte-exact"
        );
        assert_eq!(state.version(), 1, "{name}: the native state version");
        assert_eq!(state.tail().len(), 580, "{name}: the native tail length");

        let mid = read(&dir.join("mid.bin"));
        let otp = read(&dir.join("otp.bin"));
        assert_eq!(mid.len(), 60, "{name}: the native MID is 60 bytes");
        assert_eq!(&otp[0..4], &[0, 0, 0, 5], "{name}: the OTP header version");
        assert_eq!(
            &otp[4..8],
            &[0, 0, 0, 0x10],
            "{name}: the OTP payload length"
        );
        assert_eq!(&otp[24..28], &[0, 0, 0, 4], "{name}: the OTP trailer");
        mids.insert(mid.clone());
        payloads.insert(otp[8..24].to_vec());
        eprintln!(
            "matrix3[{name}]: state round-trips ({} B), Start/OTP state identical, MID {}.., OTP payload {}",
            before_otp.len(),
            hex_short(&mid),
            hex_short(&otp[8..24])
        );
    }
    assert_eq!(
        mids.len(),
        1,
        "MID = f(state): one state -> one MID across the grid"
    );
    assert_eq!(
        payloads.len(),
        GRID.len(),
        "the grid's OTP payloads must be distinct (time-varying law)"
    );
}

fn hex_short(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(10);
    for byte in bytes.iter().take(5) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn matrix3_differential_oracle() {
    let (checked, body_a_exact, digest_exact) = part_a();
    part_b();
    eprintln!(
        "matrix3: corpus cases={checked}, body-A bytes exact={body_a_exact}/160, digest bytes exact={digest_exact}/32"
    );
}
