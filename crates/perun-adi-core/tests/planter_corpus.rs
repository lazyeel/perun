// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Gated parity for [`perun_adi_core::planter`] against the private captures.
//!
//! Set `PERUN_PLANTER_DIR` to a directory holding one subdirectory per case;
//! each case must contain `planter.final.bin` (the 0x2700-byte planter dump)
//! and, when available, `spim.bin`. The raw bytes are never committed -- the
//! test only asserts the measured relations:
//!
//! * every one of the seven windows is a complete byte permutation;
//! * the five canonical windows carry their lineage-invariant constants;
//! * the five canonical windows obey the affine position law;
//! * the two extra windows are allowed to be sparse/affine or not (role open).

use std::path::{Path, PathBuf};

use perun_adi_core::planter::{Family, PlanterWindows, Window, PLANTER_LEN, WINDOW_LEN};

fn capture_dirs() -> Vec<PathBuf> {
    if let Some(single) = std::env::var_os("PERUN_PLANTER_CASE") {
        return vec![PathBuf::from(single)];
    }
    let Some(root) = std::env::var_os("PERUN_PLANTER_DIR") else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("read the planter capture root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.join("planter.final.bin").exists())
        .collect();
    dirs.sort();
    dirs
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn planter_windows_match_the_private_captures() {
    let cases = capture_dirs();
    if cases.is_empty() {
        eprintln!("PERUN_PLANTER_DIR/PERUN_PLANTER_CASE unset -- skipping the planter gate");
        return;
    }

    let mut checked = 0usize;
    for case in cases {
        let planter_path = case.join("planter.final.bin");
        let planter = read(&planter_path);
        assert_eq!(
            planter.len(),
            PLANTER_LEN,
            "{}: the planter object is 0x2700 bytes",
            planter_path.display()
        );

        let windows = PlanterWindows::parse(&planter)
            .unwrap_or_else(|error| panic!("{}: {error}", planter_path.display()));

        // Constants are lineage-invariant on the five canonical windows.
        assert!(
            windows.constants_match_measurements(),
            "{}: canonical window constants diverged from the seven-lineage measurement",
            planter_path.display()
        );

        // The five canonical windows are complete permutations.
        for family in Family::CANONICAL {
            let window = windows.window(family);
            let mut seen = [false; WINDOW_LEN];
            for &byte in window.as_bytes() {
                assert!(
                    !seen[byte as usize],
                    "{} {} is not a permutation",
                    case.display(),
                    family.name()
                );
                seen[byte as usize] = true;
            }
        }

        // The five canonical windows obey the affine position law.
        assert!(
            windows.canonical_windows_are_affine(),
            "{}: a canonical window broke w[i] = c ^ XOR basis[k]",
            planter_path.display()
        );

        // And their eight basis bytes are GF(2)-independent, so the law is a
        // bijection. This is what makes the nine bytes of `Params` a total
        // description of each canonical window.
        assert_eq!(
            windows.canonical_basis_ranks(),
            [8, 8, 8, 8, 8],
            "{}: a canonical window has a dependent basis",
            planter_path.display()
        );

        // Every canonical window must round-trip through the nine bytes.
        for family in Family::CANONICAL {
            let window = windows.window(family);
            let rebuilt = Window::from_params(&window.params());
            assert_eq!(
                rebuilt.as_bytes(),
                window.as_bytes(),
                "{} {} did not round-trip through Params",
                case.display(),
                family.name()
            );
        }

        // The two extras are filled by a different path: they are permutations
        // here, but they do not obey the affine law on any of the seven
        // captures. Pinning the negative keeps a future affine finding visible.
        for family in [Family::ExtraC50, Family::Extra1280] {
            assert!(
                !windows.window(family).affine_matches_table(),
                "{} {} unexpectedly obeys the affine law",
                case.display(),
                family.name()
            );
        }

        checked += 1;
    }

    assert!(checked >= 1, "at least one planter capture must be checked");
    eprintln!("planter windows: {checked} private captures verified");
}

#[test]
fn window_rejects_a_non_permutation() {
    let mut table = [0u8; WINDOW_LEN];
    for (i, slot) in table.iter_mut().enumerate() {
        *slot = i as u8;
    }
    table[200] = table[100];
    assert!(Window::from_permutation(table).is_err());
}
