// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Gated checks of `spim` against private native captures.
//!
//! Set `PERUN_SPIM_DIR` to a directory holding one subdirectory per case;
//! each case must contain `cap/spim.bin` and `cap/cpim.bin` (or the caller can
//! point at a single case directory with `PERUN_SPIM_CASE`). The raw bytes are
//! never committed -- the test only asserts the measured relations.

use std::path::{Path, PathBuf};

use perun_adi_core::cpim::CpimLayout;
use perun_adi_core::spim::{Spim, BODY_B_LEN, SPIM_LEN};

fn case_dirs() -> Vec<PathBuf> {
    if let Some(single) = std::env::var_os("PERUN_SPIM_CASE") {
        return vec![PathBuf::from(single)];
    }
    let Some(root) = std::env::var_os("PERUN_SPIM_DIR") else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("read the case root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.join("cap").join("cpim.bin").exists())
        .collect();
    dirs.sort();
    dirs
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn spim_anatomy_holds_on_the_private_corpus() {
    let cases = case_dirs();
    if cases.is_empty() {
        eprintln!("PERUN_SPIM_DIR/PERUN_SPIM_CASE unset -- skipping the corpus test");
        return;
    }

    let mut checked = 0usize;
    for case in cases {
        let spim_path = case.join("cap").join("spim.bin");
        let cpim_path = case.join("cap").join("cpim.bin");
        if !spim_path.exists() || !cpim_path.exists() {
            continue;
        }
        let spim_bytes = read(&spim_path);
        let cpim_bytes = read(&cpim_path);
        assert_eq!(spim_bytes.len(), SPIM_LEN, "{}", spim_path.display());

        let spim = Spim::parse(&spim_bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", spim_path.display()));
        assert_eq!(spim.body_b_len(), BODY_B_LEN as u32);
        assert_eq!(spim_bytes.len(), SPIM_LEN);

        if cpim_bytes.len() == CpimLayout::REFERENCE_LEN {
            let container = CpimLayout::parse(&cpim_bytes)
                .unwrap_or_else(|error| panic!("{}: {error}", cpim_path.display()));
            assert_eq!(
                container.body_b,
                spim.body_b(),
                "{}: the CPIM Body B must be the SPIM tail",
                case.display()
            );
        }
        checked += 1;
    }

    assert!(checked >= 1, "at least one complete pair must be checked");
    eprintln!("SPIM anatomy: {checked} native pairs verified");
}
