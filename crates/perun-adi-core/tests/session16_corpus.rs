// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private byte-parity gate for the independent `session16` producer.
//!
//! Set `PERUN_SESSION16_DIR` to the local mode-`0700` capture root. The test
//! reads only each case's `cap/cpim.bin`; expected bytes are never printed or
//! committed. With the variable unset, the public hash-only unit vectors remain
//! the hermetic CI gate.

use perun_adi_core::session::{session16_from_entropy, ENTROPY_LEN};
use std::path::PathBuf;

fn cases() -> Vec<(&'static str, [u8; ENTROPY_LEN])> {
    vec![
        ("mttwist32nd-seq-fourth", core::array::from_fn(|i| i as u8)),
        ("session16-dec2", core::array::from_fn(|i| 39 - i as u8)),
        ("session16-01", [0x01; ENTROPY_LEN]),
        ("session16-11", [0x11; ENTROPY_LEN]),
        ("session16-22", [0x22; ENTROPY_LEN]),
        ("session16-33", [0x33; ENTROPY_LEN]),
        ("session16-44", [0x44; ENTROPY_LEN]),
        ("session16-55", [0x55; ENTROPY_LEN]),
        ("session16-7f", [0x7f; ENTROPY_LEN]),
        ("session16-80", [0x80; ENTROPY_LEN]),
        ("mttwist31nd-a5-seed", [0xa5; ENTROPY_LEN]),
        ("session16-ff", [0xff; ENTROPY_LEN]),
    ]
}

#[test]
fn session16_matches_private_cpim_byte_for_byte() {
    let Some(root) = std::env::var_os("PERUN_SESSION16_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_SESSION16_DIR unset -- skipping the private session16 gate");
        return;
    };
    let mut checked = 0usize;
    for (name, draw) in cases() {
        let path = root.join(name).join("cap/cpim.bin");
        let cpim =
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(cpim.len() >= 20, "{}: truncated CPIM", path.display());
        let actual = session16_from_entropy(draw);
        assert!(
            actual.as_slice() == &cpim[4..20],
            "{name}: pure-Rust session16 diverged from the native capture"
        );
        checked += 1;
    }
    assert_eq!(checked, 12);
    eprintln!("pure-Rust session16: {checked} private captures matched byte for byte");
}
