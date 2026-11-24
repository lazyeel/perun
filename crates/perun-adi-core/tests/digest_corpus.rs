// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private store-time digest parity. The producer reads only
//! `pair_wp_words.txt`; `cap/cpim.bin` is used by the test as the oracle after
//! generation. Expected bytes are never printed or committed.

use perun_adi_core::body_a::generate_digest_from_tapes;
use std::path::PathBuf;

#[test]
fn digest_matches_private_cpim_without_cpim_anchored_selection() {
    let Some(root) = std::env::var_os("PERUN_DIGEST_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_DIGEST_DIR unset -- skipping the private digest gate");
        return;
    };
    let mut checked = 0usize;
    for name in ["digest-watch-seq", "digest-watch-a5"] {
        let dir = root.join(name);
        let path = dir.to_str().expect("UTF-8 private digest path");
        let actual = generate_digest_from_tapes(path).expect("store-time digest producer");
        let cpim = std::fs::read(dir.join("cap/cpim.bin")).expect("private reference CPIM");
        assert!(cpim.len() == 0x114);
        assert!(
            actual.as_slice() == &cpim[0xB8..0xD8],
            "{name}: pure-Rust digest diverged from native"
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
    eprintln!("pure-Rust digest: {checked} private captures, all eight store-time words matched");
}
