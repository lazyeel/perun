// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gate for the fixed native provisioning-state prefix.

use perun_adi_core::end_header::{end_header, END_HEADER_LEN};
use std::path::PathBuf;

#[test]
fn header_matches_two_independent_native_states() {
    let Some(root) = std::env::var_os("PERUN_END_HEADER_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_HEADER_DIR unset -- skipping fixed-header gate");
        return;
    };
    let actual = end_header();
    for case in ["case1", "case2"] {
        let native = std::fs::read(root.join(format!("{case}.bin"))).expect("read native state");
        assert_eq!(native.len(), 617, "native provisioning-state length");
        assert!(
            actual == native[..END_HEADER_LEN],
            "{case}: fixed prefix diverged"
        );
    }
    eprintln!("independent End header: 2 states and 53 bytes per state matched");
}
