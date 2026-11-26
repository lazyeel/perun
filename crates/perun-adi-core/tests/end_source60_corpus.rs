// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gate for the independent 60-byte End source stage.

use perun_adi_core::end_source60::{
    transform_source60, Source60State, SOURCE60_INPUT_LEN, SOURCE60_LEN,
};
use std::path::PathBuf;

const FRAME_LEN: usize = 0x500;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const BUNDLE_LEN: usize =
    128 + FRAME_LEN + HEAP_LEN + DATA_LEN + SOURCE60_INPUT_LEN + 2 * SOURCE60_LEN;

fn load(path: PathBuf) -> (Source60State, [u8; SOURCE60_LEN]) {
    let bytes = std::fs::read(path).expect("read private End source-60 bundle");
    assert_eq!(
        bytes.len(),
        BUNDLE_LEN,
        "private End source-60 bundle length"
    );
    let mut registers = [0u64; 16];
    for (index, slot) in registers.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let source_end = data_end + SOURCE60_INPUT_LEN;
    let tail_end = source_end + SOURCE60_LEN;
    let state = Source60State {
        registers,
        frame: bytes[128..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        source: bytes[data_end..source_end].try_into().unwrap(),
        tail: bytes[source_end..tail_end].try_into().unwrap(),
    };
    let expected = bytes[tail_end..].try_into().unwrap();
    (state, expected)
}

#[test]
fn source60_matches_two_independent_native_states() {
    let Some(root) = std::env::var_os("PERUN_END_SOURCE60_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_SOURCE60_DIR unset -- skipping the independent End source-60 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load(root.join(format!("{case}.bin")));
        let actual = transform_source60(&mut state);
        let mismatches = actual
            .iter()
            .zip(&expected)
            .filter(|(left, right)| left != right)
            .count();
        let first = actual
            .iter()
            .zip(&expected)
            .position(|(left, right)| left != right);
        assert!(
            mismatches == 0,
            "{case}: {mismatches} source-60 mismatches; first={first:?}"
        );
        assert!(
            state.tail == expected,
            "{case}: returned state differs from the output"
        );
    }
    eprintln!("independent End source-60: 2 states and 60 bytes per state matched");
}
