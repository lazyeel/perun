// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gates for the two linked 32-byte End source stages.

use perun_adi_core::end_source32a::{
    transform_source32a, Source32aState, SOURCE32A_INPUT_LEN, SOURCE32A_LEN,
};
use perun_adi_core::end_source32b::{
    transform_source32b, Source32bState, SOURCE32B_INPUT_LEN, SOURCE32B_LEN,
};
use std::path::{Path, PathBuf};

const FRAME_LEN: usize = 0x4500;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const BUNDLE_A: usize =
    128 + FRAME_LEN + HEAP_LEN + DATA_LEN + SOURCE32A_INPUT_LEN + 2 * SOURCE32A_LEN;
const BUNDLE_B: usize =
    128 + FRAME_LEN + HEAP_LEN + DATA_LEN + SOURCE32B_INPUT_LEN + 2 * SOURCE32B_LEN;

fn registers(bytes: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    out
}

fn load_a(path: &Path) -> (Source32aState, [u8; SOURCE32A_LEN]) {
    let bytes = std::fs::read(path).expect("read private source-32a bundle");
    assert_eq!(bytes.len(), BUNDLE_A, "private source-32a bundle length");
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let source_end = data_end + SOURCE32A_INPUT_LEN;
    let tail_end = source_end + SOURCE32A_LEN;
    let state = Source32aState {
        registers: registers(&bytes),
        frame: bytes[128..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        source: bytes[data_end..source_end].try_into().unwrap(),
        tail: bytes[source_end..tail_end].try_into().unwrap(),
    };
    let expected = bytes[tail_end..].try_into().unwrap();
    (state, expected)
}

fn load_b(path: &Path) -> (Source32bState, [u8; SOURCE32B_LEN]) {
    let bytes = std::fs::read(path).expect("read private source-32b bundle");
    assert_eq!(bytes.len(), BUNDLE_B, "private source-32b bundle length");
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let source_end = data_end + SOURCE32B_INPUT_LEN;
    let tail_end = source_end + SOURCE32B_LEN;
    let state = Source32bState {
        registers: registers(&bytes),
        frame: bytes[128..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        source: bytes[data_end..source_end].try_into().unwrap(),
        tail: bytes[source_end..tail_end].try_into().unwrap(),
    };
    let expected = bytes[tail_end..].try_into().unwrap();
    (state, expected)
}

fn mismatches(actual: &[u8], expected: &[u8]) -> usize {
    actual
        .iter()
        .zip(expected)
        .filter(|(left, right)| left != right)
        .count()
}

#[test]
fn source32_stages_match_and_chain_on_two_states() {
    let Some(root_a) = std::env::var_os("PERUN_END_SOURCE32A_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_SOURCE32A_DIR unset -- skipping source-32 gates");
        return;
    };
    let Some(root_b) = std::env::var_os("PERUN_END_SOURCE32B_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_SOURCE32B_DIR unset -- skipping source-32 gates");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state_a, expected_a) = load_a(&root_a.join(format!("{case}.bin")));
        let actual_a = transform_source32a(&mut state_a);
        assert!(
            mismatches(&actual_a, &expected_a) == 0,
            "{case}: source-32a diverged"
        );

        let (mut state_b, expected_b) = load_b(&root_b.join(format!("{case}.bin")));
        assert!(
            actual_a == state_b.tail,
            "{case}: source-32a output is not the source-32b input"
        );
        let actual_b = transform_source32b(&mut state_b);
        assert!(
            mismatches(&actual_b, &expected_b) == 0,
            "{case}: source-32b diverged"
        );
        assert!(
            state_a.tail == expected_a,
            "{case}: source-32a state output"
        );
        assert!(
            state_b.tail == expected_b,
            "{case}: source-32b state output"
        );
    }
    eprintln!("independent source-32: 2 linked stages, 2 states and 32 bytes per stage matched");
}
