// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gate for the independent 34-block End tail circuit.

use perun_adi_core::end_tail::{transform_tail, TailState, TAIL_LEN, TAIL_STATE_LEN};
use std::path::PathBuf;

const FRAME_LEN: usize = 0x500;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const BUNDLE_LEN: usize = 128 + FRAME_LEN + HEAP_LEN + DATA_LEN + TAIL_STATE_LEN + TAIL_LEN;

fn load(path: PathBuf) -> (TailState, [u8; TAIL_LEN]) {
    let bytes = std::fs::read(path).expect("read private End tail bundle");
    assert_eq!(bytes.len(), BUNDLE_LEN, "private End tail bundle length");
    let mut registers = [0u64; 16];
    for (index, slot) in registers.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let tail_end = data_end + TAIL_STATE_LEN;
    let state = TailState {
        registers,
        frame: bytes[128..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        tail: bytes[data_end..tail_end].try_into().unwrap(),
    };
    let expected = bytes[tail_end..].try_into().unwrap();
    (state, expected)
}

#[test]
fn tail_matches_two_independent_native_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAIL_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAIL_DIR unset -- skipping the independent End tail gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load(root.join(format!("{case}.bin")));
        let actual = transform_tail(&mut state);
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
            "{case}: {mismatches} tail mismatches; first={first:?}"
        );
        assert!(
            state.tail[..TAIL_LEN] == expected,
            "{case}: returned state differs from the output"
        );
    }
    eprintln!("independent End tail: 2 states and 544 bytes per state matched");
}
