// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private full-state differential gate for the final-four producer.

use perun_adi_core::end_final4::{final4, transform_final4, Final4State, FINAL4_OUTPUT_LEN};
use std::path::{Path, PathBuf};

const REGISTERS_LEN: usize = 128;
const XMM_LEN: usize = 256;
const FRAME_LEN: usize = 0x700;
const STATE_LEN: usize = REGISTERS_LEN + XMM_LEN + FRAME_LEN + 2 * FINAL4_OUTPUT_LEN;

fn registers(bytes: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    out
}

fn load_state(bytes: &[u8]) -> Final4State {
    assert_eq!(bytes.len(), STATE_LEN);
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let source_end = frame_end + FINAL4_OUTPUT_LEN;
    let mut xmm = [[0u8; 16]; 16];
    for (index, slot) in xmm.iter_mut().enumerate() {
        let at = REGISTERS_LEN + index * 16;
        slot.copy_from_slice(&bytes[at..at + 16]);
    }
    Final4State {
        registers: registers(bytes),
        xmm,
        frame: bytes[xmm_end..frame_end].to_vec(),
        source: bytes[frame_end..source_end].try_into().unwrap(),
        tail: bytes[source_end..].try_into().unwrap(),
    }
}

fn load(path: &Path) -> (Final4State, Final4State, [u8; 4]) {
    let bytes = std::fs::read(path).expect("read private final-four bundle");
    assert_eq!(
        bytes.len(),
        2 * STATE_LEN + 4,
        "private final-four bundle length"
    );
    let state = load_state(&bytes[..STATE_LEN]);
    let expected = load_state(&bytes[STATE_LEN..2 * STATE_LEN]);
    let final4 = bytes[2 * STATE_LEN..].try_into().unwrap();
    (state, expected, final4)
}

fn assert_state_eq(actual: &Final4State, expected: &Final4State, case: &str) {
    assert!(
        actual.registers == expected.registers,
        "{case}: GP mismatch"
    );
    assert!(actual.xmm == expected.xmm, "{case}: XMM mismatch");
    assert!(actual.frame == expected.frame, "{case}: frame mismatch");
    assert!(actual.source == expected.source, "{case}: source mismatch");
    assert!(actual.tail == expected.tail, "{case}: output mismatch");
}

#[test]
fn final4_producer_matches_two_complete_native_checkpoint_states() {
    let Some(root) = std::env::var_os("PERUN_END_FINAL4_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_FINAL4_DIR unset -- skipping final-four gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected, expected_final4) = load(&root.join(format!("{case}.bin")));
        let actual = transform_final4(&mut state);
        assert_state_eq(&state, &expected, case);
        assert!(actual == state.tail, "{case}: returned output mismatch");
        assert!(
            final4(&actual) == expected_final4,
            "{case}: final-four word mismatch"
        );
    }
    eprintln!("independent End final-four: 2 complete states and 20 output bytes matched");
}
