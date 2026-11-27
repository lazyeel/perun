// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private full-state differential gate for the first middle-tag stage.

use perun_adi_core::end_tag_middle0::{transform_tag_middle0, TagMiddle0State};
use perun_adi_core::end_tag_round::{transform_tag_round, TagRoundState, TAG_ROUND_OUTPUT_LEN};
use std::path::{Path, PathBuf};

const REGISTERS_LEN: usize = 128;
const XMM_LEN: usize = 256;
const FRAME_LEN: usize = 0x700;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const STATE_LEN: usize = REGISTERS_LEN + XMM_LEN + FRAME_LEN + HEAP_LEN + DATA_LEN + 16;

fn registers(bytes: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    out
}

fn load_state(bytes: &[u8]) -> TagMiddle0State {
    assert_eq!(bytes.len(), STATE_LEN);
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let mut xmm = [[0u8; 16]; 16];
    for (index, slot) in xmm.iter_mut().enumerate() {
        let at = REGISTERS_LEN + index * 16;
        slot.copy_from_slice(&bytes[at..at + 16]);
    }
    TagMiddle0State {
        registers: registers(bytes),
        xmm,
        frame: bytes[xmm_end..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        tag: bytes[data_end..].try_into().unwrap(),
    }
}

fn load(path: &Path) -> (TagMiddle0State, TagMiddle0State) {
    let bytes = std::fs::read(path).expect("read private middle-0 bundle");
    assert_eq!(bytes.len(), 2 * STATE_LEN, "private middle-0 bundle length");
    (
        load_state(&bytes[..STATE_LEN]),
        load_state(&bytes[STATE_LEN..]),
    )
}

fn load_round(
    path: &Path,
) -> (
    TagRoundState,
    [u8; TAG_ROUND_OUTPUT_LEN],
    [u8; TAG_ROUND_OUTPUT_LEN],
) {
    let bytes = std::fs::read(path).expect("read private tag-round bundle");
    let round_state_len = STATE_LEN - 16;
    assert_eq!(
        bytes.len(),
        round_state_len + 2 * TAG_ROUND_OUTPUT_LEN,
        "private tag-round bundle length"
    );
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let expected_a_end = data_end + TAG_ROUND_OUTPUT_LEN;
    let mut xmm = [[0u8; 16]; 16];
    for (index, slot) in xmm.iter_mut().enumerate() {
        let at = REGISTERS_LEN + index * 16;
        slot.copy_from_slice(&bytes[at..at + 16]);
    }
    let state = TagRoundState {
        registers: registers(&bytes),
        xmm,
        frame: bytes[xmm_end..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
    };
    let expected_a = bytes[data_end..expected_a_end].try_into().unwrap();
    let expected_b = bytes[expected_a_end..].try_into().unwrap();
    (state, expected_a, expected_b)
}

fn assert_state_eq(actual: &TagMiddle0State, expected: &TagMiddle0State, case: &str) {
    assert!(
        actual.registers == expected.registers,
        "{case}: GP registers diverged"
    );
    assert!(actual.xmm == expected.xmm, "{case}: XMM registers diverged");
    assert!(actual.frame == expected.frame, "{case}: frame diverged");
    assert!(
        actual.heap == expected.heap,
        "{case}: dynamic heap diverged"
    );
    assert!(
        actual.data == expected.data,
        "{case}: relocated RW diverged"
    );
    assert!(actual.tag == expected.tag, "{case}: tag bytes diverged");
}

#[test]
fn middle0_matches_two_complete_native_checkpoint_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAG_MIDDLE0_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_MIDDLE0_DIR unset -- skipping middle-0 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load(&root.join(format!("{case}.bin")));
        transform_tag_middle0(&mut state);
        assert_state_eq(&state, &expected, case);
    }
    eprintln!("independent End middle-0: 2 complete checkpoint states matched");
}

#[test]
fn tag_round_chains_into_middle0_on_two_states() {
    let Some(round_root) = std::env::var_os("PERUN_END_TAG_ROUND_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_ROUND_DIR unset -- skipping round-to-middle-0 gate");
        return;
    };
    let Some(middle_root) = std::env::var_os("PERUN_END_TAG_MIDDLE0_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_MIDDLE0_DIR unset -- skipping round-to-middle-0 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut round, expected_a, expected_b) =
            load_round(&round_root.join(format!("{case}.bin")));
        let (middle, expected) = load(&middle_root.join(format!("{case}.bin")));
        let (actual_a, actual_b) = transform_tag_round(&mut round);
        assert!(actual_a == expected_a && actual_b == expected_b);
        assert!(
            round.registers == middle.registers,
            "{case}: round-to-middle GP boundary"
        );
        assert!(
            round.xmm == middle.xmm,
            "{case}: round-to-middle XMM boundary"
        );
        assert!(
            round.frame == middle.frame,
            "{case}: round-to-middle frame boundary"
        );
        assert!(
            round.heap == middle.heap,
            "{case}: round-to-middle heap boundary"
        );
        assert!(
            round.data == middle.data,
            "{case}: round-to-middle RW boundary"
        );

        let mut chained = TagMiddle0State {
            registers: round.registers,
            xmm: round.xmm,
            frame: round.frame,
            heap: round.heap,
            data: round.data,
            tag: middle.tag,
        };
        transform_tag_middle0(&mut chained);
        assert_state_eq(&chained, &expected, case);
    }
    eprintln!("independent End tag chain: tag_round -> middle0 matched on 2 states");
}
