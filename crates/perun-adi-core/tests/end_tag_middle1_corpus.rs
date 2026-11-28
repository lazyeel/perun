// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private full-state and same-process chain gates for the second middle stage.

use perun_adi_core::end_tag_middle0::{transform_tag_middle0, TagMiddle0State};
use perun_adi_core::end_tag_middle1::{transform_tag_middle1, TagMiddle1State};
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

fn xmm(bytes: &[u8]) -> [[u8; 16]; 16] {
    let mut out = [[0u8; 16]; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = REGISTERS_LEN + index * 16;
        slot.copy_from_slice(&bytes[at..at + 16]);
    }
    out
}

fn load_middle0(bytes: &[u8]) -> TagMiddle0State {
    assert_eq!(bytes.len(), STATE_LEN);
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    TagMiddle0State {
        registers: registers(bytes),
        xmm: xmm(bytes),
        frame: bytes[xmm_end..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        tag: bytes[data_end..].try_into().unwrap(),
    }
}

fn load_middle1(bytes: &[u8]) -> TagMiddle1State {
    assert_eq!(bytes.len(), STATE_LEN);
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    TagMiddle1State {
        registers: registers(bytes),
        xmm: xmm(bytes),
        frame: bytes[xmm_end..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        tag: bytes[data_end..].try_into().unwrap(),
    }
}

fn load_middle0_pair(path: &Path) -> (TagMiddle0State, TagMiddle0State) {
    let bytes = std::fs::read(path).expect("read private middle-0 bundle");
    assert_eq!(bytes.len(), 2 * STATE_LEN);
    (
        load_middle0(&bytes[..STATE_LEN]),
        load_middle0(&bytes[STATE_LEN..]),
    )
}

fn load_middle1_pair(path: &Path) -> (TagMiddle1State, TagMiddle1State) {
    let bytes = std::fs::read(path).expect("read private middle-1 bundle");
    assert_eq!(bytes.len(), 2 * STATE_LEN);
    (
        load_middle1(&bytes[..STATE_LEN]),
        load_middle1(&bytes[STATE_LEN..]),
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
    assert_eq!(bytes.len(), round_state_len + 2 * TAG_ROUND_OUTPUT_LEN);
    let xmm_end = REGISTERS_LEN + XMM_LEN;
    let frame_end = xmm_end + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let expected_a_end = data_end + TAG_ROUND_OUTPUT_LEN;
    let state = TagRoundState {
        registers: registers(&bytes),
        xmm: xmm(&bytes),
        frame: bytes[xmm_end..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
    };
    let expected_a = bytes[data_end..expected_a_end].try_into().unwrap();
    let expected_b = bytes[expected_a_end..].try_into().unwrap();
    (state, expected_a, expected_b)
}

fn assert_middle0_eq(actual: &TagMiddle0State, expected: &TagMiddle0State, case: &str) {
    assert!(
        actual.registers == expected.registers,
        "{case}: GP mismatch"
    );
    assert!(actual.xmm == expected.xmm, "{case}: XMM mismatch");
    assert!(actual.frame == expected.frame, "{case}: frame mismatch");
    assert!(actual.heap == expected.heap, "{case}: heap mismatch");
    assert!(actual.data == expected.data, "{case}: RW mismatch");
    assert!(actual.tag == expected.tag, "{case}: tag mismatch");
}

fn assert_middle1_eq(actual: &TagMiddle1State, expected: &TagMiddle1State, case: &str) {
    assert!(
        actual.registers == expected.registers,
        "{case}: GP mismatch"
    );
    assert!(actual.xmm == expected.xmm, "{case}: XMM mismatch");
    assert!(actual.frame == expected.frame, "{case}: frame mismatch");
    assert!(actual.heap == expected.heap, "{case}: heap mismatch");
    assert!(actual.data == expected.data, "{case}: RW mismatch");
    assert!(actual.tag == expected.tag, "{case}: tag mismatch");
}

#[test]
fn middle1_matches_two_complete_native_checkpoint_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAG_MIDDLE1_CHAIN1_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_MIDDLE1_CHAIN1_DIR unset -- skipping middle-1 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load_middle1_pair(&root.join(format!("{case}.bin")));
        transform_tag_middle1(&mut state);
        assert_middle1_eq(&state, &expected, case);
    }
    eprintln!("independent End middle-1: 2 complete checkpoint states matched");
}

#[test]
fn tag_round_chains_through_middle0_and_middle1_on_two_states() {
    let Some(round_root) = std::env::var_os("PERUN_END_TAG_ROUND_CHAIN1_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_ROUND_CHAIN1_DIR unset -- skipping three-stage gate");
        return;
    };
    let Some(middle0_root) =
        std::env::var_os("PERUN_END_TAG_MIDDLE0_CHAIN1_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE0_CHAIN1_DIR unset -- skipping three-stage gate");
        return;
    };
    let Some(middle1_root) =
        std::env::var_os("PERUN_END_TAG_MIDDLE1_CHAIN1_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE1_CHAIN1_DIR unset -- skipping three-stage gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut round, expected_a, expected_b) =
            load_round(&round_root.join(format!("{case}.bin")));
        let (middle0, middle1_boundary) =
            load_middle0_pair(&middle0_root.join(format!("{case}.bin")));
        let (middle1, expected) = load_middle1_pair(&middle1_root.join(format!("{case}.bin")));

        let (actual_a, actual_b) = transform_tag_round(&mut round);
        assert!(actual_a == expected_a && actual_b == expected_b);
        assert!(round.registers == middle0.registers && round.xmm == middle0.xmm);
        assert!(
            round.frame == middle0.frame
                && round.heap == middle0.heap
                && round.data == middle0.data
        );

        let mut chained0 = TagMiddle0State {
            registers: round.registers,
            xmm: round.xmm,
            frame: round.frame,
            heap: round.heap,
            data: round.data,
            tag: middle0.tag,
        };
        transform_tag_middle0(&mut chained0);
        assert_middle0_eq(&chained0, &middle1_boundary, case);
        assert!(chained0.registers == middle1.registers && chained0.xmm == middle1.xmm);
        assert!(
            chained0.frame == middle1.frame
                && chained0.heap == middle1.heap
                && chained0.data == middle1.data
        );

        let mut chained1 = TagMiddle1State {
            registers: chained0.registers,
            xmm: chained0.xmm,
            frame: chained0.frame,
            heap: chained0.heap,
            data: chained0.data,
            tag: chained0.tag,
        };
        transform_tag_middle1(&mut chained1);
        assert_middle1_eq(&chained1, &expected, case);
    }
    eprintln!("independent End tag chain: tag_round -> middle0 -> middle1 matched on 2 states");
}
