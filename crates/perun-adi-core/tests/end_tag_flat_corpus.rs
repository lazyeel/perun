// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Full-state and complete same-process tag-chain gates for the flat CFF suffix.

use perun_adi_core::end_tag_middle0::{transform_tag_middle0, TagMiddle0State};
use perun_adi_core::end_tag_middle1::{transform_tag_middle1, TagMiddle1State};
use perun_adi_core::end_tag_middle2::{transform_tag_middle2, TagMiddle2State};
use perun_adi_core::end_tag_middle3::{transform_tag_middle3, TagMiddle3State};
use perun_adi_core::end_tag_round::{transform_tag_round, TagRoundState, TAG_ROUND_OUTPUT_LEN};
use perun_adi_core::end_tagfinal::{transform_tagfinal, TagFinalState};
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

macro_rules! middle_state {
    ($type:ident, $bytes:expr) => {{
        let bytes = $bytes;
        assert_eq!(bytes.len(), STATE_LEN);
        let xmm_end = REGISTERS_LEN + XMM_LEN;
        let frame_end = xmm_end + FRAME_LEN;
        let heap_end = frame_end + HEAP_LEN;
        let data_end = heap_end + DATA_LEN;
        $type {
            registers: registers(bytes),
            xmm: xmm(bytes),
            frame: bytes[xmm_end..frame_end].to_vec(),
            heap: bytes[frame_end..heap_end].try_into().unwrap(),
            data: bytes[heap_end..data_end].try_into().unwrap(),
            tag: bytes[data_end..].try_into().unwrap(),
        }
    }};
}

macro_rules! load_pair {
    ($type:ident, $path:expr) => {{
        let bytes = std::fs::read($path).expect("read private middle bundle");
        assert_eq!(bytes.len(), 2 * STATE_LEN);
        (
            Box::new(middle_state!($type, &bytes[..STATE_LEN])),
            Box::new(middle_state!($type, &bytes[STATE_LEN..])),
        )
    }};
}

macro_rules! assert_state {
    ($actual:expr, $expected:expr, $case:expr) => {{
        assert!(
            $actual.registers == $expected.registers,
            "{}: GP mismatch",
            $case
        );
        assert!($actual.xmm == $expected.xmm, "{}: XMM mismatch", $case);
        assert!(
            $actual.frame == $expected.frame,
            "{}: frame mismatch",
            $case
        );
        assert!($actual.heap == $expected.heap, "{}: heap mismatch", $case);
        assert!($actual.data == $expected.data, "{}: RW mismatch", $case);
        assert!($actual.tag == $expected.tag, "{}: tag mismatch", $case);
    }};
}

fn load_round(
    path: &Path,
) -> (
    Box<TagRoundState>,
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
    (Box::new(state), expected_a, expected_b)
}

fn load_tagfinal(path: &Path) -> (Box<TagFinalState>, [u8; 16]) {
    let bytes = std::fs::read(path).expect("read private tag-final bundle");
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let source_end = data_end + 16;
    let tail_end = source_end + 16;
    assert_eq!(bytes.len(), tail_end + 16);
    let state = TagFinalState {
        registers: registers(&bytes),
        frame: bytes[128..frame_end].to_vec(),
        heap: bytes[frame_end..heap_end].try_into().unwrap(),
        data: bytes[heap_end..data_end].try_into().unwrap(),
        source: bytes[data_end..source_end].try_into().unwrap(),
        tail: bytes[source_end..tail_end].try_into().unwrap(),
    };
    let expected = bytes[tail_end..].try_into().unwrap();
    (Box::new(state), expected)
}

#[test]
fn middle2_matches_two_complete_native_checkpoint_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAG_MIDDLE2_FLAT_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_MIDDLE2_FLAT_DIR unset -- skipping middle-2 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load_pair!(TagMiddle2State, root.join(format!("{case}.bin")));
        transform_tag_middle2(&mut state);
        assert_state!(state, expected, case);
    }
    eprintln!("independent End middle-2: 2 complete checkpoint states matched");
}

#[test]
fn middle3_matches_two_complete_native_checkpoint_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAG_MIDDLE3_FLAT_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_MIDDLE3_FLAT_DIR unset -- skipping middle-3 gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load_pair!(TagMiddle3State, root.join(format!("{case}.bin")));
        transform_tag_middle3(&mut state);
        assert_state!(state, expected, case);
    }
    eprintln!("independent End middle-3: 2 complete checkpoint states matched");
}

#[test]
fn complete_tag_chain_matches_on_two_states() {
    let Some(round_root) = std::env::var_os("PERUN_END_TAG_ROUND_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_ROUND_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };
    let Some(middle0_root) = std::env::var_os("PERUN_END_TAG_MIDDLE0_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE0_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };
    let Some(middle1_root) = std::env::var_os("PERUN_END_TAG_MIDDLE1_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE1_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };
    let Some(middle2_root) = std::env::var_os("PERUN_END_TAG_MIDDLE2_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE2_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };
    let Some(middle3_root) = std::env::var_os("PERUN_END_TAG_MIDDLE3_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAG_MIDDLE3_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };
    let Some(final_root) = std::env::var_os("PERUN_END_TAGFINAL_FLAT_DIR").map(PathBuf::from)
    else {
        eprintln!("PERUN_END_TAGFINAL_FLAT_DIR unset -- skipping complete tag chain");
        return;
    };

    for case in ["case1", "case2"] {
        let (mut round, expected_a, expected_b) =
            load_round(&round_root.join(format!("{case}.bin")));
        let (middle0, middle1_boundary) =
            load_pair!(TagMiddle0State, middle0_root.join(format!("{case}.bin")));
        let (middle1, middle2_boundary) =
            load_pair!(TagMiddle1State, middle1_root.join(format!("{case}.bin")));
        let (middle2, middle3_boundary) =
            load_pair!(TagMiddle2State, middle2_root.join(format!("{case}.bin")));
        let (middle3, final_boundary) =
            load_pair!(TagMiddle3State, middle3_root.join(format!("{case}.bin")));
        let (_, expected_tag) = load_tagfinal(&final_root.join(format!("{case}.bin")));

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
        assert_state!(chained0, middle1_boundary, case);
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
        assert_state!(chained1, middle2_boundary, case);
        assert!(chained1.registers == middle2.registers && chained1.xmm == middle2.xmm);
        assert!(
            chained1.frame == middle2.frame
                && chained1.heap == middle2.heap
                && chained1.data == middle2.data
        );

        let mut chained2 = TagMiddle2State {
            registers: chained1.registers,
            xmm: chained1.xmm,
            frame: chained1.frame,
            heap: chained1.heap,
            data: chained1.data,
            tag: chained1.tag,
        };
        transform_tag_middle2(&mut chained2);
        assert_state!(chained2, middle3_boundary, case);
        assert!(chained2.registers == middle3.registers && chained2.xmm == middle3.xmm);
        assert!(
            chained2.frame == middle3.frame
                && chained2.heap == middle3.heap
                && chained2.data == middle3.data
        );

        let mut chained3 = TagMiddle3State {
            registers: chained2.registers,
            xmm: chained2.xmm,
            frame: chained2.frame,
            heap: chained2.heap,
            data: chained2.data,
            tag: chained2.tag,
        };
        transform_tag_middle3(&mut chained3);
        assert_state!(chained3, final_boundary, case);

        let mut final_state = TagFinalState {
            registers: chained3.registers,
            frame: chained3.frame,
            heap: chained3.heap,
            data: chained3.data,
            source: chained3.tag,
            tail: chained3.tag,
        };
        let actual_tag = transform_tagfinal(&mut final_state);
        assert!(
            actual_tag == expected_tag,
            "{case}: complete tag-chain output mismatch"
        );
        assert!(
            final_state.tail == expected_tag,
            "{case}: complete tag-chain state mismatch"
        );
    }
    eprintln!("complete End tag chain: tag_round -> middle0 -> middle1 -> middle2 -> middle3 -> tagfinal matched on 2 states");
}
