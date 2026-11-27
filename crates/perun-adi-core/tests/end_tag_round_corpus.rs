// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gate for the repeated SSE circuit inside End's tag stage.

use perun_adi_core::end_tag_round::{transform_tag_round, TagRoundState, TAG_ROUND_OUTPUT_LEN};
use std::path::{Path, PathBuf};

const REGISTERS_LEN: usize = 128;
const XMM_LEN: usize = 16 * 16;
const FRAME_LEN: usize = 0x500;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const BUNDLE_LEN: usize =
    REGISTERS_LEN + XMM_LEN + FRAME_LEN + HEAP_LEN + DATA_LEN + 2 * TAG_ROUND_OUTPUT_LEN;

fn registers(bytes: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    out
}

fn load(
    path: &Path,
) -> (
    TagRoundState,
    [u8; TAG_ROUND_OUTPUT_LEN],
    [u8; TAG_ROUND_OUTPUT_LEN],
) {
    let bytes = std::fs::read(path).expect("read private tag-round bundle");
    assert_eq!(bytes.len(), BUNDLE_LEN, "private tag-round bundle length");
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

#[test]
fn tag_round_matches_two_independent_native_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAG_ROUND_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAG_ROUND_DIR unset -- skipping tag-round gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected_a, expected_b) = load(&root.join(format!("{case}.bin")));
        let (actual_a, actual_b) = transform_tag_round(&mut state);
        assert!(
            actual_a == expected_a,
            "{case}: first tag-round buffer diverged"
        );
        assert!(
            actual_b == expected_b,
            "{case}: second tag-round buffer diverged"
        );
    }
    eprintln!("independent End tag round: 2 states and 2 x 1024 bytes per state matched");
}
