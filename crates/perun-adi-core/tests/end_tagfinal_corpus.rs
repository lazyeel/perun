// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private differential gate for the final 16-byte End tag serializer.

use perun_adi_core::end_tagfinal::{transform_tagfinal, TagFinalState, TAGFINAL_LEN};
use std::path::{Path, PathBuf};

const FRAME_LEN: usize = 0x600;
const HEAP_LEN: usize = 0x4000;
const DATA_LEN: usize = 0x5000;
const BUNDLE_LEN: usize = 128 + FRAME_LEN + HEAP_LEN + DATA_LEN + 3 * TAGFINAL_LEN;

fn registers(bytes: &[u8]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        let at = index * 8;
        *slot = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    }
    out
}

fn load(path: &Path) -> (TagFinalState, [u8; TAGFINAL_LEN]) {
    let bytes = std::fs::read(path).expect("read private tag-final bundle");
    assert_eq!(bytes.len(), BUNDLE_LEN, "private tag-final bundle length");
    let frame_end = 128 + FRAME_LEN;
    let heap_end = frame_end + HEAP_LEN;
    let data_end = heap_end + DATA_LEN;
    let source_end = data_end + TAGFINAL_LEN;
    let tail_end = source_end + TAGFINAL_LEN;
    let state = TagFinalState {
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

#[test]
fn tagfinal_matches_two_independent_native_states() {
    let Some(root) = std::env::var_os("PERUN_END_TAGFINAL_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_END_TAGFINAL_DIR unset -- skipping tag-final gate");
        return;
    };
    for case in ["case1", "case2"] {
        let (mut state, expected) = load(&root.join(format!("{case}.bin")));
        let actual = transform_tagfinal(&mut state);
        assert!(actual == expected, "{case}: final tag serializer diverged");
        assert!(state.tail == expected, "{case}: final tag state output");
    }
    eprintln!("independent End tag final: 2 states and 16 bytes per state matched");
}
