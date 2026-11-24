// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private full-body differential gate for the independent ten-round circuit.
//! Initial states are explicit development inputs, never production captures.

use perun_adi_core::mixer::{body_a, MixerState};
use std::path::{Path, PathBuf};

fn load_state(path: &Path) -> MixerState {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    assert_eq!(bytes.len(), 128 + 0x6000 + 0xA0);
    let mut registers = [0u64; 16];
    for (slot, chunk) in registers.iter_mut().zip(bytes[..128].as_chunks::<8>().0) {
        *slot = u64::from_le_bytes(*chunk);
    }
    let frame = bytes[128..128 + 0x6000].to_vec();
    let heap = bytes[128 + 0x6000..]
        .try_into()
        .expect("160-byte mixer heap");
    MixerState::new(registers, frame, heap).expect("mixer frame length")
}

#[test]
fn ten_mixer_rounds_match_private_body_a() {
    let Some(root) = std::env::var_os("PERUN_MIXER_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_MIXER_DIR unset -- skipping the private mixer gate");
        return;
    };
    let state_root = root.join("mixer-state");
    for (state_name, capture_name) in [
        ("sequential.bin", "mttwist32nd-seq"),
        ("a5.bin", "kdfcore-a5"),
    ] {
        let mut state = load_state(&state_root.join(state_name));
        let actual = body_a(&mut state);
        let cpim = std::fs::read(root.join(capture_name).join("cap/cpim.bin"))
            .expect("private reference CPIM");
        assert_eq!(cpim.len(), 0x114);
        assert!(
            actual.as_slice() == &cpim[0x18..0xB8],
            "{capture_name}: independent mixer circuit diverged"
        );
    }
    eprintln!("pure-Rust mixer: 2 private inputs, all ten rounds and 160/160 bytes matched");
}
