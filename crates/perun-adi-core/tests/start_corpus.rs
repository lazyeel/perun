// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Full CPIM differential gate from explicit semantic inputs, with no
//! reference CPIM, depot, zone or mixer tape on the generation path.

use perun_adi_core::body_a::digest_inputs_from_watch_tape;
use perun_adi_core::cpim::CpimLayout;
use perun_adi_core::mixer::MixerState;
use perun_adi_core::spim::Spim;
use perun_adi_core::start::generate_cpim_from_state;
use perun_adi_core::start::StartInputs;
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
fn full_cpim_is_generated_without_oracle_inputs() {
    let Some(root) = std::env::var_os("PERUN_START_DIR").map(PathBuf::from) else {
        eprintln!("PERUN_START_DIR unset -- skipping the private full-CPIM gate");
        return;
    };
    for (state_name, capture_name, digest_name, entropy) in [
        (
            "sequential.bin",
            "start-seq",
            "start-seq",
            core::array::from_fn(|i| i as u8),
        ),
        ("a5.bin", "start-a5", "start-a5", [0xA5; 40]),
    ] {
        let spim_bytes =
            std::fs::read(root.join(capture_name).join("spim.bin")).expect("private SPIM");
        let spim = Spim::parse(&spim_bytes).expect("valid private SPIM");
        let mixer = load_state(&root.join("start-state").join(state_name));
        let watch = std::fs::read_to_string(root.join(digest_name).join("pair_wp_words.txt"))
            .expect("private store-time digest tape");
        let digest = digest_inputs_from_watch_tape(&watch).expect("digest inputs");
        let actual = generate_cpim_from_state(StartInputs {
            spim,
            entropy,
            mixer,
            digest,
        });
        CpimLayout::parse(&actual).expect("generated CPIM must have the measured layout");
        let cpim = std::fs::read(root.join(capture_name).join("cap/cpim.bin"))
            .expect("private reference CPIM");
        let differences = actual
            .iter()
            .zip(&cpim)
            .filter(|(left, right)| left != right)
            .count();
        assert!(
            actual.as_slice() == cpim.as_slice(),
            "{capture_name}: independent full CPIM diverged at {differences} positions"
        );
    }
    eprintln!("pure-Rust Start: 2 private inputs, complete 276/276-byte CPIM matched");
}
