// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Capture-free CPIM assembly from explicit semantic Start state.
//!
//! This is not the old oracle-backed packer: no reference CPIM, zone tape,
//! depot dump or native process is read. SPIM and entropy are direct inputs;
//! the mixer and digest states are explicit semantic boundaries with their own
//! separately tracked genesis.

use crate::cpim::CpimLayout;
use crate::digest::{generate_digest, DigestInputs};
use crate::mixer::{body_a, MixerState};
use crate::session::{session16_from_entropy, ENTROPY_LEN};
use crate::spim::Spim;

/// Inputs required by the independent CPIM producer.
#[derive(Clone)]
pub struct StartInputs {
    /// The structurally validated 347-byte server input.
    pub spim: Spim,
    /// The controlled 40-byte native entropy draw.
    pub entropy: [u8; ENTROPY_LEN],
    /// Semantic state at the first mixer read.
    pub mixer: MixerState,
    /// Eight digest channel words from the subsequent digest stage.
    pub digest: DigestInputs,
}

/// Generate the full 276-byte CPIM without reading any oracle artifact.
pub fn generate_cpim_from_state(inputs: StartInputs) -> [u8; 0x114] {
    let StartInputs {
        spim,
        entropy,
        mut mixer,
        digest,
    } = inputs;
    let body_a = body_a(&mut mixer);
    let body_a_digest = generate_digest(&digest);
    let session = session16_from_entropy(entropy);
    CpimLayout::from_spim(&spim, session, body_a, body_a_digest)
        .to_bytes()
        .try_into()
        .expect("the CPIM layout is always 276 bytes")
}
