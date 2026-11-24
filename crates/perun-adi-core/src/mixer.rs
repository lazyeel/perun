// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent mixer-round arithmetic over an explicit initial state.
//!
//! [`MixerState`] is the semantic boundary at the first mixer read. Its genesis
//! from SPIM/entropy is a separate track; the ten-round circuit itself is fixed,
//! contains no capture reads, native code or libc calls, and returns all 160
//! body-A bytes.

pub use crate::mixer_core::{body_a, InvalidMixerFrame, MixerState};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(MixerState::new([0; 16], vec![0; 15], [0; 0xA0]).is_err());
    }
}
