// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for one 60-byte End source-generation stage.
//!
//! [`Source60State`] is an explicit semantic boundary, not a complete
//! `ProvisioningEnd`. The circuit uses no Apple image, capture read, libc call
//! or native subprocess.

pub use crate::end_source60_core::{transform_source60, InvalidSource60Frame, Source60State};

/// Number of output bytes produced by this stage.
pub const SOURCE60_LEN: usize = 0x3c;

/// Number of independent source bytes consumed by this stage.
pub const SOURCE60_INPUT_LEN: usize = 0x3c;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(Source60State::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; SOURCE60_INPUT_LEN],
            [0; SOURCE60_LEN]
        )
        .is_err());
    }
}
