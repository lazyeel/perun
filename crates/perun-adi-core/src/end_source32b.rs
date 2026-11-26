// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the second 32-byte End source stage.
//!
//! [`Source32bState`] is an explicit semantic boundary, not a complete
//! `ProvisioningEnd`. No Apple image, capture read, libc call or native
//! subprocess is used.

pub use crate::end_source32b_core::{transform_source32b, InvalidSource32bFrame, Source32bState};

/// Number of output bytes produced by this stage.
pub const SOURCE32B_LEN: usize = 0x20;

/// Number of input bytes transformed by this stage.
pub const SOURCE32B_INPUT_LEN: usize = 0x20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(Source32bState::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; SOURCE32B_INPUT_LEN],
            [0; SOURCE32B_LEN]
        )
        .is_err());
    }
}
