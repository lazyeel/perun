// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the first 32-byte End source stage.
//!
//! [`Source32aState`] is an explicit semantic boundary, not a complete
//! `ProvisioningEnd`. No Apple image, capture read, libc call or native
//! subprocess is used.

pub use crate::end_source32a_core::{transform_source32a, InvalidSource32aFrame, Source32aState};

/// Number of output bytes produced by this stage.
pub const SOURCE32A_LEN: usize = 0x20;

/// Number of independent source bytes consumed by this stage.
pub const SOURCE32A_INPUT_LEN: usize = 0x20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(Source32aState::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; SOURCE32A_INPUT_LEN],
            [0; SOURCE32A_LEN]
        )
        .is_err());
    }
}
