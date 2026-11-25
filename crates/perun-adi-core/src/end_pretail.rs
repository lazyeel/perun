// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the 544 one-byte iterations preceding End tail.
//!
//! [`PretailState`] is an explicit semantic boundary, not a complete
//! `ProvisioningEnd`. Genesis of this state and the following 34-block stage
//! remain separate work. The circuit uses no Apple image, capture read, libc
//! call or native subprocess.

pub use crate::end_pretail_core::{transform_pretail, InvalidPretailFrame, PretailState};

/// Length of the intermediate output region.
pub const PRETAIL_LEN: usize = 0x220;

/// Output plus sixteen following state bytes available to the circuit.
pub const PRETAIL_STATE_LEN: usize = 0x230;

/// Length of the independent read-only source region.
pub const PRETAIL_SOURCE_LEN: usize = 0x220;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(PretailState::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; PRETAIL_SOURCE_LEN],
            [0; PRETAIL_STATE_LEN]
        )
        .is_err());
    }
}
