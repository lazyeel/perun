// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the 34-block transformation inside native End.
//!
//! [`TailState`] is an explicit semantic boundary, not a provisioning record or
//! a complete `ProvisioningEnd`. Genesis of the intermediate tail and the
//! surrounding header/trailer remains separate work. The circuit itself uses no
//! Apple image, capture read, libc call or native subprocess.

pub use crate::end_tail_core::{transform_tail, InvalidTailFrame, TailState};

/// Length of the output region transformed by the circuit.
pub const TAIL_LEN: usize = 0x220;

/// Output plus the 16-byte chaining/trailer input read by the circuit.
pub const TAIL_STATE_LEN: usize = 0x230;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(TailState::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; TAIL_STATE_LEN]
        )
        .is_err());
    }
}
