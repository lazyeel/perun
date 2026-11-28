// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent producer of the final four-byte native state word.
//!
//! The 28-instruction circuit runs exactly twenty times and produces a 20-byte
//! intermediate buffer whose last four bytes are copied by the measured
//! finalizer. [`Final4State`] is an explicit semantic boundary, not a complete
//! `ProvisioningEnd`. No Apple image, capture read or native subprocess is used.

pub use crate::end_final4_core::{transform_final4, Final4State, InvalidFinal4Frame};

/// Length of the intermediate output buffer.
pub const FINAL4_OUTPUT_LEN: usize = 20;

/// Return the four bytes consumed by the finalizer.
pub fn final4(output: &[u8; FINAL4_OUTPUT_LEN]) -> [u8; 4] {
    output[16..20].try_into().expect("the final four bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(Final4State::new([0; 16], [[0; 16]; 16], vec![0; 15], [0; 20], [0; 20],).is_err());
    }

    #[test]
    fn finalizer_uses_the_last_four_bytes() {
        let output = core::array::from_fn(|index| index as u8);
        assert_eq!(final4(&output), [16, 17, 18, 19]);
    }
}
