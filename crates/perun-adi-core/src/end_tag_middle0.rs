// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Initial limb/XOR mixing stage after End's repeated tag circuit.
//!
//! [`TagMiddle0State`] is an explicit semantic boundary. The function advances
//! it to the following masked/shift phase; it is not the complete tag producer
//! or `ProvisioningEnd`. No Apple image, capture read or native subprocess is
//! used.

pub use crate::end_tag_middle0_core::{
    transform_tag_middle0, InvalidTagMiddle0StateFrame, TagMiddle0State,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(TagMiddle0State::new(
            [0; 16],
            [[0; 16]; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; 16],
        )
        .is_err());
    }
}
