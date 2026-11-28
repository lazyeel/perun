// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Large straight-line middle-tag stage before prior-tag consumption.
//!
//! [`TagMiddle2State`] is an explicit semantic boundary. This is not the
//! complete tag producer or `ProvisioningEnd`; no Apple image, capture read or
//! native subprocess is used.

pub use crate::end_tag_middle2_core::{
    transform_tag_middle2, InvalidTagMiddle2StateFrame, TagMiddle2State,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(TagMiddle2State::new(
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
