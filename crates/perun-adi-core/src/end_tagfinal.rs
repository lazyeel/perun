// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the final 16-byte End tag serializer.
//!
//! [`TagFinalState`] is an explicit semantic boundary after the preceding tag
//! suffix stages. This is not the complete tag producer or `ProvisioningEnd`.
//! No Apple image, capture read, libc call or native subprocess is used.

pub use crate::end_tagfinal_core::{transform_tagfinal, InvalidTagFinalFrame, TagFinalState};

/// Number of bytes written by the final serializer.
pub const TAGFINAL_LEN: usize = 0x10;

/// Number of prior tag bytes held at the semantic boundary.
pub const TAGFINAL_INPUT_LEN: usize = 0x10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(TagFinalState::new(
            [0; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000],
            [0; TAGFINAL_INPUT_LEN],
            [0; TAGFINAL_LEN]
        )
        .is_err());
    }
}
