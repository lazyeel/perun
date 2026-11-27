// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent arithmetic for the repeated SSE circuit inside End's tag stage.
//!
//! [`TagRoundState`] is an explicit semantic boundary. The circuit produces two
//! 1,024-byte intermediate buffers; it is not the complete 16-byte tag producer
//! or `ProvisioningEnd`. No Apple image, capture read, libc call or native
//! subprocess is used.

pub use crate::end_tag_round_core::{transform_tag_round, InvalidTagRoundFrame, TagRoundState};

/// Number of repetitions of the measured 321-instruction circuit.
pub const TAG_ROUND_COUNT: usize = 64;

/// Size of each intermediate output buffer.
pub const TAG_ROUND_OUTPUT_LEN: usize = 0x400;

pub(crate) type Xmm = [u8; 16];

pub(crate) fn word(value: &Xmm, lane: usize) -> u16 {
    let at = lane * 2;
    u16::from_le_bytes(value[at..at + 2].try_into().unwrap())
}

pub(crate) fn dword(value: &Xmm, lane: usize) -> u32 {
    let at = lane * 4;
    u32::from_le_bytes(value[at..at + 4].try_into().unwrap())
}

pub(crate) fn qword(value: &Xmm, lane: usize) -> u64 {
    let at = lane * 8;
    u64::from_le_bytes(value[at..at + 8].try_into().unwrap())
}

fn set_word(value: &mut Xmm, lane: usize, word: u16) {
    value[lane * 2..lane * 2 + 2].copy_from_slice(&word.to_le_bytes());
}

fn set_dword(value: &mut Xmm, lane: usize, dword: u32) {
    value[lane * 4..lane * 4 + 4].copy_from_slice(&dword.to_le_bytes());
}

fn set_qword(value: &mut Xmm, lane: usize, qword: u64) {
    value[lane * 8..lane * 8 + 8].copy_from_slice(&qword.to_le_bytes());
}

pub(crate) fn from_dword(value: u64) -> Xmm {
    let mut out = [0; 16];
    set_dword(&mut out, 0, value as u32);
    out
}

#[cfg(test)]
pub(crate) fn from_qword(value: u64) -> Xmm {
    let mut out = [0; 16];
    set_qword(&mut out, 0, value);
    out
}

pub(crate) fn insert_dword(mut value: Xmm, lane: usize, dword: u64) -> Xmm {
    set_dword(&mut value, lane, dword as u32);
    value
}

pub(crate) fn insert_word(mut value: Xmm, lane: usize, word: u64) -> Xmm {
    set_word(&mut value, lane, word as u16);
    value
}

fn map_dwords(a: Xmm, b: Xmm, op: impl Fn(u32, u32) -> u32) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..4 {
        set_dword(&mut out, lane, op(dword(&a, lane), dword(&b, lane)));
    }
    out
}

fn map_qwords(a: Xmm, b: Xmm, op: impl Fn(u64, u64) -> u64) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..2 {
        set_qword(&mut out, lane, op(qword(&a, lane), qword(&b, lane)));
    }
    out
}

pub(crate) fn paddd(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, u32::wrapping_add)
}

pub(crate) fn psubd(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, u32::wrapping_sub)
}

pub(crate) fn pand(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, |x, y| x & y)
}

pub(crate) fn pxor(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, |x, y| x ^ y)
}

pub(crate) fn por(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, |x, y| x | y)
}

pub(crate) fn paddq(a: Xmm, b: Xmm) -> Xmm {
    map_qwords(a, b, u64::wrapping_add)
}

pub(crate) fn psubq(a: Xmm, b: Xmm) -> Xmm {
    map_qwords(a, b, u64::wrapping_sub)
}

pub(crate) fn pcmpgtd(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(
        a,
        b,
        |x, y| {
            if (x as i32) > (y as i32) {
                u32::MAX
            } else {
                0
            }
        },
    )
}

pub(crate) fn pcmpeqd(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, |x, y| if x == y { u32::MAX } else { 0 })
}

pub(crate) fn pminud(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, u32::min)
}

pub(crate) fn pmulld(a: Xmm, b: Xmm) -> Xmm {
    map_dwords(a, b, u32::wrapping_mul)
}

pub(crate) fn psrld(mut value: Xmm, count: u64) -> Xmm {
    for lane in 0..4 {
        let shifted = if count < 32 {
            dword(&value, lane) >> count
        } else {
            0
        };
        set_dword(&mut value, lane, shifted);
    }
    value
}

pub(crate) fn pslld(mut value: Xmm, count: u64) -> Xmm {
    for lane in 0..4 {
        let shifted = if count < 32 {
            dword(&value, lane) << count
        } else {
            0
        };
        set_dword(&mut value, lane, shifted);
    }
    value
}

pub(crate) fn psrlq(mut value: Xmm, count: u64) -> Xmm {
    for lane in 0..2 {
        let shifted = if count < 64 {
            qword(&value, lane) >> count
        } else {
            0
        };
        set_qword(&mut value, lane, shifted);
    }
    value
}

pub(crate) fn psllq(mut value: Xmm, count: u64) -> Xmm {
    for lane in 0..2 {
        let shifted = if count < 64 {
            qword(&value, lane) << count
        } else {
            0
        };
        set_qword(&mut value, lane, shifted);
    }
    value
}

pub(crate) fn pshufd(value: Xmm, control: u8) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..4 {
        let source = usize::from((control >> (lane * 2)) & 3);
        set_dword(&mut out, lane, dword(&value, source));
    }
    out
}

pub(crate) fn pshufb(value: Xmm, control: Xmm) -> Xmm {
    let mut out = [0; 16];
    for (lane, mask) in control.into_iter().enumerate() {
        out[lane] = if mask & 0x80 != 0 {
            0
        } else {
            value[usize::from(mask & 0x0f)]
        };
    }
    out
}

pub(crate) fn pmovzxdq(value: Xmm) -> Xmm {
    let mut out = [0; 16];
    set_qword(&mut out, 0, u64::from(dword(&value, 0)));
    set_qword(&mut out, 1, u64::from(dword(&value, 1)));
    out
}

pub(crate) fn pmovsxdq(value: Xmm) -> Xmm {
    let mut out = [0; 16];
    set_qword(&mut out, 0, (dword(&value, 0) as i32) as i64 as u64);
    set_qword(&mut out, 1, (dword(&value, 1) as i32) as i64 as u64);
    out
}

pub(crate) fn pmovzxwd(value: Xmm) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..4 {
        set_dword(&mut out, lane, u32::from(word(&value, lane)));
    }
    out
}

pub(crate) fn punpckhdq(a: Xmm, b: Xmm) -> Xmm {
    let mut out = [0; 16];
    set_dword(&mut out, 0, dword(&a, 2));
    set_dword(&mut out, 1, dword(&b, 2));
    set_dword(&mut out, 2, dword(&a, 3));
    set_dword(&mut out, 3, dword(&b, 3));
    out
}

pub(crate) fn blendvpd(a: Xmm, b: Xmm, mask: Xmm) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..2 {
        let selected = if qword(&mask, lane) & (1 << 63) != 0 {
            qword(&b, lane)
        } else {
            qword(&a, lane)
        };
        set_qword(&mut out, lane, selected);
    }
    out
}

pub(crate) fn shufps(a: Xmm, b: Xmm, control: u8) -> Xmm {
    let mut out = [0; 16];
    for lane in 0..2 {
        let source = usize::from((control >> (lane * 2)) & 3);
        set_dword(&mut out, lane, dword(&a, source));
    }
    for lane in 0..2 {
        let source = usize::from((control >> ((lane + 2) * 2)) & 3);
        set_dword(&mut out, lane + 2, dword(&b, source));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lanes(values: [u32; 4]) -> Xmm {
        let mut out = [0; 16];
        for (lane, value) in values.into_iter().enumerate() {
            set_dword(&mut out, lane, value);
        }
        out
    }

    #[test]
    fn state_rejects_a_truncated_frame() {
        assert!(TagRoundState::new(
            [0; 16],
            [[0; 16]; 16],
            vec![0; 15],
            [0; 0x4000],
            [0; 0x5000]
        )
        .is_err());
    }

    #[test]
    fn dword_lane_operations_wrap_and_compare() {
        let a = lanes([u32::MAX, 2, 3, 4]);
        let b = lanes([2, u32::MAX, 3, 4]);
        assert_eq!(dword(&paddd(a, b), 0), 1);
        assert_eq!(dword(&psubd(a, b), 1), 3);
        assert_eq!(pcmpgtd(a, b), lanes([0, u32::MAX, 0, 0]));
        assert_eq!(pcmpeqd(a, b), lanes([0, 0, u32::MAX, u32::MAX]));
        assert_eq!(pminud(a, b), lanes([2, 2, 3, 4]));
    }

    #[test]
    fn shifts_use_the_x86_out_of_range_rule() {
        let value = lanes([1, 2, 3, 4]);
        assert_eq!(pslld(value, 3), lanes([8, 16, 24, 32]));
        assert_eq!(psrld(value, 32), [0; 16]);
        assert_eq!(psllq(value, 64), [0; 16]);
        assert_eq!(qword(&psllq(from_qword(3), 4), 0), 48);
    }

    #[test]
    fn shuffles_and_inserts_preserve_the_measured_lane_layout() {
        let value = lanes([0x11, 0x22, 0x33, 0x44]);
        assert_eq!(pshufd(value, 0b11_10_01_00), value);
        assert_eq!(pshufd(value, 0), lanes([0x11; 4]));
        assert_eq!(dword(&insert_dword(value, 2, 0xaabbccdd), 2), 0xaabbccdd);
        assert_eq!(word(&insert_word(value, 1, 0xbeef), 1), 0xbeef);

        let mut control = [0x80; 16];
        control[0] = 15;
        control[1] = 0;
        let shuffled = pshufb(value, control);
        assert_eq!(shuffled[0], value[15]);
        assert_eq!(shuffled[1], value[0]);
        assert!(shuffled[2..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn conversions_and_variable_blend_are_exact() {
        let value = lanes([0x89abcdef, 0x80000000, 3, 4]);
        assert_eq!(qword(&pmovzxdq(value), 0), 0x89abcdef);
        assert_eq!(qword(&pmovsxdq(value), 0), 0xffffffff89abcdef);
        assert_eq!(qword(&pmovsxdq(value), 1), 0xffffffff80000000);
        assert_eq!(dword(&pmovzxwd(value), 1), 0x89ab);

        let a = from_qword(0x11);
        let b = from_qword(0x22);
        let mask = from_qword(1 << 63);
        assert_eq!(qword(&blendvpd(a, b, mask), 0), 0x22);
        assert_eq!(qword(&blendvpd(a, b, [0; 16]), 0), 0x11);
    }
}
