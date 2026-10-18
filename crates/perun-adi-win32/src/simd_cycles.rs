// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The fold machine's SSE cascade -- stage 1 of the pure-Rust white
//! box.
//!
//! Transpiled from the DLL zone 0x7c86c5fe..0x7c86e453 (1772
//! instructions, 97 SSE ops, 21 broadcast constants) by
//! tools/transpile_simd.py. The zone is the fold cascade's main
//! body: 128-bit lanes over [u32; 4], pure portable Rust -- the
//! semantics of paddd/psubd/pxor/pand/pmuludq/pshufd/punpck* are
//! exact wrapping lane arithmetic, so no intrinsics and no unsafe
//! are needed to reproduce them bit for bit.
//!
//! The cascade's 21 memory operands are broadcast constants (four
//! identical lanes) baked from the image -- they are the fold
//! machine's round keys. The xmm inputs arrive from the cursor-table
//! dispatch (0x7c95fc90); the harness feeds them from the measured
//! session, and the parity tests pin them.

/// A 128-bit SSE register: four u32 lanes, little-endian lane order.
pub type Lanes = [u32; 4];

/// The fold machine's round keys -- the 21 broadcast constants the
/// cascade reads out of the image, baked at transpile time.
pub mod keys {
    use super::Lanes;

    pub const K_7C954560: Lanes = [0x2a000000; 4];
    pub const K_7C954570: Lanes = [0x15936d71; 4];
    pub const K_7C954580: Lanes = [0x5a278f86; 4];
    pub const K_7C954590: Lanes = [0xad934743; 4];
    pub const K_7C9545A0: Lanes = [0x7e870000; 4];
    pub const K_7C9545B0: Lanes = [0xfff73a77; 4];
    pub const K_7C9545C0: Lanes = [0xfeef0100; 4];
    pub const K_7C9545D0: Lanes = [0x02108a11; 4];
    pub const K_7C9545E0: Lanes = [0x7e74fffe; 4];
    pub const K_7C9545F0: Lanes = [0xfce8fefd; 4];
    pub const K_7C954600: Lanes = [0x7e874743; 4];
    pub const K_7C954610: Lanes = [0xff8fedc7; 4];
    pub const K_7C954620: Lanes = [0xfe1fdb8f; 4];
    pub const K_7C954630: Lanes = [0x7f18a292; 4];
    pub const K_7C954640: Lanes = [0x3e000000; 4];
    pub const K_7C954650: Lanes = [0x1f6fca4b; 4];
    pub const K_7C954660: Lanes = [0xc8010000; 4];
    pub const K_7C954670: Lanes = [0xe429693e; 4];
    pub const K_7C954680: Lanes = [0x029693e; 4];
    pub const K_7C954690: Lanes = [0xad000000; 4];
    pub const K_7C942730: Lanes = [0x4000000; 4];
}

/// The cascade's register file: the xmm state the zone consumes and
/// produces. Lane semantics are exact; every field is copied, never
/// aliased, so the emitted code reads like the disassembly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XmmState {
    pub xmm0: Lanes,
    pub xmm1: Lanes,
    pub xmm2: Lanes,
    pub xmm3: Lanes,
    pub xmm4: Lanes,
    pub xmm5: Lanes,
    pub xmm6: Lanes,
    pub xmm7: Lanes,
    pub xmm8: Lanes,
    pub xmm9: Lanes,
    pub xmm10: Lanes,
    pub xmm11: Lanes,
    pub xmm12: Lanes,
    pub xmm13: Lanes,
    pub xmm14: Lanes,
    pub xmm15: Lanes,
}

/// paddd: wrapping add, lane-wise.
#[inline]
pub fn paddd(a: Lanes, b: Lanes) -> Lanes {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
    ]
}

/// psubd: wrapping sub, lane-wise.
#[inline]
pub fn psubd(a: Lanes, b: Lanes) -> Lanes {
    [
        a[0].wrapping_sub(b[0]),
        a[1].wrapping_sub(b[1]),
        a[2].wrapping_sub(b[2]),
        a[3].wrapping_sub(b[3]),
    ]
}

/// pxor: lane-wise xor.
#[inline]
pub fn pxor(a: Lanes, b: Lanes) -> Lanes {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// pand: lane-wise and.
#[inline]
pub fn pand(a: Lanes, b: Lanes) -> Lanes {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

/// por: lane-wise or.
#[inline]
pub fn por(a: Lanes, b: Lanes) -> Lanes {
    [a[0] | b[0], a[1] | b[1], a[2] | b[2], a[3] | b[3]]
}

/// pshufd: dst lane i takes src lane ((imm >> 2i) & 3).
#[inline]
pub fn pshufd(imm: u8, src: Lanes) -> Lanes {
    [
        src[(imm & 3) as usize],
        src[((imm >> 2) & 3) as usize],
        src[((imm >> 4) & 3) as usize],
        src[((imm >> 6) & 3) as usize],
    ]
}

/// pmuludq: the two 64-bit low-halves of a and b multiplied, packed
/// into lanes 0 and 2 (64-bit results, stored as u32 pairs).
#[inline]
pub fn pmuludq(a: Lanes, b: Lanes) -> Lanes {
    let p0 = u64::from(a[0]) * u64::from(b[0]);
    let p2 = u64::from(a[2]) * u64::from(b[2]);
    [p0 as u32, (p0 >> 32) as u32, p2 as u32, (p2 >> 32) as u32]
}

/// punpckldq: interleave the two low lanes of both operands.
#[inline]
pub fn punpckldq(a: Lanes, b: Lanes) -> Lanes {
    [a[0], b[0], a[1], b[1]]
}

/// punpckhdq: interleave the two high lanes of both operands.
#[inline]
pub fn punpckhdq(a: Lanes, b: Lanes) -> Lanes {
    [a[2], b[2], a[3], b[3]]
}

/// punpcklqdq: the two 64-bit low-halves of a and b concatenated.
#[inline]
pub fn punpcklqdq(a: Lanes, b: Lanes) -> Lanes {
    [a[0], a[1], b[0], b[1]]
}

/// movd: a u32 extracted from lane 0 (the only lane SSE movd reads).
#[inline]
pub fn movd(a: Lanes) -> u32 {
    a[0]
}

/// movd from a u32: lane 0 set, the rest zeroed.
#[inline]
pub fn movd_from_u32(v: u32) -> Lanes {
    [v, 0, 0, 0]
}

/// movq load: two u32s into lanes 0 and 1.
#[inline]
pub fn movq_from_u64(v: u64) -> Lanes {
    [v as u32, (v >> 32) as u32, 0, 0]
}

/// movq store: lanes 0 and 1 packed back into a u64.
#[inline]
pub fn movq_to_u64(a: Lanes) -> u64 {
    u64::from(a[0]) | (u64::from(a[1]) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pmuludq must reproduce the exact 64-bit low-half products.
    #[test]
    fn pmuludq_low_halves() {
        let a = [0xffffffff, 0, 0x12345678, 0];
        let b = [0xffffffff, 0, 0x9abcdef0, 0];
        let r = pmuludq(a, b);
        let p0 = u64::from(0xffffffffu32) * u64::from(0xffffffffu32);
        let p2 = u64::from(0x12345678u32) * u64::from(0x9abcdef0u32);
        assert_eq!(
            r,
            [p0 as u32, (p0 >> 32) as u32, p2 as u32, (p2 >> 32) as u32]
        );
    }

    /// pshufd follows the imm-bit select order (2 bits per dst lane).
    #[test]
    fn pshufd_select_order() {
        let src = [10, 11, 12, 13];
        assert_eq!(pshufd(0b11_10_01_00, src), [10, 11, 12, 13]);
        assert_eq!(pshufd(0b00_00_00_00, src), [10, 10, 10, 10]);
        assert_eq!(pshufd(0b01_01_01_01, src), [11, 11, 11, 11]);
        assert_eq!(pshufd(0xf5, src), [11, 11, 13, 13]);
    }

    /// The round keys are broadcast constants -- all four lanes equal.
    #[test]
    fn keys_are_broadcasts() {
        assert_eq!(keys::K_7C954560, [0x2a000000; 4]);
        assert_eq!(keys::K_7C954690, [0xad000000; 4]);
        assert_eq!(keys::K_7C942730, [0x4000000; 4]);
    }

    /// punpck semantics against the manual's lane layouts.
    #[test]
    fn unpack_lane_layouts() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        assert_eq!(punpckldq(a, b), [1, 5, 2, 6]);
        assert_eq!(punpckhdq(a, b), [3, 7, 4, 8]);
        assert_eq!(punpcklqdq(a, b), [1, 2, 5, 6]);
    }
}
