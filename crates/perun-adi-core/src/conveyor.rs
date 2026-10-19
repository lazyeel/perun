// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The r9 conveyor: the writer-cluster prologue's tape fold,
//! transcribed from the disassembly (RVA 0x6f854..0x6f892) and
//! pinned by the measured round-0 entry state (ww_fa2c_full.log).
//!
//! The conveyor builds the round's `r9d` -- the register every
//! word channel hangs off -- as a six-step XOR fold over the
//! frame tape and the four T-tables:
//!
//! ```text
//! r9d  = [rsp+0x68]              (the tape: r15d(prev) >> 8)
//! r9d ^= [rsp+0x5c0]             (the frame constant)
//! r9d ^= T8 [ (byte)[rsp+0x88] ] (0x6f869: the edi-prev >> 24 byte)
//! r9d ^= T14[ (ebx>>16 & 0xff) ^ 0xe4 ]    (0x6f87a)
//! r9d ^= T12[ cl ^ 0x70 ]                 (0x6f884)
//! r9d ^= Tdx[ (bpl + 0x70) ^ 0x70 ]       (0x6f892)
//! ```
//!
//! the channel seeds fall straight out of r9d:
//! `[rsp+0x140] = r9d >> 16`, `r13d = r9d >> 8` -- which is why
//! the four channels' targets (r9d>>24 == 0xc4, r9b == 0xd2,
//! the +5 mix == 0x73) are a single condition on the fold.
//!
//! The T-tables are 256xu32 pages owned by the cfg prologue
//! (see FINDINGS 2026-10-23e for the allocation timing); this
//! module takes them as plain input arrays so the fold can be
//! replayed offline against any captured table row.

/// The four T-tables of the conveyor: T8, T12, T14, Tdx.
#[derive(Debug, Clone)]
pub struct TTables {
    pub t8: Vec<u32>,
    pub t12: Vec<u32>,
    pub t14: Vec<u32>,
    pub tdx: Vec<u32>,
}

/// The frame tape the conveyor folds: the two frame slots plus the
/// round's register byte sources.
#[derive(Debug, Clone, Copy)]
pub struct ConveyorInput {
    /// `[rsp+0x68]` at 0x6f854 -- the tape entry.
    pub tape: u32,
    /// `[rsp+0x5c0]` at 0x6f859 -- the frame constant (low 32 of
    /// the 64-bit slot).
    pub frame5c0: u32,
    /// `[rsp+0x88]` at 0x6f861 -- the full slot the guest loads
    /// into rax as the T8 index (measured: 0x8e).
    pub frame88: u32,
    /// `ebx` at 0x6f86d (the T14 index source).
    pub ebx: u32,
    /// `cl` at 0x6f87e (the T12 index source).
    pub cl: u8,
    /// `bpl` at 0x6f88b (the Tdx index source).
    pub bpl: u8,
}

/// The conveyor's output: the round's r9d and the channel seeds.
#[derive(Debug, Clone, Copy)]
pub struct ConveyorOutput {
    /// The folded r9d (the cluster-entry register).
    pub r9d: u32,
    /// `[rsp+0x140]` at 0x6f8ff -- `r9d >> 16`.
    pub frame140: u32,
    /// `r13d` at 0x6f918 -- `r9d >> 8`.
    pub r13d: u32,
}

/// Fold one round: the measured six-step conveyor.
#[must_use]
pub fn fold_round(inp: &ConveyorInput, tables: &TTables) -> ConveyorOutput {
    // 0x6f854: r9 = [rsp+0x68]
    let mut r9d = inp.tape;
    // 0x6f859: r9d ^= [rsp+0x5c0]
    r9d ^= inp.frame5c0;
    // 0x6f861..0x6f869: r9d ^= T8[[rsp+0x88]] -- the guest loads
    // the FULL slot into rax and indexes with it (measured: 0x8e).
    let i8 = inp.frame88 as usize;
    r9d ^= tables.t8[i8 % tables.t8.len()];
    // 0x6f86d..0x6f87a: r9d ^= T14[((ebx >> 16) & 0xff) ^ 0xe4]
    let i14 = (((inp.ebx >> 16) & 0xff) ^ 0xe4) as usize;
    r9d ^= tables.t14[i14 % tables.t14.len()];
    // 0x6f87e..0x6f884: r9d ^= T12[cl ^ 0x70]
    let i12 = (inp.cl ^ 0x70) as usize;
    r9d ^= tables.t12[i12 % tables.t12.len()];
    // 0x6f888..0x6f892: r9d ^= Tdx[(bpl + 0x70) ^ 0x70]
    let idxdx = (inp.bpl.wrapping_add(0x70)) ^ 0x70;
    let i_dx = idxdx as usize;
    r9d ^= tables.tdx[i_dx % tables.tdx.len()];

    ConveyorOutput {
        r9d,
        frame140: r9d >> 16,
        r13d: r9d >> 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured round-0 entry state (ww_fa2c_full.log probe at
    /// 0x6f869 + the TIDX probe ww_tidx.log): the frame tape, the
    /// register byte sources, and the FOUR TABLE WORDS at the
    /// round's own indexes. The conveyor must fold to the
    /// measured cluster-entry r9d = 0x73dc77fa -- the full
    /// algebraic parity of the conveyor head.
    #[test]
    fn conveyor_folds_the_measured_round0() {
        let inp = ConveyorInput {
            tape: 0x1e49_3a48,
            frame5c0: 0x46bd_257e,
            frame88: 0x8e,
            ebx: 0xbf5f_6ae0,
            cl: 0xb9,
            bpl: 0xd4,
        };

        // The tape head alone (empty tables): tape ^ frame5c0 =
        // the probe's own r9 read at 0x6f869.
        let empty = TTables {
            t8: vec![0; 256],
            t12: vec![0; 256],
            t14: vec![0; 256],
            tdx: vec![0; 256],
        };
        let head = fold_round(&inp, &empty);
        assert_eq!(head.r9d, 0x58f4_1f36, "tape ^ frame5c0 = the probe read");

        // The four measured words at the round's indexes (TIDX probe).
        let mut t8 = vec![0u32; 256];
        t8[0x8e] = 0xaf9e_a051;
        let mut t14 = vec![0u32; 256];
        t14[0xbb] = 0xb7aa_8ad2;
        let mut t12 = vec![0u32; 256];
        t12[0xc9] = 0xc440_a9e3;
        let mut tdx = vec![0u32; 256];
        tdx[0x34] = 0xf75c_ebac;
        let rows = TTables { t8, t12, t14, tdx };
        let out = fold_round(&inp, &rows);
        assert_eq!(out.r9d, 0x73dc_77fa, "the full fold = cluster entry");
        // And the channel seeds are pure shifts of the fold:
        assert_eq!(out.frame140, 0x73dc, "[rsp+0x140] = r9d >> 16");
        assert_eq!((out.frame140 & 0xff) ^ 0xe5, 0x39, "the +5 mixer input");
        assert_eq!(out.r13d, 0x0073_dc77);
    }
}
