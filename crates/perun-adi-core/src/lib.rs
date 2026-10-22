// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! perun-adi-core: the independent native ADI mathematics on pure
//! Rust -- no Windows, no guests, no runtime instrumentation.
//!
//! This crate is the campaign's "white box" as a library:
//!
//! * [`simd_cycles`] -- the SSE lane kernel (paddd/psubd/pxor/... as
//!   portable [u32; 4] arithmetic) plus the 21 baked round keys;
//! * [`fold_zone`]   -- the fold machine's zone (RVA 0x6c5fe..0x6e453)
//!   transpiled instruction-for-instruction from the DLL;
//! * [`word_channels`] -- the Configuration verdict word's four byte
//!   channels with the collapsed MBA mixers (parity-proven against
//!   the ww1.log session: [0x90, 0x58, 0xb9, 0xad] reproduced byte for byte);
//! * [`conveyor`]    -- the r9 conveyor of the writer-cluster prologue
//!   (the tape fold over the four T-tables), transcribed from the
//!   measured round-0 entry state;
//! * [`cpim`]        -- the 276-byte CPIM anatomy (the reference
//!   cold-canon dump parsed to its length-delimited sections).
//!
//! The integration layer lives in [`chain`]: the entry vector ->
//! fold/conveyor -> word channels -> the verdict word, and the CPIM
//! reference validator used by the parity_cpim test.

pub mod chain;
pub mod conveyor;
pub mod cpim;
pub mod body_a;
pub mod cpim_engine;
pub mod digest;
pub mod early_series;
pub mod early_zone;
pub mod fold_zone;
pub mod simd_cycles;
pub mod word_channels;
