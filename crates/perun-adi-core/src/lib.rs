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
//!   cold-canon dump parsed to its length-delimited sections);
//! * [`start`]       -- capture-free 276-byte CPIM assembly from explicit
//!   semantic SPIM/entropy/mixer/digest inputs;
//! * [`state`]       -- the versioned provisioning-state container and
//!   the lossless codec for Apple's `adi.pb`;
//! * [`identity`]    -- the 16-byte `adi_identifier` and its bound half;
//! * [`spim`]        -- the 347-byte Start input: 264 payload + Body B + tag;
//! * [`mixer`]       -- the fixed ten-round body-A circuit over an explicit
//!   semantic initial state (whose own genesis is tracked separately);
//! * [`otp`]         -- independent warm-OTP execution with a semantic native
//!   ABI rather than trace/callee replay;
//! * [`end_header`] -- the measured fixed 53-byte provisioning-state prefix;
//! * [`end_source32a`] / [`end_source32b`] / [`end_source32c`] -- three linked
//!   independent 32-byte End source-generation stages;
//! * [`end_source60`] -- one independent 60-byte End source-generation stage;
//! * [`end_tag_round`] -- the independent 64-round SSE subcircuit producing two
//!   1,024-byte intermediate buffers (not the complete 16-byte tag);
//! * [`end_tagfinal`] -- the independent final 16-byte tag serializer over an
//!   explicit post-suffix semantic state;
//! * [`end_tag_middle0`] -- the initial limb/XOR mixing stage between those
//!   two tag boundaries, checked against complete checkpoint states;
//! * [`end_pretail`] -- the independent 544-iteration End pre-transformation
//!   over an explicit semantic intermediate state (not full ProvisioningEnd);
//! * [`end_tail`]    -- the independent 34-block End transformation over an
//!   explicit semantic intermediate state (not full ProvisioningEnd);
//! * [`session`]     -- the entropy-to-`session16` KDF, including both measured
//!   MT twist families and the nonzero-byte output loop;
//! * [`sha256`]      -- the dependency-free SHA-256/HMAC used by the
//!   state tag.
//!
//! The integration layer lives in [`chain`]: the entry vector ->
//! fold/conveyor -> word channels -> the verdict word, and the CPIM
//! reference validator used by the parity_cpim test.

pub mod body_a;
pub mod chain;
pub mod conveyor;
pub mod cpim;
pub mod cpim_engine;
pub mod digest;
pub mod early_series;
pub mod early_zone;
pub mod end_header;
pub mod end_pretail;
mod end_pretail_core;
mod end_pretail_tables;
pub mod end_source32a;
mod end_source32a_core;
mod end_source32a_tables;
pub mod end_source32b;
mod end_source32b_core;
mod end_source32b_tables;
pub mod end_source32c;
mod end_source32c_core;
mod end_source32c_tables;
pub mod end_source60;
mod end_source60_core;
mod end_source60_tables;
pub mod end_tag_middle0;
mod end_tag_middle0_core;
mod end_tag_middle0_tables;
pub mod end_tag_round;
mod end_tag_round_core;
mod end_tag_round_tables;
pub mod end_tagfinal;
mod end_tagfinal_core;
mod end_tagfinal_tables;
pub mod end_tail;
mod end_tail_core;
mod end_tail_tables;
pub mod fold_zone;
pub mod identity;
pub mod mixer;
mod mixer_core;
mod mixer_tables;
pub mod otp;
pub mod planter;
mod planter_core;
mod planter_tables;
pub mod session;
pub mod sha256;
pub mod simd_cycles;
pub mod spim;
pub mod start;
pub mod state;
pub mod warmvm;
pub mod word_channels;
