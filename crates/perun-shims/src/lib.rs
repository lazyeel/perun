// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! perun-shims: the Win32 → POSIX translation matrix, plus the Mach-O
//! libSystem surface for the SAP phase.
//!
//! Style lints are relaxed crate-wide: the Win32 half mirrors the native
//! ABI (CRITICAL_SECTION, wYear, FARPROC…), and the Mach half carries
//! Apple's C names verbatim — renaming them to Rust style would break
//! the 1:1 mapping to the reference interposer. Phase-1 shims are kept
//! even where the SAP path no longer exercises them.
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
// Shim signatures mirror the host OS ABI argument-for-argument; an argument
// the body ignores still has to be there. Underscore-renaming every such
// parameter would churn the signatures for no behavioral gain.
#![allow(unused_variables)]
// Every shim is `unsafe extern` because guests call them with arbitrary
// register contents; per-function `# Safety` prose would be identical
// boilerplate on all of them.
#![allow(clippy::missing_safety_doc)]

pub mod files;
pub mod files_enum;
pub mod mach;
pub mod memory;
pub mod process;
pub mod registry;
pub mod runtime_state;
pub mod seh_tls;
pub mod shell_path;
pub mod strings_env;
pub mod sync;
pub mod table;
pub mod util;
pub mod win32;

pub use table::ShimTable;
pub use util::{get_last_error, set_last_error};
