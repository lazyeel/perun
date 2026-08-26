// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! perun-shims: the Win32 → POSIX translation matrix.

pub mod files;
pub mod files_enum;
pub mod memory;
pub mod process;
pub mod registry;
pub mod runtime_state;
pub mod seh_tls;
pub mod strings_env;
pub mod sync;
pub mod table;
pub mod util;
pub mod win32;

pub use table::ShimTable;
pub use util::{get_last_error, set_last_error};
