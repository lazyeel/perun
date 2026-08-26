// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! perun-core: binary projection of PE32+ images into a Linux process.

pub mod image;
pub mod loader;
pub mod stub;
pub mod teb;

pub use loader::{Image, LoadError};
pub use stub::StubPoolGuard;

/// Access the process-wide trap micro-stub pool (used by the loader for
/// unresolved imports).
pub fn stub_pool() -> StubPoolGuard {
    stub::stub_pool()
}
