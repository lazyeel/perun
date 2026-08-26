// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Dynamic runtime state: per-module exports, dynamic imports and runtime traps.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Raw pointer wrapper that is Send (the guest guarantees single-owner access).
#[derive(Clone, Copy)]
struct SendPtr(*mut core::ffi::c_void);
unsafe impl Send for SendPtr {}

static RUNTIME_EXPORTS: Mutex<Option<BTreeMap<(usize, String), SendPtr>>> =
    Mutex::new(None);

/// Register an export address for `(module_handle, symbol_name)`.
pub fn register_export(module: usize, name: &str, ptr: *mut core::ffi::c_void) {
    let mut g = RUNTIME_EXPORTS.lock().unwrap();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert((module, name.to_string()), SendPtr(ptr));
}

/// Lookup a registered export by handle and name.
pub fn lookup_export(module: usize, name: &str) -> Option<*mut core::ffi::c_void> {
    let g = RUNTIME_EXPORTS.lock().unwrap();
    g.as_ref()
        .and_then(|m| m.get(&(module, name.to_string())).map(|p| p.0))
}
