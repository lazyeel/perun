// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Dynamic runtime state: per-module exports, dynamic imports and runtime traps.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Raw pointer wrapper that is Send (the guest guarantees single-owner access).
#[derive(Clone, Copy)]
struct SendPtr(*mut core::ffi::c_void);
unsafe impl Send for SendPtr {}

static RUNTIME_EXPORTS: Mutex<Option<BTreeMap<(usize, String), SendPtr>>> = Mutex::new(None);

/// Lookup a registered export by handle and name.
pub fn lookup_export(module: usize, name: &str) -> Option<*mut core::ffi::c_void> {
    let g = RUNTIME_EXPORTS.lock().unwrap();
    g.as_ref()
        .and_then(|m| m.get(&(module, name.to_string())).map(|p| p.0))
}

/// Register an export under a module handle: a host that loaded a guest
/// DLL can hand its exports to another guest's GetProcAddress calls.
/// The handle space is the host's choice; perun reserves 0xAD000000+.
pub fn register_export(module: usize, name: &str, ptr: *const core::ffi::c_void) {
    let mut g = RUNTIME_EXPORTS.lock().unwrap();
    g.get_or_insert_with(BTreeMap::new)
        .insert((module, name.to_string()), SendPtr(ptr as *mut _));
}
