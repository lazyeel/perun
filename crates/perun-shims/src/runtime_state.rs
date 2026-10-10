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

/// The spy trampoline: when a guest asks GetProcAddress for a watched
/// name, it receives this logger instead of the real function. The
/// trampoline dumps the four register args, the first 128 bytes of the
/// ctx pointer, the input packet the ctx's first slot points to, calls
/// the REAL export, and dumps the return code plus the ctx and packet
/// again -- one intercepted call is a complete envelope specimen.
static SPY_TARGET: Mutex<Option<(String, SendPtr)>> = Mutex::new(None);

/// Install the spy: `name` is watched (e.g. "vdfut768ig"); `real` is the
/// genuine export the trampoline forwards to.
pub fn install_spy(name: &str, real: *mut core::ffi::c_void) {
    *SPY_TARGET.lock().unwrap() = Some((name.to_string(), SendPtr(real)));
}

/// The trampoline's address, for GetProcAddress to hand out.
pub fn spy_trampoline_addr() -> *mut core::ffi::c_void {
    spy_trampoline as unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 as *mut core::ffi::c_void
}

/// Does GetProcAddress have to hand out the trampoline for this name?
pub fn spy_hits(name: &str) -> bool {
    SPY_TARGET
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|(n, _)| n == name)
}

fn hex_of(p: *const u8, n: usize) -> String {
    if p.is_null() {
        return "(null)".into();
    }
    let s = unsafe { std::slice::from_raw_parts(p, n) };
    s.iter().map(|b| format!("{b:02x}")).collect()
}

unsafe extern "win64" fn spy_trampoline(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    // ctx = a1 for the vdfut dispatcher (opcode, ctx, ...) -- but log
    // BOTH register orders; the wrapper's ABI is what we are measuring.
    println!("[spy] vdfut called: a0={a0:#x} a1={a1:#x} a2={a2:#x} a3={a3:#x}");
    let ctx = a1 as *const u8;
    if !ctx.is_null() {
        println!("[spy] ctx[0..128] = {}", hex_of(ctx, 128));
        let pkt = unsafe { std::ptr::read_unaligned(ctx as *const u64) } as *const u8;
        if pkt as usize > 0x1000 {
            println!("[spy] pkt[0..128] = {}", hex_of(pkt, 128));
        }
    }
    let real_ptr = {
        let g = SPY_TARGET.lock().unwrap();
        g.as_ref().unwrap().1.0
    };
    let real: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(real_ptr) };
    let rc = unsafe { real(a0, a1, a2, a3) };
    println!("[spy] vdfut returned rc={rc:#x} ({rc})");
    if !ctx.is_null() {
        println!("[spy] ctx after  = {}", hex_of(ctx, 128));
        let pkt = unsafe { std::ptr::read_unaligned(ctx as *const u64) } as *const u8;
        if pkt as usize > 0x1000 {
            println!("[spy] pkt after  = {}", hex_of(pkt, 128));
        }
    }
    rc
}
