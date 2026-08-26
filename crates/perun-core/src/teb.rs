// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Thread Environment Block (TEB) and Process Environment Block (PEB) layout
//! and GS_BASE setup.
//!
//! Windows x64 code expects `GS:[0x30]` to point at the current TEB,
//! `GS:[0x60]` at the PEB, and `GS:[0x68]` at LastErrorValue. On Linux x86_64,
//! `FS` is owned by glibc/pthread TLS; `GS` is free for user space.

const ARCH_SET_GS: libc::c_int = 0x1001;

/// Minimal FakeTEB backing structure (page-aligned in heap).
#[repr(C, align(4096))]
pub struct FakeTeb {
    pub reserved_0: u64,           // +0x00
    pub stack_base: u64,           // +0x08
    pub stack_limit: u64,          // +0x10
    pub sub_system_tib: u64,       // +0x18
    pub fiber_data: u64,           // +0x20
    pub arbitrary_data: u64,       // +0x28
    pub self_ptr: u64,             // +0x30 NtCurrentTeb()
    pub environment_pointer: u64,  // +0x38
    pub client_id_pid: u64,        // +0x40
    pub client_id_tid: u64,        // +0x48
    pub rpc_handle: u64,           // +0x50
    pub tls_array: u64,            // +0x58
    pub peb_ptr: u64,              // +0x60
    pub last_error: u32,           // +0x68
    pub last_status: u32,          // +0x6C
    pub reserved_1: [u64; 24],     // up to TLS slots
    pub tls_slots: [u64; 64],      // inline TLS slots array
    pub peb: FakePeb,              // inline PEB storage
}

/// Minimal FakePEB backing structure.
#[repr(C)]
pub struct FakePeb {
    pub inherited_address_space: u8, // +0x00
    pub read_image_file_exec: u8,    // +0x01
    pub being_debugged: u8,          // +0x02
    pub bit_field: u8,               // +0x03
    pub mutant: u64,                 // +0x08
    pub image_base_address: u64,     // +0x10
    pub ldr_data: u64,               // +0x18
    pub process_parameters: u64,     // +0x20
    pub sub_system_data: u64,        // +0x28
    pub process_heap: u64,           // +0x30
}

thread_local! {
    static CURRENT_TEB: std::cell::RefCell<Option<Box<FakeTeb>>> = const { std::cell::RefCell::new(None) };
}

/// Initialize the per-thread FakeTEB and set `GS_BASE` via `arch_prctl`.
///
/// # Safety
/// Invokes `syscall(SYS_arch_prctl, ARCH_SET_GS, ptr)`. Safe on x86_64 Linux.
pub unsafe fn init_thread_teb(image_base: u64) -> *mut FakeTeb {
    CURRENT_TEB.with(|slot| {
        let mut b = Box::new(std::mem::zeroed::<FakeTeb>());
        let p = &mut *b as *mut FakeTeb as u64;
        b.stack_base = 0x7FFF_FFFF_F000;
        b.stack_limit = 0x7FFF_0000_0000;
        b.self_ptr = p;
        b.tls_array = (p + 0x100) as u64; // points to tls_slots array
        b.peb_ptr = (p + std::mem::offset_of!(FakeTeb, peb) as u64) as u64;
        b.last_error = 0;
        b.peb.image_base_address = image_base;
        b.peb.being_debugged = 0;
        b.peb.process_heap = 1; // matches GetProcessHeap shim

        let teb_ptr = &mut *b as *mut FakeTeb;
        *slot.borrow_mut() = Some(b);

        let res = libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb_ptr as u64);
        if res != 0 {
            eprintln!("[perun] ARCH_SET_GS failed: errno={}", *libc::__errno_location());
        }
        teb_ptr
    })
}

/// Access the current thread's LastErrorValue pointer directly (for shims).
///
/// # Safety
/// Must be called after `init_thread_teb`.
pub unsafe fn get_last_error_ptr() -> *mut u32 {
    CURRENT_TEB.with(|slot| match slot.borrow().as_ref() {
        Some(b) => &b.last_error as *const u32 as *mut u32,
        None => std::ptr::null_mut(),
    })
}

/// Access the current thread's inline TLS slot array (for FLS shims).
///
/// # Safety
/// Must be called after `init_thread_teb`.
pub unsafe fn get_tls_slot_ptr(index: usize) -> *mut u64 {
    CURRENT_TEB.with(|slot| match slot.borrow().as_ref() {
        Some(b) if index < b.tls_slots.len() => {
            b.tls_slots.as_ptr().add(index) as *mut u64
        }
        _ => std::ptr::null_mut(),
    })
}

/// Number of inline TLS slots available for FLS backing.
pub const TLS_SLOT_COUNT: usize = 64;
