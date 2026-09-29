// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Thread Environment Block (TEB) and Process Environment Block (PEB) layout
//! and `GS_BASE` setup.
//!
//! Windows x64 code expects `GS:[0x30]` to point at the current TEB,
//! `GS:[0x60]` at the PEB, and `GS:[0x68]` at `LastErrorValue`. On Linux `x86_64`,
//! `FS` is owned by glibc/pthread TLS; `GS` is free for user space.

const ARCH_SET_GS: libc::c_int = 0x1001;

/// Minimal `FakeTEB` backing structure (page-aligned in heap).
#[repr(C, align(4096))]
pub struct FakeTeb {
    pub reserved_0: u64,          // +0x00
    pub stack_base: u64,          // +0x08
    pub stack_limit: u64,         // +0x10
    pub sub_system_tib: u64,      // +0x18
    pub fiber_data: u64,          // +0x20
    pub arbitrary_data: u64,      // +0x28
    pub self_ptr: u64,            // +0x30 NtCurrentTeb()
    pub environment_pointer: u64, // +0x38
    pub client_id_pid: u64,       // +0x40
    pub client_id_tid: u64,       // +0x48
    pub rpc_handle: u64,          // +0x50
    pub tls_array: u64,           // +0x58
    pub peb_ptr: u64,             // +0x60
    pub last_error: u32,          // +0x68
    pub last_status: u32,         // +0x6C
    pub reserved_1: [u64; 24],    // up to TLS slots
    pub tls_slots: [u64; 64],     // inline TLS slots array
    pub peb: FakePeb,             // inline PEB storage
}

/// Minimal `FakePEB` backing structure.
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

/// Initialize the per-thread `FakeTEB` and set `GS_BASE` via `arch_prctl`.
///
/// # Safety
/// Invokes `syscall(SYS_arch_prctl, ARCH_SET_GS, ptr)`. Safe on `x86_64` Linux.
///
/// Deliberately `#[must_use]`: the returned block is what the shims reach
/// through `GS:[0x30]`, and a caller that drops it on the floor has almost
/// always made a mistake. The four setup sites that only want the side effect
/// say so with an explicit `let _ =`.
#[must_use]
pub unsafe fn init_thread_teb(image_base: u64) -> *mut FakeTeb {
    unsafe {
        CURRENT_TEB.with(|slot| {
            let mut b = Box::new(std::mem::zeroed::<FakeTeb>());
            let p = &raw mut *b as u64;

            // Stack bounds must reflect the REAL Linux stack. MSVC's __chkstk
            // reads gs:[0x10] (StackLimit) and probes pages downward toward it;
            // a fake limit above the actual stack makes the probe run into
            // unmapped memory and fault. Query pthread for the true range.
            let (stack_base, stack_limit) = real_stack_bounds();
            b.stack_base = stack_base;
            b.stack_limit = stack_limit;

            b.self_ptr = p;
            b.tls_array = (p + 0x100) as u64; // points to tls_slots array
            b.peb_ptr = (p + std::mem::offset_of!(FakeTeb, peb) as u64) as u64;
            b.last_error = 0;
            b.peb.image_base_address = image_base;
            b.peb.being_debugged = 0;
            b.peb.process_heap = 1; // matches GetProcessHeap shim

            let teb_ptr = &raw mut *b;
            *slot.borrow_mut() = Some(b);

            let res = libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb_ptr as u64);
            if res != 0 {
                eprintln!(
                    "[perun] ARCH_SET_GS failed: errno={}",
                    *libc::__errno_location()
                );
            }
            teb_ptr
        })
    }
}

/// Return `(stack_base, stack_limit)` = (top, bottom) of the current thread's
/// real stack, via `pthread_getattr_np`. Falls back to a conservative window
/// around the current stack pointer if the query fails.
fn real_stack_bounds() -> (u64, u64) {
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &raw mut attr) == 0 {
            let mut stack_addr: *mut libc::c_void = std::ptr::null_mut();
            let mut stack_size: usize = 0;
            let ok = libc::pthread_attr_getstack(
                &raw const attr,
                &raw mut stack_addr,
                &raw mut stack_size,
            ) == 0;
            libc::pthread_attr_destroy(&raw mut attr);
            if ok && !stack_addr.is_null() && stack_size > 0 {
                let bottom = stack_addr as u64;
                let top = bottom + stack_size as u64;
                return (top, bottom);
            }
        }
    }
    // Fallback: bracket the current stack pointer. Probe a local to get rsp.
    let local: u64 = 0;
    let rsp = &raw const local as u64;
    // Assume up to 8 MiB of stack below the current pointer.
    (rsp + 0x1000, rsp.saturating_sub(8 * 1024 * 1024))
}

/// Access the current thread's `LastErrorValue` pointer directly (for shims).
///
/// # Safety
/// Must be called after `init_thread_teb`.
#[must_use]
pub unsafe fn get_last_error_ptr() -> *mut u32 {
    CURRENT_TEB.with(|slot| match slot.borrow().as_ref() {
        Some(b) => (&raw const b.last_error).cast_mut(),
        None => std::ptr::null_mut(),
    })
}

/// Access the current thread's inline TLS slot array (for FLS shims).
///
/// # Safety
/// Must be called after `init_thread_teb`.
#[must_use]
pub unsafe fn get_tls_slot_ptr(index: usize) -> *mut u64 {
    unsafe {
        CURRENT_TEB.with(|slot| match slot.borrow().as_ref() {
            Some(b) if index < b.tls_slots.len() => b.tls_slots.as_ptr().add(index).cast_mut(),
            _ => std::ptr::null_mut(),
        })
    }
}

/// Number of inline TLS slots available for FLS backing.
pub const TLS_SLOT_COUNT: usize = 64;

// ── an isolated stack for the PE lane ────────────────────────────────────────
//
// The PE lane used to run the guest on the host thread's stack, so the frame
// the export builds with `sub rsp,0x16a8` landed on whatever perun's own Rust
// execution had left there. Two places in the guest read uninitialised memory
// as a result, and both matter: RVA 0xb15c8 is `movzx eax,byte [rcx+rax]`,
// whose byte forms the CFF dispatch index, and RVA 0x6783f reads the caller's
// packet byte by byte. Zeroing the host stack is not a fix -- it is a 1 MiB
// `memset` that does not restore the 16-byte alignment Win64 requires at the
// call, which is what turned into SIGSEGV.
//
// So: give the guest its own mapping. The kernel hands out zeroed pages, so
// the "uninitialised" read becomes a deterministic zero, and the bounds the
// guest's own stack probe consults through gs:[0x08] and gs:[0x10] are the
// real bounds of the mapping rather than of the thread it left.

/// Default guest stack size for the PE lane.
pub const PE_STACK_SIZE: usize = 8 << 20;

/// Map `size` bytes for the guest and return `(limit, base)`.
///
/// The base is a fixed hint so runs are reproducible; `MAP_FIXED_NOREPLACE`
/// keeps it from clobbering anything if the hint happens to be taken.
pub unsafe fn alloc_pe_stack(size: usize) -> Option<(u64, u64)> {
    unsafe {
        let want = 0x7FF7_CF80_0000u64;
        let p = libc::mmap(
            want as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if p as isize == -1 {
            return None;
        }
        let base = p as u64 + size as u64;
        // The kernel already zeroed it; make that a property rather than a
        // hope, since everything above depends on it.
        std::ptr::write_bytes(p, 0, size);
        Some((p as u64, base))
    }
}

/// Point the TEB's stack bounds at the guest's own mapping.
///
/// `gs:[0x10]` is what MSVC's `__chkstk` probes downward toward, so leaving
/// the host thread's limits in place while the guest runs on another stack
/// makes the probe walk off the mapping.
pub unsafe fn set_pe_stack_bounds(limit: u64, base: u64) {
    CURRENT_TEB.with(|slot| {
        if let Some(b) = slot.borrow_mut().as_mut() {
            b.stack_limit = limit;
            b.stack_base = base;
        }
    });
}

core::arch::global_asm!(
    ".text",
    ".globl pe_call_on_stack",
    ".hidden pe_call_on_stack",
    ".type pe_call_on_stack, @function",
    "pe_call_on_stack:",
    // Six registers carry the whole contract: rdi target, rsi new stack top,
    // rdx/rcx/r8/r9 the four arguments. Nothing else is live.
    "  push rbp",
    "  mov  rbp, rsp",
    "  push rbx",
    "  push r12",
    "  push r13",
    "  push r14",
    "  push r15",
    "  sub  rsp, 8",   // keep the frame 16-aligned
    "  mov  r12, rsp", // host stack, callee-saved so it survives
    "  mov  r13, rdi", // target, also callee-saved
    "  mov  r10, rsi", // new stack top
    "  and  r10, -16",
    "  sub  r10, 32",  // Win64 shadow space
    "  mov  rsp, r10", // rsp % 16 == 0 here, as a call requires
    "  mov  rdi, rdx",
    "  mov  rsi, rcx",
    "  call r13",
    "  mov  rsp, r12",
    "  lea  rsp, [rsp+8]",
    "  pop  r15",
    "  pop  r14",
    "  pop  r13",
    "  pop  r12",
    "  pop  rbx",
    "  pop  rbp",
    "  ret",
);

unsafe extern "C" {
    fn pe_call_on_stack(target: usize, stack_top: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64;
}

/// Call `f` on the stack whose top is `stack_top`, and come back to ours.
pub unsafe fn call_on_stack(
    f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64,
    stack_top: u64,
    args: [u64; 4],
) -> u64 {
    unsafe { pe_call_on_stack(f as usize, stack_top, args[0], args[1], args[2], args[3]) }
}
