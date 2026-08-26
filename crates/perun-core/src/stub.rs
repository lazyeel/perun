// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Trap micro-stub pool for unimplemented imports.
//!
//! Every unresolved IAT entry points at a 20-byte stub carved from an RWX
//! page:
//!
//! ```text
//! 41 BA xx xx xx xx    mov r10d, <import index>
//! FF 25 00 00 00 00    jmp qword ptr [rip+0]
//! <8 bytes>            absolute address of perun_trap_dispatcher
//! ```
//!
//! The jump is ABSOLUTE (rip-relative indirect through an embedded 64-bit
//! pointer), not `jmp rel32`. The RWX page is allocated by `mmap(NULL)` at an
//! arbitrary address while the dispatcher lives in the main binary; ASLR can
//! place them terabytes apart, far beyond the +/-2 GB reach of a rel32 jump.
//! An absolute jump is distance-independent.
//!
//! The shared dispatcher (one small, stable `global_asm!` block below)
//! forwards the guest's argument registers plus the index to a Rust reporter
//! and returns 0 to the guest, so a stray call logs loudly instead of
//! crashing silently.
//!
//! Why assembly here: the dispatcher has to place the index as the fifth
//! Win64 stack argument and normalize the stack before returning to guest
//! code. That is three instructions of stack choreography that no portable
//! Rust expresses; everything above this layer stays pure Rust. Implemented
//! shims never pass through here — their IAT slots hold direct
//! `extern "win64"` pointers.

use std::sync::Mutex;

/// One RWX page holds several twenty-byte stubs (`mov r10d, imm32` is 6
/// bytes, `jmp [rip+0]` is 6 bytes, embedded target address is 8 bytes).
const PAGE_SIZE: usize = 0x1000;
const STUB_SIZE: usize = 20;
const MAX_STUBS: usize = PAGE_SIZE / STUB_SIZE;

struct PoolInner {
    /// Base of the RWX page, or None until the first allocation.
    page: *mut u8,
    labels: Vec<String>,
}

// SAFETY: the page is process-local; access is serialized through the mutex,
// and the emitted code pages are never mutated after emission.
unsafe impl Send for PoolInner {}

static POOL: Mutex<Option<PoolInner>> = Mutex::new(None);

/// Global access handle used by the loader.
pub struct StubPoolGuard {
    _guard: std::sync::MutexGuard<'static, Option<PoolInner>>,
}

impl StubPoolGuard {
    /// Emit the next micro-stub and return its executable address.
    pub fn allocate(&mut self, label: String) -> *const u8 {
        // SAFETY: page allocation and stub emission below are bounded by
        // MAX_STUBS and the page size.
        unsafe {
            let pool = self._guard.get_or_insert_with(|| PoolInner {
                page: std::ptr::null_mut(),
                labels: Vec::new(),
            });
            assert!(pool.labels.len() < MAX_STUBS, "trap stub pool exhausted");
            if pool.page.is_null() {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert!(p != libc::MAP_FAILED, "failed to allocate trap page");
                pool.page = p.cast();
            }
            let index = pool.labels.len();
            let slot = pool.page.add(index * STUB_SIZE);
            let disp = perun_trap_dispatcher as *const u8 as u64;
            // 41 BA imm32        mov r10d, <index>      (6 bytes)
            // FF 25 00 00 00 00  jmp qword ptr [rip+0]  (6 bytes)
            // <8 bytes>          absolute dispatcher address
            let mut full: [u8; 20] = [
                0x41,
                0xBA,
                (index & 0xFF) as u8,
                ((index >> 8) & 0xFF) as u8,
                ((index >> 16) & 0xFF) as u8,
                ((index >> 24) & 0xFF) as u8,
                0xFF,
                0x25,
                0x00,
                0x00,
                0x00,
                0x00,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
            full[12..20].copy_from_slice(&disp.to_le_bytes());
            std::ptr::copy_nonoverlapping(full.as_ptr(), slot, STUB_SIZE);
            pool.labels.push(label);
            slot
        }
    }

    /// Look up a label by stub index.
    pub fn label(&self, index: usize) -> Option<&str> {
        self._guard.as_ref().and_then(|p| p.labels.get(index).map(|s| s.as_str()))
    }
}

pub(crate) fn stub_pool() -> StubPoolGuard {
    StubPoolGuard {
        _guard: POOL.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

/// Reporter invoked by the dispatcher with the guest's argument registers.
///
/// # Safety
/// Called only from the asm dispatcher with valid register snapshots.
#[no_mangle]
pub unsafe extern "win64" fn perun_trap_report(
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    index: u64,
) -> i32 {
    let label = stub_pool()
        .label(index as usize)
        .unwrap_or("<unknown>")
        .to_string();
    eprintln!(
        "[perun] TRAP: {label}({arg0:#x}, {arg1:#x}, {arg2:#x}, {arg3:#x}) — \
         no implementation. Run: cargo run -p perun-cli -- scaffold \"{label}\""
    );
    0
}

core::arch::global_asm!(
    "
    .text
    .globl perun_trap_dispatcher
    .type perun_trap_dispatcher, @function
    // Win64 convention: guest args arrive in rcx/rdx/r8/r9, our stub left the
    // import index in r10d. Forward all five to perun_trap_report and return
    // 0 to the guest.
    perun_trap_dispatcher:
        sub   rsp, 0x28
        mov   [rsp + 0x20], r10          // 5th integer argument slot
        mov   [rsp + 0x00], rcx          // shadow store (also keeps alignment)
        mov   [rsp + 0x08], rdx
        mov   [rsp + 0x10], r8
        mov   [rsp + 0x18], r9
        call  perun_trap_report
        add   rsp, 0x28
        xor   eax, eax
        ret
    "
);

extern "win64" {
    fn perun_trap_dispatcher() -> i32;
}
