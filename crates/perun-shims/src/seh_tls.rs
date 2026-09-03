// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! SEH surface, TLS and misc: minimal detect-and-report implementations by
//! design (see ROADMAP "explicitly out of scope" for the unwinder).

use crate::util::*;
use crate::win32::*;
use crate::win32_api;

// ── SEH surface (detect/report only) ─────────────────────────────────────

win32_api! {
    /// void RaiseException(DWORD, DWORD, DWORD, CONST ULONG_PTR*);
    unsafe extern "win64" fn RaiseException(
        code: DWORD,
        flags: DWORD,
        nargs: DWORD,
        args: *const usize,
    ) {
        let mut a = [0usize; 4];
        if !args.is_null() && nargs > 0 {
            for (i, slot) in a.iter_mut().enumerate().take(nargs.min(4) as usize) {
                *slot = *args.add(i);
            }
        }
        eprintln!(
            "[perun] guest raised exception code={code:#010x} flags={flags:#x} args={a:x?}"
        );
        // No unwinding: phase-1 guests must not raise in normal flow. If one
        // does, execution continues here — the caller sees a normal return.
    }
}

win32_api! {
    /// LONG UnhandledExceptionFilter(LPEXCEPTION_POINTERS);
    unsafe extern "win64" fn UnhandledExceptionFilter(_ptrs: *mut core::ffi::c_void) -> LONG {
        eprintln!("[perun] unhandled exception filter invoked");
        0 // EXCEPTION_CONTINUE_SEARCH
    }
}

win32_api! {
    /// LONG SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);
    unsafe extern "win64" fn SetUnhandledExceptionFilter(
        filter: *const core::ffi::c_void,
    ) -> *const core::ffi::c_void {
        // Accept and remember; we never invoke it without a real exception
        // path (phase 1 has none).
        static PREV: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        PREV.store(filter as usize, std::sync::atomic::Ordering::Relaxed);
        filter
    }
}

win32_api! {
    /// void RtlCaptureContext(PCONTEXT);
    unsafe extern "win64" fn RtlCaptureContext(ctx: *mut core::ffi::c_void) {
        // Zero the CONTEXT blob (1232 bytes on x64): callers only need it to
        // be valid-shaped before they poke specific fields.
        std::ptr::write_bytes(ctx as *mut u8, 0, 1232);
    }
}

win32_api! {
    /// PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
    unsafe extern "win64" fn RtlLookupFunctionEntry(
        control_pc: u64,
        image_base: *mut u64,
        _table: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void {
        // Report "not found" (null) with base 0: callers treat this as leaf
        // function and stop walking — exactly what our no-unwind policy wants.
        if !image_base.is_null() {
            *image_base = 0;
        }
        std::ptr::null_mut()
    }
}

win32_api! {
    /// BOOLEAN RtlVirtualUnwind(...);
    unsafe extern "win64" fn RtlVirtualUnwind(
        _handler_type: DWORD,
        _image_base: u64,
        _control_pc: u64,
        _entry: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
        _data: *mut *mut core::ffi::c_void,
        _frame: *mut u64,
        _ctx_ptr: *mut core::ffi::c_void,
    ) -> i32 {
        0 // FALSE: no handler
    }
}

win32_api! {
    /// void RtlUnwindEx(...);
    #[allow(clippy::too_many_arguments)]
    unsafe extern "win64" fn RtlUnwindEx(
        target_frame: *mut core::ffi::c_void,
        target_ip: *mut core::ffi::c_void,
        _exception_record: *mut core::ffi::c_void,
        retval: *mut core::ffi::c_void,
        _original_context: *mut core::ffi::c_void,
        _history_table: *mut core::ffi::c_void,
    ) {
        eprintln!(
            "[perun] RtlUnwindEx(target_frame={target_frame:?}, ip={target_ip:?}) — unwind not implemented; returning"
        );
        let _ = retval;
    }
}

// ── SList primitives ─────────────────────────────────────────────────────

win32_api! {
    /// void InitializeSListHead(PSLIST_HEADER);
    unsafe extern "win64" fn InitializeSListHead(head: *mut core::ffi::c_void) {
        // SLIST_HEADER is 16 bytes on x64.
        std::ptr::write_bytes(head as *mut u8, 0, 16);
    }
}

win32_api! {
    /// PSLIST_ENTRY InterlockedFlushSList(PSLIST_HEADER);
    unsafe extern "win64" fn InterlockedFlushSList(head: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        let first = head as *mut std::sync::atomic::AtomicUsize;
        let old = (*first).swap(0, std::sync::atomic::Ordering::AcqRel);
        // Second quad holds depth/sequence; reset both halves honestly.
        *(head as *mut usize).add(1) = 0;
        old as *mut core::ffi::c_void
    }
}

// ── TLS ──────────────────────────────────────────────────────────────────

static TLS_BITMAP: std::sync::Mutex<u32> = std::sync::Mutex::new(0);
thread_local! {
    static TLS_SLOTS: std::cell::RefCell<Vec<usize>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn tls_alloc() -> DWORD {
    let mut b = TLS_BITMAP.lock().unwrap();
    for bit in 0..64u32 {
        if *b & (1 << bit) == 0 {
            *b |= 1 << bit;
            return bit;
        }
    }
    TLS_OUT_OF_INDEXES
}

win32_api! {
    /// DWORD TlsAlloc(VOID);
    unsafe extern "win64" fn TlsAlloc() -> DWORD {
        let idx = tls_alloc();
        if idx != TLS_OUT_OF_INDEXES {
            TLS_SLOTS.with(|s| {
                let mut s = s.borrow_mut();
                while s.len() <= idx as usize {
                    s.push(0);
                }
                s[idx as usize] = 0;
            });
        }
        idx
    }
}

win32_api! {
    /// LPVOID TlsGetValue(DWORD);
    unsafe extern "win64" fn TlsGetValue(index: DWORD) -> LPVOID {
        TLS_SLOTS.with(|s| {
            s.borrow()
                .get(index as usize)
                .copied()
                .unwrap_or(0)
        }) as LPVOID
    }
}

win32_api! {
    /// BOOL TlsSetValue(DWORD, LPVOID);
    unsafe extern "win64" fn TlsSetValue(index: DWORD, value: LPVOID) -> BOOL {
        let ok = index < 64;
        if ok {
            TLS_SLOTS.with(|s| {
                let mut s = s.borrow_mut();
                while s.len() <= index as usize {
                    s.push(0);
                }
                s[index as usize] = value as usize;
            });
        }
        if ok {
            TRUE
        } else {
            FALSE
        }
    }
}

win32_api! {
    /// BOOL TlsFree(DWORD);
    unsafe extern "win64" fn TlsFree(index: DWORD) -> BOOL {
        let mut b = TLS_BITMAP.lock().unwrap();
        if index >= 64 || *b & (1 << index) == 0 {
            return FALSE;
        }
        *b &= !(1u32 << index);
        TRUE
    }
}

// ── Process-level odds and ends ──────────────────────────────────────────

win32_api! {
    /// BOOL GetUserNameA(LPSTR, LPDWORD);
    unsafe extern "win64" fn GetUserNameA(buf: LPSTR, size: *mut DWORD) -> BOOL {
        let user = std::env::var("USER").unwrap_or_else(|_| "perun".into());
        let bytes = user.as_bytes();
        let need = bytes.len() + 1;
        let cap = if size.is_null() { 0 } else { *size as usize };
        if !size.is_null() {
            *size = need as DWORD;
        }
        if cap < need || buf.is_null() {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        *buf.add(bytes.len()) = 0;
        TRUE
    }
}

win32_api! {
    /// void ExitProcess(UINT);
    unsafe extern "win64" fn ExitProcess(code: UINT) {
        eprintln!("[perun] ExitProcess({code})");
        libc::_exit(code as i32);
    }
}

win32_api! {
    /// BOOL TerminateProcess(HANDLE, UINT);
    unsafe extern "win64" fn TerminateProcess(h: HANDLE, code: UINT) -> BOOL {
        let _ = h;
        eprintln!("[perun] TerminateProcess({code})");
        libc::_exit(code as i32);
    }
}

// ── FLS (Fiber Local Storage) ────────────────────────────────────────────
// MSVC CRT uses FLS for thread-local bookkeeping. We back it with the
// FakeTEB inline TLS slot array; a global bitmap tracks allocated indices.

const FLS_OUT_OF_INDEXES: DWORD = 0xFFFF_FFFF;

static FLS_BITMAP: std::sync::Mutex<u64> = std::sync::Mutex::new(0);

win32_api! {
    /// DWORD FlsAlloc(PFLS_CALLBACK_FUNCTION);
    unsafe extern "win64" fn FlsAlloc(_callback: *mut core::ffi::c_void) -> DWORD {
        let mut bm = FLS_BITMAP.lock().unwrap();
        let free = (!*bm).trailing_zeros();
        if free >= perun_core::teb::TLS_SLOT_COUNT as u32 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FLS_OUT_OF_INDEXES;
        }
        *bm |= 1u64 << free;
        free
    }
}

win32_api! {
    /// BOOL FlsSetValue(DWORD, PVOID);
    unsafe extern "win64" fn FlsSetValue(index: DWORD, data: *mut core::ffi::c_void) -> BOOL {
        let p = perun_core::teb::get_tls_slot_ptr(index as usize);
        if p.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *p = data as u64;
        TRUE
    }
}

win32_api! {
    /// PVOID FlsGetValue(DWORD);
    unsafe extern "win64" fn FlsGetValue(index: DWORD) -> *mut core::ffi::c_void {
        let p = perun_core::teb::get_tls_slot_ptr(index as usize);
        if p.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return std::ptr::null_mut();
        }
        *p as *mut core::ffi::c_void
    }
}

win32_api! {
    /// BOOL FlsFree(DWORD);
    unsafe extern "win64" fn FlsFree(index: DWORD) -> BOOL {
        let mut bm = FLS_BITMAP.lock().unwrap();
        if index >= perun_core::teb::TLS_SLOT_COUNT as u32 || *bm & (1u64 << index) == 0 {
            return FALSE;
        }
        *bm &= !(1u64 << index);
        TRUE
    }
}

win32_api! {
    /// BOOL InitializeCriticalSectionEx(PCRITICAL_SECTION, DWORD, DWORD);
    unsafe extern "win64" fn InitializeCriticalSectionEx(
        cs: *mut core::ffi::c_void,
        spin: DWORD,
        _flags: DWORD,
    ) -> BOOL {
        crate::sync::InitializeCriticalSectionAndSpinCount(cs, spin)
    }
}
