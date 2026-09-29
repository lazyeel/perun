// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Memory management shims: heap + virtual memory over POSIX.

use crate::util::set_last_error;
use crate::win32::{
    BOOL, DWORD, ERROR_INVALID_PARAMETER, FALSE, HANDLE, HEAP_ZERO_MEMORY, LPCVOID, LPVOID,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, SIZE_T, TRUE,
};
use crate::win32_api;

win32_api! {
    /// HANDLE GetProcessHeap(VOID);
    unsafe extern "win64" fn GetProcessHeap() -> HANDLE {
        1 as HANDLE
    }
}

win32_api! {
    /// LPVOID HeapAlloc(HANDLE, DWORD, SIZE_T);
    unsafe extern "win64" fn HeapAlloc(heap: HANDLE, flags: DWORD, size: SIZE_T) -> LPVOID { unsafe {
        let _ = heap;
        // calloc gives zeroing for free; HEAP_ZERO_MEMORY (0x8) wants zeros.
        let ptr = if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(size, 1)
        } else {
            libc::malloc(size)
        };
        // The memory shims are not covered by the other traced shims, so a
        // run could not previously say whether a block came from here at all.
        // That mattered: the gate object is installed by a `lock cmpxchg` from
        // a block this library allocated itself, and nothing below the
        // allocator said how big it was or who asked for it.
        if std::env::var_os("PERUN_TRACE").is_some() {
            let m = format!(
                "[perun] HeapAlloc(flags={flags:#x}, size={size:#x}) = {:p}\n",
                ptr
            );
            libc::write(2, m.as_ptr().cast(), m.len());
        }
        // PERUN_HEAP_TRAP=<size> was tried here and is deliberately absent.
        // The idea was to raise a trap on that one allocation so a debugger
        // could arm write watchpoints on the block before the guest filled
        // it, which is the only moment the address is known. It does not work
        // and it is recorded rather than left in place: the pointer cannot be
        // carried across the trap in a register, because the compiler clobbers
        // rax setting up the call to raise() itself, and a trap that reports
        // rax = 0 looks exactly like an allocator that returned nothing.
        // A facility that silently reports the wrong thing is worse than no
        // facility, which is why the heap handle and the cmpxchg are
        // established by correlation in a run instead: both of those readings
        // come from values that are actually true when they are taken.

        // PERUN_GATE_SEED=<field>:<value> seeds the provisioning state object.
        // The operation export allocates a 0x28-byte block and then zeroes its
        // own first qword, which is the gate flag -- so a seed on field 0 is
        // erased before the check. Seed any of the seven other qwords instead.
        if let Ok(spec) = std::env::var("PERUN_GATE_SEED")
            && size == 0x28
            && let Some((f, v)) = spec.split_once(':')
            && let (Ok(fi), Ok(val)) = (f.parse::<usize>(), v.parse::<u64>())
            && fi < 4
        {
            (ptr as *mut u64).add(fi + 1).write_volatile(val);
        }
        ptr as LPVOID
    }}
}

win32_api! {
    /// SIZE_T HeapSize(HANDLE, DWORD, LPCVOID);
    unsafe extern "win64" fn HeapSize(heap: HANDLE, flags: DWORD, ptr: LPCVOID) -> SIZE_T {
        let _ = (heap, flags);
        if ptr.is_null() {
            // Win32 reports failure as (SIZE_T)-1 with ERROR_INVALID_PARAMETER
            // set, and a guest that checks the error and ignores the size will
            // survive a constant here, which a wrong-but-plausible size would not.
            set_last_error(ERROR_INVALID_PARAMETER);
            return !0;
        }
        // The honest size. This used to return the constant 16 on the grounds
        // that "its guest tolerated it", and that is precisely the kind of
        // measurement that means nothing: nothing had established how often it
        // was called, and PERUN_TRACE does not cover the memory shims, so a
        // call count was never available. glibc's allocator is what HeapAlloc
        // and HeapReAlloc hand back, so its own usable-size is the same answer
        // the real API would give for these blocks.
        let n = libc::malloc_usable_size(ptr as *mut libc::c_void) as SIZE_T;
        if std::env::var_os("PERUN_TRACE").is_some() {
            let m = format!("[perun] HeapSize({ptr:p}) = {n}\n");
            libc::write(2, m.as_ptr().cast(), m.len());
        }
        n
    }
}

win32_api! {
    /// LPVOID HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
    unsafe extern "win64" fn HeapReAlloc(
        heap: HANDLE,
        flags: DWORD,
        ptr: LPVOID,
        size: SIZE_T,
    ) -> LPVOID { unsafe {
        let _ = (heap, flags);
        libc::realloc(ptr, size) as LPVOID
    }}
}

win32_api! {
    /// BOOL HeapFree(HANDLE, DWORD, LPVOID);
    unsafe extern "win64" fn HeapFree(heap: HANDLE, flags: DWORD, ptr: LPVOID) -> BOOL { unsafe {
        let _ = (heap, flags);
        libc::free(ptr);
        TRUE
    }}
}

fn win_prot_to_posix(protect: DWORD) -> i32 {
    match protect {
        PAGE_NOACCESS => libc::PROT_NONE,
        PAGE_READONLY => libc::PROT_READ,
        PAGE_READWRITE | PAGE_WRITECOPY => libc::PROT_READ | libc::PROT_WRITE,
        PAGE_EXECUTE_READ => libc::PROT_READ | libc::PROT_EXEC,
        PAGE_EXECUTE_READWRITE => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        // Unknown → RWX so the guest never dies on our guess.
        _ => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    }
}

pub(crate) fn round_up_page(v: SIZE_T) -> SIZE_T {
    (v + 0xFFF) & !0xFFF
}

win32_api! {
    /// LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
    unsafe extern "win64" fn VirtualAlloc(
        addr: LPVOID,
        size: SIZE_T,
        alloc_type: DWORD,
        protect: DWORD,
    ) -> LPVOID { unsafe {
        if size == 0 {
            return core::ptr::null_mut();
        }
        let len = round_up_page(size);
        let prot = win_prot_to_posix(protect);

        // MEM_COMMIT without MEM_RESERVE on a non-null address: the Windows
        // semantic is "commit within an existing reservation"; phase-1 maps
        // fresh anonymous memory at the hint.
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        let committing_only = alloc_type & MEM_COMMIT != 0 && alloc_type & MEM_RESERVE == 0;

        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let p = libc::mmap(addr, len, prot, flags, -1, 0);
        if p == libc::MAP_FAILED {
            return core::ptr::null_mut();
        }
        if committing_only && !addr.is_null() && p != addr {
            // Could not honor the requested address; still usable memory.
            set_last_error(ERROR_INVALID_PARAMETER);
        }
        p
    }}
}

win32_api! {
    /// BOOL VirtualFree(LPVOID, SIZE_T, DWORD);
    unsafe extern "win64" fn VirtualFree(addr: LPVOID, size: SIZE_T, free_type: DWORD) -> BOOL { unsafe {
        // MEM_RELEASE ignores the size on Windows; we must supply one for
        // munmap. Track nothing: unmap one page granularity chunk at minimum.
        const MEM_RELEASE: u32 = 0x8000;
        let _ = free_type;
        let len = if size == 0 { 0x1000 } else { round_up_page(size) };
        if libc::munmap(addr, len) == 0 {
            TRUE
        } else {
            FALSE
        }
    }}
}

win32_api! {
    /// BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
    unsafe extern "win64" fn VirtualProtect(
        addr: LPVOID,
        size: SIZE_T,
        new_protect: DWORD,
        old_protect: *mut DWORD,
    ) -> BOOL { unsafe {
        if old_protect.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        let page_base = ((addr as usize) & !0xFFF) as LPVOID;
        let len = round_up_page((addr as usize - page_base as usize) + size);
        if libc::mprotect(page_base, len, win_prot_to_posix(new_protect)) == 0 {
            *old_protect = PAGE_READWRITE; // honest-ish default
            TRUE
        } else {
            FALSE
        }
    }}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prot_mapping() {
        assert_eq!(win_prot_to_posix(PAGE_READONLY), libc::PROT_READ);
        assert_eq!(
            win_prot_to_posix(PAGE_EXECUTE_READWRITE),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
        assert_eq!(
            win_prot_to_posix(0xDEAD),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }

    #[test]
    fn page_rounding() {
        assert_eq!(round_up_page(1), 0x1000);
        assert_eq!(round_up_page(0x1000), 0x1000);
        assert_eq!(round_up_page(0x1001), 0x2000);
    }
}
