// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Memory management shims: heap + virtual memory over POSIX.

use crate::win32_api;
use crate::util;
use crate::util::set_last_error;
use crate::win32::*;

win32_api! {
    /// HANDLE GetProcessHeap(VOID);
    unsafe extern "win64" fn GetProcessHeap() -> HANDLE {
        1 as HANDLE
    }
}

win32_api! {
    /// LPVOID HeapAlloc(HANDLE, DWORD, SIZE_T);
    unsafe extern "win64" fn HeapAlloc(heap: HANDLE, flags: DWORD, size: SIZE_T) -> LPVOID {
        let _ = heap;
        // calloc gives zeroing for free; HEAP_ZERO_MEMORY (0x8) wants zeros.
        let ptr = if flags & HEAP_ZERO_MEMORY != 0 {
            libc::calloc(size, 1)
        } else {
            libc::malloc(size)
        };
        // Research hooks (off unless enabled):
        //   PERUN_HEAP_TRACE=1              -> log size/flags/result
        //   PERUN_HEAP_FILL=<size>:<qword>  -> write <qword> at offset 0 of
        //                                      every allocation of <size>
        if let Ok(v) = std::env::var("PERUN_HEAP_TRACE") {
            if v == "1" {
                eprintln!("[perun] HeapAlloc size={size:#x} flags={flags:#x} -> {ptr:?}");
            }
        }
        if let Ok(spec) = std::env::var("PERUN_HEAP_FILL") {
            if let Some((sz, val)) = spec.split_once(':') {
                let sz_hex = sz.trim().trim_start_matches("0x");
                let sz: usize =
                    usize::from_str_radix(sz_hex, 16).unwrap_or_else(|_| sz.trim().parse().unwrap_or(0));
                let val: u64 = u64::from_str_radix(
                    val.trim().trim_start_matches("0x"),
                    16,
                )
                .or_else(|_| val.trim().parse())
                .unwrap_or(0);
                if size as usize == sz && !ptr.is_null() {
                    std::ptr::write_volatile(ptr as *mut u64, val);
                    // Late-fill support: remember this allocation so a later shim
                    // (SHGetFolderPathW) can re-write the value AFTER the guest's own
                    // zero-init ran. See shell_path.rs / PERUN_GATE_POKE.
                    crate::util::track_gate_candidate(ptr as u64);
                }
            }
        }
        ptr as LPVOID
    }
}

win32_api! {
    /// SIZE_T HeapSize(HANDLE, DWORD, LPCVOID);
    unsafe extern "win64" fn HeapSize(heap: HANDLE, flags: DWORD, ptr: LPCVOID) -> SIZE_T {
        let _ = (heap, flags);
        // glibc malloc_size equivalents are not portable; the validated
        // prototype returned a small constant and its guest tolerated it.
        let _ = ptr;
        16
    }
}

win32_api! {
    /// LPVOID HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
    unsafe extern "win64" fn HeapReAlloc(
        heap: HANDLE,
        flags: DWORD,
        ptr: LPVOID,
        size: SIZE_T,
    ) -> LPVOID {
        let _ = (heap, flags);
        libc::realloc(ptr, size) as LPVOID
    }
}

win32_api! {
    /// BOOL HeapFree(HANDLE, DWORD, LPVOID);
    unsafe extern "win64" fn HeapFree(heap: HANDLE, flags: DWORD, ptr: LPVOID) -> BOOL {
        let _ = (heap, flags);
        libc::free(ptr);
        TRUE
    }
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
    ) -> LPVOID {
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
    }
}

win32_api! {
    /// BOOL VirtualFree(LPVOID, SIZE_T, DWORD);
    unsafe extern "win64" fn VirtualFree(addr: LPVOID, size: SIZE_T, free_type: DWORD) -> BOOL {
        // MEM_RELEASE ignores the size on Windows; we must supply one for
        // munmap. Track nothing: unmap one page granularity chunk at minimum.
        const MEM_RELEASE: u32 = 0x8000;
        let _ = free_type;
        let len = if size == 0 { 0x1000 } else { round_up_page(size) };
        (libc::munmap(addr, len) == 0)
            .then_some(TRUE)
            .unwrap_or(FALSE)
    }
}

win32_api! {
    /// BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
    unsafe extern "win64" fn VirtualProtect(
        addr: LPVOID,
        size: SIZE_T,
        new_protect: DWORD,
        old_protect: *mut DWORD,
    ) -> BOOL {
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
    }
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
        assert_eq!(win_prot_to_posix(0xDEAD), libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
    }

    #[test]
    fn page_rounding() {
        assert_eq!(round_up_page(1), 0x1000);
        assert_eq!(round_up_page(0x1000), 0x1000);
        assert_eq!(round_up_page(0x1001), 0x2000);
    }
}
