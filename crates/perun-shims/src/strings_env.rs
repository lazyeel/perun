// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! String, environment, module and console shims.

use crate::files::{file_of, WriteFile};
use crate::win32_api;
use crate::util::*;
use crate::util::set_last_error;
use crate::win32::*;

// ── UTF conversion ───────────────────────────────────────────────────────

fn utf16_to_utf8(src: &[u16], dst: *mut u8, cap: usize) -> usize {
    let owned = String::from_utf16_lossy(src);
    let bytes = owned.as_bytes();
    if dst.is_null() {
        return bytes.len() + 1; // include NUL in the requirement
    }
    if bytes.len() + 1 > cap {
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        *dst.add(bytes.len()) = 0;
    }
    bytes.len() + 1
}


win32_api! {
    /// int MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
    unsafe extern "win64" fn MultiByteToWideChar(
        codepage: UINT,
        flags: DWORD,
        src: LPCSTR,
        src_len: i32,
        dst: LPWSTR,
        dst_len: i32,
    ) -> i32 {
        let _ = (codepage & 0xFFFF, flags);
        let bytes = if src_len < 0 {
            read_narrow(src)
        } else {
            std::slice::from_raw_parts(src, src_len as usize).to_vec()
        };
        let s = String::from_utf8_lossy(&bytes);
        let wide = wide_from_str(&s);
        let need = wide.len() + 1;
        if dst.is_null() || dst_len == 0 {
            return need as i32;
        }
        let cap = dst_len as usize;
        if need > cap {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        *dst.add(wide.len()) = 0;
        need as i32
    }
}

win32_api! {
    /// int WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, ...);
    unsafe extern "win64" fn WideCharToMultiByte(
        codepage: UINT,
        flags: DWORD,
        src: LPCWSTR,
        src_len: i32,
        dst: LPSTR,
        dst_len: i32,
        default_char: *const u8,
        used_default: *mut BOOL,
    ) -> i32 {
        let _ = (codepage, flags, default_char);
        let wide = if src_len < 0 {
            read_wide(src)
        } else {
            std::slice::from_raw_parts(src, src_len as usize).to_vec()
        };
        if !used_default.is_null() {
            *used_default = FALSE;
        }
        let s = String::from_utf16_lossy(&wide);
        let bytes = s.as_bytes();
        let need = bytes.len() + 1;
        if dst.is_null() || dst_len == 0 {
            return need as i32;
        }
        if need > dst_len as usize {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        *dst.add(bytes.len()) = 0;
        need as i32
    }
}

// Case mapping is ASCII-only by design: locale tables are out of scope for a
// micro-runtime, and the target guests compare file names/keys case-wise.
fn map_string_w(src: &[u16], upper: bool) -> Vec<u16> {
    let s = String::from_utf16_lossy(src);
    let mapped = if upper { s.to_uppercase() } else { s.to_lowercase() };
    wide_from_str(&mapped)
}

win32_api! {
    /// int LCMapStringW(DWORD, DWORD, LPCWSTR, int, LPWSTR, int);
    unsafe extern "win64" fn LCMapStringW(
        locale: DWORD,
        map_flags: DWORD,
        src: LPCWSTR,
        src_len: i32,
        dst: LPWSTR,
        dst_len: i32,
    ) -> i32 {
        const LCMAP_UPPERCASE: DWORD = 0x0000_0200;
        const LCMAP_LOWERCASE: DWORD = 0x0000_0100;
        let _ = locale;
        let wide = if src_len < 0 {
            read_wide(src)
        } else {
            std::slice::from_raw_parts(src, src_len as usize).to_vec()
        };
        let mapped = if map_flags & LCMAP_UPPERCASE != 0 {
            map_string_w(&wide, true)
        } else if map_flags & LCMAP_LOWERCASE != 0 {
            map_string_w(&wide, false)
        } else {
            wide
        };
        let need = mapped.len() + 1;
        if dst.is_null() || dst_len == 0 {
            return need as i32;
        }
        if need > dst_len as usize {
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        std::ptr::copy_nonoverlapping(mapped.as_ptr(), dst, mapped.len());
        *dst.add(mapped.len()) = 0;
        need as i32
    }
}

win32_api! {
    /// int CompareStringW(DWORD, DWORD, PCNZWCH, int, PCNZWCH, int);
    unsafe extern "win64" fn CompareStringW(
        locale: DWORD,
        flags: DWORD,
        s1: LPCWSTR,
        l1: i32,
        s2: LPCWSTR,
        l2: i32,
    ) -> i32 {
        const CSTR_LESS_THAN: i32 = 1;
        const CSTR_EQUAL: i32 = 2;
        const CSTR_GREATER_THAN: i32 = 3;
        const NORM_IGNORECASE: DWORD = 0x0000_0001;
        let _ = (locale, NORM_IGNORECASE);
        let a = if l1 < 0 { read_wide(s1) } else { std::slice::from_raw_parts(s1, l1 as usize).to_vec() };
        let b = if l2 < 0 { read_wide(s2) } else { std::slice::from_raw_parts(s2, l2 as usize).to_vec() };
        match a.cmp(&b) {
            std::cmp::Ordering::Less => CSTR_LESS_THAN,
            std::cmp::Ordering::Equal => CSTR_EQUAL,
            std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
        }
    }
}

win32_api! {
    /// BOOL GetStringTypeW(DWORD, LPCWSTR, int, LPWORD);
    unsafe extern "win64" fn GetStringTypeW(
        type_flag: DWORD,
        src: LPCWSTR,
        len: i32,
        out: *mut WORD,
    ) -> BOOL {
        const CT_CTYPE1: DWORD = 1;
        let _ = CT_CTYPE1;
        let wide = if len < 0 { read_wide(src) } else { std::slice::from_raw_parts(src, len as usize).to_vec() };
        if out.is_null() && !wide.is_empty() {
            return FALSE;
        }
        for (i, ch) in wide.iter().enumerate() {
            let c = *ch as u32;
            let ascii = c < 0x80;
            let cls: WORD = if ascii && (c as u8).is_ascii_alphabetic() {
                0x0001 | 0x0100 // C1_ALPHA | C1_UPPER approximated
            } else if ascii && (c as u8).is_ascii_digit() {
                0x0004
            } else if ascii && (c as u8).is_ascii_whitespace() {
                0x0010
            } else {
                0
            };
            *out.add(i) = cls;
        }
        TRUE
    }
}

// ── Environment / command line ───────────────────────────────────────────

static COMMAND_LINE: &[u8] = b"perun\0";

win32_api! {
    /// LPCSTR GetCommandLineA(VOID);
    unsafe extern "win64" fn GetCommandLineA() -> LPCSTR {
        COMMAND_LINE.as_ptr()
    }
}

win32_api! {
    /// LPCWSTR GetCommandLineW(VOID);
    unsafe extern "win64" fn GetCommandLineW() -> LPCWSTR {
        static WIDE: [u16; 6] = [
            b'p' as u16, b'e' as u16, b'r' as u16, b'u' as u16, b'n' as u16, 0,
        ];
        WIDE.as_ptr()
    }
}

win32_api! {
    /// LPCWSTR GetEnvironmentStringsW(VOID);
    unsafe extern "win64" fn GetEnvironmentStringsW() -> LPCWSTR {
        // Build a double-NUL-terminated block of NAME=VALUE\0 pairs.
        let mut block: Vec<u16> = Vec::new();
        for (k, v) in std::env::vars_os() {
            let line = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
            block.extend(line.encode_utf16());
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        // Leak: Windows frees this with FreeEnvironmentStringsW, which is our
        // no-op; the CRT calls it once per process.
        let p = libc::malloc(block.len() * 2) as *mut u16;
        std::ptr::copy_nonoverlapping(block.as_ptr(), p, block.len());
        p as LPCWSTR
    }
}

win32_api! {
    /// BOOL FreeEnvironmentStringsW(LPCWSTR);
    unsafe extern "win64" fn FreeEnvironmentStringsW(_block: LPCWSTR) -> BOOL {
        // Intentionally not freed (see GetEnvironmentStringsW).
        TRUE
    }
}

win32_api! {
    /// BOOL SetEnvironmentVariableA(LPCSTR, LPCSTR);
    unsafe extern "win64" fn SetEnvironmentVariableA(name: LPCSTR, value: LPCSTR) -> BOOL {
        let n = String::from_utf8_lossy(&read_narrow(name)).into_owned();
        if value.is_null() {
            std::env::remove_var(&n);
        } else {
            let v = String::from_utf8_lossy(&read_narrow(value)).into_owned();
            std::env::set_var(&n, v);
        }
        TRUE
    }
}

// ── Modules ──────────────────────────────────────────────────────────────

win32_api! {
    /// HMODULE GetModuleHandleW(LPCWSTR);
    unsafe extern "win64" fn GetModuleHandleW(_name: LPCWSTR) -> HANDLE {
        // The main image handle. Guests use it with GetProcAddress to find
        // their own exports.
        0x0000_5AFE_0000_0001usize as HANDLE
    }
}

win32_api! {
    /// BOOL GetModuleHandleExW(DWORD, LPCWSTR, HMODULE*);
    unsafe extern "win64" fn GetModuleHandleExW(
        flags: DWORD,
        name: LPCWSTR,
        result: *mut HANDLE,
    ) -> BOOL {
        let _ = flags;
        if !result.is_null() {
            *result = GetModuleHandleW(name);
        }
        TRUE
    }
}

win32_api! {
    /// HANDLE LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
    unsafe extern "win64" fn LoadLibraryExW(
        name: LPCWSTR,
        _file: HANDLE,
        _flags: DWORD,
    ) -> HANDLE {
        // Phase 1: dependent DLL loading is not implemented; report the main
        // module so init proceeds, traps will surface anything actually used.
        eprintln!(
            "[perun] LoadLibraryExW({:?}) — static phase: returning main-module token",
            String::from_utf16_lossy(&read_wide(name))
        );
        GetModuleHandleW(std::ptr::null())
    }
}

win32_api! {
    /// FARPROC GetProcAddress(HMODULE, LPCSTR);
    unsafe extern "win64" fn GetProcAddress(module: HANDLE, name: LPCSTR) -> *mut core::ffi::c_void {
        let n = read_narrow(name);
        let n = String::from_utf8_lossy(&n);
        // 1. Explicitly registered runtime exports (per-module overrides).
        if let Some(p) = crate::runtime_state::lookup_export(module as usize, &n) {
            return p;
        }
        // 2. Api-set DLLs (api-ms-win-*) are forwarders: the functions they
        //    "export" are ordinary Win32 APIs we already shim. Fall back to
        //    the shim table so CRT dynamic resolution keeps working.
        if let Some(p) = crate::table::ShimTable::collect().get(&n) {
            if std::env::var("PERUN_TRACE").is_ok() {
                eprintln!("[perun] GetProcAddress({:?}) -> shim", n);
            }
            return p as *mut core::ffi::c_void;
        }
        eprintln!("[perun] GetProcAddress({:?}) -> NULL (not implemented)", n);
        std::ptr::null_mut()
    }
}

win32_api! {
    /// BOOL FreeLibrary(HMODULE);
    unsafe extern "win64" fn FreeLibrary(h: HANDLE) -> BOOL {
        let _ = h;
        TRUE
    }
}

win32_api! {
    /// DWORD GetModuleFileNameA(HMODULE, LPSTR, DWORD);
    unsafe extern "win64" fn GetModuleFileNameA(
        _module: HANDLE,
        buf: LPSTR,
        cap: DWORD,
    ) -> DWORD {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "perun".into());
        let bytes = exe.as_bytes();
        let need = bytes.len() + 1;
        if cap as usize >= need {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
            *buf.add(bytes.len()) = 0;
            return bytes.len() as DWORD;
        }
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        0
    }
}

// ── Error / console ──────────────────────────────────────────────────────

win32_api! {
    /// void SetLastError(DWORD);
    unsafe extern "win64" fn SetLastError(code: DWORD) {
        set_last_error(code);
    }
}

win32_api! {
    /// DWORD GetLastError(VOID);
    unsafe extern "win64" fn GetLastError() -> DWORD {
        get_last_error()
    }
}

win32_api! {
    /// BOOL GetConsoleMode(HANDLE, LPDWORD);
    unsafe extern "win64" fn GetConsoleMode(h: HANDLE, mode: *mut DWORD) -> BOOL {
        match file_of(h) {
            Some((fd, shared)) => {
                if !shared && libc::isatty(fd) != 1 {
                    return FALSE; // not a console
                }
                if !mode.is_null() {
                    // ENABLE_PROCESSED_OUTPUT | ENABLE_LINE_INPUT-ish defaults.
                    *mode = 0x0003;
                }
                TRUE
            }
            None => FALSE,
        }
    }
}

win32_api! {
    /// DWORD GetConsoleCP(VOID);
    unsafe extern "win64" fn GetConsoleCP() -> DWORD {
        65001 // UTF-8 — honest for Linux
    }
}

win32_api! {
    /// BOOL WriteConsoleW(HANDLE, PCWCH, DWORD, LPDWORD, LPVOID);
    unsafe extern "win64" fn WriteConsoleW(
        h: HANDLE,
        text: LPCWSTR,
        chars: DWORD,
        written: *mut DWORD,
        _reserved: *mut core::ffi::c_void,
    ) -> BOOL {
        let wide = std::slice::from_raw_parts(text, chars as usize);
        let s = String::from_utf16_lossy(wide);
        let bytes = s.as_bytes();
        WriteFile(
            h,
            bytes.as_ptr() as LPCVOID,
            bytes.len() as DWORD,
            written,
            std::ptr::null_mut(),
        )
    }
}
