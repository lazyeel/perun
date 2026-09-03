// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Shell and path shims: folder locations (CSIDL) and SHLWAPI path helpers.
//!
//! Windows folder locations are mapped under a perun-owned root so guest
//! writes land in a stable, inspectable place:
//!
//! ```text
//! $PERUN_APPDATA (default $HOME/.perun/appdata)
//!   ├── Roaming/   CSIDL_APPDATA        (0x001a)
//!   ├── Local/     CSIDL_LOCAL_APPDATA  (0x001c)
//!   └── Common/    CSIDL_COMMON_APPDATA (0x0023)
//! ```

use crate::win32::*;
use crate::win32_api;

const MAX_PATH: usize = 260;
const S_OK: i32 = 0;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;

const CSIDL_APPDATA: u32 = 0x001a;
const CSIDL_LOCAL_APPDATA: u32 = 0x001c;
const CSIDL_COMMON_APPDATA: u32 = 0x0023;
const CSIDL_FLAG_CREATE: u32 = 0x8000;
const CSIDL_MASK: u32 = 0x00FF;

/// Root directory for all mapped Windows folders.
fn appdata_root() -> std::path::PathBuf {
    match std::env::var("PERUN_APPDATA") {
        Ok(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            std::path::PathBuf::from(home)
                .join(".perun")
                .join("appdata")
        }
    }
}

/// Map a CSIDL to a subdirectory name, if known.
fn csidl_subdir(csidl: u32) -> Option<&'static str> {
    match csidl & CSIDL_MASK {
        CSIDL_APPDATA => Some("Roaming"),
        CSIDL_LOCAL_APPDATA => Some("Local"),
        CSIDL_COMMON_APPDATA => Some("Common"),
        _ => None,
    }
}

fn mkdirs(path: &std::path::Path) {
    let _ = std::fs::create_dir_all(path);
}

/// Write a Rust string into a Win32 LPWSTR buffer (MAX_PATH wchars).
fn write_wide(dst: LPWSTR, s: &str) {
    if dst.is_null() {
        return;
    }
    let wide: Vec<u16> = s.encode_utf16().collect();
    let n = wide.len().min(MAX_PATH - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, n);
        *dst.add(n) = 0;
    }
}

win32_api! {
    /// HRESULT SHGetFolderPathW(HWND, int csidl, HANDLE, DWORD, LPWSTR);
    unsafe extern "win64" fn SHGetFolderPathW(
        _hwnd: HANDLE,
        csidl: i32,
        _token: HANDLE,
        _flags: DWORD,
        out_path: LPWSTR,
    ) -> i32 {
        let csidl = csidl as u32;
        let subdir = match csidl_subdir(csidl) {
            Some(s) => s,
            None => {
                eprintln!("[perun] SHGetFolderPathW(csidl={csidl:#x}) — unmapped CSIDL");
                return E_INVALIDARG;
            }
        };
        let dir = appdata_root().join(subdir);
        if csidl & CSIDL_FLAG_CREATE != 0 {
            mkdirs(&dir);
        }
        write_wide(out_path, &dir.to_string_lossy());
        eprintln!(
            "[perun] SHGetFolderPathW(csidl={csidl:#x}) -> {:?}",
            dir.to_string_lossy()
        );
        S_OK
    }
}

/// Read a NUL-terminated UTF-16 string into a Rust String.
fn wide_to_string(p: LPCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 && len < 32768 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

win32_api! {
    /// BOOL PathAppendW(LPWSTR pszPath, LPCWSTR pMore);
    unsafe extern "win64" fn PathAppendW(path: LPWSTR, more: LPCWSTR) -> BOOL {
        if path.is_null() {
            return FALSE;
        }
        let base = wide_to_string(path);
        let extra = wide_to_string(more);
        let joined = if base.is_empty() {
            extra.clone()
        } else if base.ends_with('\\') || base.ends_with('/') {
            format!("{base}{extra}")
        } else {
            format!("{base}\\{extra}")
        };
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] PathAppendW({:?} + {:?}) -> {:?}", base, extra, joined);
        }
        write_wide(path, &joined);
        TRUE
    }
}

win32_api! {
    /// BOOL PathIsDirectoryW(LPCWSTR pszPath);
    unsafe extern "win64" fn PathIsDirectoryW(path: LPCWSTR) -> BOOL {
        let p = wide_to_string(path);
        let unix = p.replace('\\', "/");
        let is_dir = std::path::Path::new(&unix).is_dir();
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] PathIsDirectoryW({:?}) -> {}", p, is_dir);
        }
        BOOL::from(is_dir)
    }
}

win32_api! {
    /// BOOL PathFileExistsW(LPCWSTR pszPath);
    unsafe extern "win64" fn PathFileExistsW(path: LPCWSTR) -> BOOL {
        let p = wide_to_string(path);
        let unix = p.replace('\\', "/");
        let exists = std::path::Path::new(&unix).exists();
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] PathFileExistsW({:?}) -> {}", p, exists);
        }
        BOOL::from(exists)
    }
}

win32_api! {
    /// BOOL CreateDirectoryExW(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);
    unsafe extern "win64" fn CreateDirectoryExW(
        _template: LPCWSTR,
        name: LPCWSTR,
        _sa: *const core::ffi::c_void,
    ) -> BOOL {
        let p = wide_to_string(name);
        let unix = p.replace('\\', "/");
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] CreateDirectoryExW({:?})", p);
        }
        match std::fs::create_dir_all(&unix) {
            Ok(()) => TRUE,
            Err(_) => FALSE,
        }
    }
}
