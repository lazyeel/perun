// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

// The shell shims return `HRESULT` values the guest will compare, and the
// // buffer lengths they report are the caller's own.
#![allow(unknown_lints)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

//! Shell and path shims: folder locations (CSIDL) and SHLWAPI path helpers.
//!
//! Windows folder locations are mapped under a perun-owned root so guest
//! writes land in a stable, inspectable place:
//!
//! ```text
//! $PERUN_DIR/appdata (default $HOME/.perun/appdata)
//!   ├── Roaming/   CSIDL_APPDATA        (0x001a)
//!   ├── Local/     CSIDL_LOCAL_APPDATA  (0x001c)
//!   └── Common/    CSIDL_COMMON_APPDATA (0x0023)
//! ```

use crate::util::set_last_error;
use crate::win32::{BOOL, DWORD, FALSE, HANDLE, LPCWSTR, LPWSTR, TRUE};
use crate::win32_api;

const MAX_PATH: usize = 260;
const S_OK: i32 = 0;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;

const CSIDL_APPDATA: u32 = 0x001a;
const CSIDL_LOCAL_APPDATA: u32 = 0x001c;
const CSIDL_COMMON_APPDATA: u32 = 0x0023;
const CSIDL_FLAG_CREATE: u32 = 0x8000;
const CSIDL_MASK: u32 = 0x00FF;

/// Root directory for all mapped Windows folders: `PERUN_DIR/appdata`, the
/// same single-root configuration every other perun lane uses. An unusable
/// `PERUN_DIR` (aimed at a system tree) has no safe folder root to offer,
/// so the mapping reports failure.
fn appdata_root() -> Option<std::path::PathBuf> {
    perun_core::paths::appdata().ok()
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

/// Write a Rust string into a Win32 LPWSTR buffer (`MAX_PATH` wchars).
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
        // Log every request, mapped or not, with the buffer pointer: the guest
        // building its provisioning path was observed allocating its own buffer
        // and passing it straight to GetFullPathNameW, so whether it ever reads
        // this buffer back is worth seeing rather than assuming.
        eprintln!(
            "[perun] SHGetFolderPathW(csidl={csidl:#x} create={} out_path={:?})",
            csidl & CSIDL_FLAG_CREATE != 0,
            out_path
        );
        let subdir = if let Some(s) = csidl_subdir(csidl) { s } else {
            eprintln!("[perun] SHGetFolderPathW(csidl={csidl:#x}) — unmapped CSIDL");
            return E_INVALIDARG;
        };
        let Some(base) = appdata_root() else {
            eprintln!("[perun] SHGetFolderPathW(csidl={csidl:#x}) — no usable PERUN_DIR");
            return E_INVALIDARG;
        };
        let dir = base.join(subdir);
        // The jail resolves the directory this shim hands out: PERUN_DIR
        // is an environment variable, and a value pointing at a host system
        // root must not turn the create-flag into a `mkdir -p` against it.
        // The jail root *is* the appdata tree, so the resolution both
        // validates it and canonicalises it.
        match crate::jail::resolve_in_jail(&dir.to_string_lossy()) {
            Ok(jailed) => {
                if csidl & CSIDL_FLAG_CREATE != 0 {
                    mkdirs(&jailed);
                }
                write_wide(out_path, &jailed.to_string_lossy());
                eprintln!(
                    "[perun] SHGetFolderPathW(csidl={csidl:#x}) -> {:?}",
                    jailed.to_string_lossy()
                );
            }
            Err(code) => {
                eprintln!(
                    "[perun] SHGetFolderPathW(csidl={csidl:#x}) — appdata root {dir:?} is jailed (err {code})"
                );
                set_last_error(code);
                return E_INVALIDARG;
            }
        }
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
    /// DWORD GetFullPathNameW(LPCWSTR, DWORD, LPWSTR, LPWSTR *);
    pub unsafe extern "win64" fn GetFullPathNameW(
        name: LPCWSTR,
        buf_len: DWORD,
        buf: LPWSTR,
        file_part: *mut LPWSTR,
    ) -> DWORD {
        let raw = wide_to_string(name);
        if raw.is_empty() {
            return 0;
        }
        // The guest builds the adi.pb path out of an uninitialized buffer
        // (the Windows wrapper that carries the provisioning path does not
        // exist in the seq harness), so the prefix is stack garbage while
        // the LEAF names a real ADI cache file. Redirect any such path onto
        // the canonical appdata tree, where a valid adi.pb already lives.
        let raw = if raw.contains("adi.pb") {
            let leaf = if raw.contains("adi-843A713B.pb") {
                "adi-843A713B.pb"
            } else {
                "adi.pb"
            };
            let base = appdata_root().unwrap_or_else(|| {
                std::path::PathBuf::from("/opt/data/home/.perun/appdata/Common")
            });
            let canonical = format!(
                "{}/Apple Computer/iTunes/adi/{leaf}",
                base.display()
            );
            eprintln!("[perun] adi-path redirect: {raw:?} -> {canonical:?}");
            canonical
        } else {
            raw
        };
        // Resolve through the host so the guest sees a real absolute path, the
        // same canonical form Win32 would have returned. This is the first call
        // on the -45034 continuation that reaches the filesystem, so the guest
        // is resolving a real path rather than being handed a stub's absence.
        let full = std::fs::canonicalize(&raw)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                if raw.starts_with('/') {
                    raw.clone()
                } else {
                    std::env::current_dir()
                        .map(|d| d.join(&raw).to_string_lossy().into_owned())
                        .unwrap_or_else(|_| raw.clone())
                }
            });
        let wide: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();
        let need = wide.len() as DWORD;
        if !buf.is_null() {
            let room = (buf_len as usize).min(wide.len());
            unsafe {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), buf, room);
                if room == wide.len() && !file_part.is_null() {
                    *file_part = buf;
                }
            }
        }
        eprintln!("[perun] GetFullPathNameW({raw:?}, {buf_len}) -> {full:?}");
        need
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
            eprintln!("[perun] PathAppendW({base:?} + {extra:?}) -> {joined:?}");
        }
        write_wide(path, &joined);
        TRUE
    }
}

win32_api! {
    /// DWORD GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
    ///
    /// The guest resolves a relative cache-file name through this, so it is on
    /// the SPIM path. It was missing, and an unresolved import is a trap that
    /// returns without writing the buffer.
    unsafe extern "win64" fn GetCurrentDirectoryW(n: DWORD, buf: LPWSTR) -> DWORD {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
        let need = wide.len() as DWORD;
        if !buf.is_null() {
            // Windows writes at most n characters, NUL-terminated, and returns
            // the length it needed -- so a short buffer reports the true size
            // rather than a truncated string.
            let room = (n as usize).min(wide.len());
            unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), buf, room) };
        }
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] GetCurrentDirectoryW({n}) -> {cwd:?}");
        }
        need
    }
}

win32_api! {
    /// BOOL SetCurrentDirectoryW(LPCWSTR);
    unsafe extern "win64" fn SetCurrentDirectoryW(dir: LPWSTR) -> BOOL {
        let p = wide_to_string(dir);
        let unix = p.replace('\\', "/");
        // The guest's cwd is a host-process-global and every later relative
        // path inherits it; an unjailed chdir is what let a garbage pointer
        // turn `chmod(".")` into a chmod of the host root. Resolve into the
        // jail and chdir there — the guest sees its own tree, the host cwd
        // never moves outside it.
        match crate::jail::resolve_in_jail(&unix) {
            Ok(jailed) => BOOL::from(std::env::set_current_dir(&jailed).is_ok()),
            Err(code) => {
                set_last_error(code);
                FALSE
            }
        }
    }
}

win32_api! {
    /// BOOL PathIsDirectoryW(LPCWSTR pszPath);
    unsafe extern "win64" fn PathIsDirectoryW(path: LPCWSTR) -> BOOL {
        let p = wide_to_string(path);
        let unix = p.replace('\\', "/");
        let is_dir = std::path::Path::new(&unix).is_dir();
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] PathIsDirectoryW({p:?}) -> {is_dir}");
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
            eprintln!("[perun] PathFileExistsW({p:?}) -> {exists}");
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
            eprintln!("[perun] CreateDirectoryExW({p:?})");
        }
        // Same jail as CreateDirectoryW: `create_dir_all` walks the whole
        // path, so a traversal inside it would build directories across a
        // system root, not just at the leaf.
        let jailed = match crate::jail::resolve_in_jail(&unix) {
            Ok(path) => path,
            Err(code) => {
                set_last_error(code);
                if std::env::var_os("PERUN_TRACE").is_some() {
                    eprintln!("[perun] CreateDirectoryExW({p:?}) — jailed (err {code})");
                }
                return FALSE;
            }
        };
        match std::fs::create_dir_all(&jailed) {
            Ok(()) => TRUE,
            Err(_) => FALSE,
        }
    }
}
