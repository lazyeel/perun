// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

// Error codes and handle arithmetic are the Win32 ABI as the guest sees it;
// // the conversions at this boundary are the contract.
#![allow(unknown_lints)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

//! Win32 type surface shared by all shims.
//!
//! Sizes and layout match the Windows x64 ABI: `BOOL` is 4 bytes, handles
//! are pointer-sized, `LARGE_INTEGER` is a raw i64. Guest code reads these
//! through the calling convention, so the exact width matters.

#![allow(non_camel_case_types, dead_code)]

pub type DWORD = u32;
pub type WORD = u16;
pub type BOOL = i32;
pub type BYTE = u8;
pub type CHAR = i8;
pub type WCHAR = u16;
pub type UINT = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type SIZE_T = usize;
pub type HANDLE = *mut core::ffi::c_void;
pub type LPCSTR = *const u8;
pub type LPSTR = *mut u8;
pub type LPCWSTR = *const WCHAR;
pub type LPWSTR = *mut WCHAR;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const INFINITE: DWORD = 0xFFFF_FFFF;
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 0x102;
pub const TLS_OUT_OF_INDEXES: DWORD = 0xFFFF_FFFF;

pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

// Memory protection constants (Win32 values).
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

// File creation dispositions.
pub const CREATE_NEW: DWORD = 1;
pub const CREATE_ALWAYS: DWORD = 2;
pub const OPEN_EXISTING: DWORD = 3;
pub const OPEN_ALWAYS: DWORD = 4;
pub const TRUNCATE_EXISTING: DWORD = 5;

// Generic access rights.
pub const GENERIC_READ: DWORD = 0x8000_0000;
pub const GENERIC_WRITE: DWORD = 0x4000_0000;

pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x10;
pub const FILE_ATTRIBUTE_READONLY: DWORD = 0x01;

pub const HEAP_ZERO_MEMORY: DWORD = 0x0000_0008;

pub const ERROR_SUCCESS: DWORD = 0;
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
pub const ERROR_MORE_DATA: DWORD = 234;

/// The one host tree the shims may act on. Every path the guest names is
/// resolved inside it (`jail::resolve_in_jail`); this function is the
/// lexical fallback that backs the same rule on kernels without `openat2`
/// (pre-5.6) and the fast pre-filter for it.
///
/// The rule is an **allowlist by construction**: there is no list of
/// forbidden host directories that someone must remember to keep complete —
/// the first list shipped with exactly that shape blocked the *default*
/// appdata layout (`/home/<user>/.perun/appdata`) because it named `/home`.
/// One allowed tree, everything else denied.
pub fn sanitize_guest_path(path: &std::path::Path) -> Result<std::path::PathBuf, DWORD> {
    let s = path.to_string_lossy();
    if s.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    // Resolve `.` and `..` lexically. `Path::components` already skips `.`
    // and a leading `//`; `..` is folded against the preceding component the
    // way the kernel's path walker would fold it.
    let mut normalised = std::path::PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                // `..` at the root of the normalised prefix: the path walks
                // above its own anchor. Only a jail root can still contain it,
                // so pop; a prefix-less `..` chain keeps the path relative and
                // it will be rejected by the allowlist comparison below.
                normalised.pop();
            }
            std::path::Component::CurDir => {}
            other => normalised.push(other.as_os_str()),
        }
    }
    let norm_str = normalised.to_string_lossy();
    if norm_str.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    // A relative path is not a violation: the caller resolves it against
    // the jail root (this is what `jail::resolve_in_jail` does before
    // calling in, and what the standalone lexical callers rely on too).
    // Rebase it under the root and re-check the prefix, so both callers
    // share one rule: the final target must live inside the jail.
    let root = crate::jail::lexical_jail_root()?;
    let absolute = if normalised.is_absolute() {
        normalised.clone()
    } else {
        root.join(&normalised)
    };
    if absolute == root || absolute.starts_with(&root) {
        Ok(if normalised.is_absolute() {
            normalised
        } else {
            absolute
        })
    } else {
        Err(ERROR_ACCESS_DENIED)
    }
}

#[cfg(test)]
mod jail_tests {
    use super::*;

    fn with_root<T>(f: impl FnOnce(std::path::PathBuf) -> T) -> T {
        let _guard = crate::jail::test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // A private root for each test: the allowlist is read per call from
        // PERUN_DIR, and ambient state from other tests must not leak. The
        // jail root is `<PERUN_DIR>/appdata`, so the paths under test are
        // built relative to that.
        let base = std::env::temp_dir().join(format!("perun-lexical-jail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // Edition 2024: env mutation is unsafe; no guest threads exist at test time.
        unsafe { std::env::set_var("PERUN_DIR", &base) };
        let r = f(base.join("appdata"));
        unsafe { std::env::remove_var("PERUN_DIR") };
        let _ = std::fs::remove_dir_all(&base);
        r
    }

    #[test]
    fn empty_path_is_rejected() {
        with_root(|_| {
            assert_eq!(
                sanitize_guest_path(std::path::Path::new("")),
                Err(ERROR_INVALID_PARAMETER)
            );
        });
    }

    #[test]
    fn system_roots_are_denied() {
        with_root(|_| {
            for denied in [
                "/", "/etc", "/var", "/run", "/tmp", "/nix", "/boot", "/usr", "/bin",
            ] {
                assert_eq!(
                    sanitize_guest_path(std::path::Path::new(denied)),
                    Err(ERROR_ACCESS_DENIED),
                    "{denied} must not resolve"
                );
            }
        });
    }

    #[test]
    fn paths_inside_system_roots_are_denied() {
        with_root(|_| {
            assert_eq!(
                sanitize_guest_path(std::path::Path::new("/etc/passwd")),
                Err(ERROR_ACCESS_DENIED)
            );
            assert_eq!(
                sanitize_guest_path(std::path::Path::new("/tmp/scratch/adi.pb")),
                Err(ERROR_ACCESS_DENIED)
            );
            assert_eq!(
                sanitize_guest_path(std::path::Path::new("/usr/lib/dylib")),
                Err(ERROR_ACCESS_DENIED)
            );
        });
    }

    #[test]
    fn dotdot_escape_into_a_host_root_is_rejected() {
        with_root(|root| {
            let deep = root.join("Common/x/y");
            assert_eq!(
                sanitize_guest_path(&deep.join("../../../..")),
                Err(ERROR_ACCESS_DENIED),
                "climb out of the jail root must deny, not pop past it"
            );
            assert_eq!(
                sanitize_guest_path(std::path::Path::new("/etc/../..")),
                Err(ERROR_ACCESS_DENIED)
            );
        });
    }

    #[test]
    fn the_jail_root_and_everything_inside_it_is_allowed() {
        with_root(|root| {
            assert_eq!(
                sanitize_guest_path(&root),
                Ok(root.clone()),
                "the jail root itself must resolve"
            );
            let leaf = root.join("Common/Apple Computer/iTunes/adi");
            assert_eq!(sanitize_guest_path(&leaf), Ok(leaf));
        });
    }

    #[test]
    fn the_default_home_layout_is_allowed() {
        // Regression for the denylist version: a literal `/home` entry
        // denied the *default* appdata root on any ordinary distro, where
        // HOME is /home/<user>. The allowlist cannot reproduce that bug,
        // and this test pins it.
        with_root(|root| {
            let leaf = root.join("Roaming/x");
            assert!(sanitize_guest_path(&leaf).is_ok());
            unsafe { std::env::remove_var("PERUN_DIR") };
            let home_layout = std::path::Path::new("/home/admin/.perun/appdata/Roaming/x");
            let saved = std::env::var("HOME").unwrap_or_default();
            unsafe { std::env::set_var("HOME", "/home/admin") };
            // The default derives from HOME; PERUN_DIR must stay unset for
            // the default path to be taken.
            unsafe { std::env::remove_var("PERUN_DIR") };
            assert_eq!(
                sanitize_guest_path(home_layout),
                Ok(home_layout.to_path_buf())
            );
            unsafe { std::env::set_var("HOME", saved) };
        });
    }

    #[test]
    fn relative_paths_are_allowed_but_normalised() {
        with_root(|root| {
            // A relative path is not a violation: it lands under the jail
            // root (the rebase `jail::resolve_in_jail` also relies on), and
            // the result is the absolute host path inside the root.
            let ok = sanitize_guest_path(std::path::Path::new("appdata/Common/x/y/../../z"));
            assert_eq!(ok.unwrap(), root.join("appdata/Common/z"));
        });
    }

    #[test]
    fn prefix_words_outside_the_jail_are_denied() {
        // The allowlist is a prefix on *paths*, not on strings: a sibling
        // of the jail root that merely shares its name must not pass.
        with_root(|root| {
            let sibling = std::path::PathBuf::from(format!("{}-sibling", root.display()));
            assert_eq!(
                sanitize_guest_path(&sibling),
                Err(ERROR_ACCESS_DENIED),
                "a string-prefixed sibling {sibling:?} must not resolve"
            );
        });
    }
}

pub const ERROR_NO_MORE_FILES: DWORD = 18;

/// `SYSTEMTIME`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SYSTEMTIME {
    pub wYear: WORD,
    pub wMonth: WORD,
    pub wDayOfWeek: WORD,
    pub wDay: WORD,
    pub wHour: WORD,
    pub wMinute: WORD,
    pub wSecond: WORD,
    pub wMilliseconds: WORD,
}

/// `TIME_ZONE_INFORMATION` ( Bias, two names of 32 wchars, two dates/biases).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TIME_ZONE_INFORMATION {
    pub Bias: LONG,
    pub StandardName: [WCHAR; 32],
    pub StandardDate: SYSTEMTIME,
    pub StandardBias: LONG,
    pub DaylightName: [WCHAR; 32],
    pub DaylightDate: SYSTEMTIME,
    pub DaylightBias: LONG,
}

impl Default for TIME_ZONE_INFORMATION {
    fn default() -> Self {
        // SAFETY: all-zero is a valid value pattern for this POD struct.
        unsafe { std::mem::zeroed() }
    }
}

pub const TIME_ZONE_ID_UNKNOWN: DWORD = 0;
pub const TIME_ZONE_ID_STANDARD: DWORD = 1;
pub const TIME_ZONE_ID_DAYLIGHT: DWORD = 2;

/// `WIN32_FIND_DATAA` (ANSI variant used by `FindFirstFileExA`).
pub const MAX_PATH_A: usize = 260;
pub const MAX_FILE_NAME_A: usize = 14;

#[repr(C)]
pub struct WIN32_FIND_DATAA {
    pub dwFileAttributes: DWORD,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: DWORD,
    pub nFileSizeLow: DWORD,
    pub dwReserved0: DWORD,
    pub dwReserved1: DWORD,
    pub cFileName: [u8; MAX_PATH_A],
    pub cAlternateFileName: [u8; MAX_FILE_NAME_A],
}

impl Default for WIN32_FIND_DATAA {
    fn default() -> Self {
        // SAFETY: all-zero is valid for this POD struct.
        unsafe { std::mem::zeroed() }
    }
}

/// `FILE_ATTRIBUTE_DATA` for `GetFileAttributesExW`.
#[repr(C)]
pub struct WIN32_FILE_ATTRIBUTE_DATA {
    pub dwFileAttributes: DWORD,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: DWORD,
    pub nFileSizeLow: DWORD,
}

impl Default for WIN32_FILE_ATTRIBUTE_DATA {
    fn default() -> Self {
        // SAFETY: all-zero is valid for this POD struct.
        unsafe { std::mem::zeroed() }
    }
}

/// `FILETIME`: 100-ns intervals since 1601-01-01 UTC.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

impl FILETIME {
    #[must_use]
    pub fn from_u64(v: u64) -> FILETIME {
        FILETIME {
            dwLowDateTime: v as u32,
            dwHighDateTime: (v >> 32) as u32,
        }
    }
    #[must_use]
    pub fn as_u64(self) -> u64 {
        u64::from(self.dwHighDateTime) << 32 | u64::from(self.dwLowDateTime)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: DWORD,
    pub OffsetHigh: DWORD,
    pub hEvent: HANDLE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

/// Win32 error codes are stored per-thread in the TEB (`+0x68`); see
/// `util::set_last_error` / `util::get_last_error` for the implementation.
/// `STARTUPINFOW` (Win64 layout, 104 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: *mut BYTE,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

// The CRT resolves this by name at startup to decide between ANSI and
// Unicode file APIs. Returning NULL (an unimplemented name) leaves the
// caller with no valid answer, and CoreADI64.dll's path parser ran off an
// invalid table index on that path (SIGSEGV at RVA 0xaf68e).
crate::win32_api! {
    /// BOOL AreFileApisANSI(void);
    unsafe extern "win64" fn AreFileApisANSI() -> BOOL { TRUE }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_roundtrip() {
        let t = FILETIME::from_u64(0x0123_4567_89ab_cdef);
        assert_eq!(t.as_u64(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn invalid_handle_is_all_ones() {
        let h = INVALID_HANDLE_VALUE as usize;
        assert_eq!(h, usize::MAX);
    }
}
