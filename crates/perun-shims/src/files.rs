// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! File I/O and path shims over POSIX.

use crate::util::*;
use crate::win32::*;
use crate::win32_api;

fn open_flags(access: DWORD, disposition: DWORD) -> (i32, i32) {
    let mut flags = match access & 0xF000_0000 {
        GENERIC_READ if access & GENERIC_WRITE != 0 => libc::O_RDWR,
        GENERIC_READ => libc::O_RDONLY,
        GENERIC_WRITE => libc::O_WRONLY,
        _ => libc::O_RDONLY,
    };
    flags |= match disposition {
        CREATE_NEW => libc::O_CREAT | libc::O_EXCL,
        CREATE_ALWAYS => libc::O_CREAT | libc::O_TRUNC,
        OPEN_EXISTING => 0,
        OPEN_ALWAYS => libc::O_CREAT,
        TRUNCATE_EXISTING => libc::O_TRUNC,
        _ => 0,
    };
    (flags, 0o644)
}

win32_api! {
    /// HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, ..., DWORD, DWORD, HANDLE);
    unsafe extern "win64" fn CreateFileW(
        name: LPCWSTR,
        access: DWORD,
        share: DWORD,
        sa: *const SECURITY_ATTRIBUTES,
        disposition: DWORD,
        attrs: DWORD,
        template: HANDLE,
    ) -> HANDLE {
        let _ = (sa, template);
        let wide = read_wide(name);
        let path = String::from_utf16_lossy(&wide);

        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!(
                "[perun] CreateFileW({:?}, access={access:#x}, disp={disposition})",
                path
            );
        }

        // Directory open (used by guests probing folder existence).
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 && disposition == OPEN_EXISTING {
            let mode = libc::O_RDONLY | libc::O_DIRECTORY;
            let fd = libc::open(path.as_bytes().as_ptr() as *const i8, mode);
            return if fd >= 0 {
                handle_new(HostKind::File { fd, shared: false })
            } else {
                INVALID_HANDLE_VALUE
            };
        }

        let (mut flags, mode) = open_flags(access, disposition);
        let _ = share;
        // Path helpers (shlwapi) are stubs in phase 1; guests often probe
        // "C:\"-style paths — map a drive-root prefix to the process cwd.
        let path = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            format!(".{}", &path[2..])
        } else {
            path
        };
        flags |= libc::O_CLOEXEC;
        let fd = libc::open(
            std::ffi::CString::new(path).unwrap_or_default().as_ptr(),
            flags,
            mode,
        );
        if fd >= 0 {
            handle_new(HostKind::File { fd, shared: false })
        } else {
            INVALID_HANDLE_VALUE
        }
    }
}

win32_api! {
    /// HANDLE CreateFileA(...);
    unsafe extern "win64" fn CreateFileA(
        name: LPCSTR,
        access: DWORD,
        share: DWORD,
        sa: *const SECURITY_ATTRIBUTES,
        disposition: DWORD,
        attrs: DWORD,
        template: HANDLE,
    ) -> HANDLE {
        let narrow = read_narrow(name);
        let wide = narrow
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u16)
            .collect::<Vec<u16>>();
        let cname = std::ffi::CString::new(wide.iter().map(|&w| w as u8).take_while(|&b| b != 0).collect::<Vec<u8>>())
            .unwrap_or_default();
        // Reuse the W implementation by widening the name.
        let wname = wide_from_str(&String::from_utf8_lossy(cname.as_bytes()));
        let wname_ptr = wname.as_ptr();
        CreateFileW(wname_ptr, access, share, sa, disposition, attrs, template)
    }
}

pub(crate) fn file_of(h: HANDLE) -> Option<(i32, bool)> {
    unsafe { handle_get(h) }.and_then(|o| match o.kind {
        HostKind::File { fd, shared } => Some((fd, shared)),
        _ => None,
    })
}

win32_api! {
    /// BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    unsafe extern "win64" fn ReadFile(
        h: HANDLE,
        buf: *mut u8,
        to_read: DWORD,
        out_read: *mut DWORD,
        overlapped: *mut OVERLAPPED,
    ) -> BOOL {
        let (fd, _) = match file_of(h) {
            Some(f) => f,
            None => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        };
        if !overlapped.is_null() && overlapped.read().Offset != 0 {
            // Positional read via the OVERLAPPED offset.
            let off = ((overlapped.read().OffsetHigh as u64) << 32)
                | overlapped.read().Offset as u64;
            let n = libc::pread(fd, buf as *mut core::ffi::c_void, to_read as usize, off as i64);
            if n < 0 {
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if !out_read.is_null() {
                *out_read = n as DWORD;
            }
            return TRUE;
        }
        let n = libc::read(fd, buf as *mut core::ffi::c_void, to_read as usize);
        if n < 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if !out_read.is_null() {
            *out_read = n as DWORD;
        }
        TRUE
    }
}

win32_api! {
    /// BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    unsafe extern "win64" fn WriteFile(
        h: HANDLE,
        buf: LPCVOID,
        to_write: DWORD,
        out_written: *mut DWORD,
        _overlapped: *mut OVERLAPPED,
    ) -> BOOL {
        let (fd, _) = match file_of(h) {
            Some(f) => f,
            None => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        };
        let n = libc::write(fd, buf, to_write as usize);
        if n < 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if !out_written.is_null() {
            *out_written = n as DWORD;
        }
        TRUE
    }
}

win32_api! {
    /// BOOL CloseHandle(HANDLE);
    unsafe extern "win64" fn CloseHandle(h: HANDLE) -> BOOL {
        match handle_free(h) {
            true => TRUE,
            false => FALSE,
        }
    }
}

win32_api! {
    /// BOOL SetEndOfFile(HANDLE);
    unsafe extern "win64" fn SetEndOfFile(h: HANDLE) -> BOOL {
        let (fd, _) = match file_of(h) {
            Some(f) => f,
            None => return FALSE,
        };
        let pos = libc::lseek(fd, 0, libc::SEEK_CUR);
        if libc::ftruncate(fd, pos) == 0 {
            TRUE
        } else {
            FALSE
        }
    }
}

win32_api! {
    /// BOOL FlushFileBuffers(HANDLE);
    unsafe extern "win64" fn FlushFileBuffers(h: HANDLE) -> BOOL {
        match file_of(h) {
            Some((fd, _)) => {
                if libc::fsync(fd) == 0 {
                    TRUE
                } else {
                    FALSE
                }
            }
            None => FALSE,
        }
    }
}

win32_api! {
    /// BOOL SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
    unsafe extern "win64" fn SetFilePointerEx(
        h: HANDLE,
        dist: i64,
        new_pos: *mut i64,
        method: DWORD,
    ) -> BOOL {
        let (fd, _) = match file_of(h) {
            Some(f) => f,
            None => return FALSE,
        };
        let whence = match method {
            0 => libc::SEEK_SET,
            1 => libc::SEEK_CUR,
            2 => libc::SEEK_END,
            _ => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
        };
        let pos = libc::lseek(fd, dist, whence);
        if pos < 0 {
            return FALSE;
        }
        if !new_pos.is_null() {
            *new_pos = pos;
        }
        TRUE
    }
}

win32_api! {
    /// BOOL DeleteFileW(LPCWSTR);
    unsafe extern "win64" fn DeleteFileW(name: LPCWSTR) -> BOOL {
        let path = String::from_utf16_lossy(&read_wide(name));
        let c = std::ffi::CString::new(path).unwrap_or_default();
        if libc::unlink(c.as_ptr()) == 0 {
            TRUE
        } else {
            FALSE
        }
    }
}

win32_api! {
    /// BOOL CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
    unsafe extern "win64" fn CreateDirectoryW(
        name: LPCWSTR,
        _sa: *const SECURITY_ATTRIBUTES,
    ) -> BOOL {
        let path = String::from_utf16_lossy(&read_wide(name));
        let c = std::ffi::CString::new(path).unwrap_or_default();
        if libc::mkdir(c.as_ptr(), 0o755) == 0 {
            TRUE
        } else {
            FALSE
        }
    }
}

fn attributes_for_path(path: &[u8]) -> DWORD {
    let c = match std::ffi::CString::new(path.to_vec()) {
        Ok(c) => c,
        Err(_) => return INVALID_FILE_ATTRIBUTES,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return INVALID_FILE_ATTRIBUTES;
    }
    let mut attrs = FILE_ATTRIBUTE_NORMAL;
    if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    if st.st_uid == 0 {
        attrs |= FILE_ATTRIBUTE_READONLY; // approximation for root-owned files
    }
    attrs
}

pub const INVALID_FILE_ATTRIBUTES: DWORD = 0xFFFF_FFFF;

win32_api! {
    /// DWORD GetFileAttributesW(LPCWSTR);
    unsafe extern "win64" fn GetFileAttributesW(name: LPCWSTR) -> DWORD {
        let path = String::from_utf16_lossy(&read_wide(name));
        let attrs = attributes_for_path(path.as_bytes());
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] GetFileAttributesW({:?}) -> {attrs:#x}", path);
        }
        attrs
    }
}

win32_api! {
    /// DWORD GetFileAttributesA(LPCSTR);
    unsafe extern "win64" fn GetFileAttributesA(name: LPCSTR) -> DWORD {
        let path = read_narrow(name);
        let attrs = attributes_for_path(&path);
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!(
                "[perun] GetFileAttributesA({:?}) -> {attrs:#x}",
                String::from_utf8_lossy(&path)
            );
        }
        attrs
    }
}

win32_api! {
    /// DWORD GetFileSize(HANDLE, LPDWORD);
    unsafe extern "win64" fn GetFileSize(h: HANDLE, high: *mut DWORD) -> DWORD {
        let (fd, _) = match file_of(h) {
            Some(f) => f,
            None => return 0xFFFF_FFFF, // INVALID_FILE_SIZE
        };
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return 0xFFFF_FFFF;
        }
        let size = st.st_size as u64;
        if !high.is_null() {
            *high = (size >> 32) as DWORD;
        }
        size as DWORD
    }
}

win32_api! {
    /// DWORD GetFileType(HANDLE);
    unsafe extern "win64" fn GetFileType(h: HANDLE) -> DWORD {
        const FILE_TYPE_CHAR: DWORD = 0x0002;
        const FILE_TYPE_DISK: DWORD = 0x0001;
        match file_of(h) {
            Some((fd, shared)) => {
                if shared || libc::isatty(fd) == 1 {
                    FILE_TYPE_CHAR
                } else {
                    FILE_TYPE_DISK
                }
            }
            None => 0,
        }
    }
}

// ── Std streams ──────────────────────────────────────────────────────────

win32_api! {
    /// HANDLE GetStdHandle(DWORD);
    unsafe extern "win64" fn GetStdHandle(which: DWORD) -> HANDLE {
        const STD_INPUT_HANDLE: DWORD = 0xFFFF_FFF6;
        const STD_OUTPUT_HANDLE: DWORD = 0xFFFF_FFF5;
        const STD_ERROR_HANDLE: DWORD = 0xFFFF_FFF4;
        let fd = match which {
            STD_INPUT_HANDLE => 0,
            STD_OUTPUT_HANDLE => 1,
            STD_ERROR_HANDLE => 2,
            _ => {
                set_last_error(ERROR_INVALID_PARAMETER);
                return core::ptr::null_mut();
            }
        };
        handle_new(HostKind::File { fd, shared: true })
    }
}

win32_api! {
    /// BOOL SetStdHandle(DWORD, HANDLE);
    unsafe extern "win64" fn SetStdHandle(_which: DWORD, _h: HANDLE) -> BOOL {
        // Phase 1: redirection is not supported; report success so CRT init
        // proceeds. Real redirection lands with descriptor tracking.
        TRUE
    }
}
