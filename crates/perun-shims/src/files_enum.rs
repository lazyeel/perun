// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Directory enumeration (Find* family), drive/volume queries and the
//! remaining kernel32 surface the prototype's guests touched.

use crate::util::*;
use crate::win32::*;
use crate::win32_api;

fn filetime_from_timespec(secs: i64, nanos: i64) -> FILETIME {
    FILETIME::from_u64(unix_to_filetime(secs, nanos.clamp(0, 999_999_999) as u32))
}

/// Convert a Win32 `FindFirstFileExA` glob ("dir\*.ext") into a directory
/// path + optional suffix filter.
fn split_pattern(pattern: &str) -> (String, Option<String>) {
    match pattern.rsplit_once(['\\', '/']) {
        Some((dir, pat)) if !dir.is_empty() => {
            let filter = if pat == "*.*" || pat == "*" {
                None
            } else {
                Some(pat.to_ascii_lowercase())
            };
            (dir.to_string(), filter)
        }
        _ => (pattern.to_string(), None),
    }
}

fn fill_find_data(fd: &mut WIN32_FIND_DATAA, st: &libc::stat, name: &[u8]) {
    fd.dwFileAttributes = if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    fd.ftCreationTime = filetime_from_timespec(st.st_ctime, st.st_ctime_nsec);
    fd.ftLastAccessTime = filetime_from_timespec(st.st_atime, st.st_atime_nsec);
    fd.ftLastWriteTime = filetime_from_timespec(st.st_mtime, st.st_mtime_nsec);
    let size = st.st_size as u64;
    fd.nFileSizeHigh = (size >> 32) as DWORD;
    fd.nFileSizeLow = size as DWORD;
    let n = name.len().min(MAX_PATH_A - 1);
    fd.cFileName[..n].copy_from_slice(&name[..n]);
    fd.cFileName[n] = 0;
}

win32_api! {
    /// HANDLE FindFirstFileExA(LPCSTR, FINDEX_INFO_LEVELS, LPVOID, ..., ...);
    unsafe extern "win64" fn FindFirstFileExA(
        pattern: LPCSTR,
        _info_level: i32,
        out_find_data: *mut core::ffi::c_void,
        _search_op: i32,
        _filter: *const core::ffi::c_void,
        _flags: DWORD,
    ) -> HANDLE {
        let raw = read_narrow(pattern);
        let pattern = String::from_utf8_lossy(&raw).into_owned();
        let (dir_path, filter) = split_pattern(&pattern);
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] FindFirstFileExA({:?})", pattern);
        }

        let cdir = match std::ffi::CString::new(dir_path.clone()) {
            Ok(c) => c,
            Err(_) => return INVALID_HANDLE_VALUE,
        };
        let dir = libc::opendir(cdir.as_ptr());
        if dir.is_null() {
            set_last_error(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        let find = out_find_data as *mut WIN32_FIND_DATAA;

        // FindFirstFile also returns the first matching entry directly.
        loop {
            let ent = libc::readdir(dir);
            if ent.is_null() {
                libc::closedir(dir);
                set_last_error(ERROR_NO_MORE_FILES);
                return INVALID_HANDLE_VALUE;
            }
            let ent = &*ent;
            let name = std::slice::from_raw_parts(ent.d_name.as_ptr() as *const u8, libc::strlen(ent.d_name.as_ptr()));
            if name != b"." && name != b".." {
                if let Some(f) = filter.as_ref() {
                    if !name.to_ascii_lowercase().ends_with(f.as_bytes()) {
                        continue;
                    }
                }
                let full = format!("{}/{}", dir_path, String::from_utf8_lossy(name));
                if let Ok(c) = std::ffi::CString::new(full) {
                    let mut st: libc::stat = std::mem::zeroed();
                    if libc::stat(c.as_ptr(), &mut st) == 0 {
                        (*find).dwFileAttributes = 0; // zeroed then filled
                        fill_find_data(&mut *find, &st, name);
                    }
                }
                return handle_new(HostKind::Dir { dir, pattern: filter.unwrap_or_default() });
            }
        }
    }
}

win32_api! {
    /// BOOL FindNextFileA(HANDLE, LPVOID);
    unsafe extern "win64" fn FindNextFileA(h: HANDLE, out_find_data: *mut core::ffi::c_void) -> BOOL {
        let dir = match unsafe { handle_get(h) }.map(|o| &o.kind) {
            Some(HostKind::Dir { dir, .. }) => *dir,
            _ => return FALSE,
        };
        loop {
            let ent = libc::readdir(dir);
            if ent.is_null() {
                set_last_error(ERROR_NO_MORE_FILES);
                return FALSE;
            }
            let ent = &*ent;
            let name = std::slice::from_raw_parts(ent.d_name.as_ptr() as *const u8, libc::strlen(ent.d_name.as_ptr()));
            if name == b"." || name == b".." {
                continue;
            }
            let find = out_find_data as *mut WIN32_FIND_DATAA;
            // Phase-1 note: per-handle filter is stored but suffix filtering
            // was applied during FindFirstFile; subsequent entries pass raw.
            (*find).dwFileAttributes = 0;
            let mut data = WIN32_FIND_DATAA::default();
            data.cFileName[..name.len()].copy_from_slice(name);
            data.cFileName[name.len()] = 0;
            *find = data;
            return TRUE;
        }
    }
}

win32_api! {
    /// BOOL FindClose(HANDLE);
    unsafe extern "win64" fn FindClose(h: HANDLE) -> BOOL {
        if handle_free(h) {
            TRUE
        } else {
            FALSE
        }
    }
}

win32_api! {
    /// UINT GetDriveTypeW(LPCWSTR);
    unsafe extern "win64" fn GetDriveTypeW(root: LPCWSTR) -> UINT {
        const DRIVE_FIXED: UINT = 3;
        let _ = read_wide(root);
        DRIVE_FIXED
    }
}

win32_api! {
    /// BOOL GetVolumeInformationW(...);
    #[allow(clippy::too_many_arguments)]
    unsafe extern "win64" fn GetVolumeInformationW(
        root: LPCWSTR,
        volume_name: LPWSTR,
        volume_name_size: DWORD,
        _serial: *mut DWORD,
        max_component_len: *mut DWORD,
        fs_flags: *mut DWORD,
        fs_name: LPWSTR,
        fs_name_size: DWORD,
    ) -> BOOL {
        let _ = read_wide(root);
        let label = wide_from_str("PERUN");
        let written = write_wide(volume_name, volume_name_size as usize, &label);
        if volume_name.is_null() || written > volume_name_size as usize {
            // keep going: Windows still fills the FS part when asked
        }
        let fs = wide_from_str("NTFS");
        write_wide(fs_name, fs_name_size as usize, &fs);
        if !max_component_len.is_null() {
            *max_component_len = 255;
        }
        if !fs_flags.is_null() {
            *fs_flags = 0;
        }
        TRUE
    }
}

win32_api! {
    /// BOOL PeekNamedPipe(HANDLE, ..., LPDWORD, LPDWORD, LPDWORD);
    unsafe extern "win64" fn PeekNamedPipe(
        h: HANDLE,
        _buf: *mut core::ffi::c_void,
        _buf_size: DWORD,
        _read: *mut DWORD,
        avail: *mut DWORD,
        _left: *mut DWORD,
    ) -> BOOL {
        let (fd, _) = match unsafe { handle_get(h) }.map(|o| &o.kind) {
            Some(HostKind::File { fd, shared }) => (*fd, *shared),
            _ => return FALSE,
        };
        let mut pollfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let r = libc::poll(&mut pollfd, 1, 0);
        if r < 0 {
            return FALSE;
        }
        if !avail.is_null() {
            *avail = if pollfd.revents & libc::POLLIN != 0 { 1 } else { 0 };
        }
        TRUE
    }
}

win32_api! {
    /// BOOL GetFileInformationByHandle(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
    unsafe extern "win64" fn GetFileInformationByHandle(
        h: HANDLE,
        info: *mut core::ffi::c_void,
    ) -> BOOL {
        let (fd, _) = match unsafe { handle_get(h) }.map(|o| &o.kind) {
            Some(HostKind::File { fd, shared }) => (*fd, *shared),
            _ => return FALSE,
        };
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 || info.is_null() {
            return FALSE;
        }
        // Layout-compatible prefix of BY_HANDLE_FILE_INFORMATION:
        // attrs(4), creation(8), access(8), write(8), sizeHigh(4), sizeLow(4).
        #[repr(C)]
        struct InfoPrefix {
            attributes: DWORD,
            creation: FILETIME,
            access: FILETIME,
            write: FILETIME,
            size_high: DWORD,
            size_low: DWORD,
        }
        let out = info as *mut InfoPrefix;
        (*out).attributes = if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        (*out).creation = filetime_from_timespec(st.st_ctime, st.st_ctime_nsec);
        (*out).access = filetime_from_timespec(st.st_atime, st.st_atime_nsec);
        (*out).write = filetime_from_timespec(st.st_mtime, st.st_mtime_nsec);
        (*out).size_high = ((st.st_size as u64) >> 32) as DWORD;
        (*out).size_low = (st.st_size as u64) as DWORD;
        TRUE
    }
}
