// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

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
pub const ERROR_INVALID_PARAMETER: DWORD = 87;
pub const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;
pub const ERROR_MORE_DATA: DWORD = 234;
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

/// `WIN32_FIND_DATAA` (ANSI variant used by FindFirstFileExA).
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

/// `FILE_ATTRIBUTE_DATA` for GetFileAttributesExW.
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
    pub fn from_u64(v: u64) -> FILETIME {
        FILETIME {
            dwLowDateTime: v as u32,
            dwHighDateTime: (v >> 32) as u32,
        }
    }
    pub fn as_u64(self) -> u64 {
        (self.dwHighDateTime as u64) << 32 | self.dwLowDateTime as u64
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
