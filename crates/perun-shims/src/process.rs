// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Process, thread info, entropy, crypto and time shims.

use crate::util::*;
use crate::win32::*;
use crate::win32_api;

// ── Process / thread identity ─────────────────────────────────────────────

win32_api! {
    /// DWORD GetCurrentProcessId(VOID);
    unsafe extern "win64" fn GetCurrentProcessId() -> DWORD {
        unsafe { libc::getpid() as DWORD }
    }
}

win32_api! {
    /// DWORD GetCurrentThreadId(VOID);
    unsafe extern "win64" fn GetCurrentThreadId() -> DWORD {
        unsafe { libc::syscall(libc::SYS_gettid) as DWORD }
    }
}

win32_api! {
    /// HANDLE GetCurrentProcess(VOID);
    unsafe extern "win64" fn GetCurrentProcess() -> HANDLE {
        PSEUDO_PROCESS
    }
}

win32_api! {
    /// HANDLE GetCurrentThread(VOID);
    unsafe extern "win64" fn GetCurrentThread() -> HANDLE {
        PSEUDO_THREAD
    }
}

win32_api! {
    /// BOOL IsDebuggerPresent(VOID);
    unsafe extern "win64" fn IsDebuggerPresent() -> BOOL {
        // TracerPid from /proc/self/status.
        let mut s = String::new();
        if std::fs::File::open("/proc/self/status")
            .and_then(|mut f| std::io::Read::read_to_string(&mut f, &mut s))
            .is_ok()
        {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    return rest.trim().parse::<u32>().map(|v| (v != 0) as BOOL).unwrap_or(0);
                }
            }
        }
        0
    }
}

win32_api! {
    /// BOOL IsProcessorFeaturePresent(DWORD);
    unsafe extern "win64" fn IsProcessorFeaturePresent(feature: DWORD) -> BOOL {
        // PF_XSAVE_ENABLED = 17 is what MSVC CRT startup probes most often;
        // x86_64 Linux always has xsave. Everything else: report present too —
        // a false "yes" only matters if the guest then uses the feature,
        // which x86_64 baseline supports anyway.
        const PF_XSAVE_ENABLED: DWORD = 17;
        let _ = feature;
        (PF_XSAVE_ENABLED == feature || true) as BOOL
    }
}

// ── Time ─────────────────────────────────────────────────────────────────

win32_api! {
    /// void GetSystemTimeAsFileTime(LPFILETIME);
    unsafe extern "win64" fn GetSystemTimeAsFileTime(ft: *mut FILETIME) {
        let mut ts: libc::timespec = std::mem::zeroed();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        *ft = FILETIME::from_u64(unix_to_filetime(ts.tv_sec as i64, ts.tv_nsec as u32));
    }
}

win32_api! {
    /// BOOL QueryPerformanceCounter(LARGE_INTEGER*);
    unsafe extern "win64" fn QueryPerformanceCounter(counter: *mut i64) -> BOOL {
        let mut ts: libc::timespec = std::mem::zeroed();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        *counter = (ts.tv_sec as i64) * 1_000_000_000 + ts.tv_nsec as i64;
        TRUE
    }
}

fn systemtime_from_tm(tm: &libc::tm, millis: u16) -> SYSTEMTIME {
    // Windows: Sunday=0..Saturday=6; tm: Sunday=0 — same mapping.
    SYSTEMTIME {
        wYear: (tm.tm_year + 1900) as WORD,
        wMonth: (tm.tm_mon + 1) as WORD,
        wDayOfWeek: tm.tm_wday as WORD,
        wDay: tm.tm_mday as WORD,
        wHour: tm.tm_hour as WORD,
        wMinute: tm.tm_min as WORD,
        wSecond: tm.tm_sec as WORD,
        wMilliseconds: millis,
    }
}

win32_api! {
    /// void GetLocalTime(LPSYSTEMTIME);
    unsafe extern "win64" fn GetLocalTime(st: *mut SYSTEMTIME) {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        unsafe { libc::localtime_r(&t, &mut tm) };
        *st = systemtime_from_tm(&tm, 0);
    }
}

win32_api! {
    /// DWORD GetTimeZoneInformation(LPTIME_ZONE_INFORMATION);
    unsafe extern "win64" fn GetTimeZoneInformation(tz: *mut TIME_ZONE_INFORMATION) -> DWORD {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        unsafe { libc::localtime_r(&t, &mut tm) };
        // Windows Bias is minutes west of UTC; tm_gmtoff is seconds east.
        (*tz).Bias = -((tm.tm_gmtoff / 60) as LONG);
        (*tz).StandardBias = 0;
        // Phase-1: no DST name/date tables; report unknown so guests do not
        // apply daylight corrections against empty strings.
        (*tz).DaylightBias = 0;
        TIME_ZONE_ID_UNKNOWN
    }
}

// ── Entropy / crypto (advapi32 surface) ───────────────────────────────────

win32_api! {
    /// BOOL CryptAcquireContextA(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
    unsafe extern "win64" fn CryptAcquireContextA(
        prov: *mut HANDLE,
        _container: LPCSTR,
        _provider: LPCSTR,
        prov_type: DWORD,
        flags: DWORD,
    ) -> BOOL {
        const CRYPT_VERIFYCONTEXT: DWORD = 0xF000_0000;
        let _ = (prov_type, CRYPT_VERIFYCONTEXT);
        if !prov.is_null() {
            // Non-null, non-invalid sentinel distinct from other handles.
            *prov = 0x0000_C1F0usize as HANDLE;
        }
        TRUE
    }
}

win32_api! {
    /// BOOL CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
    unsafe extern "win64" fn CryptAcquireContextW(
        prov: *mut HANDLE,
        container: LPCWSTR,
        provider: LPCWSTR,
        prov_type: DWORD,
        flags: DWORD,
    ) -> BOOL {
        let _ = (read_wide(container), read_wide(provider));
        CryptAcquireContextA(prov, std::ptr::null(), std::ptr::null(), prov_type, flags)
    }
}

win32_api! {
    /// BOOL CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
    unsafe extern "win64" fn CryptGenRandom(prov: HANDLE, len: DWORD, buf: *mut BYTE) -> BOOL {
        let _ = prov;
        if buf.is_null() || len == 0 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        // getrandom(2): no fd juggling, no partial-read dance on these sizes.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                buf as *mut core::ffi::c_void,
                len as usize,
                0usize,
            )
        };
        if n as isize == len as isize {
            TRUE
        } else {
            set_last_error(ERROR_INVALID_PARAMETER);
            FALSE
        }
    }
}

win32_api! {
    /// BOOL CryptReleaseContext(HCRYPTPROV, DWORD);
    unsafe extern "win64" fn CryptReleaseContext(prov: HANDLE, flags: DWORD) -> BOOL {
        let _ = (prov, flags);
        TRUE
    }
}

// ── Registry stubs over the synthetic store ──────────────────────────────

use crate::registry::{RegType, Registry};

const HKEY_LOCAL_MACHINE: HANDLE = 0x8000_0002usize as HANDLE;
const HKEY_CURRENT_USER: HANDLE = 0x8000_0001usize as HANDLE;

win32_api! {
    /// LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    unsafe extern "win64" fn RegOpenKeyExA(
        key: HANDLE,
        subkey: LPCSTR,
        _options: DWORD,
        _access: u32,
        result: *mut HANDLE,
    ) -> LONG {
        let root = if key == HKEY_LOCAL_MACHINE {
            "HKEY_LOCAL_MACHINE"
        } else if key == HKEY_CURRENT_USER {
            "HKEY_CURRENT_USER"
        } else {
            "?"
        };
        let sub = read_narrow(subkey);
        let sub = String::from_utf8_lossy(&sub);
        let path = format!("{root}\\{}", sub.replace('/', "\\"));
        let exists = Registry::global().key_exists(&path);
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] RegOpenKeyExA({:?}) -> {}", path, if exists { 0 } else { 2 });
        }
        if exists {
            if !result.is_null() {
                *result = path.len() as HANDLE; // opaque key token
            }
            0 // ERROR_SUCCESS
        } else {
            2 // ERROR_FILE_NOT_FOUND
        }
    }
}

win32_api! {
    /// LONG RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    unsafe extern "win64" fn RegQueryValueExA(
        key: HANDLE,
        value_name: LPCSTR,
        _reserved: *mut DWORD,
        out_type: *mut DWORD,
        out_data: *mut BYTE,
        inout_size: *mut DWORD,
    ) -> LONG {
        // The key token is the path length; we cannot recover the path from it
        // in phase 1, so queries succeed only for preseeded lookups by name.
        let _ = key;
        let name = read_narrow(value_name);
        let name = String::from_utf8_lossy(&name);
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] RegQueryValueExA({:?})", name);
        }
        match Registry::global().get(&name) {
            Some(v) => {
                let need = v.data.len() as DWORD;
                let cap = if inout_size.is_null() { 0 } else { *inout_size };
                if !out_type.is_null() {
                    *out_type = match v.kind {
                        RegType::Sz => 1,       // REG_SZ
                        RegType::Dword => 4,    // REG_DWORD
                        RegType::Binary => 3,   // REG_BINARY
                    };
                }
                if !inout_size.is_null() {
                    *inout_size = need;
                }
                if !out_data.is_null() && cap >= need {
                    std::ptr::copy_nonoverlapping(v.data.as_ptr(), out_data, need as usize);
                }
                if cap < need {
                    ERROR_MORE_DATA as LONG
                } else {
                    0
                }
            }
            None => 2, // ERROR_FILE_NOT_FOUND
        }
    }
}

win32_api! {
    /// LONG RegCloseKey(HKEY);
    unsafe extern "win64" fn RegCloseKey(key: HANDLE) -> LONG {
        let _ = key;
        0
    }
}

win32_api! {
    /// void GetStartupInfoW(LPSTARTUPINFOW);
    unsafe extern "win64" fn GetStartupInfoW(si: *mut STARTUPINFOW) {
        // Zeroed startup info with cb set; no console, no std handles.
        // CRT only needs a valid block here during DLL init.
        if !si.is_null() {
            std::ptr::write_bytes(si as *mut u8, 0, std::mem::size_of::<STARTUPINFOW>());
            (*si).cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
        }
    }
}

win32_api! {
    /// UINT GetACP(void);
    unsafe extern "win64" fn GetACP() -> UINT {
        // 65001 = UTF-8. Matches the shim layer's string handling.
        65001
    }
}
