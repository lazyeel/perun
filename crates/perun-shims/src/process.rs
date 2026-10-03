// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

// A process shim hands the guest the PID and TID it was given, the
// // thread index Windows counts in a `DWORD`, and the environment block
// // offsets it composes. Those are the guest's own widths; narrowing one
// // is a caller contract violation the shim reports, not one it hides.
#![allow(unknown_lints)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

//! Process, thread info, entropy, crypto and time shims.

use crate::util::{
    PSEUDO_PROCESS, PSEUDO_THREAD, read_narrow, read_wide, set_last_error, unix_to_filetime,
};
use crate::win32::{
    BOOL, BYTE, DWORD, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, FALSE, FILETIME, HANDLE, LONG,
    LPCSTR, LPCWSTR, LPWSTR, STARTUPINFOW, SYSTEMTIME, TIME_ZONE_ID_UNKNOWN, TIME_ZONE_INFORMATION,
    TRUE, UINT, WORD,
};
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
                    return rest.trim().parse::<u32>().map_or(0, |v| BOOL::from(v != 0));
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
        BOOL::from(PF_XSAVE_ENABLED == feature || true)
    }
}

// ── Time ─────────────────────────────────────────────────────────────────

win32_api! {
    /// void GetSystemTimeAsFileTime(LPFILETIME);
    unsafe extern "win64" fn GetSystemTimeAsFileTime(ft: *mut FILETIME) {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut ts);
        *ft = FILETIME::from_u64(unix_to_filetime(ts.tv_sec as i64, ts.tv_nsec as u32));
    }
    }
}

win32_api! {
    /// BOOL QueryPerformanceCounter(LARGE_INTEGER*);
    unsafe extern "win64" fn QueryPerformanceCounter(counter: *mut i64) -> BOOL {
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
        *counter = (ts.tv_sec as i64) * 1_000_000_000 + ts.tv_nsec as i64;
        TRUE
    }
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
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&raw const t, &raw mut tm);
        *st = systemtime_from_tm(&tm, 0);
    }
    }
}

win32_api! {
    /// BOOL FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME);
    ///
    /// The inverse of `SystemTimeToFileTime`, and the conversion an SPIM needs:
    /// the ADI cache carries timestamps in `FILETIME`, so reading one reaches
    /// this before anything else. It was missing, and an unresolved import here
    /// is a trap that returns without writing the output — the caller then reads
    /// whatever was already in the buffer, which is how a *reachable* cache file
    /// still produced nothing downstream.
    unsafe extern "win64" fn FileTimeToSystemTime(ft: *const FILETIME, st: *mut SYSTEMTIME) -> BOOL {
    unsafe {
        if ft.is_null() || st.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        // FILETIME counts 100ns ticks from 1601-01-01; the epoch offset is the
        // 369 years between that and 1970 in seconds, then scaled to ticks.
        let ticks = (*ft).as_u64();
        let secs = (ticks / 10_000_000) as i64 - 11_644_473_600;
        let sub = (ticks % 10_000_000) / 10_000;
        let mut tm: libc::tm = std::mem::zeroed();
        let t = secs as libc::time_t;
        if libc::gmtime_r(&raw const t, &raw mut tm).is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *st = systemtime_from_tm(&tm, sub as u16);
        TRUE
    }
    }
}

win32_api! {
    /// BOOL SystemTimeToFileTime(const SYSTEMTIME*, LPFILETIME);
    unsafe extern "win64" fn SystemTimeToFileTime(st: *const SYSTEMTIME, ft: *mut FILETIME) -> BOOL {
    unsafe {
        if st.is_null() || ft.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        // timegm(), not mktime(): a FILETIME has no zone, so the fields are
        // already UTC and applying the local offset would shift them twice.
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = (*st).wYear as i32 - 1900;
        tm.tm_mon = (*st).wMonth as i32 - 1;
        tm.tm_mday = (*st).wDay as i32;
        tm.tm_hour = (*st).wHour as i32;
        tm.tm_min = (*st).wMinute as i32;
        tm.tm_sec = (*st).wSecond as i32;
        let secs = libc::timegm(&raw mut tm);
        if secs == -1 {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        let ticks = (secs + 11_644_473_600).max(0) as u64 * 10_000_000
            + u64::from((*st).wMilliseconds) * 10_000;
        *ft = FILETIME::from_u64(ticks);
        TRUE
    }
    }
}

win32_api! {
    /// BOOL SystemTimeToTzSpecificLocalTime(LPTIME_ZONE_INFORMATION,
    ///                                      LPSYSTEMTIME, LPSYSTEMTIME);
    ///
    /// Converts UTC to a named zone's wall clock. A null zone pointer means
    /// "the current zone", which is what the ADI SPIM path passes: it stamps
    /// cache entries with local times, so a resolved cache file reaches this
    /// immediately. It was an unresolved import, and an unresolved import is a
    /// trap that returns without writing the output buffer — the caller then
    /// reads whatever was already there, which is why a *found* SPIM still
    /// yielded no token.
    unsafe extern "win64" fn SystemTimeToTzSpecificLocalTime(
        tz: *const TIME_ZONE_INFORMATION,
        utc: *const SYSTEMTIME,
        local: *mut SYSTEMTIME,
    ) -> BOOL {
    unsafe {
        if utc.is_null() || local.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        // Bias is minutes *west* of UTC, so the wall clock is bias minutes
        // ahead of the UTC fields.
        let bias = if tz.is_null() { host_bias_minutes() } else { (*tz).Bias };
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = (*utc).wYear as i32 - 1900;
        tm.tm_mon = (*utc).wMonth as i32 - 1;
        tm.tm_mday = (*utc).wDay as i32;
        tm.tm_hour = (*utc).wHour as i32;
        tm.tm_min = (*utc).wMinute as i32;
        tm.tm_sec = (*utc).wSecond as i32;
        tm.tm_isdst = -1;
        let shifted = libc::timegm(&raw mut tm) + i64::from(bias) * 60;
        let mut out: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&raw const shifted, &raw mut out).is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *local = systemtime_from_tm(&out, (*utc).wMilliseconds);
        TRUE
    }
    }
}

win32_api! {
    /// BOOL TzSpecificLocalTimeToSystemTime(LPTIME_ZONE_INFORMATION,
    ///                                      LPSYSTEMTIME, LPSYSTEMTIME);
    unsafe extern "win64" fn TzSpecificLocalTimeToSystemTime(
        tz: *const TIME_ZONE_INFORMATION,
        local: *const SYSTEMTIME,
        utc: *mut SYSTEMTIME,
    ) -> BOOL {
    unsafe {
        if local.is_null() || utc.is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        let bias = if tz.is_null() { host_bias_minutes() } else { (*tz).Bias };
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = (*local).wYear as i32 - 1900;
        tm.tm_mon = (*local).wMonth as i32 - 1;
        tm.tm_mday = (*local).wDay as i32;
        tm.tm_hour = (*local).wHour as i32;
        tm.tm_min = (*local).wMinute as i32;
        tm.tm_sec = (*local).wSecond as i32;
        let back = libc::timegm(&raw mut tm) - i64::from(bias) * 60;
        let mut out: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&raw const back, &raw mut out).is_null() {
            set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *utc = systemtime_from_tm(&out, (*local).wMilliseconds);
        TRUE
    }
    }
}

/// Minutes west of UTC for the host, the quantity Win32 calls `Bias`.
fn host_bias_minutes() -> i32 {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&raw const t, &raw mut tm);
        -((tm.tm_gmtoff / 60) as i32)
    }
}

win32_api! {
    /// DWORD GetTimeZoneInformation(LPTIME_ZONE_INFORMATION);
    unsafe extern "win64" fn GetTimeZoneInformation(tz: *mut TIME_ZONE_INFORMATION) -> DWORD {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&raw const t, &raw mut tm);
        // Windows Bias is minutes west of UTC; tm_gmtoff is seconds east.
        (*tz).Bias = -((tm.tm_gmtoff / 60) as LONG);
        (*tz).StandardBias = 0;
        // Phase-1: no DST name/date tables; report unknown so guests do not
        // apply daylight corrections against empty strings.
        (*tz).DaylightBias = 0;
        TIME_ZONE_ID_UNKNOWN
    }
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
    unsafe {
        const CRYPT_VERIFYCONTEXT: DWORD = 0xF000_0000;
        let _ = (prov_type, CRYPT_VERIFYCONTEXT);
        if !prov.is_null() {
            // Non-null, non-invalid sentinel distinct from other handles.
            *prov = 0x0000_C1F0usize as HANDLE;
        }
        TRUE
    }
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
    unsafe {
        let _ = (read_wide(container), read_wide(provider));
        CryptAcquireContextA(prov, std::ptr::null(), std::ptr::null(), prov_type, flags)
    }
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
                buf.cast::<core::ffi::c_void>(),
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
    unsafe {
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
    unsafe {
        // The key token is the path length; we cannot recover the path from it
        // in phase 1, so queries succeed only for preseeded lookups by name.
        let _ = key;
        let name = read_narrow(value_name);
        let name = String::from_utf8_lossy(&name);
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] RegQueryValueExA({name:?})");
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
    unsafe {
        // Zeroed startup info with cb set; no console, no std handles.
        // CRT only needs a valid block here during DLL init.
        if !si.is_null() {
            std::ptr::write_bytes(si.cast::<u8>(), 0, std::mem::size_of::<STARTUPINFOW>());
            (*si).cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
        }
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

win32_api! {
    /// DWORD GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
    /// The path of a loaded module. CoreFP.dll asks for its own at DllMain.
    unsafe extern "win64" fn GetModuleFileNameW(
        module: HANDLE,
        buf: LPWSTR,
        size: DWORD,
    ) -> DWORD {
        unsafe {
            let _ = module;
            // The path of the image as the guest would see it on its own
            // platform. This runtime exists to present that platform, not to
            // report the host's: an empty string is truthful about Linux and
            // useless to a Windows DLL, which reads it as "running somewhere
            // strange" and takes a different path. Note the earlier version of
            // this comment argued the opposite and was wrong on the axis --
            // fidelity is owed to the guest's platform, not to the container.
            static PATH: &[u8] = b"C:\\Program Files\\iTunes\\iTunes.exe\0";
            let wide_len = PATH.len() - 1;              // characters, no NUL
            if buf.is_null() || size == 0 {
                return 0;
            }
            // Win32 truncates and reports the stored length, not the source
            // length; the caller sizes the buffer from the return value.
            let n = (wide_len).min(size as usize);
            for (i, &b) in PATH.iter().take(n).enumerate() {
                *buf.add(i) = b as u16;
            }
            if (size as usize) <= wide_len {
                // No room for the terminator: the API still returns the full
                // length it tried to store.
                return wide_len as DWORD;
            }
            *buf.add(n) = 0;
            wide_len as DWORD
        }
    }
}

win32_api! {
    /// BOOL IsValidCodePage(UINT);
    /// CoreFP.dll probes the OEM code page during DllMain. Every code page the
    /// runtime can serve is valid, so the probe answers true.
    unsafe extern "win64" fn IsValidCodePage(cp: UINT) -> i32 {
        let _ = cp;
        1
    }
}
