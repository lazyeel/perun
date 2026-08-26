// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Synchronization shims: critical sections, events, mutexes, waits.

use std::sync::Condvar;

use crate::win32_api;
use crate::util::*;
use crate::win32::*;

win32_api! {
    /// BOOL InitializeCriticalSectionAndSpinCount(PCRITICAL_SECTION, DWORD);
    unsafe extern "win64" fn InitializeCriticalSectionAndSpinCount(
        cs: *mut CRITICAL_SECTION,
        spin: DWORD,
    ) -> BOOL {
        let _ = spin;
        // Guest allocates the CRITICAL_SECTION blob; we require it to be at
        // least pointer-sized and store a boxed recursive mutex inside.
        let inner = Box::new(recursive_mutex_init());
        std::ptr::write(cs as *mut Box<MutexHandle>, inner);
        TRUE
    }
}

type MutexHandle = pthread_mutex_t_boxed;
type pthread_mutex_t_boxed = libc::pthread_mutex_t;

fn recursive_mutex_init() -> libc::pthread_mutex_t {
    let mut m: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
    let mut attr: libc::pthread_mutexattr_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::pthread_mutexattr_init(&mut attr);
        libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        libc::pthread_mutex_init(&mut m, &attr);
        libc::pthread_mutexattr_destroy(&mut attr);
    }
    m
}

/// Interpret the guest-provided critical section blob.
///
/// # Safety
/// `cs` must be a blob previously passed to InitializeCriticalSection*.
unsafe fn cs_lock(cs: *mut core::ffi::c_void) -> &'static mut libc::pthread_mutex_t {
    let boxed = (cs as *mut Box<MutexHandle>).as_mut().expect("cs blob");
    &mut **boxed
}

win32_api! {
    /// void InitializeCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn InitializeCriticalSection(cs: *mut CRITICAL_SECTION) {
        InitializeCriticalSectionAndSpinCount(cs, 0);
    }
}

// Keep the raw signature callable from Enter/Leave via the same storage.
type CRITICAL_SECTION = core::ffi::c_void;

win32_api! {
    /// void EnterCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn EnterCriticalSection(cs: *mut CRITICAL_SECTION) {
        libc::pthread_mutex_lock(cs_lock(cs));
    }
}

win32_api! {
    /// void LeaveCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn LeaveCriticalSection(cs: *mut CRITICAL_SECTION) {
        libc::pthread_mutex_unlock(cs_lock(cs));
    }
}

win32_api! {
    /// void DeleteCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn DeleteCriticalSection(cs: *mut CRITICAL_SECTION) {
        let mut boxed = Box::from_raw(cs as *mut Box<MutexHandle>);
        libc::pthread_mutex_destroy(&mut **boxed);
        drop(boxed);
    }
}

win32_api! {
    /// HANDLE CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
    unsafe extern "win64" fn CreateEventA(
        _sa: *const SECURITY_ATTRIBUTES,
        manual_reset: BOOL,
        initial_state: BOOL,
        _name: LPCSTR,
    ) -> HANDLE {
        handle_new(HostKind::Event(EventState {
            state: std::sync::Mutex::new(EventFlags {
                manual_reset: manual_reset != 0,
                signaled: initial_state != 0,
            }),
            cond: Condvar::new(),
        }))
    }
}

win32_api! {
    /// HANDLE CreateEventW(...);
    unsafe extern "win64" fn CreateEventW(
        sa: *const SECURITY_ATTRIBUTES,
        manual_reset: BOOL,
        initial_state: BOOL,
        name: LPCWSTR,
    ) -> HANDLE {
        // Named events are not shared across guests in phase 1.
        let _name = read_wide(name);
        CreateEventA(sa, manual_reset, initial_state, std::ptr::null())
    }
}

win32_api! {
    /// BOOL SetEvent(HANDLE);
    unsafe extern "win64" fn SetEvent(h: HANDLE) -> BOOL {
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Event(e)) => {
                let mut f = e.state.lock().unwrap();
                f.signaled = true;
                if f.manual_reset {
                    e.cond.notify_all();
                } else {
                    e.cond.notify_one();
                }
                TRUE
            }
            _ => FALSE,
        }
    }
}

win32_api! {
    /// BOOL ResetEvent(HANDLE);
    unsafe extern "win64" fn ResetEvent(h: HANDLE) -> BOOL {
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Event(e)) => {
                e.state.lock().unwrap().signaled = false;
                TRUE
            }
            _ => FALSE,
        }
    }
}

fn wait_on_event(e: &EventState, timeout_ms: DWORD) -> DWORD {
    let deadline = if timeout_ms == INFINITE {
        None
    } else {
        Some(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64))
    };
    let mut f = e.state.lock().unwrap();
    while !f.signaled {
        match deadline {
            None => {
                f = e.cond.wait(f).unwrap();
            }
            Some(dl) => {
                let now = std::time::Instant::now();
                if now >= dl {
                    return WAIT_TIMEOUT;
                }
                let (f2, res) = e
                    .cond
                    .wait_timeout(f, dl - now)
                    .unwrap();
                f = f2;
                if res.timed_out() && !f.signaled {
                    return WAIT_TIMEOUT;
                }
            }
        }
    }
    if !f.manual_reset {
        f.signaled = false; // auto-reset consumes the signal
    }
    WAIT_OBJECT_0
}

win32_api! {
    /// DWORD WaitForSingleObject(HANDLE, DWORD);
    unsafe extern "win64" fn WaitForSingleObject(h: HANDLE, timeout_ms: DWORD) -> DWORD {
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Event(e)) => wait_on_event(e, timeout_ms),
            Some(HostKind::Mutex { state, cond }) => {
                let mut locked = state.lock().unwrap();
                while *locked {
                    if timeout_ms == INFINITE {
                        locked = cond.wait(locked).unwrap();
                    } else {
                        let dl =
                            std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
                        let (l2, res) = cond.wait_timeout(locked, dl - std::time::Instant::now()).unwrap();
                        locked = l2;
                        if res.timed_out() && *locked {
                            return WAIT_TIMEOUT;
                        }
                    }
                }
                *locked = true;
                WAIT_OBJECT_0
            }
            // Pseudo-handles and unknown objects succeed immediately, matching
            // the validated prototype behavior for this guest class.
            _ => WAIT_OBJECT_0,
        }
    }
}

win32_api! {
    /// DWORD SignalObjectAndWait(HANDLE, HANDLE, DWORD, BOOL);
    unsafe extern "win64" fn SignalObjectAndWait(
        to_signal: HANDLE,
        to_wait: HANDLE,
        timeout_ms: DWORD,
        alertable: BOOL,
    ) -> DWORD {
        let _ = alertable;
        SetEvent(to_signal);
        WaitForSingleObject(to_wait, timeout_ms)
    }
}

win32_api! {
    /// HANDLE CreateMutexA(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
    unsafe extern "win64" fn CreateMutexA(
        _sa: *const SECURITY_ATTRIBUTES,
        initial_owner: BOOL,
        _name: LPCSTR,
    ) -> HANDLE {
        handle_new(HostKind::Mutex {
            state: std::sync::Mutex::new(initial_owner != 0),
            cond: Condvar::new(),
        })
    }
}

win32_api! {
    /// HANDLE CreateMutexW(...);
    unsafe extern "win64" fn CreateMutexW(
        sa: *const SECURITY_ATTRIBUTES,
        initial_owner: BOOL,
        name: LPCWSTR,
    ) -> HANDLE {
        let name_s = String::from_utf16_lossy(&read_wide(name));
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] CreateMutexW({:?})", name_s);
        }
        let _ = name_s;
        CreateMutexA(sa, initial_owner, std::ptr::null())
    }
}

win32_api! {
    /// BOOL ReleaseMutex(HANDLE);
    unsafe extern "win64" fn ReleaseMutex(h: HANDLE) -> BOOL {
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Mutex { state, cond }) => {
                let mut l = state.lock().unwrap();
                if *l {
                    *l = false;
                    cond.notify_one();
                    TRUE
                } else {
                    FALSE // not owned
                }
            }
            _ => FALSE,
        }
    }
}
