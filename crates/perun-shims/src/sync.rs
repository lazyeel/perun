// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Synchronization shims: critical sections, events, mutexes, waits.

use std::sync::Condvar;

use crate::util::{
    EventFlags, EventState, HostKind, handle_adopt, handle_get, handle_new, read_wide,
};
use crate::win32::{
    BOOL, DWORD, FALSE, HANDLE, INFINITE, LPCSTR, LPCWSTR, SECURITY_ATTRIBUTES, TRUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use crate::win32_api;

win32_api! {
    /// BOOL InitializeCriticalSectionAndSpinCount(PCRITICAL_SECTION, DWORD);
    unsafe extern "win64" fn InitializeCriticalSectionAndSpinCount(
        cs: *mut CRITICAL_SECTION,
        spin: DWORD,
    ) -> BOOL { unsafe {
        let _ = spin;
        // Guest allocates the CRITICAL_SECTION blob; we require it to be at
        // least pointer-sized and store a boxed recursive mutex inside.
        let inner = Box::new(recursive_mutex_init());
        std::ptr::write(cs.cast::<Box<MutexHandle>>(), inner);
        TRUE
    }}
}

type MutexHandle = pthread_mutex_t_boxed;
type pthread_mutex_t_boxed = libc::pthread_mutex_t;

fn recursive_mutex_init() -> libc::pthread_mutex_t {
    let mut m: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
    let mut attr: libc::pthread_mutexattr_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::pthread_mutexattr_init(&raw mut attr);
        libc::pthread_mutexattr_settype(&raw mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        libc::pthread_mutex_init(&raw mut m, &raw const attr);
        libc::pthread_mutexattr_destroy(&raw mut attr);
    }
    m
}

/// Interpret the guest-provided critical section blob.
///
/// # Safety
/// `cs` must be a blob previously passed to `InitializeCriticalSection`*.
unsafe fn cs_lock(cs: *mut core::ffi::c_void) -> &'static mut libc::pthread_mutex_t {
    unsafe { (cs.cast::<Box<MutexHandle>>().as_mut().expect("cs blob")) as _ }
}

win32_api! {
    /// void InitializeCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn InitializeCriticalSection(cs: *mut CRITICAL_SECTION) { unsafe {
        InitializeCriticalSectionAndSpinCount(cs, 0);
    }}
}

// Keep the raw signature callable from Enter/Leave via the same storage.
type CRITICAL_SECTION = core::ffi::c_void;

win32_api! {
    /// void EnterCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn EnterCriticalSection(cs: *mut CRITICAL_SECTION) { unsafe {
        libc::pthread_mutex_lock(cs_lock(cs));
    }}
}

win32_api! {
    /// void LeaveCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn LeaveCriticalSection(cs: *mut CRITICAL_SECTION) { unsafe {
        libc::pthread_mutex_unlock(cs_lock(cs));
    }}
}

win32_api! {
    /// void DeleteCriticalSection(PCRITICAL_SECTION);
    unsafe extern "win64" fn DeleteCriticalSection(cs: *mut CRITICAL_SECTION) { unsafe {
        let mut boxed = Box::from_raw(cs.cast::<Box<MutexHandle>>());
        libc::pthread_mutex_destroy(&raw mut **boxed);
        drop(boxed);
    }}
}

/// Build a real event object and hand back its handle, so a harness can put a
/// genuine synchronization object where the guest expects one.
///
/// The guest's first move inside the gate object is a blocking
/// `WaitForSingleObject([+0x10], INFINITE)`. An unknown handle makes that shim
/// answer `WAIT_OBJECT_0` at once, which is a fiction: on Windows an unsignaled
/// event would park the thread. This constructor is the only way to give the
/// guest a handle the shim really has to wait on, and therefore the only way to
/// find out whether the guest depends on that answer.
pub fn host_event(manual_reset: bool, signaled: bool) -> HANDLE {
    handle_new(HostKind::Event(EventState {
        state: std::sync::Mutex::new(EventFlags {
            manual_reset,
            signaled,
        }),
        cond: Condvar::new(),
    }))
}

win32_api! {
    /// HANDLE CreateEventA(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
    unsafe extern "win64" fn CreateEventA(
        _sa: *const SECURITY_ATTRIBUTES,
        manual_reset: BOOL,
        initial_state: BOOL,
        name: LPCSTR,
    ) -> HANDLE {
        if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
            eprintln!(
                "[sync] CreateEventA(manual_reset={}, initial={}, name={:?})",
                manual_reset,
                initial_state,
                name as *const i8 as usize
            );
        }
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
    ) -> HANDLE { unsafe {
        // Named events are not shared across guests in phase 1.
        let _name = read_wide(name);
        CreateEventA(sa, manual_reset, initial_state, std::ptr::null())
    }}
}

win32_api! {
    /// BOOL SetEvent(HANDLE);
    unsafe extern "win64" fn SetEvent(h: HANDLE) -> BOOL { unsafe {
        if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
            eprintln!("[sync] SetEvent({:#x})", h as usize);
        }
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
    }}
}

win32_api! {
    /// BOOL ResetEvent(HANDLE);
    unsafe extern "win64" fn ResetEvent(h: HANDLE) -> BOOL { unsafe {
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Event(e)) => {
                e.state.lock().unwrap().signaled = false;
                TRUE
            }
            _ => FALSE,
        }
    }}
}

fn wait_on_event(e: &EventState, timeout_ms: DWORD) -> DWORD {
    // PERUN_EVENT_NOBLOCK=1: single-threaded seq runs have no second thread
    // to SetEvent the object the guest parks on, so an unsignaled event
    // would hang the whole run forever (measured: SignalObjectAndWait into
    // [r14+0x18] never returns). With the switch, the shim answers
    // WAIT_OBJECT_0 at once — the same fiction an unknown handle gets —
    // and the run advances to the next real gate.
    if std::env::var_os("PERUN_EVENT_NOBLOCK").is_some() {
        return WAIT_OBJECT_0;
    }
    let deadline = if timeout_ms == INFINITE {
        None
    } else {
        Some(std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms)))
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
                let (f2, res) = e.cond.wait_timeout(f, dl - now).unwrap();
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
    unsafe extern "win64" fn WaitForSingleObject(h: HANDLE, timeout_ms: DWORD) -> DWORD { unsafe {
        if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
            eprintln!("[sync] WaitForSingleObject({:#x}, {timeout_ms}) kind={:?}", h as usize,
                handle_get(h).map(|o| match o.kind { HostKind::Event(_) => "Event", HostKind::Mutex{..} => "Mutex", _ => "other" }));
        }
        // PERUN_ADOPT_EVENT=1: the worker's success branch reads an event
        // handle through a slot the session never filled -- a truncated
        // heap pointer the handle table cannot know. On Windows the
        // session layer would have minted a real event there. With the
        // switch on, an unknown-but-plausible handle is ADOPTED: the shim
        // mints a fresh host event (signaled, so the wait returns at
        // once), registers it in the table under this handle value, and
        // reports success. The session director can then coordinate it.
        let known = handle_get(h).map(|o| &o.kind);
        if known.is_none()
            && std::env::var_os("PERUN_ADOPT_EVENT").is_some()
            && h as usize >= 0x1000
        {
            let e = host_event(false, true);
            handle_adopt(h, e);
            return WAIT_OBJECT_0;
        }
        match handle_get(h).map(|o| &o.kind) {
            Some(HostKind::Event(e)) => wait_on_event(e, timeout_ms),
            Some(HostKind::Mutex { state, cond }) => {
                let mut locked = state.lock().unwrap();
                while *locked {
                    if timeout_ms == INFINITE {
                        locked = cond.wait(locked).unwrap();
                    } else {
                        let dl =
                            std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));
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
    }}
}

win32_api! {
    /// DWORD SignalObjectAndWait(HANDLE, HANDLE, DWORD, BOOL);
    unsafe extern "win64" fn SignalObjectAndWait(
        to_signal: HANDLE,
        to_wait: HANDLE,
        timeout_ms: DWORD,
        alertable: BOOL,
    ) -> DWORD { unsafe {
        let _ = alertable;
        // PERUN_SESSION_DIRECTOR: the iTunes contract has the HOST own the
        // second thread of the producer-consumer pair -- CoreADI64 never
        // creates one (no CreateThread in its imports). With the switch on,
        // a one-shot host thread stands in: it waits for the guest's
        // hEventWorkReady (to_signal) and then sets hEventWorkDone
        // (to_wait), so the guest's own INFINITE wait returns instead of
        // parking forever on a one-thread host.
        if std::env::var_os("PERUN_SESSION_DIRECTOR").is_some()
            && matches!(handle_get(to_wait).map(|o| &o.kind), Some(HostKind::Event(_)))
        {
            session_director_once(to_signal, to_wait);
        }
        SetEvent(to_signal);
        WaitForSingleObject(to_wait, timeout_ms)
    }}
}

/// One-shot stand-in for the host's worker thread. Spawned the first time a
/// SignalObjectAndWait sees an event pair with the director enabled; parked
/// on the ready-event until the guest signals it, then the done-event is
/// set so the guest's wait unblocks. The thread exits after one cycle.
fn session_director_once(ready: HANDLE, done: HANDLE) {
    static DIRECTOR: std::sync::Once = std::sync::Once::new();
    DIRECTOR.call_once(|| {
        // HANDLE is a raw pointer, which is not Send. The handle table is
        // global and the objects it names outlive this thread (they are the
        // guest's own events), so the boundary crossing is sound; wrap it.
        let ready = ready as usize;
        let done = done as usize;
        std::thread::spawn(move || unsafe {
            let ready = ready as HANDLE;
            let done = done as HANDLE;
            if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
                eprintln!("[sync] session director: waiting ready {ready:?}");
            }
            // Wait for the guest's "work ready" signal. The handle kinds were
            // validated by the caller; unknown ready-handles fall through the
            // shim's unknown-object fiction and the wait returns at once.
            let _ = WaitForSingleObject(ready, INFINITE);
            if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
                eprintln!("[sync] session director: ready seen, setting done {done:?}");
            }
            let _ = SetEvent(done);
        });
    });
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
    ) -> HANDLE { unsafe {
        let name_s = String::from_utf16_lossy(&read_wide(name));
        if std::env::var("PERUN_TRACE").is_ok() {
            eprintln!("[perun] CreateMutexW({name_s:?})");
        }
        let _ = name_s;
        CreateMutexA(sa, initial_owner, std::ptr::null())
    }}
}

win32_api! {
    /// BOOL ReleaseMutex(HANDLE);
    unsafe extern "win64" fn ReleaseMutex(h: HANDLE) -> BOOL { unsafe {
        if std::env::var_os("PERUN_TRACE_SYNC").is_some() {
            eprintln!("[sync] ReleaseMutex({:#x})", h as usize);
        }
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
    }}
}
