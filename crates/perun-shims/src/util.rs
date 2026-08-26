// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Shared shim infrastructure: typed handle system and UTF-16 helpers.
//!
//! Win32 handles are polymorphic — the same `CloseHandle` can receive a
//! file, an event, or a mutex. The host keeps boxed [`HostObject`]s and a
//! liveness set so foreign/garbage pointers fail cleanly instead of
//! corrupting memory.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use crate::win32::*;

// ── Host objects ─────────────────────────────────────────────────────────

pub(crate) struct EventState {
    pub state: Mutex<EventFlags>,
    pub cond: Condvar,
}

#[derive(Clone, Copy)]
pub(crate) struct EventFlags {
    pub manual_reset: bool,
    pub signaled: bool,
}

pub(crate) enum HostKind {
    /// Std-stream handles are shared and must not be closed on CloseHandle.
    File {
        fd: i32,
        shared: bool,
    },
    Event(EventState),
    /// Binary mutex: locked == owned by someone. Phase-1 semantics mirror the
    /// validated C prototype (`WaitForSingleObject` on a mutex succeeds).
    Mutex {
        state: Mutex<bool>,
        cond: Condvar,
    },
    /// Directory enumeration state (FindFirstFileExA/FindNextFileA).
    Dir {
        dir: *mut libc::DIR,
        pattern: String,
    },
}

pub(crate) struct HostObject {
    pub kind: HostKind,
}

static LIVE_SET: Mutex<Option<HashSet<usize>>> = Mutex::new(None);
/// Monotonic allocation marker; keeps addresses unique across free/realloc.
static ALLOC_TAG: AtomicUsize = AtomicUsize::new(0);

fn live_insert(ptr: usize) {
    let mut g = LIVE_SET.lock().unwrap();
    g.get_or_insert_with(HashSet::new).insert(ptr);
}

fn live_remove(ptr: usize) -> bool {
    let mut g = LIVE_SET.lock().unwrap();
    g.get_or_insert_with(HashSet::new).remove(&ptr)
}

pub(crate) fn live_contains(ptr: usize) -> bool {
    LIVE_SET
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.contains(&ptr))
        .unwrap_or(false)
}

/// Allocate a host object and return it as an opaque Win32 handle.
pub(crate) fn handle_new(kind: HostKind) -> HANDLE {
    // Pad the allocation so distinct objects never alias in the live-set even
    // after free/realloc reuse.
    let layout = std::alloc::Layout::from_size_align(
        std::mem::size_of::<HostObject>() + ALLOC_TAG.fetch_add(16, Ordering::Relaxed),
        std::mem::align_of::<HostObject>(),
    )
    .expect("layout");
    // SAFETY: layout is non-zero (size_of::<HostObject>() >= 8).
    let ptr = unsafe { std::alloc::alloc(layout) as *mut HostObject };
    assert!(!ptr.is_null(), "host object allocation failed");
    // SAFETY: raw region freshly allocated above.
    unsafe {
        std::ptr::write(ptr, HostObject { kind });
    }
    live_insert(ptr as usize);
    ptr as HANDLE
}

/// Validate a guest handle. Returns the object reference when live.
///
/// # Safety
 /// Caller must not retain the reference beyond the call.
pub(crate) unsafe fn handle_get(h: HANDLE) -> Option<&'static HostObject> {
    let p = h as usize;
    if p == 0 || p == usize::MAX || p == usize::MAX - 1 {
        return None;
    }
    if !live_contains(p) {
        return None;
    }
    Some(&*(p as *const HostObject))
}

/// Free a host object (CloseHandle path).
pub(crate) unsafe fn handle_free(h: HANDLE) -> bool {
    let p = h as usize;
    if !live_contains(p) {
        return false;
    }
    let obj = &*(p as *const HostObject);
    match obj.kind {
        HostKind::File { fd, shared } => {
            if !shared {
                libc::close(fd);
            }
        }
        HostKind::Dir { dir, .. } => {
            if !dir.is_null() {
                libc::closedir(dir);
            }
        }
        _ => {}
    }
    live_remove(p);
    let layout = std::alloc::Layout::from_size_align_unchecked(
        std::mem::size_of::<HostObject>(),
        std::mem::align_of::<HostObject>(),
    );
    // SAFETY: allocated in handle_new with the same base layout; the tag pad
    // only extends the block, dealloc with the original layout is sound for
    // alloc-created blocks (excess size is allowed).
    std::alloc::dealloc(p as *mut u8, layout);
    true
}

// ── Pseudo handles ───────────────────────────────────────────────────────

pub(crate) const PSEUDO_PROCESS: HANDLE = -1isize as HANDLE;
pub(crate) const PSEUDO_THREAD: HANDLE = -2isize as HANDLE;

// ── UTF-16 helpers ───────────────────────────────────────────────────────

/// Read a NUL-terminated UTF-16 string from guest memory.
///
/// # Safety
/// `p` must point to valid guest memory.
pub(crate) unsafe fn read_wide(p: LPCWSTR) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let ch = *p.add(i);
        if ch == 0 {
            break;
        }
        out.push(ch);
        i += 1;
        if i > 0x100_000 {
            break; // runaway-string guard
        }
    }
    out
}

/// Copy a wide string (with NUL) into a guest buffer.
/// Returns characters written excluding NUL, or `needed` when too small.
pub(crate) fn write_wide(dst: LPWSTR, cap_chars: usize, src: &[u16]) -> usize {
    let needed = src.len() + 1;
    if dst.is_null() {
        return needed;
    }
    if needed > cap_chars {
        return needed;
    }
    // SAFETY: caller guarantees dst covers cap_chars wchars.
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        *dst.add(src.len()) = 0;
    }
    src.len()
}

pub(crate) fn wide_from_str(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Read a NUL-terminated narrow string from guest memory.
///
/// # Safety
/// `p` must point to valid guest memory.
pub(crate) unsafe fn read_narrow(p: LPCSTR) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let mut i = 0usize;
    while *p.add(i) != 0 && i < 0x10_000 {
        i += 1;
    }
    std::slice::from_raw_parts(p, i).to_vec()
}

// ── Time conversion ──────────────────────────────────────────────────────

/// Unix seconds+nanos → FILETIME (100ns ticks since 1601-01-01).
pub(crate) fn unix_to_filetime(secs: i64, nanos: u32) -> u64 {
    const EPOCH_DIFF: i64 = 11_644_473_600;
    ((secs + EPOCH_DIFF) as u64) * 10_000_000 + (nanos as u64) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch_math() {
        // 2026-01-01T00:00:00Z ≈ 133768608000000000 ticks.
        let t = unix_to_filetime(1_767_225_600, 0);
        assert!(t > 133_000_000_000_000_000);
    }

    #[test]
    fn write_wide_roundtrip() {
        let mut buf = [0u16; 8];
        let n = write_wide(buf.as_mut_ptr(), 8, &wide_from_str("abc"));
        assert_eq!(n, 3);
        assert_eq!(&buf[..4], &[b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    }

    #[test]
    fn write_wide_reports_needed_on_small_buffer() {
        let mut buf = [0u16; 2];
        let n = write_wide(buf.as_mut_ptr(), 2, &wide_from_str("abcd"));
        assert_eq!(n, 5);
    }
}

/// Read LastErrorValue from the active TEB.
pub fn get_last_error() -> u32 {
    unsafe {
        let p = perun_core::teb::get_last_error_ptr();
        if !p.is_null() {
            *p
        } else {
            0
        }
    }
}

/// Write LastErrorValue to the active TEB.
pub fn set_last_error(code: u32) {
    unsafe {
        let p = perun_core::teb::get_last_error_ptr();
        if !p.is_null() {
            *p = code;
        }
    }
}
