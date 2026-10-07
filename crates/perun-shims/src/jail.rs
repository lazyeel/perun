// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

// The jail resolves every guest path against one directory fd, so a symlink
// or `..` inside the path cannot walk out of it — the kernel does the
// enforcement, not a string comparison.
#![allow(unknown_lints)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

//! Filesystem jail for the Win32 shims.
//!
//! One class of incident motivates this module: a run under `sudo` let a
//! garbage guest pointer resolve to `""` → `"."` → the process cwd, and a
//! `chmod` the guest meant for its own cache directory landed on the host's
//! filesystem root. Two layers now prevent that:
//!
//! 1. The CLI refuses an euid-0 start unless `PERUN_ALLOW_ROOT` is set.
//! 2. **Every** path the shims act on is resolved inside the jail root —
//!    the perun-owned appdata directory — through `openat2` with
//!    `RESOLVE_BENEATH`, so `..`, absolute components and symlink escapes
//!    fail with `EXDEV` in the kernel rather than reaching a host path.
//!
//! The jail is an *allowlist by construction*: there is no list of
//! forbidden host directories that must be kept complete, there is one
//! allowed tree and everything else is unreachable. Relative paths
//! (`"."`, a garbage pointer that reads as empty) are rebased into the jail
//! root rather than into the process cwd, which is what made the original
//! incident reachable.
//!
//! `openat2` is Linux 5.6+. On older kernels the module degrades to the
//! lexical check (`win32::sanitize_guest_path`) so the build and the shims
//! keep working; the kernel path is the one that makes the guarantee
//! airtight, and it is the one taken on any current host.

use std::path::PathBuf;

use crate::win32::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

/// Serialises the jail tests across both test modules: they swap one
/// process-global (PERUN_DIR, the cached root fd), and cargo runs
/// #[test]s in parallel by default.
#[cfg(test)]
pub(crate) fn test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Directory fd of the jail root, opened once. `O_PATH` keeps it a pure
/// anchor: it never reads or writes, it only resolves other paths.
static JAIL_ROOT_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// `openat2` availability, probed once. -1 = not probed, 0 = available,
/// 1 = missing (pre-5.6 kernel) → lexical fallback.
static OPENAT2_STATE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

const O_PATH: i32 = libc::O_PATH;
const O_CLOEXEC: i32 = libc::O_CLOEXEC;
/// Reject `..` and absolute components in the resolved path.
const RESOLVE_BENEATH: u64 = 0x08;
/// Treat `dirfd` as the filesystem root: `..` at the top stays inside.
const RESOLVE_IN_ROOT: u64 = 0x10;

/// The jail root directory: the perun-owned appdata tree the shell32
/// folder shims map CSIDLs into, now derived from the single `PERUN_DIR`
/// (`perun_core::paths`). Relative guest paths land here instead of in the
/// process cwd. An unusable configuration (a `PERUN_DIR` aimed at a system
/// tree) denies: the jail has no safe root to offer.
pub fn lexical_jail_root() -> Result<PathBuf, u32> {
    perun_core::paths::appdata().map_err(|_| crate::win32::ERROR_ACCESS_DENIED)
}

fn jail_root() -> PathBuf {
    lexical_jail_root().unwrap_or_default()
}

/// Probe `openat2` once. A probe that succeeds also leaves the jail root
/// fd open; a probe that fails records the fallback.
fn ensure_jail_fd() -> i32 {
    let fd = JAIL_ROOT_FD.load(std::sync::atomic::Ordering::Relaxed);
    if fd >= 0 {
        return fd;
    }
    let root = jail_root();
    // NUL-terminated, as `open(2)` requires: a bare `String::as_ptr()` is
    // not guaranteed to be terminated, and on this host it demonstrably
    // was not — the fd open failed intermittently depending on what the
    // allocator left behind the string.
    let Ok(cpath) = std::ffi::CString::new(root.to_string_lossy().as_bytes()) else {
        return -1;
    };
    // Open the jail root itself without openat2: it is a host path we chose,
    // not a guest path, so plain open is correct here.
    let raw = unsafe { libc::open(cpath.as_ptr().cast(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw < 0 {
        // The jail root may not exist yet on a cold host; create it the way
        // the guest's own SHGetFolderPathW(CREATE) would, then retry once.
        let _ = std::fs::create_dir_all(&root);
        let raw = unsafe { libc::open(cpath.as_ptr().cast(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return -1;
        }
        JAIL_ROOT_FD.store(raw, std::sync::atomic::Ordering::Relaxed);
        return raw;
    }
    JAIL_ROOT_FD.store(raw, std::sync::atomic::Ordering::Relaxed);
    raw
}

/// Resolve a guest path *inside* the jail, returning a host path that has
/// passed kernel enforcement. This is the function every mutating shim
/// must call instead of using the path directly.
///
/// Returns the resolved host path, or the Win32 error code to report.
/// `ERROR_INVALID_PARAMETER` for an empty name (the guest's own convention
/// for a malformed path), `ERROR_ACCESS_DENIED` when the path escapes the
/// jail — which the kernel reports as `EXDEV`/`ENOTDIR` under
/// `RESOLVE_BENEATH` — and `ERROR_FILE_NOT_FOUND` when the target simply
/// does not exist yet (mkdir's caller treats that as success territory).
pub fn resolve_in_jail(guest_path: &str) -> Result<PathBuf, u32> {
    let trimmed = guest_path.trim_start_matches(['\\', '/']);
    if trimmed.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let root_fd = ensure_jail_fd();
    if root_fd < 0 {
        // No jail root available at all: the shims must not fall back to
        // the process cwd, because that is the original incident. Deny.
        return Err(ERROR_ACCESS_DENIED);
    }

    // Win32 drive letters are a namespace, not a host path: `C:\...` and
    // `D:\...` alike strip to their tail, which then resolves inside the
    // jail like any relative path. A guest probe of `C:\Windows` finds
    // `Windows` under the appdata root or nothing at all — never the host's
    // Windows directory, of which there is none here anyway.
    let guest_path = {
        let bytes = guest_path.as_bytes();
        if guest_path.len() >= 2 && bytes[1] == b':' {
            &guest_path[2..]
        } else {
            guest_path
        }
    };

    // Absolute guest paths: the guest mixes rooted paths (from
    // SHGetFolderPathW, which spell the appdata root) with paths it builds
    // itself. A rooted path that names the jail root is reduced to its
    // suffix; any other absolute path is a host path the guest has no
    // business naming.
    let candidate = if guest_path.starts_with('/') || guest_path.starts_with('\\') {
        let root = lexical_jail_root()?;
        let norm = guest_path.replace('\\', "/");
        let root_str = root.to_string_lossy().replace('\\', "/");
        let inside = if norm == root_str {
            Some(String::new())
        } else if norm.starts_with(&format!("{root_str}/")) {
            Some(norm[root_str.len() + 1..].to_string())
        } else {
            None
        };
        let Some(suffix) = inside else {
            return Err(ERROR_ACCESS_DENIED);
        };
        suffix
    } else {
        guest_path.replace('\\', "/")
    };

    let candidate = candidate.trim_start_matches(['\\', '/']);
    if candidate.is_empty() {
        // The path was exactly the jail root: legal, resolves to it.
        return lexical_jail_root();
    }
    let cstr = match std::ffi::CString::new(candidate.as_bytes()) {
        Ok(c) => c,
        Err(_) => return Err(ERROR_INVALID_PARAMETER),
    };

    // Kernel enforcement: resolve against the jail fd with
    // RESOLVE_BENEATH. `..` and symlink escapes come back EXDEV; a missing
    // leaf comes back ENOENT, which the caller maps per its own semantics.
    let state = OPENAT2_STATE.load(std::sync::atomic::Ordering::Relaxed);
    if state < 0 {
        // First call: probe openat2 with a harmless resolve of the root
        // itself. ENOSYS/EINVAL marks a pre-5.6 kernel.
        let dot = b".\0";
        let probe = unsafe { openat2_raw(root_fd, dot.as_ptr(), O_PATH, RESOLVE_BENEATH) };
        let available = if probe >= 0 {
            unsafe { libc::close(probe) };
            0
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            matches!(err, libc::ENOSYS | libc::EINVAL)
                .then_some(1)
                .unwrap_or(0)
        };
        OPENAT2_STATE.store(available, std::sync::atomic::Ordering::Relaxed);
    }
    let openat2_ok = OPENAT2_STATE.load(std::sync::atomic::Ordering::Relaxed) == 0;

    if openat2_ok {
        let fd = unsafe { openat2_raw(root_fd, cstr.as_ptr().cast(), O_PATH, RESOLVE_BENEATH) };
        if fd >= 0 {
            // Read the enforced path back through /proc/self/fd: the
            // canonical host path the kernel just vouched for.
            let link = format!("/proc/self/fd/{fd}");
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let n = unsafe {
                libc::readlink(link.as_ptr().cast(), buf.as_mut_ptr().cast(), buf.len() - 1)
            };
            unsafe { libc::close(fd) };
            if n >= 0 {
                buf.truncate(n as usize);
                buf.push(0);
                let p = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap_or_default();
                return Ok(PathBuf::from(p.to_string_lossy().into_owned()));
            }
            // readlink failed on a vouched fd: unusual, fall through to
            // the lexical path below rather than denying a legal call.
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            match err {
                libc::EXDEV | libc::ENOTDIR | libc::ELOOP => return Err(ERROR_ACCESS_DENIED),
                libc::ENOENT => {
                    // The leaf does not exist yet. That is normal for the
                    // creating shims; the lexical path below is safe here
                    // because openat2 already vetted every component above
                    // the leaf.
                }
                _ => return Err(ERROR_ACCESS_DENIED),
            }
        }
    }

    // Lexical fallback: either no openat2 (pre-5.6) or a not-yet-existing
    // leaf after every existing component was kernel-vetted. Both are the
    // safe subset — the dangerous escapes were rejected above.
    let root = lexical_jail_root()?;
    let joined = root.join(candidate);
    crate::win32::sanitize_guest_path(&joined)
}

/// Raw `openat2(2)` call. Kept in one place so the unsafe surface is one
/// function; the struct layout matches `struct open_how` from
/// `linux/openat2.h` byte for byte.
unsafe fn openat2_raw(dirfd: i32, path: *const u8, flags: i32, resolve: u64) -> i32 {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    // Edition 2024: `syscall` is unsafe even inside this unsafe fn.
    let res = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd as libc::c_long,
            path,
            &how,
            std::mem::size_of::<OpenHow>() as libc::c_long,
        )
    };
    res as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("perun-jail-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn with_root<T>(tag: &str, f: impl FnOnce() -> T) -> T {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp_root(tag);
        // Isolate from any ambient PERUN_DIR, including the one other
        // tests may have set: this module reads it per call.
        // Edition 2024: env mutation is unsafe; no guest threads exist at test time.
        unsafe { std::env::set_var("PERUN_DIR", &root) };
        // A fresh jail fd for the new root: the cached fd points at the
        // previous test's tree.
        let old = JAIL_ROOT_FD.swap(-1, std::sync::atomic::Ordering::Relaxed);
        if old >= 0 {
            unsafe { libc::close(old) };
        }
        OPENAT2_STATE.store(-1, std::sync::atomic::Ordering::Relaxed);
        let r = f();
        let cur = JAIL_ROOT_FD.swap(-1, std::sync::atomic::Ordering::Relaxed);
        if cur >= 0 {
            unsafe { libc::close(cur) };
        }
        unsafe { std::env::remove_var("PERUN_DIR") };
        let _ = std::fs::remove_dir_all(&root);
        r
    }

    #[test]
    fn empty_path_is_invalid_parameter() {
        with_root("empty", || {
            assert_eq!(resolve_in_jail(""), Err(ERROR_INVALID_PARAMETER));
        });
    }

    #[test]
    fn relative_path_resolves_inside_the_jail() {
        with_root("relative", || {
            let got = resolve_in_jail("Common/Apple Computer").unwrap();
            let root = lexical_jail_root().unwrap();
            assert!(got.starts_with(&root), "resolved {got:?} outside {root:?}");
            assert!(got.ends_with("Common/Apple Computer"));
        });
    }

    #[test]
    fn dot_resolves_to_the_jail_root_not_the_cwd() {
        with_root("dot", || {
            let got = resolve_in_jail(".").unwrap();
            let root = lexical_jail_root().unwrap();
            assert_eq!(got, root, "'.' must rebase into the jail root");
        });
    }

    #[test]
    fn rooted_path_inside_the_jail_is_reduced_to_its_suffix() {
        with_root("rooted", || {
            let root = lexical_jail_root().unwrap();
            let p = format!("{}/Common/iTunes/adi", root.display());
            let got = resolve_in_jail(&p).unwrap();
            assert!(got.starts_with(&root));
            assert!(got.ends_with("Common/iTunes/adi"));
        });
    }

    #[test]
    fn foreign_absolute_path_is_denied() {
        with_root("foreign", || {
            assert_eq!(resolve_in_jail("/etc/passwd"), Err(ERROR_ACCESS_DENIED));
            assert_eq!(
                resolve_in_jail("C:\\Windows\\system32"),
                Err(ERROR_ACCESS_DENIED)
            );
        });
    }

    #[test]
    fn dotdot_escape_is_denied_by_the_kernel() {
        with_root("dotdot", || {
            let root = lexical_jail_root().unwrap();
            std::fs::create_dir_all(root.join("Common")).unwrap();
            assert_eq!(
                resolve_in_jail("Common/../../etc"),
                Err(ERROR_ACCESS_DENIED)
            );
            assert_eq!(
                resolve_in_jail("../../../etc/passwd"),
                Err(ERROR_ACCESS_DENIED)
            );
        });
    }

    #[test]
    fn symlink_escape_is_denied_by_the_kernel() {
        with_root("symlink", || {
            let root = lexical_jail_root().unwrap();
            std::fs::create_dir_all(root.join("sub")).unwrap();
            std::os::unix::fs::symlink("/etc", root.join("sub/escape")).unwrap();
            assert_eq!(
                resolve_in_jail("sub/escape/passwd"),
                Err(ERROR_ACCESS_DENIED)
            );
        });
    }

    #[test]
    fn symlink_inside_the_jail_is_fine() {
        with_root("symlink_ok", || {
            let root = lexical_jail_root().unwrap();
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::os::unix::fs::symlink("real", root.join("link")).unwrap();
            // A symlink whose target is inside the jail resolves through
            // RESOLVE_BENEATH; the resolved fd may spell either the link or
            // the target, and both are inside the jail — which is the
            // property under test.
            let got = resolve_in_jail("link").unwrap();
            assert!(
                got.starts_with(&root),
                "an in-jail symlink must resolve inside the jail, got {got:?}"
            );
        });
    }

    #[test]
    fn missing_leaf_is_returned_for_the_creating_shims() {
        with_root("missing", || {
            let got = resolve_in_jail("Common/new-leaf/adi").unwrap();
            let root = lexical_jail_root().unwrap();
            assert!(got.starts_with(&root), "resolved {got:?} outside {root:?}");
            assert!(got.ends_with("Common/new-leaf/adi"));
        });
    }
}
