// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! One directory for everything perun writes, `PERUN_DIR`.
//!
//! History: the runtime used to spread five roots across the filesystem —
//! `~/.perun/appdata` (Win32 jail), `~/.local/state/perun` (store state),
//! `~/.cache/perun/sap` (SAP assets), `<stage>/adi-data` (ADI cache) — each
//! with its own environment variable. A jail rooted in an operator-aimed
//! `PERUN_APPDATA` could be pointed straight at a system directory, which
//! is how a `sudo` run nearly chmod'ed a host root in the field. All five
//! roots now derive from one variable, and that variable is validated once
//! at startup: a `PERUN_DIR` inside (or equal to) a system tree refuses to
//! boot instead of quietly becoming the sandbox.
//!
//! ```text
//! $PERUN_DIR/            (default: $HOME/.perun)
//! ├── appdata/           Win32 CSIDL mapping — the guest jail root
//! ├── state/             store lane: cookies, account, storefront, machine
//! ├── cache/sap/         SAP asset cache (CoreFP.icxs, tables)
//! └── adi/               ADI provisioning cache (adi.pb, adi-*.pb)
//! ```
//!
//! `PERUN_TRACE_FILE` stays an explicit operator path: it is diagnostics
//! the operator asked for by name, not runtime state.

use std::path::{Path, PathBuf};

/// System trees `PERUN_DIR` may never name or live inside. This is a
/// configuration sanity check at startup — one read of one variable — not a
/// per-path guest filter; the guest-side jail is `perun_shims::jail`.
const FORBIDDEN_ROOTS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/root",
    "/run", "/sbin", "/sys", "/usr", "/var",
];

/// Error returned by [`dir`]: the configuration is unusable, and the caller
/// should stop before any filesystem call rather than fall back to a
/// default the operator did not ask for.
#[derive(Debug)]
pub struct BadDir {
    pub configured: PathBuf,
    pub reason: &'static str,
}

impl std::fmt::Display for BadDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PERUN_DIR {:?} is unusable: {}",
            self.configured, self.reason
        )
    }
}

impl std::error::Error for BadDir {}

/// The one root. `$PERUN_DIR`, else `$HOME/.perun`.
///
/// Validation is lexical on purpose: it runs before the directory exists,
/// and the one hazard it guards — an operator pasting a system path into a
/// variable — is a textual one. Symlink indirection inside a configured
/// root is a trust decision the operator owns, same as any tool that takes
/// a directory.
fn raw_dir() -> Result<PathBuf, BadDir> {
    let configured = match std::env::var_os("PERUN_DIR") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".perun")
        }
    };
    let text = configured.to_string_lossy().into_owned();
    if text.is_empty() {
        return Err(BadDir {
            configured,
            reason: "empty path",
        });
    }
    // Normalise `.` and `..` lexically so `/home/../etc` cannot spell its
    // way past the comparison.
    let mut normalised = PathBuf::new();
    for comp in Path::new(&text).components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalised.pop();
            }
            other => normalised.push(other.as_os_str()),
        }
    }
    let norm = normalised.to_string_lossy().into_owned();
    for root in FORBIDDEN_ROOTS {
        if norm == *root || norm.starts_with(&format!("{root}/")) {
            return Err(BadDir {
                configured,
                reason: "names or lives inside a host system tree",
            });
        }
    }
    Ok(normalised)
}

/// The perun root, validated. Errors once per process in practice (the
/// callers print and exit); the cheap lexical validation makes caching
/// unnecessary.
pub fn dir() -> Result<PathBuf, BadDir> {
    raw_dir()
}

/// `$PERUN_DIR/appdata` — the Win32 CSIDL jail root. Every guest mutation
/// the shims perform resolves inside this tree and nowhere else.
pub fn appdata() -> Result<PathBuf, BadDir> {
    Ok(dir()?.join("appdata"))
}

/// `$PERUN_DIR/state` — store lane: cookie jar, account, storefront,
/// machine identity.
pub fn state() -> Result<PathBuf, BadDir> {
    Ok(dir()?.join("state"))
}

/// `$PERUN_DIR/cache/sap` — SAP asset cache.
pub fn sap_cache() -> Result<PathBuf, BadDir> {
    Ok(dir()?.join("cache").join("sap"))
}

/// `$PERUN_DIR/adi` — ADI provisioning cache (`adi.pb`, `adi-*.pb`).
/// Startup gate for the CLI: resolve and validate `PERUN_DIR` once, before
/// any lane has built a path. A usable configuration returns `Ok(())`
/// without creating anything; an unusable one returns the same `BadDir` the
/// per-lane resolvers would, so the caller prints it and exits.
pub fn preflight() -> Result<(), BadDir> {
    dir().map(|_| ())
}

pub fn adi_cache() -> Result<PathBuf, BadDir> {
    Ok(dir()?.join("adi"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_dir<T>(v: Option<&str>, f: impl FnOnce() -> T) -> T {
        // Serialise: PERUN_DIR is process-global and cargo runs tests in
        // parallel. No guest threads exist at test time, so the edition-2024
        // unsafe env mutation is sound here.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match v {
            Some(s) => unsafe { std::env::set_var("PERUN_DIR", s) },
            None => unsafe { std::env::remove_var("PERUN_DIR") },
        }
        let r = f();
        unsafe { std::env::remove_var("PERUN_DIR") };
        r
    }

    #[test]
    fn forbidden_roots_are_refused() {
        for bad in [
            "/",
            "/etc",
            "/etc/perun",
            "/usr/share/perun",
            "/var/lib/perun",
            "/run/perun",
            "/bin/x",
            "/root",
        ] {
            with_dir(Some(bad), || {
                let err = dir().expect_err("must refuse a system tree");
                assert_eq!(err.reason, "names or lives inside a host system tree");
            });
        }
    }

    #[test]
    fn traversal_into_a_system_tree_is_refused() {
        with_dir(Some("/home/../../etc"), || {
            assert!(dir().is_err());
        });
    }

    #[test]
    fn home_default_is_accepted() {
        // The default derives from HOME, not PERUN_DIR; give it a real
        // non-system home and it must resolve.
        with_dir(None, || {
            unsafe { std::env::set_var("HOME", "/opt/data/home") };
            let d = dir().unwrap();
            assert_eq!(d, PathBuf::from("/opt/data/home/.perun"));
            unsafe { std::env::remove_var("HOME") };
        });
    }

    #[test]
    fn user_tree_is_accepted() {
        with_dir(Some("/opt/data/perun-home"), || {
            let d = dir().unwrap();
            assert_eq!(d, PathBuf::from("/opt/data/perun-home"));
        });
    }

    #[test]
    fn subdirectories_derive_from_one_root() {
        with_dir(Some("/srv/perun"), || {
            assert_eq!(appdata().unwrap(), PathBuf::from("/srv/perun/appdata"));
            assert_eq!(state().unwrap(), PathBuf::from("/srv/perun/state"));
            assert_eq!(sap_cache().unwrap(), PathBuf::from("/srv/perun/cache/sap"));
            assert_eq!(adi_cache().unwrap(), PathBuf::from("/srv/perun/adi"));
        });
    }

    #[test]
    fn prefix_words_are_not_confused_with_roots() {
        // `/etcetera` shares the letters of `/etc` but is not inside it.
        with_dir(Some("/etcetera"), || {
            assert!(dir().is_ok());
        });
    }
}
