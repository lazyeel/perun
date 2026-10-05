// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Running the stand: a private mount namespace and a captured exit.
//!
//! Two things about this are not obvious and both cost time to find:
//!
//! * The Bionic loader resolves dependencies only by absolute path —
//!   `/system/lib64` and `/vendor/lib64` — and ignores `LD_LIBRARY_PATH`
//!   entirely. Those directories have to exist, which on a normal host means
//!   polluting `/`.
//! * `unshare(CLONE_NEWNS)` needs real root; `unshare(CLONE_NEWUSER|CLONE_NEWNS)`
//!   starts but cannot bind-mount ("wrong fs type"). And `mkdir` inside the
//!   namespace lands in the shared layer anyway, so whatever it creates has to
//!   be removed afterwards.
//!
//! Hence: `sudo unshare -m --propagation private`, bind two directories, exec.

use std::io::Read;
use std::process::{Child, Command, Stdio};

use crate::StandPaths;

/// What the stand left behind.
pub(crate) struct StandRun {
    pub text: String,
    pub status: String,
    pub status_ok: bool,
}

/// Tail of the output kept for error reporting.
const TAIL_LINES: usize = 40;

/// How long the stand may take before we call it hung.
///
/// A cold provisioning cycle is a handful of TLS round trips; 180 s is roughly
/// two orders of magnitude more than it needs and still fails fast enough to be
/// useful.
const TIMEOUT_SECS: u64 = 180;

/// Tail of the output kept for error reporting.
pub(crate) fn run(paths: &StandPaths) -> Result<StandRun, crate::AdiError> {
    if !unshare_available() {
        return Err(crate::AdiError::NoUnshare);
    }

    // sudo -n keeps this non-interactive: the stand needs root for the mount
    // namespace, and a hanging password prompt would be worse than a clear
    // error. `sh -c` rather than exec so the two paths can be quoted safely.
    let script = r#"
set -eu
mkdir -p /system /vendor
mount --bind "$1" /system || exit 90
mount --bind "$1" /vendor || exit 91
# Bionic reads this at startup; without it the loader looks for the netd daemon.
[ -e /dev/__properties__ ] || : > /dev/__properties__
shift
exec "$@"
"#;

    let libs = paths.stage.join("lib64");

    // The stand writes its provisioning cache relative to the working
    // directory, so this is not cosmetic: without it `adi_dir` is a fiction and
    // the cache lands wherever the caller happened to be.
    let _ = std::fs::create_dir_all(&paths.adi_dir);

    let mut cmd = Command::new("sudo");
    cmd.current_dir(&paths.adi_dir)
        .args([
        "-n", "unshare", "-m", "--propagation", "private", "/bin/sh", "-c", script,
    ])
    .arg("--")
    .arg(&paths.stage)
    .arg(&paths.binary)
    .arg(&libs)
    .env("LD_LIBRARY_PATH", &libs)
    .env("CA_BUNDLE", default_ca_bundle(paths))
    .env("ANDROID_ROOT", "/system")
    .env("ANDROID_DATA", &paths.adi_dir)
    .env("TMPDIR", &paths.adi_dir)
    .env("ANDROID_ASSETS_ROOT", "/system/app")
    .env("EXTERNAL_STORAGE", &paths.adi_dir)
    .env("ANDROID_RUNTIME_ROOT", "/apex/com.android.runtime")
    .env(
        "ADI_RESOLVE",
        "gsa.apple.com:443:17.179.252.2,buy.itunes.apple.com:443:17.8.136.39",
    );

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| crate::AdiError::Namespace(e.to_string()))?;

    // A stand that hangs must not hang the caller. `output()` has no timeout,
    // so poll for it and kill the whole process group on expiry.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(TIMEOUT_SECS);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    kill_group(&mut child);
                    break child.wait().ok();
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                cleanup_mount_points();
                return Err(crate::AdiError::Namespace(e.to_string()));
            }
        }
    };

    let mut text = read_pipe(child.stdout.take());
    text.push_str(&read_pipe(child.stderr.take()));

    // Whatever happened, the namespace may have created the mount points in
    // the shared layer. Leaving them behind is how a host slowly fills up with
    // empty /system and /vendor directories.
    cleanup_mount_points();

    Ok(StandRun {
        text: tail(&text),
        status: match (&status, timed_out) {
            (_, true) => "timeout".into(),
            (Some(s), _) if s.success() => "ok".into(),
            (Some(s), _) => s.code().map_or_else(|| "killed".into(), |c| c.to_string()),
            (None, _) => "unknown".into(),
        },
        status_ok: !timed_out && status.is_some_and(|s| s.success()),
    })
}

/// Read a child's pipe to the end. Lossy: the stand prints base64 and XML, and
/// anything that is not UTF-8 is not a header we can use anyway.
fn read_pipe<R: Read>(pipe: Option<R>) -> String {
    let Some(mut p) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    // R: Read is in scope from the bound, so this resolves without an import.
    let _ = Read::read_to_end(&mut p, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Kill the child and everything it started, or the stand's own sudo/unshare
/// chain would survive the timeout.
fn kill_group(child: &mut Child) {
    // The child is `sudo`, whose process group is not ours, so signal the
    // negative pid first and fall back to the child itself.
    let pid = child.id() as i32;
    if pid > 0 {
        unsafe {
            // SAFETY: kill(2) on a pid we own; a dead pid returns ESRCH.
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

/// The Apple chain lives next to the stand unless told otherwise.
fn default_ca_bundle(paths: &StandPaths) -> std::path::PathBuf {
    if let Ok(v) = std::env::var("CA_BUNDLE") {
        return std::path::PathBuf::from(v);
    }
    paths.adi_dir
        .parent()
        .map(|p| p.join("apple_chain.pem"))
        .unwrap_or_else(|| std::path::PathBuf::from("/opt/data/apk/x86/apple_chain.pem"))
}

fn cleanup_mount_points() {
    for dir in ["/system", "/vendor"] {
        let _ = Command::new("sudo")
            .args(["-n", "rm", "-rf", dir])
            .output();
    }
}

/// `unshare(CLONE_NEWNS)` needs privileges we can have here but may not.
fn unshare_available() -> bool {
    // Not a probe of the syscall — a probe of the exact capability the lane
    // needs, because CLONE_NEWUSER succeeds and then cannot bind-mount.
    Command::new("sudo")
        .args(["-n", "unshare", "-m", "--propagation", "private", "/bin/true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The timeout, spelled out for error messages and asserted by a test.
pub(crate) fn timeout_note() -> String {
    format!("after {TIMEOUT_SECS}s")
}

/// The tail of the output, for an error message.
pub(crate) fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_last_lines() {
        let text = (1..=100)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let t = tail(&text);
        assert!(t.starts_with("line 61"), "{t}");
        assert!(t.ends_with("line 100"), "{t}");
        assert_eq!(t.lines().count(), TAIL_LINES);
    }

    #[test]
    fn tail_of_a_short_output_is_the_output() {
        assert_eq!(tail("a\nb\n"), "a\nb");
        assert_eq!(tail(""), "");
    }

    #[test]
    fn names_a_timeout_distinctly() {
        // "exited 124" reads like a crash; "timed out" does not, and the
        // difference is the whole diagnosis.
        assert!(timeout_note().contains("180s"));
    }
}