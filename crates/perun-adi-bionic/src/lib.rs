// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Anisette v3 against the Android Bionic runtime, un-emulated on x86_64.
//!
//! # What "un-emulated" means here, and what it does not
//!
//! No instruction translation takes place. The stand is an x86_64 Android ELF,
//! the host is x86_64, and Apple's libraries execute on the CPU directly —
//! there is no `qemu-*` process in the process tree. What is *not* native is
//! the libc: it is Bionic, reached through a Bionic `linker64` repointed into
//! `PT_INTERP`, which is the ordinary mechanism the kernel uses to start every
//! Bionic process on a device.
//!
//! That is a requirement rather than a workaround. `libstoreservicescore.so`
//! is an Android build and sizes its provisioning state from the libc beneath
//! it; under glibc the state is the wrong size, the dispatch index leaves the
//! block, and the library returns `-45075`. So this crate does not attempt to
//! `dlopen` the libraries into a glibc process. It runs the Bionic runtime as
//! the guest it is.
//!
//! # Why a subprocess rather than an in-process call
//!
//! The ADI libraries need a Bionic linker, Bionic libc and Bionic `libcurl`.
//! A Rust process is glibc. Getting the two into one address space would mean
//! loading two libcs at once, which no loader supports. The stand therefore
//! runs as its own process, in a private mount namespace where `/system` and
//! `/vendor` exist, and this crate parses what it prints.
//!
//! Everything below is derived from the Android half only. There is no
//! reference to the Windows projection runtime anywhere in this crate, by
//! design: the two lanes share a protocol, not a runtime.

use std::fmt;
use std::path::{Path, PathBuf};

mod patches;
pub(crate) mod stand;

pub use patches::{Patch, PatchSite, PATCHES};

/// The headers Anisette v3 produces.
///
/// Both are opaque to callers: `md` rotates per token pair and `mdm` is stable
/// for a machine, which is the behaviour Apple's endpoints expect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnisetteHeaders {
    /// `X-Apple-I-MD` — the OTP, short-lived.
    pub md: String,
    /// `X-Apple-I-MD-M` — the machine information, stable.
    pub mdm: String,
}

/// Everything that can go wrong on the way to a token.
#[derive(Debug)]
pub enum AdiError {
    /// The stand, its libraries or its sysroot are not where they should be.
    StandMissing(String),
    /// The stand ran but printed nothing parseable — usually a hang or a
    /// fatal line. Carries the tail of its output so the cause is visible.
    NoTokens { tail: String },
    /// The stand exited non-zero. Carries its status and the tail of its output.
    StandFailed { status: String, tail: String },
    /// The namespace could not be set up.
    Namespace(String),
    /// `unshare(2)` is unavailable, so the absolute paths the Bionic loader
    /// requires cannot be provided.
    NoUnshare,
}

impl fmt::Display for AdiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StandMissing(p) => write!(
                f,
                "the Bionic stand is not in place at {p}\n\
                 see `perun-adi-bionic`: the runtime is built from an Android system \
                 image and is not vendored"
            ),
            Self::NoTokens { tail } => {
                write!(f, "the stand produced no X-Apple-I-MD headers")?;
                write_tail(f, tail)
            }
            Self::StandFailed { status, tail } => {
                if status == "timeout" {
                    write!(
                        f,
                        "the stand produced no answer {}",
                        crate::stand::timeout_note()
                    )?;
                } else {
                    write!(f, "the stand exited {status}")?;
                }
                write_tail(f, tail)
            }
            Self::Namespace(why) => {
                write!(f, "cannot build the mount namespace: {why}")
            }
            Self::NoUnshare => write!(
                f,
                "unshare(2) is unavailable, and without a private namespace the \
                 Bionic loader cannot resolve /system/lib64 or /vendor/lib64"
            ),
        }
    }
}

fn write_tail(f: &mut fmt::Formatter<'_>, tail: &str) -> fmt::Result {
    let tail = tail.trim();
    if tail.is_empty() {
        return Ok(());
    }
    write!(f, "\n--- stand output ---\n{tail}")
}

impl std::error::Error for AdiError {}

/// Where the stand and its runtime live on this machine.
///
/// Defaults follow the layout the recipe builds, and every field is
/// overridable so a caller can point at a different checkout.
#[derive(Clone, Debug)]
pub struct StandPaths {
    /// The cross-compiled Bionic binary (`adi_native`).
    pub binary: PathBuf,
    /// The merged library directory (platform + Apple), the source of both
    /// bind mounts.
    pub stage: PathBuf,
    /// Where the provisioning cache lives (`adi.pb`).
    pub adi_dir: PathBuf,
    /// The Bionic linker the binary's `PT_INTERP` points at.
    pub linker: PathBuf,
}

impl StandPaths {
    /// The default layout, rooted at the examples directory of this checkout.
    pub fn under(examples: &Path) -> Self {
        Self {
            binary: examples.join("adi-android/adi_native"),
            stage: PathBuf::from("/opt/data/adi-mnt/stage"),
            adi_dir: examples.join("adi-android/adi-data"),
            linker: PathBuf::from("/opt/data/ad-lk"),
        }
    }

    /// What is missing, if anything. The stand cannot run without all four.
    pub fn missing(&self) -> Option<&'static str> {
        if !self.binary.is_file() {
            return Some("the stand binary (adi-native)");
        }
        if !self.stage.join("lib64").is_dir() {
            return Some("the staged library directory");
        }
        if !self.linker.is_file() {
            return Some("the Bionic linker");
        }
        None
    }
}

impl Default for StandPaths {
    fn default() -> Self {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(|p| p.join("crates/perun-cli/examples"))
            .unwrap_or_else(|| PathBuf::from("/opt/data/perun/crates/perun-cli/examples"));
        Self::under(&examples)
    }
}

/// Produce live Anisette headers, reading the cache when it is warm.
///
/// This is the whole Android-lane API. It is deliberately synchronous and
/// side-effecting only in `adi_dir`: with a warm `adi.pb` the stand answers
/// without a network round trip, and with a cold one it performs the full
/// provisioning cycle against Apple's endpoints.
///
/// # Errors
///
/// [`AdiError`] carries the stand's own output, because every failure mode of
/// this lane looks identical from the outside — the process either hangs or
/// prints a fatal line — and the line is the only evidence there is.
pub fn generate_headers() -> Result<AnisetteHeaders, AdiError> {
    generate_headers_from(&StandPaths::default())
}

/// [`generate_headers`] against an explicit layout.
pub fn generate_headers_from(paths: &StandPaths) -> Result<AnisetteHeaders, AdiError> {
    if let Some(what) = paths.missing() {
        return Err(AdiError::StandMissing(format!("{what} ({})", paths.stage.display())));
    }
    let out = stand::run(paths)?;
    if !out.status_ok {
        return Err(AdiError::StandFailed {
            status: out.status,
            tail: out.text,
        });
    }
    // `out.text` is already owned here and is not needed again, so moving it
    // into the error costs nothing and reads better than a lazy closure.
    parse_headers(&out.text).ok_or(AdiError::NoTokens { tail: out.text })
}

/// Pull the two headers out of the stand's output.
///
/// The banner is the contract: the stand prints exactly these two lines and
/// nothing else after them, so a run that reached them cannot be confused with
/// a run that died earlier.
pub fn parse_headers(text: &str) -> Option<AnisetteHeaders> {
    let mut md = None;
    let mut mdm = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("X-Apple-I-MD-M:") {
            let v = rest.trim();
            if !v.is_empty() {
                mdm = Some(v.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("X-Apple-I-MD:") {
            let v = rest.trim();
            if !v.is_empty() {
                md = Some(v.to_owned());
            }
        }
    }
    match (md, mdm) {
        (Some(md), Some(mdm)) => Some(AnisetteHeaders { md, mdm }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_stand_banner() {
        let text = "[id] loaded existing device identifier\n\
                    \n=== SUCCESS ===\n\
                    X-Apple-I-MD:   AAAABQAAABAxGRmpChL7Nyh+ET9Wa4pIAAAABA==\n\
                    X-Apple-I-MD-M: XsDYsOOSJX77VezbrxKdvZwv8ufQbUAt4ZB8lDORVXd5ksXkDVC\n\
                    ===============\n";
        let h = parse_headers(text).expect("banner parses");
        assert_eq!(h.md, "AAAABQAAABAxGRmpChL7Nyh+ET9Wa4pIAAAABA==");
        // The MD-M prefix is the stable part; the rest is machine state.
        assert!(h.mdm.starts_with("XsDYsOOSJX77VezbrxKdvZwv8ufQ"));
    }

    #[test]
    fn refuses_a_partial_banner() {
        // A run that died after printing only one header must not be reported
        // as a success: that is exactly the failure this parse exists to catch.
        assert!(parse_headers("[net] -> 200\nX-Apple-I-MD:   AAAABQAA\n").is_none());
        assert!(parse_headers("X-Apple-I-MD-M: only-this\n").is_none());
    }

    #[test]
    fn empty_output_is_not_a_success() {
        assert!(parse_headers("").is_none());
        assert!(parse_headers("[prov] PROVISIONING COMPLETE\n").is_none());
    }

    #[test]
    fn does_not_confuse_the_md_header_with_the_mdm_one() {
        // "X-Apple-I-MD-M:" starts with "X-Apple-I-MD", so a naive prefix test
        // assigns both values from the same line.
        let text = "X-Apple-I-MD: MD-VALUE\nX-Apple-I-MD-M: MDM-VALUE\n";
        let h = parse_headers(text).unwrap();
        assert_eq!(h.md, "MD-VALUE");
        assert_eq!(h.mdm, "MDM-VALUE");
    }

    #[test]
    fn missing_parts_are_named() {
        let p = StandPaths {
            binary: PathBuf::from("/nonexistent/adi_native"),
            stage: PathBuf::from("/nonexistent/stage"),
            adi_dir: PathBuf::from("/tmp"),
            linker: PathBuf::from("/nonexistent/ad-lk"),
        };
        assert_eq!(p.missing(), Some("the stand binary (adi-native)"));
        let e = generate_headers_from(&p).unwrap_err();
        assert!(e.to_string().contains("not vendored"), "{e}");
    }

    #[test]
    fn every_patch_names_a_known_site() {
        // A patch aimed at a site the table does not know is a silent no-op at
        // best; at worst it corrupts a neighbouring section.
        for p in PATCHES {
            assert!(
                matches!(p.site, PatchSite::Libc | PatchSite::Linker | PatchSite::Llvm),
                "unknown site in {p:?}"
            );
        }
    }
}