// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Anisette v3 research runtime for `CoreADI64.dll`, executed through Perun's
//! own PE32+ projection.
//!
//! # Why this crate exists and what it is not
//!
//! The Windows lane is where the interesting question lives — the library is
//! control-flow-flattened, its dispatch state comes out of the caller's stack,
//! and the barrier is a single compare — and it is *research*: it runs the
//! real DLL on the real host and reports what the library actually answered.
//! It is not a token source. `CoreADI64.dll` imports no networking API at all
//! (`KERNEL32`, `ADVAPI32`, `SHELL32`, `SHLWAPI` — 103 symbols, nothing that
//! opens a socket), so no header can be minted from this image alone; the
//! network half in [`net`] exists to show the anonymous GSA bootstrap works,
//! not to complete a token.
//!
//! That is also why it is a separate crate. It shares the *protocol* with the
//! Bionic lane and nothing else: different libc, different loader, different
//! image format. Nothing here refers to the Android runtime, and nothing in
//! that crate refers to this one.
//!
//! The one caveat worth stating plainly: the projection runtime makes the
//! library believe it is on a Windows host, so a status of `0` from an opcode
//! means the obfuscated body took its success path *here*. Whether the values
//! it then produces are acceptable to Apple is a separate question this lane
//! cannot answer, and no header is emitted from them.

use std::fmt;

pub mod guest;
pub mod net;

pub use guest::{Probe, Stage};

/// The headers Anisette v3 produces.
///
/// Deliberately the same shape as the Bionic lane's type, and deliberately not
/// the same type: the two crates are independent, and neither depends on the
/// other. Keeping them separate is what makes the isolation checkable — if
/// either lane ever needs the other, the build stops.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnisetteHeaders {
    /// `X-Apple-I-MD` — the OTP.
    pub md: String,
    /// `X-Apple-I-MD-M` — the machine information.
    pub mdm: String,
}

/// Everything that can go wrong on the way to a Windows-side result.
#[derive(Debug)]
pub enum AdiError {
    /// No `CoreADI64.dll` was given and none was found.
    NoImage,
    /// The image could not be read, mapped or attached.
    Load(String),
    /// The image has no `vdfut768ig` export, or the entry point refused.
    NotAnAdiImage(String),
    /// The opcodes ran but did not all take their success path.
    NotSigned { report: String },
}

impl fmt::Display for AdiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoImage => write!(
                f,
                "no CoreADI64.dll given and none found in the usual places \
                 (adi-pe/, win32-adi-shim/); the ADI artefacts are not vendored"
            ),
            Self::Load(e) => write!(f, "cannot load the image: {e}"),
            Self::NotAnAdiImage(e) => write!(f, "not a usable ADI image: {e}"),
            Self::NotSigned { report } => {
                write!(f, "the opcodes did not all take their success path")?;
                write!(f, "\n{report}")
            }
        }
    }
}

impl std::error::Error for AdiError {}

/// Run `CoreADI64.dll` and report every stage.
///
/// This is the whole Windows-lane API. It is research instrumentation: the
/// report is the product, not a header value.
pub fn generate_headers_windows() -> Result<AnisetteHeaders, AdiError> {
    generate_headers_windows_from(guest::default_adi_image().as_deref(), None)
}

/// [`generate_headers_windows`] against an explicit image and cache directory.
pub fn generate_headers_windows_from(
    image_path: Option<&str>,
    adi_dir: Option<&str>,
) -> Result<AnisetteHeaders, AdiError> {
    let path = image_path
        .map(str::to_owned)
        .or_else(guest::default_adi_image)
        .ok_or(AdiError::NoImage)?;

    let probe = guest::probe(&path, adi_dir).map_err(AdiError::Load)?;

    // Every opcode must have reported success before anything is claimed.
    // This lane cannot mint a token — the image has no networking — so the
    // error carries the report rather than two empty header strings that a
    // caller might send somewhere.
    if !probe.all_signed() {
        return Err(AdiError::NotSigned { report: probe.report });
    }

    Err(AdiError::NotSigned { report: probe.report })
}

/// Run the image and return its full report, whether or not it signed.
///
/// This is what a researcher actually wants: the failure report is the
/// interesting artefact, and `generate_headers_windows` above refuses to
/// summarise it away.
pub fn probe_windows(
    image_path: Option<&str>,
    adi_dir: Option<&str>,
) -> Result<Probe, AdiError> {
    let path = image_path
        .map(str::to_owned)
        .or_else(guest::default_adi_image)
        .ok_or(AdiError::NoImage)?;
    guest::probe(&path, adi_dir).map_err(AdiError::Load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_image_is_reported_as_such() {
        let e = AdiError::NoImage;
        let text = e.to_string();
        assert!(text.contains("not vendored"), "{text}");
    }

    #[test]
    fn a_failed_probe_carries_the_report() {
        let report = "image: CoreADI64.dll\n0xcfe0b46a  provision    failed  0\n";
        let e = AdiError::NotSigned {
            report: report.to_string(),
        };
        let text = e.to_string();
        assert!(text.contains("did not all take their success path"));
        assert!(text.contains("provision"), "the report must survive: {text}");
    }

    #[test]
    fn the_error_types_render_without_a_panicking() {
        // Every variant, so a new one cannot be added without a Display arm.
        for e in [
            AdiError::NoImage,
            AdiError::Load("boom".into()),
            AdiError::NotAnAdiImage("no export".into()),
            AdiError::NotSigned {
                report: String::new(),
            },
        ] {
            let s = e.to_string();
            assert!(!s.is_empty());
        }
    }
}