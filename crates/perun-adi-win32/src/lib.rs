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

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
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

/// Feed a captured SPIM to `CoreADI64.dll` and report what came back.
///
/// The envelope is the one the working Android engine builds, measured rather
/// than assumed: `ctx[+0x00]` is the packet, `ctx[+0x08]` is its size in both
/// halves, `ctx[+0x0c]` is the output size the library is asked to require and
/// writes back what it produced. The Android capture puts the SPIM at `ctx[0]`
/// with `ctx[8]` as its length, and that is the shape reproduced here.
///
/// `oracle` is the CPIM the Android engine produced from the same SPIM. When it
/// is supplied the two are compared byte for byte, because "did it work" and
/// "did it produce the same thing" are different questions and only the second
/// one settles whether the Windows image implements the transform.
pub fn replay(
    image_path: Option<&str>,
    spim: &[u8],
    oracle: Option<&[u8]>,
) -> Result<String, AdiError> {
    let path = image_path
        .map(str::to_owned)
        .or_else(guest::default_adi_image)
        .ok_or(AdiError::NoImage)?;
    let bytes = std::fs::read(&path).map_err(|e| AdiError::Load(format!("read {path}: {e}")))?;

    let mut table = perun_shims::table::ShimTable::collect();
    let image = Image::load(&bytes, &mut table)
        .map_err(|e| AdiError::Load(format!("{e:?}")))?;
    // SAFETY: per-thread TEB; this thread is the only one running.
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = unsafe { image.entry_dll_main() }
        .ok_or_else(|| AdiError::NotAnAdiImage(path.clone()))?;
    // SAFETY: DllMain(PROCESS_ATTACH) on a freshly mapped image, as `perun run`
    // does for the same file.
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        return Err(AdiError::NotAnAdiImage(format!("{path}: DllMain returned FALSE")));
    }

    let entry = image
        .get_export_by_name("vdfut768ig")
        .ok_or_else(|| AdiError::NotAnAdiImage(format!("{path}: no vdfut768ig")))?;
    // SAFETY: `HRESULT (u32, ADIRequest*, void*, void*)`, the signature
    // `perun call` already drives this export with.
    let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(entry) };

    let packet = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            packet_len(spim),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let ctx = unsafe {
        libc::mmap(
        std::ptr::null_mut(),
        0x1_0000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if packet == libc::MAP_FAILED || ctx == libc::MAP_FAILED {
        return Err(AdiError::Load("could not map the packet or context page".to_string()));
    }
    let n = packet_len(spim);
    unsafe {
        std::ptr::write_bytes(packet.cast::<u8>(), 0, n);
        std::ptr::copy_nonoverlapping(spim.as_ptr(), packet.cast::<u8>(), spim.len());
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c, packet as u64);
        // The Android frame's input-size slot is the packet length in the low
        // half and something else in the high half; -45018 means the library
        // could not read even its eight-byte header, so the size it is given
        // has to be at least that. 0x1000 is the value the working ladder used.
        let size: u64 = std::env::var("PERUN_PROV_INPUT_SIZE")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x1000);
        std::ptr::write(c.add(1), size);
        std::ptr::write(c.add(2), 0);
        std::ptr::write(c.add(10), 0xc8);
    }

    let mut out = String::new();
    out.push_str(&format!("image: {path}\n"));
    out.push_str(&format!("input: {} bytes, first 4 {:02x?}\n", spim.len(), &spim[..4.min(spim.len())]));

    for (name, opcode) in [("provision", guest::OPCODE_PROVISION), ("login code", guest::OPCODE_LOGIN)] {
        let rc = unsafe { f(opcode, ctx as u64, 0, 0) };
        let produced = unsafe { (*ctx.cast::<u64>().add(3) & 0xffff_ffff) as usize };
        out.push_str(&format!(
            "{name}: opcode {opcode:#010x} -> rc={rc} ({}), ctx[+0x0c]={produced}\n",
            describe(rc as u32)
        ));
        let got = unsafe {
            std::slice::from_raw_parts(packet.cast::<u8>(), spim.len().min(n).max(produced.min(n)))
        };
        let got = &got[..spim.len().min(got.len())];
        let changed = got != &spim[..got.len()];
        out.push_str(&format!(
            "   buffer rewritten: {changed}, non-zero after packet: {}\n",
            got.iter().filter(|b| **b != 0).count()
        ));
        match oracle {
            Some(refc) if name == "provision" => {
                let refc: &[u8] = refc;
                let same = got == refc;
                out.push_str(&format!(
                    "   vs Android CPIM ({} bytes): {}\n",
                    refc.len(),
                    if same { "IDENTICAL" } else { "differs" }
                ));
                if !same {
                    let common = got.iter().zip(refc.iter()).take_while(|(a, b)| a == b).count();
                    out.push_str(&format!(
                        "   common prefix: {common} bytes\n   windows: {}\n   android: {}\n",
                        hex(got),
                        hex(refc)
                    ));
                }
            }
            _ => {}
        }
    }

    unsafe {
        libc::munmap(packet, packet_len(spim));
        libc::munmap(ctx, 0x1_0000);
    }
    Ok(out)
}

/// The packet page has to hold the input and whatever the library writes back.
fn packet_len(spim: &[u8]) -> usize {
    let want = spim.len().next_power_of_two().max(0x1000);
    want + 0x1000
}

fn hex(b: &[u8]) -> String {
    b.iter().take(48).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn describe(status: u32) -> String {
    if status == 0 {
        return "success".to_string();
    }
    let signed = status as i32;
    format!("{signed} (0x{status:08x})")
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