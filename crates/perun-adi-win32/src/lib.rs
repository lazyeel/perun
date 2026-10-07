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
        return Err(AdiError::NotSigned {
            report: probe.report,
        });
    }

    Err(AdiError::NotSigned {
        report: probe.report,
    })
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
/// Replay an SPIM through `CoreADI64.dll` with the envelope measured on the
/// working Android engine.
///
/// The transform is `vdfut768ig(0x716bd86c, ...)` — measured from a cold
/// provisioning run where that single call sits between the SPIM capture and
/// the CPIM. Every slot below is copied from that dump rather than invented:
/// the SPIM pointer at +0x30/+0x68, the length mirrored at +0x18/+0x38/+0x58,
/// the provisioning URL at +0x20/+0x78, and the two write-backs the library
/// performs into +0x54 (CPIM length) and +0x80 (CPIM pointer).
///
/// Two opcodes are tried because the Android one may not exist as a selector
/// on this image: `0x716bd86c` is the measured transform, `0xcfe0b46a` is what
/// the Windows lane has been calling "provision" so far.
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
    let image = Image::load(&bytes, &mut table).map_err(|e| AdiError::Load(format!("{e:?}")))?;
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main =
        unsafe { image.entry_dll_main() }.ok_or_else(|| AdiError::NotAnAdiImage(path.clone()))?;
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        return Err(AdiError::NotAnAdiImage(format!(
            "{path}: DllMain returned FALSE"
        )));
    }
    let entry = image
        .get_export_by_name("vdfut768ig")
        .ok_or_else(|| AdiError::NotAnAdiImage(format!("{path}: no vdfut768ig")))?;
    let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(entry) };

    const URL: &[u8] = b"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning\0";

    let page = |len: usize| unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let packet = page(4096);
    let spimp = page(0x1000);
    let urlp = page(0x1000);
    let ctx = page(0x1_0000);
    if [packet, spimp, urlp, ctx].contains(&libc::MAP_FAILED) {
        return Err(AdiError::Load("could not map the replay pages".to_string()));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(spim.as_ptr(), spimp.cast::<u8>(), spim.len());
        std::ptr::copy_nonoverlapping(URL.as_ptr(), urlp.cast::<u8>(), URL.len());
    }

    let mut out = String::new();
    out.push_str(&format!("image: {path}\n"));
    out.push_str(&format!(
        "input: {} bytes SPIM, first 8 {:02x?}\n",
        spim.len(),
        &spim[..8.min(spim.len())]
    ));
    out.push_str("envelope: measured transform layout, opcode 0x716bd86c\n");

    let opcodes = [
        ("measured transform", 0x716bd86c_u64),
        ("windows provision", guest::OPCODE_PROVISION),
    ];
    for (name, opcode) in opcodes {
        // A fresh packet and a fresh envelope per call: the library consumes
        // and rewrites both, and the second call must not inherit the first
        // one's result struct.
        // PERUN_PACKET_VARIANT=user prescribes the hypothesis layout: header
        // 00 00 00 02 | 00 00 00 01 | the whole SPIM from +8. The default is
        // the measured Android packet: 00 00 00 02 plus 44 arbitrary bytes,
        // with the SPIM travelling through the +0x30 pointer instead.
        let user_variant = std::env::var("PERUN_PACKET_VARIANT").ok().as_deref() == Some("user");
        let in_len: u64 = if user_variant {
            (8 + spim.len()) as u64
        } else {
            0x34
        };
        unsafe {
            std::ptr::write_bytes(packet.cast::<u8>(), 0, 4096);
            // 00 00 00 02: Action 2, the header Android stamps before its call.
            *packet.cast::<u8>().add(3) = 2;
            if user_variant {
                *packet.cast::<u8>().add(7) = 1;
                std::ptr::copy_nonoverlapping(
                    spim.as_ptr(),
                    packet.cast::<u8>().add(8),
                    spim.len(),
                );
            }
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let c = ctx.cast::<u64>();
            std::ptr::write(c.add(0), packet as u64); // +0x00 request packet
            std::ptr::write(c.add(1), (4u64 << 32) | in_len); // +0x08 in_len, flags=4
            std::ptr::write(c.add(2), 0); // +0x10
            std::ptr::write(c.add(3), spim.len() as u64); // +0x18 SPIM length
            std::ptr::write(c.add(4), urlp as u64); // +0x20 provisioning URL
            std::ptr::write(c.add(5), 2); // +0x28
            std::ptr::write(c.add(6), spimp as u64); // +0x30 SPIM pointer
            std::ptr::write(c.add(7), spim.len() as u64); // +0x38
            std::ptr::write(c.add(8), 4); // +0x40
            std::ptr::write(c.add(9), 0); // +0x48 code ptr (Android-only)
            std::ptr::write(c.add(10), 0); // +0x50 -> written: CPIM len
            std::ptr::write(c.add(11), spim.len() as u64); // +0x58
            std::ptr::write(c.add(12), 0); // +0x60
            std::ptr::write(c.add(13), spimp as u64); // +0x68 SPIM pointer again
            std::ptr::write(c.add(14), 464); // +0x70 capacity
            std::ptr::write(c.add(15), urlp as u64); // +0x78 URL again
            std::ptr::write(c.add(16), 0); // +0x80 -> written: CPIM ptr
            // +0x88..+0xa8: five function pointers on Android; left zero here.
        }
        // arg2 = -1 mirrors the Android call's third argument (rdx = 0xffffffff).
        let rc = unsafe { f(opcode, ctx as u64, 0xffff_ffff, 0) };
        out.push_str(&format!(
            "{name}: opcode {opcode:#010x} -> rc={rc} ({})\n",
            describe(rc as u32)
        ));
        let cpim_len =
            unsafe { std::ptr::read_unaligned(ctx.cast::<u8>().add(0x54).cast::<u32>()) } as usize;
        let cpim_ptr =
            unsafe { std::ptr::read_unaligned(ctx.cast::<u8>().add(0x80).cast::<u64>()) };
        out.push_str(&format!(
            "   ctx[+0x54]={cpim_len:#x} ctx[+0x80]={cpim_ptr:#x}\n"
        ));
        let plausible =
            cpim_ptr > 0x1_0000 && cpim_ptr < 0x8000_0000_0000 && cpim_len > 0 && cpim_len <= 8192;
        if plausible {
            let got = unsafe { std::slice::from_raw_parts(cpim_ptr as *const u8, cpim_len) };
            out.push_str(&format!(
                "   produced {cpim_len} bytes, first 16 {:02x?}\n",
                &got[..16.min(cpim_len)]
            ));
            if let Some(refc) = oracle {
                out.push_str(&format!(
                    "   vs Android CPIM ({} bytes): {}\n",
                    refc.len(),
                    if got == refc { "IDENTICAL" } else { "differs" }
                ));
                if got != refc {
                    let common = got
                        .iter()
                        .zip(refc.iter())
                        .take_while(|(a, b)| a == b)
                        .count();
                    out.push_str(&format!("   common prefix: {common} bytes\n"));
                    if common < 24 {
                        out.push_str(&format!("   windows: {}\n", hex(got)));
                        out.push_str(&format!("   android: {}\n", hex(refc)));
                    }
                }
            }
        } else {
            let pk = unsafe { std::slice::from_raw_parts(packet.cast::<u8>(), 52) };
            out.push_str(&format!(
                "   no plausible CPIM; packet after call: {}\n",
                hex(pk)
            ));
        }
    }

    unsafe {
        libc::munmap(packet, 4096);
        libc::munmap(spimp, 0x1000);
        libc::munmap(urlp, 0x1000);
        libc::munmap(ctx, 0x1_0000);
    }
    Ok(out)
}

/// The packet page has to hold the input and whatever the library writes back.
fn hex(b: &[u8]) -> String {
    b.iter()
        .take(48)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
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
pub fn probe_windows(image_path: Option<&str>, adi_dir: Option<&str>) -> Result<Probe, AdiError> {
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
        assert!(
            text.contains("provision"),
            "the report must survive: {text}"
        );
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
