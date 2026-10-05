// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun adi headers` -- drive `CoreADI64.dll` natively and report the
//! Anisette v3 request headers it is able to produce on this host.
//!
//! The lane is deliberately narrow. `CoreADI64.dll` is a PE32+ image with no
//! networking imports at all -- `KERNEL32`, `ADVAPI32`, `SHELL32` and `SHLWAPI`
//! only, 103 symbols, nothing that opens a socket -- so whatever transport a
//! real Anisette round trip needs cannot come from this image. The command
//! therefore runs the library for real and prints what it actually produced,
//! with the status of every stage, rather than emitting header values that
//! nothing in the process computed.
//!
//! Each opcode consumes the parameter packet: `vdfut768ig` rewrites the first
//! qword of the scratch buffer on every successful call, and a second call with
//! the same packet answers `-45018`. So the packet is rebuilt before each one,
//! which is why this runs the opcodes in sequence on one loaded image instead
//! of calling the export three times from three processes.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

/// The three obfuscated selectors, as they appear in the dispatch table.
const OPCODE_INIT: u64 = 0xb0ed_a7af;
const OPCODE_PROVISION: u64 = 0xcfe0_b46a;
const OPCODE_LOGIN: u64 = 0x3e58_e7f9;

/// The parameter packet that reaches the success path.
///
/// Byte 3 is the discriminator the barrier compares against; bytes 6 and 7 are
/// the pair that has to read as `(0x00, 0x01)`. Written as explicit byte
/// stores rather than one qword poke, because a qword literal is ambiguous
/// here: `0x00000001_00000001` parses as the single number `0x100000001`, whose
/// little-endian bytes are `01 00 00 00 01 00 00 00` -- not this packet.
const PACKET: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];

/// Input size the library is told about. It has to be the size of the buffer it
/// is handed, not the size of the packet: a smaller value is rejected
/// (`-45018`) before the packet is read at all.
const INPUT_SIZE: u64 = 0x200;

/// Scratch is one page and the packet lives at its base.
const SCRATCH_LEN: usize = 0x1000;

/// Outcome of one opcode.
pub struct Stage {
    pub name: &'static str,
    pub opcode: u64,
    pub status: u32,
    /// Bytes the call left in the scratch page outside the packet.
    pub wrote_output: usize,
}

/// What one run produced: every stage's outcome, and the rendered report.
pub struct Probe {
    pub image_path: String,
    pub stages: Vec<Stage>,
    pub report: String,
}

impl Probe {
    /// True when every opcode reported success.
    pub fn all_signed(&self) -> bool {
        !self.stages.is_empty() && self.stages.iter().all(|s| signed(s.status) == 0)
    }
}

/// Run the three opcodes against one loaded image.
pub fn probe(image_path: &str, adi_dir: Option<&str>) -> Result<Probe, String> {
    let bytes = std::fs::read(image_path).map_err(|e| format!("read {image_path}: {e}"))?;
    let mut table = ShimTable::collect();
    let image = Image::load(&bytes, &mut table).map_err(|e| format!("{e:?}"))?;
    // SAFETY: the TEB is per-thread and this thread is the only one running.
    // The handle is not used afterwards; `perun call` keeps it for the same
    // reason and ignores it too.
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = unsafe { image.entry_dll_main() }
        .ok_or_else(|| format!("{image_path} has no entry point"))?;
    // SAFETY: DllMain(PROCESS_ATTACH) on a freshly mapped image with the shim
    // table installed; this is what `perun run` does for the same file.
    let attached = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if attached == 0 {
        return Err("DllMain returned FALSE".to_string());
    }

    let entry = image
        .get_export_by_name("vdfut768ig")
        .ok_or_else(|| format!("{image_path} does not export vdfut768ig"))?;
    // SAFETY: `vdfut768ig` is `HRESULT (u32, ADIRequest*, void*, void*)`, the
    // signature `perun call` already drives this export with.
    let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(entry) };

    // The guest resolves its SPIM cache through these, and it composes that
    // path in a buffer it never writes, so without this the lookup is aimed at
    // uninitialised bytes and always misses.
    if let Some(dir) = adi_dir {
        // SAFETY: this thread is the only one alive in the process at this
        // point, and nothing else reads the environment concurrently.
        unsafe { std::env::set_var("PERUN_ADI_DIR", dir) };
    }

    let scratch = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            SCRATCH_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if scratch == libc::MAP_FAILED {
        return Err("could not map the scratch page".to_string());
    }
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
    if ctx == libc::MAP_FAILED {
        unsafe { libc::munmap(scratch.cast(), SCRATCH_LEN) };
        return Err("could not map the context page".to_string());
    }

    let stages = [
        ("initialise", OPCODE_INIT),
        ("provision", OPCODE_PROVISION),
        ("login code", OPCODE_LOGIN),
    ]
    .into_iter()
    .map(|(name, opcode)| {
        // A fresh packet per call: the library consumes the one it is given.
        unsafe {
            std::ptr::write_bytes(scratch.cast::<u8>(), 0, SCRATCH_LEN);
            std::ptr::copy_nonoverlapping(PACKET.as_ptr(), scratch.cast::<u8>(), PACKET.len());
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let c = ctx.cast::<u64>();
            // +0x00 the packet pointer, +0x08 its size, +0x0c the output size
            // the library is asked to require; it writes back what it needs.
            std::ptr::write(c, scratch as u64);
            std::ptr::write(c.add(1), INPUT_SIZE);
            std::ptr::write(c.add(2), 0);
            let r = f(opcode, ctx as u64, 0, 0);
            Stage {
                name,
                opcode,
                status: r as u32,
                wrote_output: output_bytes(scratch),
            }
        }
    })
    .collect::<Vec<_>>();

    unsafe {
        libc::munmap(scratch.cast(), SCRATCH_LEN);
        libc::munmap(ctx.cast(), 0x1_0000);
    }

    Ok(Probe {
        image_path: image_path.to_string(),
        report: report(image_path, &stages),
        stages,
    })
}

/// Where the library lives when the caller does not say.
///
/// The extraction tree sits next to the repository rather than inside it, so
/// the search walks up from the current directory as well as trying the paths
/// relative to it: the ADI artefacts are not in version control.
pub fn default_adi_image() -> Option<String> {
    const RELATIVE: [&str; 3] = [
        "adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll",
        "adi-pe/CoreADI64.dll",
        "win32-adi-shim/CoreADI64.dll",
    ];
    let cwd = std::env::current_dir().ok()?;
    let mut roots = vec![cwd.clone()];
    for up in cwd.ancestors().skip(1).take(3) {
        roots.push(up.to_path_buf());
    }
    for root in &roots {
        for rel in RELATIVE {
            let p = root.join(rel);
            if p.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Bytes written into the scratch page outside the eight-byte packet.
///
/// The output pointer is not ours to know: the frame's output slots live at
/// `+0x28`/`+0x38` on the Android engine and nothing in the Windows trace ever
/// names one, so this counts what actually changed in a buffer the library
/// holds a pointer to, rather than assuming a layout.
fn output_bytes(scratch: *mut core::ffi::c_void) -> usize {
    let page = unsafe { std::slice::from_raw_parts(scratch.cast::<u8>(), SCRATCH_LEN) };
    page[PACKET.len()..].iter().filter(|b| **b != 0).count()
}

fn report(image_path: &str, stages: &[Stage]) -> String {
    let mut out = String::new();
    out.push_str(&format!("image: {image_path}\n"));
    out.push_str("opcode  stage         status   output bytes\n");
    for s in stages {
        out.push_str(&format!(
            "{:#010x}  {:<12}  {:<8}  {}\n",
            s.opcode,
            s.name,
            signed(s.status),
            s.wrote_output
        ));
    }

    let all_ok = stages.iter().all(|s| s.status == 0);
    let any_output = stages.iter().any(|s| s.wrote_output > 0);
    out.push('\n');
    if all_ok && any_output {
        out.push_str("status: all opcodes returned 0 and wrote output\n");
    } else if all_ok {
        // This is the measured state, and it is not success in the sense the
        // header block needs. Each opcode returns 0 after checking its cache
        // directory; none of them produces a token, and this image has no
        // networking imports, so the round trip that mints `X-Apple-I-MD` and
        // `X-Apple-I-MD-M` cannot happen inside it.
        out.push_str(
            "status: all opcodes returned 0, but no token bytes were written.\n\
             \n\
             This is the boundary of the Windows lane, not a missing step. The\n\
             three opcodes stop after resolving their SPIM cache directory, and\n\
             CoreADI64.dll imports no networking API at all (KERNEL32, ADVAPI32,\n\
             SHELL32, SHLWAPI; 103 symbols), so the HTTP round trip to Apple's\n\
             GrandSlam service cannot be performed by this image. An Anisette\n\
             header block needs that round trip, so no X-Apple-I-MD, X-Apple-I-MD-M\n\
             or X-Apple-I-MD-LU is emitted here rather than fabricated.\n\
             \n\
             X-Apple-I-MD-RINFO, X-Apple-I-SRL-NO, X-Apple-I-Client-Time and\n\
             X-Apple-I-TimeZone are constants or clock reads, and the store client\n\
             already supplies them; only the three token headers need the guest.\n",
        );
    } else {
        let bad: Vec<String> = stages
            .iter()
            .filter(|s| s.status != 0)
            .map(|s| format!("{} ({:#010x})", s.name, s.opcode))
            .collect();
        out.push_str(&format!("status: failed at {}\n", bad.join(", ")));
    }
    out
}

/// Win32 HRESULT as signed, which is how the guest reports errors.
pub fn signed(status: u32) -> i32 {
    status as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_is_the_measured_success_header() {
        // Byte 3 discriminates at the barrier and (6, 7) is the pair that must
        // read (0, 1). Anything else answers -45034 or -45020.
        assert_eq!(PACKET[3], 0x01);
        assert_eq!((PACKET[6], PACKET[7]), (0x00, 0x01));
        assert_eq!(PACKET.len(), 8);
    }

    #[test]
    fn error_statuses_render_signed() {
        // -45018 is invalidInputDataParamHeader, which is what a consumed or
        // malformed packet returns.
        assert_eq!(signed(0xffff_5026), -45018);
        assert_eq!(signed(0), 0);
    }

    #[test]
    fn report_names_the_lane_boundary_when_nothing_is_written() {
        let stages = [
            Stage {
                name: "initialise",
                opcode: OPCODE_INIT,
                status: 0,
                wrote_output: 0,
            },
            Stage {
                name: "provision",
                opcode: OPCODE_PROVISION,
                status: 0,
                wrote_output: 0,
            },
            Stage {
                name: "login code",
                opcode: OPCODE_LOGIN,
                status: 0,
                wrote_output: 0,
            },
        ];
        let text = report("CoreADI64.dll", &stages);
        assert!(text.contains("all opcodes returned 0, but no token bytes"));
        assert!(text.contains("imports no networking API"));
        // No header may be claimed when nothing was produced: the prose names
        // the token headers to explain their absence, but never as a value.
        assert!(!text.contains("X-Apple-I-MD: "));
        assert!(!text.contains("X-Apple-I-MD-M: "));
    }

    #[test]
    fn report_lists_the_failing_stage() {
        let stages = [Stage {
            name: "login code",
            opcode: OPCODE_LOGIN,
            status: 0xffff_5026,
            wrote_output: 0,
        }];
        let text = report("CoreADI64.dll", &stages);
        assert!(text.contains("status: failed at login code"));
    }
}
