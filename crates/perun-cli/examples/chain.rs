// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! In-process two-export chaining harness for the ADI-lane investigation.
//!
//! NOT part of the shipped CLI surface: this example exists to answer one
//! question — does the init export (`cvu8io98wun`) leave state behind (in
//! `.data` globals) that the operation export (`vdfut768ig`) then observes?
//! A cross-process `--poke` of the 16-byte struct header cannot carry such
//! state (globals die with the process), so both calls run back-to-back in
//! ONE address space here, with a `.data` snapshot/diff around each call.
//!
//! Usage:
//! ```sh
//! cargo run -p perun-cli --example chain -- /path/to/CoreADI64.dll
//! cargo run -p perun-cli --example chain -- dll [--skip-init] [--init EXP] [--op EXP]
//! ```
//!
//! `--skip-init` is the in-process control: run the op export cold, without
//! the init call first. Heap allocations and thread-local state are NOT
//! tracked (only mapped-image `.data` bytes are snapshotted) — reported.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;

/// One contiguous run of changed bytes: image-relative offset, old, new.
#[derive(Debug, PartialEq, Eq)]
struct Change {
    off: usize,
    old: Vec<u8>,
    new: Vec<u8>,
}

/// Diff two equal-length snapshots into coalesced runs of changes.
fn diff_snaps(before: &[u8], after: &[u8]) -> Vec<Change> {
    assert_eq!(before.len(), after.len());
    let mut out = Vec::new();
    let mut i = 0;
    while i < before.len() {
        if before[i] == after[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < before.len() && before[i] != after[i] {
            i += 1;
        }
        out.push(Change {
            off: start,
            old: before[start..i].to_vec(),
            new: after[start..i].to_vec(),
        });
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn report_diff(tag: &str, base_rva: u32, changes: &[Change]) {
    let total: usize = changes.iter().map(|c| c.old.len()).sum();
    println!(
        "[chain] .data diff after {tag}: {total} byte(s) in {} run(s)",
        changes.len()
    );
    for c in changes.iter().take(8) {
        let show = c.old.len().min(16);
        println!(
            "  RVA {:#x}: {} -> {}",
            base_rva as usize + c.off,
            hex(&c.old[..show]),
            hex(&c.new[..show]),
        );
    }
    if changes.len() > 8 {
        println!("  ... ({} more run(s) omitted)", changes.len() - 8);
    }
}

fn usage() -> i32 {
    eprintln!("usage: chain <dll> [--skip-init] [--init EXP] [--op EXP]");
    eprintln!("  default: cvu8io98wun(scratch,scratch), then vdfut768ig(scratch,scratch)");
    2
}

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        return usage();
    }
    let mut init_exp = "cvu8io98wun".to_string();
    let mut op_exp = "vdfut768ig".to_string();
    let mut skip_init = false;
    let mut dll: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--skip-init" => skip_init = true,
            "--init" => init_exp = it.next().cloned().unwrap_or_default(),
            "--op" => op_exp = it.next().cloned().unwrap_or_default(),
            s if s.starts_with('-') => {
                eprintln!("error: unknown flag {s:?}");
                return usage();
            }
            s => dll = Some(s.to_string()),
        }
    }
    let dll = match dll {
        Some(d) => d,
        None => return usage(),
    };
    if init_exp.is_empty() || op_exp.is_empty() {
        return usage();
    }

    let bytes = match std::fs::read(&dll) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {dll}: {e}");
            return 1;
        }
    };
    let info = match perun_core::image::PeInfo::parse(&bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: parse {e:?}");
            return 1;
        }
    };
    let data_sec = match info.sections.iter().find(|s| s.name_str() == ".data") {
        Some(s) => s,
        None => {
            eprintln!("error: no .data section");
            return 1;
        }
    };
    let data_rva = data_sec.virtual_address;
    let data_len = data_sec.virtual_size as usize;
    println!("[chain] .data RVA {data_rva:#x} len {data_len:#x}");

    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("error: load {e:?}");
            return 1;
        }
    };
    unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = match unsafe { image.entry_dll_main() } {
        Some(f) => f,
        None => {
            eprintln!("error: image has no entry point");
            return 1;
        }
    };
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        eprintln!("error: DllMain returned FALSE");
        return 3;
    }
    println!("[chain] DllMain TRUE; shim table {} APIs", table.len());

    let scratch = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if scratch == libc::MAP_FAILED {
        eprintln!("error: scratch mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(scratch as *mut u8, 0, 0x1000) };
    let scratch = scratch as u64;

    let snap = || unsafe {
        std::slice::from_raw_parts(image.base().add(data_rva as usize), data_len).to_vec()
    };
    let resolve = |name: &str| -> Option<ExportFn> {
        image
            .get_export_by_name(name)
            .map(|p| unsafe { std::mem::transmute(p) })
    };

    if !skip_init {
        let f = match resolve(&init_exp) {
            Some(f) => f,
            None => {
                eprintln!("error: export {init_exp:?} not found");
                return 1;
            }
        };
        let before = snap();
        let r = unsafe { f(scratch, scratch, 0, 0) };
        println!("[chain] {init_exp}(scratch,scratch) returned {r:#x} ({r})");
        report_diff(
            &format!("{init_exp} (rc={r:#x})"),
            data_rva,
            &diff_snaps(&before, &snap()),
        );
    } else {
        println!("[chain] --skip-init: op export runs cold");
    }

    let g = match resolve(&op_exp) {
        Some(g) => g,
        None => {
            eprintln!("error: export {op_exp:?} not found");
            return 1;
        }
    };
    let before = snap();
    let r = unsafe { g(scratch, scratch, 0, 0) };
    println!("[chain] {op_exp}(scratch,scratch) returned {r:#x} ({r})");
    report_diff(
        &format!("{op_exp} (rc={r:#x})"),
        data_rva,
        &diff_snaps(&before, &snap()),
    );

    let head = unsafe { std::slice::from_raw_parts(scratch as *const u8, 32) };
    println!("[chain] scratch[0..32] = {}", hex(head));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_diff_on_identical() {
        assert!(diff_snaps(&[1, 2, 3], &[1, 2, 3]).is_empty());
    }

    #[test]
    fn single_run_coalesces() {
        let d = diff_snaps(&[0, 0, 0, 0], &[0, 9, 8, 0]);
        assert_eq!(
            d,
            vec![Change {
                off: 1,
                old: vec![0, 0],
                new: vec![9, 8],
            }]
        );
    }

    #[test]
    fn split_runs_stay_split() {
        let d = diff_snaps(&[1, 0, 1], &[2, 0, 3]);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].off, 0);
        assert_eq!(d[1].off, 2);
    }
}
