// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! feed_spim: feed a live GSA spim (+dsId) into CoreADI64.dll via honest
//! in-process pointers. Model A (flat) vs Model B (envelope), opcodes 0..7.
//! Signal: any return outside {5016, 5026} or any cpim_out write.
//! Usage: feed_spim <dll> <spim.raw> [dsId=-2]
//!
//! Each case runs in its own child process: a wild guest can smash the host
//! stack past the crash probe, so one address space per case.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;

const KNOWN: [u64; 3] = [0xffff5016, 0xffff5026, 0xffff5036];
const CPIM_CAP: usize = 4096;

fn w64(mem: &mut [u8], off: usize, v: u64) {
    mem[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn w32(mem: &mut [u8], off: usize, v: u32) {
    mem[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn r64(mem: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(mem[off..off + 8].try_into().unwrap())
}

fn layout_a1(dsid: u64, op: u64, spim: u64, spim_len: u64, cpim: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, dsid);
    w64(&mut s, 0x08, op);
    w64(&mut s, 0x10, spim);
    w64(&mut s, 0x18, spim_len);
    w64(&mut s, 0x20, cpim);
    w32(&mut s, 0x28, 0);
    s
}

fn layout_a2(dsid: u64, op: u64, spim: u64, spim_len: u64, cpim: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, op);
    w64(&mut s, 0x08, dsid);
    w64(&mut s, 0x10, spim);
    w64(&mut s, 0x18, spim_len);
    w64(&mut s, 0x20, cpim);
    w32(&mut s, 0x28, 0);
    s
}

fn layout_b(inner: u64, op: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x20];
    w64(&mut s, 0x00, inner);
    w64(&mut s, 0x08, 347);
    w64(&mut s, 0x10, CPIM_CAP as u64);
    w64(&mut s, 0x18, op);
    s
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: feed_spim <dll> <spim.raw> [dsId=-2] [model op]");
        return 2;
    }
    // Worker mode: one case, crashes contained by the OS.
    if args.len() > 3 {
        let dsid = args[2].parse::<i64>().unwrap_or(-2) as u64;
        let op: u64 = args[4].parse().unwrap_or(0);
        return single_case(&args[0], &args[1], dsid, &args[3], op);
    }
    // Driver mode: isolate every case in a child process.
    let exe = std::env::current_exe().unwrap();
    let dsid = if args.len() > 2 {
        args[2].clone()
    } else {
        "-2".into()
    };
    let mut hits = 0;
    let mut ran = 0;
    for model in ["A1", "A2", "B"] {
        for op in 0u64..8 {
            ran += 1;
            let out = std::process::Command::new(&exe)
                .args([&args[0], &args[1], &dsid, model, &op.to_string()])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    let line = String::from_utf8_lossy(&o.stdout);
                    let line = line.trim();
                    print!("{model} op={op} worker-rc=0 {line}\n");
                    if line.starts_with("HIT") {
                        hits += 1;
                    }
                }
                Ok(o) => {
                    println!("{model} op={op} worker-died rc={}", o.status);
                    hits += 1;
                }
                Err(e) => println!("{model} op={op} spawn failed: {e}"),
            }
        }
    }
    println!("[feed] done, {hits} hit(s)/crashes out of {ran}");
    0
}

/// Run ONE (model, op) case in this address space; print one result line.
fn single_case(dll: &str, spim_path: &str, dsid: u64, model: &str, opv: u64) -> i32 {
    let spim = std::fs::read(spim_path).unwrap_or_else(|e| {
        eprintln!("read {spim_path}: {e}");
        std::process::exit(1);
    });
    let bytes = std::fs::read(dll).unwrap_or_else(|e| {
        eprintln!("read {dll}: {e}");
        std::process::exit(1);
    });
    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("load: {e:?}");
            return 1;
        }
    };
    unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = match unsafe { image.entry_dll_main() } {
        Some(f) => f,
        None => {
            eprintln!("no entry");
            return 1;
        }
    };
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        eprintln!("DllMain FALSE");
        return 3;
    }
    let op_ptr = match image.get_export_by_name("vdfut768ig") {
        Some(p) => p,
        None => {
            eprintln!("no export");
            return 1;
        }
    };
    let op: ExportFn = unsafe { std::mem::transmute(op_ptr) };

    unsafe fn region(n: usize) -> *mut u8 {
        let p = libc::mmap(
            std::ptr::null_mut(),
            n,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            eprintln!("mmap failed");
            std::process::exit(1);
        }
        std::ptr::write_bytes(p as *mut u8, 0, n);
        p as *mut u8
    }

    let rsp = unsafe { region(spim.len().max(8)) };
    unsafe { std::ptr::copy_nonoverlapping(spim.as_ptr(), rsp, spim.len()) };
    let rcp = unsafe { region(CPIM_CAP) };
    let rstruct = unsafe { region(0x1000) };
    let rinner = unsafe { region(0x1000) };
    let blob = match model {
        "A1" => layout_a1(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64),
        "A2" => layout_a2(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64),
        _ => {
            let inner = layout_a1(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64);
            unsafe {
                std::ptr::copy_nonoverlapping(inner.as_ptr(), rinner, inner.len());
            }
            layout_b(rinner as u64, opv)
        }
    };
    unsafe {
        std::ptr::copy_nonoverlapping(blob.as_ptr(), rstruct, blob.len());
    }
    let r = unsafe { op(rstruct as u64, rstruct as u64, 0, 0) };
    let scpim = unsafe { std::slice::from_raw_parts(rcp as *const u8, CPIM_CAP) };
    let wrote = scpim.iter().any(|&b| b != 0);
    if !KNOWN.contains(&r) || wrote {
        print!("HIT {model} op={opv} -> {r:#x} ({r}) cpim_wrote={wrote}");
        if wrote {
            let n = scpim.iter().take_while(|&&b| b == 0).count();
            let show = 32.min(CPIM_CAP - n);
            print!(" cpim[{n}..{}] = {}", n + show, hex(&scpim[n..n + show]));
        }
        println!();
    } else {
        println!("{model} op={opv} -> {r:#x} ({r}) cpim_wrote={wrote}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a1_offsets() {
        let s = layout_a1(0xAABB, 3, 0x1000, 347, 0x2000);
        assert_eq!(r64(&s, 0x00), 0xAABB);
        assert_eq!(r64(&s, 0x08), 3);
        assert_eq!(r64(&s, 0x10), 0x1000);
        assert_eq!(r64(&s, 0x18), 347);
        assert_eq!(r64(&s, 0x20), 0x2000);
        assert_eq!(s.len(), 0x30);
    }

    #[test]
    fn a2_offsets() {
        let s = layout_a2(0xAABB, 5, 0x1000, 347, 0x2000);
        assert_eq!(r64(&s, 0x00), 5);
        assert_eq!(r64(&s, 0x08), 0xAABB);
        assert_eq!(r64(&s, 0x10), 0x1000);
    }

    #[test]
    fn b_envelope_shape() {
        let s = layout_b(0x3000, 4);
        assert_eq!(r64(&s, 0x00), 0x3000);
        assert_eq!(r64(&s, 0x08), 347);
        assert_eq!(r64(&s, 0x10), CPIM_CAP as u64);
        assert_eq!(r64(&s, 0x18), 4);
    }
}
