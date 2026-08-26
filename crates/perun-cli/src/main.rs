// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun` — runner and inspector for native PE images under the runtime.

use perun_core::loader::{Image, LoadError, DLL_PROCESS_ATTACH};
use perun_shims::table::ShimTable;

fn main() {
    let code = run();
    // Exit via C ABI to avoid unwinding across guest frames.
    unsafe { libc::_exit(code) }
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n       perun info <image.dll>"
        );
        return 2;
    }

    match args[1].as_str() {
        "info" => cmd_info(&args[2]),
        "run" => cmd_run(&args[2..]),
        "call" => cmd_call(&args[2..]),
        _ => {
            eprintln!("unknown command: {}", args[1]);
            2
        }
    }
}

struct RunOpts {
    verbose: bool,
    trace: bool,
    trace_file: Option<String>,
    no_teb: bool,
}

fn parse_opts(args: &[String]) -> RunOpts {
    let mut o = RunOpts {
        verbose: false,
        trace: false,
        trace_file: None,
        no_teb: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--verbose" => o.verbose = true,
            "--trace" => o.trace = true,
            "--trace-file" => {
                i += 1;
                o.trace_file = args.get(i).cloned();
            }
            "--no-teb" => o.no_teb = true,
            other => eprintln!("[perun] warning: unknown flag {other} ignored"),
        }
        i += 1;
    }
    o
}

fn cmd_run(args: &[String]) -> i32 {
    let path = &args[0];
    let opts = parse_opts(&args[1..]);

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };

    if opts.verbose {
        if let Ok(info) = perun_core::image::PeInfo::parse(&bytes) {
            println!(
                "[perun] image {path}: entry={:#x} base={:#x} sections={}",
                info.opt.address_of_entry_point,
                info.opt.image_base,
                info.sections.len()
            );
        }
    }

    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(LoadError::UnsupportedMachine { machine }) => {
            eprintln!("error: unsupported machine {machine:#06x} (only x86_64 PE32+)");
            return 1;
        }
        Err(e) => {
            eprintln!("error: {e:?}");
            return 1;
        }
    };

    println!("[perun] loaded at {:#x}", image.base() as usize);
    println!("[perun] shim table: {} APIs registered", table.len());

    // Phase 0: thread context. GS must point at a FakeTEB before any guest
    // code runs; MSVC CRT startup reads TEB fields immediately. Installed
    // after mapping so the TEB can carry the real image base.
    if opts.no_teb {
        println!("[perun] phase0: TEB/GS setup SKIPPED (--no-teb)");
    } else {
        unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
        println!("[perun] phase0: FakeTEB installed at GS_BASE");
    }

    if opts.trace {
        let file = opts.trace_file.clone().unwrap_or_default();
        std::env::set_var("PERUN_TRACE", "1");
        if !file.is_empty() {
            std::env::set_var("PERUN_TRACE_FILE", file);
        }
        println!("[perun] tracing enabled");
    }

    // Phase 2: DllMain(DLL_PROCESS_ATTACH).
    let dll_main = match unsafe { image.entry_dll_main() } {
        Some(f) => f,
        None => {
            eprintln!("error: image has no entry point");
            return 1;
        }
    };
    println!("[perun] calling DllMain(DLL_PROCESS_ATTACH)...");
    let ret = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if ret != 0 {
        println!("[perun] DllMain returned TRUE — init complete");
        0
    } else {
        println!("[perun] DllMain returned FALSE — init failed (see trap log above)");
        3
    }
}

/// `perun call <image.dll> <export> [arg0 arg1 arg2 arg3]`
///
/// Loads the image, runs DllMain, then invokes the named export through the
/// Win64 ABI with up to four integer/pointer arguments. Each argument is
/// parsed as hex (0x…) or decimal. Arguments that look like pointers are
/// backed by a zeroed scratch page so the guest can read/write them safely.
fn cmd_call(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3]");
        return 2;
    }
    let path = &args[0];
    let export_name = &args[1];

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };

    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("error: {e:?}");
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
    let ret = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if ret == 0 {
        eprintln!("error: DllMain returned FALSE; refusing to call export");
        return 3;
    }
    println!("[perun] DllMain TRUE; shim table {} APIs", table.len());

    let export_ptr = match image.get_export_by_name(export_name) {
        Some(p) => p,
        None => {
            eprintln!("error: export {export_name:?} not found");
            return 1;
        }
    };
    println!("[perun] export {export_name} @ {:#x}", export_ptr as usize);

    // Scratch page for pointer-backed arguments / output capture.
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

    // A larger zeroed region to stand in for a guest context struct. The token
    // "ctx" resolves to it, so callers can point a global at a fake context.
    let ctx_size = 0x10000usize;
    let ctx = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ctx_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ctx == libc::MAP_FAILED {
        eprintln!("error: ctx mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(ctx as *mut u8, 0, ctx_size) };

    // Parse up to 4 positional args. The token "scratch" resolves to the clean
    // scratch page address, so callers can hand the guest a zeroed parameter
    // block. Options of the form --poke RVA=VALUE write a qword into guest
    // memory (image.base + RVA) before the call, letting us pre-fill globals.
    let mut argv = [0u64; 4];
    // (kind, target, value): kind 0 = guest RVA, kind 1 = ctx offset,
    // kind 2 = scratch offset
    let mut pokes: Vec<(u8, u64, u64)> = Vec::new();
    // --patch=RVA=HEXBYTES: raw code patch into the mapped image (mprotect'd)
    let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
    // --peek=RVA[,RVA...]: read guest qwords after the call
    let mut peeks: Vec<String> = Vec::new();
    // --peek-ptr=RVA[,RVA...]: dereference guest RVA as host pointer, dump object
    let mut peek_ptrs: Vec<String> = Vec::new();
    let mut ai = 0usize;
    let resolve = |tok: &str| -> Option<u64> {
        match tok {
            "scratch" => Some(scratch as u64),
            "ctx" => Some(ctx as u64),
            _ => parse_num(tok),
        }
    };
    for a in args[2..].iter() {
        if let Some(spec) = a.strip_prefix("--patch=") {
            let (rva_s, hex_s) = spec.split_once('=').unwrap_or((spec, ""));
            let rva = parse_num(rva_s).unwrap_or_else(|| {
                eprintln!("error: bad --patch rva {rva_s:?}");
                std::process::exit(2);
            });
            let clean: String = hex_s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if clean.len() % 2 != 0 || clean.is_empty() {
                eprintln!("error: bad --patch bytes {hex_s:?}");
                std::process::exit(2);
            }
            let bytes: Vec<u8> = (0..clean.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
                .collect();
            patches.push((rva, bytes));
            continue;
        }
        if let Some(spec) = a.strip_prefix("--peek=") {
            peeks.push(spec.to_string());
            continue;
        }
        if let Some(spec) = a.strip_prefix("--peek-ptr=") {
            peek_ptrs.push(spec.to_string());
            continue;
        }
        if let Some(spec) = a.strip_prefix("--poke=") {
            let (tgt_s, val_s) = spec.split_once('=').unwrap_or((spec, ""));
            let val = resolve(val_s).unwrap_or_else(|| {
                eprintln!("error: bad --poke value {val_s:?}");
                std::process::exit(2);
            });
            if let Some(off_s) = tgt_s.strip_prefix("ctx+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad ctx offset {off_s:?}");
                    std::process::exit(2);
                });
                pokes.push((1, off, val));
            } else if let Some(off_s) = tgt_s.strip_prefix("scratch+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad scratch offset {off_s:?}");
                    std::process::exit(2);
                });
                pokes.push((2, off, val));
            } else {
                let rva = parse_num(tgt_s).unwrap_or_else(|| {
                    eprintln!("error: bad --poke rva {tgt_s:?}");
                    std::process::exit(2);
                });
                pokes.push((0, rva, val));
            }
            continue;
        }
        if let Some(spec) = a.strip_prefix("--poke-ptr=") {
            // --poke-ptr=RVA=VALUE: read the qword at guest RVA as a host
            // pointer, then write VALUE to the pointed-to memory. Used to poke
            // through the provisioning gate's double dereference.
            let (rva_s, val_s) = spec.split_once('=').unwrap_or((spec, ""));
            let rva = parse_num(rva_s).unwrap_or_else(|| {
                eprintln!("error: bad --poke-ptr rva {rva_s:?}");
                std::process::exit(2);
            });
            let val = resolve(val_s).unwrap_or_else(|| {
                eprintln!("error: bad --poke-ptr value {val_s:?}");
                std::process::exit(2);
            });
            let slot = (image.base() as u64).wrapping_add(rva) as *const u64;
            let target = unsafe { std::ptr::read(slot) };
            unsafe { std::ptr::write(target as *mut u64, val) };
            println!(
                "[perun] poke-ptr [RVA {rva:#x}] -> {target:#x} := {val:#x}"
            );
            continue;
        }
        if ai < 4 {
            argv[ai] = resolve(a).unwrap_or_else(|| {
                eprintln!("error: bad argument {a:?}");
                std::process::exit(2);
            });
            ai += 1;
        }
    }

    // Apply pokes. kind 0 -> guest memory (image.base + rva); kind 1 -> ctx
    // region; kind 2 -> scratch (parameter) region.
    for (kind, tgt, val) in &pokes {
        let addr = match kind {
            0 => (image.base() as u64).wrapping_add(*tgt) as *mut u64,
            1 => (ctx as u64).wrapping_add(*tgt) as *mut u64,
            _ => (scratch as u64).wrapping_add(*tgt) as *mut u64,
        };
        unsafe { std::ptr::write(addr, *val) };
        let label = match kind {
            0 => format!("[RVA {tgt:#x}]"),
            1 => format!("ctx[{tgt:#x}]"),
            _ => format!("scratch[{tgt:#x}]"),
        };
        println!("[perun] poke {label} = {val:#x} (abs {addr:p})");
    }

    // Apply raw code patches. The image sections are mapped RX, so flip the
    // target page(s) to RWX, write the bytes, then restore RX.
    for (rva, bytes) in &patches {
        let addr = (image.base() as u64).wrapping_add(*rva) as *mut u8;
        let page = (addr as usize) & !0xfff;
        let end = (addr as usize) + bytes.len();
        let npages = (end - page + 0xfff) / 0x1000;
        unsafe {
            libc::mprotect(
                page as *mut libc::c_void,
                npages * 0x1000,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr, bytes.len());
            libc::mprotect(
                page as *mut libc::c_void,
                npages * 0x1000,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
        println!("[perun] patch RVA {rva:#x} <- {} bytes", bytes.len());
        // Read back to confirm the write landed (mprotect may have failed).
        let rb = unsafe { std::slice::from_raw_parts(addr, bytes.len().min(8)) };
        println!("[perun]   readback: {}", hexdump(rb));
    }

    type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
    let f: ExportFn = unsafe { std::mem::transmute(export_ptr) };
    println!(
        "[perun] calling {export_name}({:#x}, {:#x}, {:#x}, {:#x})...",
        argv[0], argv[1], argv[2], argv[3]
    );
    let r = unsafe { f(argv[0], argv[1], argv[2], argv[3]) };
    println!("[perun] {export_name} returned {r:#x} ({r})");

    // Dump tracked gate candidates (PERUN_HEAP_FILL research hook) so the
    // caller can correlate them with the --peek-ptr object address.
    for (addr, v) in perun_shims::util::gate_candidates_snapshot() {
        println!("[perun] gate-candidate {addr:#x} fill={v:#x}");
    }

    // --peek=RVA[,RVA...]: read qwords from guest memory after the call so the
    // caller can watch globals (e.g. the provisioning gate) for writes.
    for spec in peeks.iter() {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }
            let rva = parse_num(part).unwrap_or_else(|| {
                eprintln!("error: bad --peek rva {part:?}");
                std::process::exit(2);
            });
            let addr = (image.base() as u64).wrapping_add(rva) as *const u64;
            let v = unsafe { std::ptr::read(addr) };
            println!("[perun] peek [RVA {rva:#x}] = {v:#x}");
        }
    }

    // --peek-ptr=RVA[,RVA...]: read the qword at each guest RVA as a host
    // pointer and dump the first 64 bytes of the pointed-to object. This is
    // how we inspect the provisioning-gate object behind the double deref.
    for spec in peek_ptrs.iter() {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let rva = parse_num(part).unwrap_or_else(|| {
                eprintln!("error: bad --peek-ptr rva {part:?}");
                std::process::exit(2);
            });
            let slot = (image.base() as u64).wrapping_add(rva) as *const u64;
            let target = unsafe { std::ptr::read(slot) };
            println!("[perun] peek-ptr [RVA {rva:#x}] -> {target:#x}");
            if target != 0 {
                let obj = unsafe { std::slice::from_raw_parts(target as *const u8, 64) };
                println!("[perun]   object[0..64] = {}", hexdump(obj));
            }
        }
    }

    // Dump the scratch page head in case the guest wrote output there.
    let head = unsafe { std::slice::from_raw_parts(scratch as *const u8, 64) };
    if head.iter().any(|&b| b != 0) {
        println!("[perun] scratch[0..64] = {}", hexdump(head));
    }

    // Dump memory behind any argument that looks like a readable pointer, so
    // we can see what the guest wrote into its parameter blocks.
    for (i, a) in argv.iter().enumerate() {
        let p = *a as *const u8;
        if p.is_null() {
            continue;
        }
        // Probe readability with a 64-byte read; skip on fault.
        let readable = unsafe { probe_read(p, 64) };
        if readable {
            let bytes = unsafe { std::slice::from_raw_parts(p, 64) };
            if bytes.iter().any(|&b| b != 0) {
                println!("[perun] arg{i} [{a:#x}] -> {}", hexdump(bytes));
            }
        }
    }
    0
}

/// Return true if `len` bytes at `p` are readable without faulting.
/// Uses a mincore-style probe via msync on a copy; simplest portable check is
/// to attempt the read under a SIGSEGV guard. Here we use a process_vm-style
/// self-read via a pipe: write the memory to a pipe and see if it succeeds.
unsafe fn probe_read(p: *const u8, len: usize) -> bool {
    // mincore requires page-aligned addr; instead do a bounded read via
    // /dev/null write using write(2) on the pointer directly.
    let fd = libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_WRONLY);
    if fd < 0 {
        return false;
    }
    // write(2) will return EFAULT instead of crashing if the range is bad.
    let n = libc::write(fd, p as *const core::ffi::c_void, len);
    libc::close(fd);
    n == len as isize
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn hexdump(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn cmd_info(path: &str) -> i32 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };
    match perun_core::image::PeInfo::parse(&bytes) {
        Ok(info) => {
            println!("Image:           {path}");
            println!("Size:            {} bytes", bytes.len());
            println!("Machine:         x86_64 (validated by parser)");
            println!("Entry point RVA: {:#x}", info.opt.address_of_entry_point);
            println!("Preferred base:  {:#x}", info.opt.image_base);
            println!("Size of image:   {:#x}", info.opt.size_of_image);
            for s in &info.sections {
                println!(
                    "  {:8} VA={:#08x} VSize={:#x} Raw={:#x}",
                    s.name_str(),
                    s.virtual_address,
                    s.virtual_size,
                    s.size_of_raw_data,
                );
            }
            0
        }
        Err(e) => {
            eprintln!("parse failed: {e:?}");
            1
        }
    }
}
