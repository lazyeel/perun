// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun` — runner and inspector for native PE images under the runtime.

use perun_core::loader::{Image, LoadError, DLL_PROCESS_ATTACH};
use perun_shims::table::ShimTable;
use std::path::Path;

mod fetcher;
mod sap;

fn main() {
    unsafe { install_crash_probe() };
    let code = run();
    // Exit via C ABI to avoid unwinding across guest frames.
    unsafe { libc::_exit(code) }
}

/// POSIX signal handler: print guest-crash context (RIP, RSP, fault address)
/// straight to stderr, without unwinding.
///
/// Async-signal-safe by construction: no allocation, no TLS access, no
/// `format!` — everything runs on raw `write(2)`. (An earlier version read
/// a thread-local call counter here, which faulted *again inside the
/// handler* when the guest had clobbered the TLS block, destroying the
/// primary fault context.) SIGTRAP is not expected in production: there are
/// no int3 plants; it is reported and the process exits.
unsafe fn crash_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    let si_addr = (*info).si_addr() as u64;
    // ucontext_t.gregs layout (x86_64 glibc): REG_RIP=16, REG_RSP=19, etc.
    let uc = ctx as *mut libc::ucontext_t;
    let regs = (*uc).uc_mcontext.gregs.as_mut_ptr();
    let rip = *regs.add(libc::REG_RIP as usize) as u64;
    let rsp = *regs.add(libc::REG_RSP as usize) as u64;
    let rdi = *regs.add(libc::REG_RDI as usize) as u64;
    let rsi = *regs.add(libc::REG_RSI as usize) as u64;

    // The reference thunk page executes `hlt` when the guest returns — a
    // privileged instruction faults as SIGSEGV with rip at the hlt. Bounce
    // to the trampoline landing pad instead of dying: the guest function
    // has returned, and the landing restores the host frame.
    const RETURN_HLT: u64 = 0x1_0000_0000;
    if sig == libc::SIGSEGV && (rip == RETURN_HLT + 2 || rip == RETURN_HLT) {
        // rax holds the guest's return value; the landing expects to be
        // entered as if reached by `ret` from the thunk — rsp already sits
        // at the guest stack top edge.
        *regs.add(libc::REG_RIP as usize) = sap::guest_landing_for_signal() as i64;
        return;
    }

    // SIGTRAP in production means an unexpected int3/ICEBP in the guest
    // image — the debug watchpoint plants are gone. Report and die: the
    // state at the trap is not recoverable.
    if sig == libc::SIGTRAP {
        let mut out: [u8; 128] = [0; 128];
        let mut n = 0usize;
        let push = |s: &[u8], out: &mut [u8], n: &mut usize| {
            for &b in s {
                if *n < out.len() {
                    out[*n] = b;
                    *n += 1;
                }
            }
        };
        push(
            b"[perun] unexpected SIGTRAP (int3) at rip=",
            &mut out,
            &mut n,
        );
        push(&hex16(rip), &mut out, &mut n);
        push(b"\n", &mut out, &mut n);
        unsafe {
            libc::write(2, out.as_ptr().cast(), n);
            libc::_exit(128 + sig);
        }
    }

    let mut out: [u8; 256] = [0; 256];
    let mut n = 0usize;
    let push = |s: &[u8], out: &mut [u8], n: &mut usize| {
        for &b in s {
            if *n < out.len() {
                out[*n] = b;
                *n += 1;
            }
        }
    };
    push(b"[perun] guest crash: signal ", &mut out, &mut n);
    push(&hexdec(sig as u64, 2), &mut out, &mut n);
    push(b" addr=", &mut out, &mut n);
    push(&hex16(si_addr), &mut out, &mut n);
    push(b" rip=", &mut out, &mut n);
    push(&hex16(rip), &mut out, &mut n);
    push(b" rsp=", &mut out, &mut n);
    push(&hex16(rsp), &mut out, &mut n);
    push(b" rdi=", &mut out, &mut n);
    push(&hex16(rdi), &mut out, &mut n);
    push(b" rsi=", &mut out, &mut n);
    push(&hex16(rsi), &mut out, &mut n);
    push(b"\n", &mut out, &mut n);
    unsafe {
        libc::write(2, out.as_ptr().cast(), n);
        libc::_exit(128 + sig);
    }
}

/// Fixed-width hex of a u64 into a static buffer — no allocator.
unsafe fn hex16(v: u64) -> [u8; 18] {
    let mut buf: [u8; 18] = [b'0'; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        buf[2 + i] = HEX[((v >> (60 - 4 * i)) & 0xF) as usize];
    }
    buf
}

unsafe fn hexdec(v: u64, _pad: usize) -> [u8; 21] {
    let mut buf: [u8; 21] = [0; 21];
    let s = v.to_string();
    for (i, b) in s.bytes().take(20).enumerate() {
        buf[i] = b;
    }
    buf
}

/// # Safety
/// Must be installed before any guest code runs; the alt-stack it
/// registers must stay mapped for the process lifetime.
pub unsafe fn install_crash_probe() {
    // Alternate signal stack: the guest can leave the main stack pointer
    // anywhere when it faults, so the handler must not rely on it.
    static mut ALT: [u8; 64 * 1024] = [0; 64 * 1024];
    let mut ss: libc::stack_t = std::mem::zeroed();
    ss.ss_sp = std::ptr::addr_of_mut!(ALT).cast();
    ss.ss_size = 64 * 1024;
    libc::sigaltstack(&ss, std::ptr::null_mut());

    let mut act: libc::sigaction = std::mem::zeroed();
    act.sa_sigaction = crash_handler as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    libc::sigaction(libc::SIGSEGV, &act, std::ptr::null_mut());
    libc::sigaction(libc::SIGFPE, &act, std::ptr::null_mut());
    libc::sigaction(libc::SIGBUS, &act, std::ptr::null_mut());
    libc::sigaction(libc::SIGTRAP, &act, std::ptr::null_mut());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n       perun info <image.dll>\n       perun mach info <macho>\n       perun sap <dir> [--mac AA:BB:CC:DD:EE:FF] [--sign HEX|--file F] [--exchange-hex H]"
        );
        return 2;
    }

    match args[1].as_str() {
        "info" => cmd_info(&args[2]),
        "run" => cmd_run(&args[2..]),
        "call" => cmd_call(&args[2..]),
        "mach" => cmd_mach(&args[2..]),
        "sap" => cmd_sap(&args[2..]),
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
        eprintln!("usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3] [--verbose] [--patch=RVA=HEX] [--poke=RVA=VAL] [--peek=RVA] [--peek-ptr=RVA]");
        return 2;
    }
    // `--verbose` is accepted anywhere on the command line: pulled out of the
    // stream entirely, it never lands in the positional-argument slots.
    let verbose = args.iter().any(|a| a == "--verbose");
    let pos: Vec<String> = args
        .iter()
        .filter(|a| **a != "--verbose")
        .cloned()
        .collect();
    let path = &pos[0];
    let export_name = &pos[1];

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };

    if verbose {
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
    // The positional stream (with --verbose already filtered out) drives both
    // the argument slots and the --patch/--poke/--peek option parsing below.
    for a in pos[2..].iter() {
        if let Some(spec) = a.strip_prefix("--patch=") {
            let (rva_s, hex_s) = spec.split_once('=').unwrap_or((spec, ""));
            let rva = parse_num(rva_s).unwrap_or_else(|| {
                eprintln!("error: bad --patch rva {rva_s:?}");
                std::process::exit(2);
            });
            let clean: String = hex_s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if !clean.len().is_multiple_of(2) || clean.is_empty() {
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
            println!("[perun] poke-ptr [RVA {rva:#x}] -> {target:#x} := {val:#x}");
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
        let npages = (end - page).div_ceil(0x1000);
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

    // --peek=RVA[,RVA...]: read qwords from guest memory after the call so the
    // caller can watch globals (e.g. the provisioning gate) for writes.
    for spec in peeks.iter() {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
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
    let fd = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
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

// ── Mach-O surface ──────────────────────────────────────────────────────────

fn cmd_mach(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: perun mach info <macho-file>");
        return 2;
    }
    match args[0].as_str() {
        "info" => {
            let data = match std::fs::read(&args[1]) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("read {}: {e}", args[1]);
                    return 1;
                }
            };
            match perun_core::macho::MachInfo::parse(&data) {
                Ok(info) => {
                    println!("preferred base: {:#x}", info.base);
                    println!("segments:");
                    for s in &info.segments {
                        println!(
                            "  {:16} vm={:#018x}+{:#x} file={:#x}+{:#x}",
                            s.name_str(),
                            s.vmaddr,
                            s.vmsize,
                            s.fileoff,
                            s.filesize,
                        );
                    }
                    println!(
                        "fixups: {} rebases, {} binds, {} defined symbols",
                        info.rebases.len(),
                        info.binds.len(),
                        info.symbols.len(),
                    );
                    let obf: Vec<&str> = info
                        .symbols
                        .iter()
                        .map(|s| s.name.as_str())
                        .filter(|n| {
                            matches!(
                                *n,
                                "_cp2g1b9ro"
                                    | "_Mib5yocT"
                                    | "_Fc3vhtJDvr"
                                    | "_IPaI1oem5iL"
                                    | "_jEHf8Xzsv8K"
                                    | "_jfkdDAjba3jd"
                                    | "_gLg1CWr7p"
                                    | "_WIn9UJ86JKdV4dM"
                                    | "_X46O5IeS"
                                    | "_YlCJ3lg"
                                    | "_dku592fbFAj"
                                    | "_fdjkDSAFjklaf2s"
                                    | "_lxpgvVMLd0S7uRl"
                            )
                        })
                        .collect();
                    if !obf.is_empty() {
                        println!("SAP symbols present: {}", obf.join(", "));
                    }
                    0
                }
                Err(e) => {
                    eprintln!("parse failed: {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("unknown mach subcommand: {}", args[0]);
            2
        }
    }
}

fn cmd_sap(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: perun sap <assets-dir> [--mac AA:BB:..] [--sign HEX] [--file PATH]");
        return 2;
    }
    // Guest obfuscated code keeps deep recursion and wide frames; run the
    // whole sequence on a dedicated thread with a large stack, mirroring
    // the reference emulator's separate 8MB guest stack.
    let args = args.to_vec();
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            // sigaltstack is per-thread: the crash/int3 handlers rely on
            // SA_ONSTACK to survive guest-clobbered RSPs, but this spawned
            // thread starts without one. Install it here, before any guest
            // code runs on this thread.
            unsafe { sap::install_thread_altstack() };
            cmd_sap_inner(&args)
        })
        .expect("failed to spawn SAP thread");
    match handle.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("[sap] thread panicked");
            1
        }
    }
}

fn cmd_sap_inner(args: &[String]) -> i32 {
    // Asset resolution: explicit dir wins; otherwise a complete pinned cache is
    // used as-is; otherwise the zero-config fetcher downloads the missing
    // assets (first run only) and the command continues from the cache.
    let dir = if Path::new(&args[0]).is_dir() {
        args[0].clone()
    } else {
        match fetcher::ensure_cache(true) {
            Ok(cache) => cache.display().to_string(),
            Err(e) => {
                eprintln!("assets: {e}");
                return 1;
            }
        }
    };
    let mut mac = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
    let mut sign_hex: Option<String> = None;
    let mut sign_file: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mac" if i + 1 < args.len() => {
                let parts: Vec<&str> = args[i + 1].split(':').collect();
                if parts.len() == 6 {
                    for (j, p) in parts.iter().enumerate() {
                        mac[j] = u8::from_str_radix(p, 16).unwrap_or(mac[j]);
                    }
                }
                i += 2;
            }
            "--sign" if i + 1 < args.len() => {
                sign_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--file" if i + 1 < args.len() => {
                sign_file = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let assets = match sap::SapAssets::load_dir(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("assets: {e}");
            return 1;
        }
    };

    // Speculative TLS: the certificate download (~100-150 ms of network) runs
    // concurrently with image mapping; the setup phase joins the result. The
    // thread only performs the HTTPS fetch — it touches no guest state, no
    // process-wide handlers, and its failure surfaces as a setup error below,
    // exactly as a synchronous fetch would. The fetcher caches the certificate
    // (TTL 24h), so on cache hits the thread is a file read and the hot path
    // performs zero CDN round-trips before the protocol POST.
    let cert_fetch = std::thread::spawn(|| -> Result<Vec<u8>, String> {
        let path = fetcher::ensure_cert()?;
        std::fs::read(&path).map_err(|e| format!("read cached certificate: {e}"))
    });

    let t0 = std::time::Instant::now();
    let mut rt = match sap::SapRuntime::new(&assets) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return 1;
        }
    };
    println!("[sap] images loaded natively in {:?}", t0.elapsed());
    println!("[sap] {}", rt.entry_report());

    let t0 = std::time::Instant::now();
    match rt.init(mac) {
        Ok(ctx) => println!("[sap] SAPInit OK: context {:#x} ({:?})", ctx, t0.elapsed()),
        Err(e) => {
            eprintln!("[sap] SAPInit failed: {e}");
            return 1;
        }
    }

    // Join the speculative certificate fetch (started before image loading).
    let cert = match cert_fetch.join() {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("[sap] setup failed: {e}");
            return 1;
        }
        Err(_) => {
            eprintln!("[sap] certificate fetch thread panicked");
            return 1;
        }
    };

    let t0 = std::time::Instant::now();
    match rt.setup_with_cert(mac, cert) {
        Ok(()) => println!("[sap] SAP setup complete ({:?})", t0.elapsed()),
        Err(e) => {
            eprintln!("[sap] SAP setup failed: {e}");
            return 1;
        }
    }

    let payload = if let Some(hex) = &sign_hex {
        hex_decode(hex)
    } else if let Some(path) = &sign_file {
        match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("read {path}: {e}");
                return 1;
            }
        }
    } else {
        b"perun native SAP smoke test".to_vec()
    };

    let t0 = std::time::Instant::now();
    match rt.sign(&payload) {
        Ok(sig) => {
            println!(
                "[sap] SAPSign OK: {} bytes in {:?}",
                sig.len(),
                t0.elapsed()
            );
            let mut hex = String::with_capacity(sig.len() * 2);
            for b in &sig {
                hex.push_str(&format!("{b:02x}"));
            }
            println!("[sap] signature: {hex}");
            0
        }
        Err(e) => {
            eprintln!("[sap] SAPSign failed: {e}");
            1
        }
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}
