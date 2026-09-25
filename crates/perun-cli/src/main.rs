// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun` — runner and inspector for native PE images under the runtime.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image, LoadError};
use perun_shims::table::ShimTable;
use std::path::Path;

mod fetcher;
mod sap;
mod scaffold;
mod store;

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
    // Edition 2024: an unsafe fn body is no longer an unsafe context; the
    // whole handler is one unsafe block by intent.
    unsafe {
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

        // Census mode: a `0xCC` we planted over a pinned rdtsc site. Record
        // it, give the guest the same RAX/RDX the real patch gives it, and
        // resume just past the idiom. Signal context, so the census module
        // does a binary search and a bitmap store — no allocation, no locks.
        #[cfg(feature = "rdtsc-census")]
        if sig == libc::SIGTRAP
            && let Some(resume) = perun_core::census::on_trap(rip.wrapping_sub(1))
        {
            *regs.add(libc::REG_RAX as usize) = 0;
            *regs.add(libc::REG_RDX as usize) = 0;
            *regs.add(libc::REG_RIP as usize) = resume as i64;
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
            libc::write(2, out.as_ptr().cast(), n);
            libc::_exit(128 + sig);
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
    unsafe {
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
}

/// TEMP (census branch): Rss/Dirty/Clean per guest VMA.
#[cfg(feature = "rdtsc-census")]
fn vma_report(tag: &str) {
    use std::io::Read;
    let path = "/proc/self/smaps";
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let mut hdr = String::new();
    let (mut r, mut d, mut c) = (0u64, 0u64, 0u64);
    let emit = |h: &str, r: u64, d: u64, c: u64| {
        if h.starts_with("7ff80") {
            eprintln!("[vma:{tag}] rss={r} dirty={d} clean={c} {h}");
        }
    };
    for line in s.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        let is_hdr =
            first.contains('-') && first.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-');
        if is_hdr {
            emit(&hdr, r, d, c);
            hdr = line.to_string();
            r = 0;
            d = 0;
            c = 0;
            continue;
        }
        let v = |k: &str| -> Option<u64> {
            line.strip_prefix(k)
                .and_then(|x| x.split_whitespace().next())
                .and_then(|x| x.parse().ok())
        };
        if let Some(kb) = v("Rss:") {
            r = kb;
        } else if let Some(kb) = v("Private_Dirty:") {
            d = kb;
        } else if let Some(kb) = v("Private_Clean:") {
            c = kb;
        }
    }
    emit(&hdr, r, d, c);
}

/// Help text for the low-level lane, printed without running anything.
///
/// Intercepted in `run()` before the dispatch, never inside the commands: `sap`
/// spawns a 256 MiB guest thread and may fetch Apple's assets, `run` maps a PE,
/// `seq` executes a script, `call` would export-call a guest and `scaffold` would
/// try to parse the flag as a trap line, so a `--help` reaching them either starts
/// real work or fails confusingly. `-h` and `--help` count anywhere in the tail,
/// the way every other flag here does.
fn low_level_help(sub: &str) -> Option<&'static str> {
    Some(match sub {
        "run" => concat!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n\n",
            "  Loads a PE32+ image, resolves its imports against the Win32 shim table,\n",
            "  installs a per-thread TEB, and calls DllMain(DLL_PROCESS_ATTACH).\n\n",
            "  --verbose        print the image summary before loading\n",
            "  --trace          log the instrumented Win32 call sites (partial coverage)\n",
            "  --trace-file F   redirect stderr onto F, where the trace lines land\n",
            "  --no-teb         skip TEB initialization\n"
        ),
        "info" => concat!(
            "usage: perun info <image.dll>\n\n",
            "  Prints the PE32+ header and sections, then the import table (DLL, named and\n",
            "  ordinal) and the export names. Accepts PE32+ only; a Mach-O file goes to\n",
            "  `perun mach info`.\n"
        ),
        "mach" => concat!(
            "usage: perun mach info <macho>\n\n",
            "  Parses a 64-bit Mach-O image: header, segments, sections and the symbol\n",
            "  table, without mapping it or running any guest code.\n"
        ),
        "sap" => concat!(
            "usage: perun sap [<assets-dir>] [--mac AA:BB:CC:DD:EE:FF] [--sign HEX | --file F]\n\n",
            "  Runs the FairPlay SAP session (init, two exchange rounds, sign) against the\n",
            "  live endpoints. With no arguments the asset cache is used as-is, and a first\n",
            "  run fetches the missing images itself from Apple's public update package.\n\n",
            "  <assets-dir>     use this directory instead of the default cache\n",
            "  --mac            force the machine address for this run, overriding the pin\n",
            "  --sign HEX       sign this payload instead of the built-in smoke string\n",
            "  --file F         sign the contents of F instead\n\n",
            "  This command starts a real session and may perform network I/O.\n"
        ),
        "seq" => concat!(
            "usage: perun seq <image.dll> <export> --script=FILE\n\n",
            "  Loads one image and runs DllMain once, then drives a script of export calls\n",
            "  in the same process so guest state carries between them. One verb per line,\n",
            "  `#` starts a comment:\n\n",
            "    load NAME FILE   read FILE into a named guest buffer\n",
            "    poke T V         write a qword; T = scratch+OFF | ctx+OFF | RVA\n",
            "    call [EXPORT] A0 A1 A2 A3\n",
            "                     call the export (default vdfut768ig); args are tokens:\n",
            "                     buffer names, scratch/ctx with optional +OFF, or numbers\n",
            "    zero scratch|ctx clear that region\n",
            "    dump            print the non-zero qwords of scratch and ctx\n\n",
            "  Export names match the export table case-sensitively.\n"
        ),
        "call" => concat!(
            "usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3] [flags]\n\n",
            "  Loads the image, runs DllMain once, then calls one export with up to four\n",
            "  positional arguments in Win64 order (rcx, rdx, r8, r9). Values may be plain\n",
            "  numbers or the tokens `scratch`, `ctx`, and either with a +OFF suffix.\n\n",
            "  --load=NAME=FILE   read FILE into a named guest buffer, usable as a value\n",
            "  --patch=RVA=HEX    patch bytes into the mapped image (mprotect'd, RX after)\n",
            "  --poke=T=V         write a qword before the call; T = RVA | scratch+OFF | ctx+OFF\n",
            "  --poke-ptr=RVA=V   write V through the pointer stored at guest RVA\n",
            "  --peek=RVA[,RVA…]  read guest qwords after the call\n",
            "  --peek-ptr=RVA     dereference a guest RVA as a host pointer and dump it\n",
            "  --verbose          print the image summary before loading\n\n",
            "  Option values resolve after the whole command line is parsed, so a buffer\n",
            "  name works as a value wherever its --load sits.\n",
            "  PERUN_SEQ=N repeats one call in-process (call#0, call#1, …).\n"
        ),
        "scaffold" => concat!(
            "usage: perun scaffold \"TRAP-line\" [...]\n\n",
            "  Turns an unresolved-import trap report into a compiling `win32_api!` stub\n",
            "  with the observed arguments and the file whose family owns the API. Accepts\n",
            "  the bare `DLL!func(args)` shape, the full `[perun] TRAP: …` line, and the\n",
            "  hint payload pasted back verbatim. Several lines may be given at once.\n\n",
            "  example: perun scaffold \"[perun] TRAP: KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)\"\n",
            "           perun scaffold 'KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)'\n\n",
            "  Exit 0 when every line parsed, 1 when one did not.\n"
        ),
        _ => return None,
    })
}

/// True when the tail carries a help flag anywhere, the way the other parsers
/// accept their flags in any position.
fn help_flag_present(tail: &[String]) -> bool {
    tail.iter().any(|a| a == "-h" || a == "--help")
}

/// Returns `Some(0)` when a help request was satisfied without running anything.
fn low_level_help_requested(sub: &str, tail: &[String]) -> Option<i32> {
    if !help_flag_present(tail) {
        return None;
    }
    print!("{}", low_level_help(sub)?);
    Some(0)
}

fn run() -> i32 {
    run_with_args(&std::env::args().collect::<Vec<String>>())
}

/// The dispatcher, separated from `main` so the argv-driven help interception is
/// testable without launching a process.
fn run_with_args(args: &[String]) -> i32 {
    // argv[0] persona: a binary invoked as `ipatool` (basename) runs the
    // strict majd/ipatool grammar for EVERYTHING, including the bare
    // `--help`/`--version` root flags; `perun` keeps its native grammar.
    let argv0 = args
        .first()
        .map(|s| {
            std::path::Path::new(s)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let ipatool_persona = argv0 == "ipatool";
    if ipatool_persona {
        return store::cli::run(&args[1..]);
    }
    if args.len() < 2 {
        eprintln!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n       perun info <image.dll>\n       perun mach info <macho>\n       perun scaffold \"TRAP-line\" [...]\n       perun sap [--mac AA:BB:CC:DD:EE:FF] [--sign HEX|--file F]\n       perun store <auth|search|purchase|download|list-purchases|list-versions|get-version-metadata> ...\n       ipatool aliases: perun auth login|info|revoke · perun search -t ... · perun purchase -i ...\n                        perun download -i ... · perun list-purchases · perun list-versions ..."
        );
        return 2;
    }

    // `-h`/`--help` for the low-level lane never reaches the commands: `sap`
    // would spawn a guest thread and hit Apple's endpoints, `seq` would run its
    // script, `run` would map the image. Answered here instead.
    if let Some(code) = low_level_help_requested(&args[1], &args[2..]) {
        return code;
    }

    match args[1].as_str() {
        "info" => cmd_info(&args[2]),
        "run" => cmd_run(&args[2..]),
        "call" => cmd_call(&args[2..]),
        "mach" => cmd_mach(&args[2..]),
        "scaffold" => scaffold::run(&args[2..]),
        "sap" => cmd_sap(&args[2..]),
        "store" => store::cli::run(&args[2..]),
        "seq" => cmd_seq(&args[2..]),
        // ipatool-compatible top-level aliases: same grammar, no "store".
        "auth" => store::cli::run(&args[1..]),
        "search" => store::cli::run(&args[1..]),
        "purchase" => store::cli::run(&args[1..]),
        "download" => store::cli::run(&args[1..]),
        "list-purchases" | "purchases" => store::cli::run(&args[1..]),
        "list-versions" => store::cli::run(&args[1..]),
        "get-version-metadata" => store::cli::run(&args[1..]),
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

    if opts.verbose
        && let Ok(info) = perun_core::image::PeInfo::parse(&bytes)
    {
        println!(
            "[perun] image {path}: entry={:#x} base={:#x} sections={}",
            info.opt.address_of_entry_point,
            info.opt.image_base,
            info.sections.len()
        );
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
        // Edition 2024: set_var touches global state, now unsafe.
        // We run this before any guest threads exist.
        unsafe {
            std::env::set_var("PERUN_TRACE", "1");
            if !file.is_empty() {
                std::env::set_var("PERUN_TRACE_FILE", &file);
            }
        }
        // PERUN_TRACE_FILE used to be accepted but never read: every shim
        // checks only PERUN_TRACE and logs to stderr. Make --trace-file
        // real by pointing stderr at the file, so all eprintln trace lines
        // (shims, traps, loader) land there instead of the console.
        if !file.is_empty() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
            {
                Ok(f) => {
                    use std::os::unix::io::AsRawFd;
                    let fd = f.as_raw_fd();
                    // dup2 is async-signal-safe wrt the later crash handler;
                    // after this eprintln goes to the file.
                    if unsafe { libc::dup2(fd, 2) } < 0 {
                        eprintln!("[perun] warning: dup2 --trace-file {file}: failed");
                    }
                    // `f` closes here; fd 2 keeps the description open.
                }
                Err(e) => {
                    eprintln!("[perun] warning: open --trace-file {file}: {e}");
                }
            }
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
        eprintln!(
            "usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3] [--verbose] [--load=NAME=FILE] [--patch=RVA=HEX] [--poke=RVA=VAL] [--poke-ptr=RVA=VAL] [--peek=RVA] [--peek-ptr=RVA]   (PERUN_SEQ=N repeats the call in-process)"
        );
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

    if verbose && let Ok(info) = perun_core::image::PeInfo::parse(&bytes) {
        println!(
            "[perun] image {path}: entry={:#x} base={:#x} sections={}",
            info.opt.address_of_entry_point,
            info.opt.image_base,
            info.sections.len()
        );
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

    // --load=NAME=FILE: read a file into a fresh guest-visible buffer and
    // register NAME as a token resolving to its address. This is how real
    // server material (e.g. a GrandSlam `spim` blob) gets handed to the
    // dispatcher's param struct, mirroring what the Android ADI engine feeds
    // ADIProvisioningStart.
    let mut loads: Vec<(String, u64, usize)> = Vec::new(); // (name, addr, len)

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
    // Positional args are collected first, resolved after all options.
    let mut positional: Vec<String> = Vec::new();
    let resolve = |tok: &str| -> Option<u64> {
        match tok {
            "scratch" => Some(scratch as u64),
            "ctx" => Some(ctx as u64),
            _ => parse_num(tok),
        }
    };
    // --poke specs are stored raw and resolved after the loop so values can
    // reference loaded buffers by name regardless of CLI order.
    // (kind, target, value_string)
    let mut poke_specs: Vec<(u8, u64, String)> = Vec::new();
    let mut poke_ptr_specs: Vec<(u64, String)> = Vec::new();
    // The positional stream (with --verbose already filtered out) drives both
    // the argument slots and the --patch/--poke/--peek option parsing below.
    for a in pos[2..].iter() {
        if let Some(spec) = a.strip_prefix("--load=") {
            let (name, path) = spec.split_once('=').unwrap_or((spec, ""));
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: --load {path:?}: {e}");
                    std::process::exit(2);
                }
            };
            let len = data.len();
            let buf = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len.max(1),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if buf == libc::MAP_FAILED {
                eprintln!("error: --load mmap failed");
                std::process::exit(2);
            }
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, len) };
            println!("[perun] load {name:?} <- {path} ({len} bytes @ {buf:p})");
            loads.push((name.to_string(), buf as u64, len));
            continue;
        }
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
            if let Some(off_s) = tgt_s.strip_prefix("ctx+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad ctx offset {off_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((1, off, val_s.to_string()));
            } else if let Some(off_s) = tgt_s.strip_prefix("scratch+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad scratch offset {off_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((2, off, val_s.to_string()));
            } else {
                let rva = parse_num(tgt_s).unwrap_or_else(|| {
                    eprintln!("error: bad --poke rva {tgt_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((0, rva, val_s.to_string()));
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
            poke_ptr_specs.push((rva, val_s.to_string()));
            continue;
        }
        if ai < 4 {
            positional.push(a.clone());
        }
    }

    // Resolve positional args after all options so --load/--poke/--patch are
    // registered first regardless of CLI order.
    for a in positional.iter() {
        if ai >= 4 {
            break;
        }
        // Loaded buffers are addressable by name (e.g. "spim").
        let loaded = loads
            .iter()
            .find(|(n, _, _)| n == a)
            .map(|(_, addr, _)| *addr);
        argv[ai] = loaded.or_else(|| resolve(a)).unwrap_or_else(|| {
            eprintln!("error: bad argument {a:?}");
            std::process::exit(2);
        });
        ai += 1;
    }

    // Resolve deferred poke values now that all --load buffers are registered.
    // A value may be a loaded buffer name, scratch/ctx (optionally +OFF), or a
    // number.
    let resolve_val = |s: &str| -> Option<u64> {
        if let Some((_, addr, _)) = loads.iter().find(|(n, _, _)| n == s) {
            return Some(*addr);
        }
        if let Some(off_s) = s.strip_prefix("ctx+") {
            let off = parse_num(off_s)?;
            return Some((ctx as u64).wrapping_add(off));
        }
        if let Some(off_s) = s.strip_prefix("scratch+") {
            let off = parse_num(off_s)?;
            return Some((scratch as u64).wrapping_add(off));
        }
        resolve(s)
    };
    for (kind, tgt, val_s) in &poke_specs {
        let val = resolve_val(val_s).unwrap_or_else(|| {
            eprintln!("error: bad --poke value {val_s:?}");
            std::process::exit(2);
        });
        pokes.push((*kind, *tgt, val));
    }
    for (rva, val_s) in &poke_ptr_specs {
        let val = resolve_val(val_s).unwrap_or_else(|| {
            eprintln!("error: bad --poke-ptr value {val_s:?}");
            std::process::exit(2);
        });
        let slot = (image.base() as u64).wrapping_add(*rva) as *const u64;
        let target = unsafe { std::ptr::read(slot) };
        unsafe { std::ptr::write(target as *mut u64, val) };
        println!("[perun] poke-ptr [RVA {rva:#x}] -> {target:#x} := {val:#x}");
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

    // PERUN_SEQ=N: repeat the call N times in the SAME process so gate state set
    // by an earlier call carries into later ones (Android provisioning is a
    // sequence of calls in one process; the Windows dispatcher folds them in).
    let seq_n: usize = std::env::var("PERUN_SEQ")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    for iter in 0..seq_n {
        println!(
            "[perun] call#{iter} {export_name}({:#x}, {:#x}, {:#x}, {:#x})...",
            argv[0], argv[1], argv[2], argv[3]
        );
        let r = unsafe { f(argv[0], argv[1], argv[2], argv[3]) };
        println!("[perun] call#{iter} {export_name} returned {r:#x} ({r})");
    }

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

    // Dump every non-zero qword in the scratch page with its offset, so the
    // caller can see exactly which output fields the dispatcher wrote.
    {
        let page = unsafe { std::slice::from_raw_parts(scratch as *const u64, 0x1000 / 8) };
        let mut any = false;
        for (i, &q) in page.iter().enumerate() {
            if q != 0 {
                println!("[perun] scratch[{:#x}] = {q:#x}", i * 8);
                any = true;
            }
        }
        if !any {
            println!("[perun] scratch: all zero (no output written)");
        }
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

/// Resolve a token to a guest-visible address: loaded buffer name, scratch/ctx
/// (optionally +OFF), or a plain number.
fn resolve_token(tok: &str, scratch: u64, ctx: u64, loads: &[(String, u64, usize)]) -> Option<u64> {
    if let Some((_, addr, _)) = loads.iter().find(|(n, _, _)| n == tok) {
        return Some(*addr);
    }
    if let Some(off_s) = tok.strip_prefix("ctx+") {
        let off = parse_num(off_s)?;
        return Some(ctx.wrapping_add(off));
    }
    if let Some(off_s) = tok.strip_prefix("scratch+") {
        let off = parse_num(off_s)?;
        return Some(scratch.wrapping_add(off));
    }
    match tok {
        "scratch" => Some(scratch),
        "ctx" => Some(ctx),
        _ => parse_num(tok),
    }
}

/// `perun seq <image.dll> <export> --script=FILE`
///
/// Load the image once, run DllMain once, then drive a SCRIPT of export calls
/// in the SAME process so guest state carries across calls. This mirrors how a
/// real host (iTunes on Windows, the ADI engine on Android) drives the ADI
/// provisioning sequence: SetProvisioningPath -> SetAndroidID -> GetLoginCode
/// -> ProvisioningStart -> ProvisioningEnd, all folded into dispatcher command
/// codes on the Windows DLL.
///
/// Script lines (whitespace-separated, `#` starts a comment):
///   load NAME FILE          read FILE into a named guest buffer
///   poke TARGET VALUE       write a qword; TARGET = scratch+OFF | ctx+OFF | RVA
///   call A0 A1 A2 A3        call the export; args are tokens (see resolve_token)
///   zero scratch|ctx        clear the region
///   dump                    print non-zero qwords of scratch and ctx
fn cmd_seq(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("usage: perun seq <image.dll> <export> --script=FILE");
        return 2;
    }
    let path = &args[0];
    let export_name = &args[1];
    let mut script_path: Option<String> = None;
    for a in args[2..].iter() {
        if let Some(p) = a.strip_prefix("--script=") {
            script_path = Some(p.to_string());
        }
    }
    let script_path = match script_path {
        Some(p) => p,
        None => {
            eprintln!("error: --script=FILE required");
            return 2;
        }
    };

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
        eprintln!("error: DllMain returned FALSE");
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

    // Each `call` step re-resolves the export by name, so the default export
    // resolved above is only the fallback for scripts that never name one.
    let mut loads: Vec<(String, u64, usize)> = Vec::new();
    let script = match std::fs::read_to_string(&script_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read script {script_path}: {e}");
            return 1;
        }
    };

    let dump_region = |name: &str, base: u64, nq: usize| {
        let page = unsafe { std::slice::from_raw_parts(base as *const u64, nq) };
        let mut any = false;
        for (i, &q) in page.iter().enumerate() {
            if q != 0 {
                println!("[perun] {name}[{:#x}] = {q:#x}", i * 8);
                any = true;
            }
        }
        if !any {
            println!("[perun] {name}: all zero");
        }
    };

    let mut step = 0usize;
    for raw in script.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        step += 1;
        let toks: Vec<&str> = line.split_whitespace().collect();
        match toks[0] {
            "load" => {
                if toks.len() < 3 {
                    eprintln!("[seq] step {step}: load NAME FILE");
                    return 2;
                }
                let data = match std::fs::read(toks[2]) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[seq] step {step}: load {}: {e}", toks[2]);
                        return 1;
                    }
                };
                let len = data.len();
                let buf = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len.max(1),
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if buf == libc::MAP_FAILED {
                    eprintln!("[seq] step {step}: load mmap failed");
                    return 1;
                }
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, len) };
                println!(
                    "[seq] step {step}: load {:?} <- {} ({len} bytes @ {buf:p})",
                    toks[1], toks[2]
                );
                loads.push((toks[1].to_string(), buf as u64, len));
            }
            "poke" => {
                if toks.len() < 3 {
                    eprintln!("[seq] step {step}: poke TARGET VALUE");
                    return 2;
                }
                let tgt = toks[1];
                let val = match resolve_token(toks[2], scratch as u64, ctx as u64, &loads) {
                    Some(v) => v,
                    None => {
                        eprintln!("[seq] step {step}: bad poke value {:?}", toks[2]);
                        return 2;
                    }
                };
                let (dst, label) = if let Some(off_s) = tgt.strip_prefix("scratch+") {
                    let off = parse_num(off_s).unwrap();
                    (
                        (scratch as u64).wrapping_add(off),
                        format!("scratch[{off:#x}]"),
                    )
                } else if let Some(off_s) = tgt.strip_prefix("ctx+") {
                    let off = parse_num(off_s).unwrap();
                    ((ctx as u64).wrapping_add(off), format!("ctx[{off:#x}]"))
                } else {
                    let rva = parse_num(tgt).unwrap_or_else(|| {
                        eprintln!("[seq] step {step}: bad poke target {tgt:?}");
                        std::process::exit(2);
                    });
                    (
                        (image.base() as u64).wrapping_add(rva),
                        format!("RVA[{rva:#x}]"),
                    )
                };
                unsafe { std::ptr::write(dst as *mut u64, val) };
                println!("[seq] step {step}: poke {label} = {val:#x}");
            }
            "zero" => {
                if toks.len() < 2 {
                    eprintln!("[seq] step {step}: zero scratch|ctx");
                    return 2;
                }
                match toks[1] {
                    "scratch" => unsafe { std::ptr::write_bytes(scratch as *mut u8, 0, 0x1000) },
                    "ctx" => unsafe { std::ptr::write_bytes(ctx as *mut u8, 0, ctx_size) },
                    other => {
                        eprintln!("[seq] step {step}: zero {other}?");
                        return 2;
                    }
                }
                println!("[seq] step {step}: zero {}", toks[1]);
            }
            "dump" => {
                println!("[seq] step {step}: dump");
                dump_region("scratch", scratch as u64, 0x1000 / 8);
                dump_region("ctx", ctx as u64, 0x10000 / 8);
            }
            "call" => {
                let export_name = toks.get(1).copied().unwrap_or("vdfut768ig");
                let export_ptr = match image.get_export_by_name(export_name) {
                    Some(p) => p,
                    None => {
                        eprintln!("[seq] step {step}: export {export_name:?} not found");
                        return 1;
                    }
                };
                type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
                let f: ExportFn = unsafe { std::mem::transmute(export_ptr) };
                let mut argv = [0u64; 4];
                for (i, slot) in argv.iter_mut().enumerate() {
                    let tok = toks.get(i + 2).copied().unwrap_or("0");
                    *slot = match resolve_token(tok, scratch as u64, ctx as u64, &loads) {
                        Some(v) => v,
                        None => {
                            eprintln!("[seq] step {step}: bad call arg {tok:?}");
                            return 2;
                        }
                    };
                }
                println!(
                    "[seq] step {step}: call {export_name}({:#x}, {:#x}, {:#x}, {:#x})...",
                    argv[0], argv[1], argv[2], argv[3]
                );
                let r = unsafe { f(argv[0], argv[1], argv[2], argv[3]) };
                println!("[seq] step {step}: returned {r:#x} ({r})");
                // Show what the guest wrote into the scratch param block.
                dump_region("scratch", scratch as u64, 0x1000 / 8);
            }
            other => {
                eprintln!("[seq] step {step}: unknown verb {other:?}");
                return 2;
            }
        }
    }
    println!("[seq] done ({step} steps)");
    0
}

/// Return true if `len` bytes at `p` are readable without faulting.
/// Uses a mincore-style probe via msync on a copy; simplest portable check is
/// to attempt the read under a SIGSEGV guard. Here we use a process_vm-style
/// self-read via a pipe: write the memory to a pipe and see if it succeeds.
unsafe fn probe_read(p: *const u8, len: usize) -> bool {
    unsafe {
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
            let imports = info.imports(&bytes);
            if imports.is_empty() {
                println!("Imports:         (none)");
            } else {
                let total: usize = imports.iter().map(|(_, s)| s.len()).sum();
                println!(
                    "Imports:         {} dll(s), {total} symbol(s)",
                    imports.len()
                );
                for (dll, syms) in &imports {
                    for sym in syms {
                        match sym {
                            perun_core::image::ImportSymbol::Name(n) => {
                                println!("  {dll}!{n}");
                            }
                            perun_core::image::ImportSymbol::Ordinal(o) => {
                                println!("  {dll}!#{o}");
                            }
                        }
                    }
                }
            }
            let exports = info.exports(&bytes);
            if exports.is_empty() {
                println!("Exports:         (none)");
            } else {
                println!("Exports:         {} name(s)", exports.len());
                for name in &exports {
                    println!("  {name}");
                }
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
    // Bare `perun sap` is the zero-config smoke test: cached (or freshly
    // fetched) assets, auto-detected machine address, built-in payload.
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
    // Asset resolution: an explicit directory wins; otherwise a complete
    // pinned cache is used as-is; otherwise the zero-config fetcher
    // downloads the missing assets (first run only) and the command
    // continues from the cache. A directory is recognized positionally
    // (first non-flag argument), so flag-only invocations work.
    let dir = if !args.is_empty() && Path::new(&args[0]).is_dir() {
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
    // Machine address: auto-detected (pinned on first use), or forced
    // per-run with --mac for differential-testing the FairPlay identity.
    let mut mac: Option<[u8; 6]> = None;
    let mut sign_hex: Option<String> = None;
    let mut sign_file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mac" if i + 1 < args.len() => {
                match store::parse_mac_text(&args[i + 1]) {
                    Ok(m) => mac = Some(m),
                    Err(e) => {
                        eprintln!("--mac: {e}: {}", args[i + 1]);
                        return 2;
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
    let mac = match mac {
        Some(m) => m,
        None => store::primary_mac(),
    };
    let guid = store::appstore::guid_from_mac(&mac);
    println!("[sap] machine guid: {guid}");

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
    #[cfg(feature = "rdtsc-census")]
    vma_report("after-load");
    match rt.sign(&payload) {
        Ok(sig) => {
            println!(
                "[sap] SAPSign OK: {} bytes in {:?}",
                sig.len(),
                t0.elapsed()
            );
            let mut hex = String::with_capacity(sig.len() * 2);

            // Census report: which planted sites did the guest actually reach.
            #[cfg(feature = "rdtsc-census")]
            if std::env::var("PERUN_RDTSC_CENSUS").is_ok() {
                let fired = perun_core::census::fired();
                let total = perun_core::census::total();
                eprintln!("[census] executed {}/{} sites", fired.len(), total);
                let mut by_image: std::collections::BTreeMap<&str, Vec<u32>> =
                    std::collections::BTreeMap::new();
                for (img, off) in &fired {
                    by_image.entry(img).or_default().push(*off);
                }
                // Every image is printed, including the ones that fired zero
                // times: an absent line would be indistinguishable from a
                // reporting bug, and "CoreFP: 0" is the whole result.
                for img in ["CoreFP", "CommerceKit", "CommerceCore", "unknown"] {
                    let empty: Vec<u32> = Vec::new();
                    let offs = by_image.get(img).unwrap_or(&empty);
                    if offs.is_empty() {
                        eprintln!("[census] {img}: 0 executed");
                    } else {
                        eprintln!("[census] {img}: {} executed: {:x?}", offs.len(), offs);
                    }
                }
            }
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

#[cfg(test)]
mod help_tests {
    use super::*;

    const LOW_LEVEL: [&str; 7] = ["run", "info", "mach", "sap", "seq", "call", "scaffold"];

    #[test]
    fn bare_auth_prints_help_instead_of_panicking() {
        // Regression: `sub[1..]` used to be evaluated before the empty check, so a
        // bare `auth` panicked with a slice-range error in both personas.
        for persona_bin in ["ipatool", "perun"] {
            let args = vec![persona_bin.to_string(), "auth".to_string()];
            let code = run_with_args(&args);
            assert!(
                code == 0 || code == 2,
                "{persona_bin} auth returned {code}, expected help (0) or usage (2)"
            );
        }
    }

    #[test]
    fn every_low_level_command_has_help() {
        for sub in LOW_LEVEL {
            assert!(low_level_help(sub).is_some(), "{sub} should have help");
        }
    }

    #[test]
    fn help_is_absent_for_commands_that_route_to_the_store_lane() {
        // The store lane owns its own cobra help, byte-for-byte; the low-level
        // intercept must not shadow it.
        for sub in [
            "store",
            "auth",
            "search",
            "purchase",
            "download",
            "list-purchases",
            "list-versions",
        ] {
            assert!(
                low_level_help(sub).is_none(),
                "{sub} must not be intercepted"
            );
        }
    }

    #[test]
    fn help_text_carries_no_runtime_log_line() {
        // The regression this pins: `perun sap --help` used to fall through to the
        // command and run a live session, emitting [fetcher]/[sap] log lines and
        // performing network I/O. A help string must not contain a log prefix.
        for sub in LOW_LEVEL {
            let text = low_level_help(sub).expect("help exists");
            assert!(
                !text.lines().any(|l| l.starts_with('[')),
                "{sub} help must not contain a bracketed log line"
            );
            assert!(!text.is_empty(), "{sub} help must not be empty");
        }
    }

    #[test]
    fn help_flag_is_found_in_any_position() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        assert!(help_flag_present(&v(&["--help"])));
        assert!(help_flag_present(&v(&["-h"])));
        assert!(help_flag_present(&v(&[
            "--mac", "AA:BB", "--help", "extra"
        ])));
        assert!(!help_flag_present(&v(&[])));
        assert!(!help_flag_present(&v(&["--verbose", "--trace"])));
    }

    #[test]
    fn dispatcher_answers_help_before_running_the_command() {
        // The bug lived in the wiring, not the helper: `--help` reached the
        // command and started real work. Drive the dispatcher directly and assert
        // it returns 0 without touching the filesystem, a guest thread or network.
        for sub in LOW_LEVEL {
            for flag in ["-h", "--help"] {
                let args: Vec<String> =
                    ["perun", sub, flag].iter().map(|x| x.to_string()).collect();
                assert_eq!(run_with_args(&args), 0, "perun {sub} {flag}");
            }
        }
    }

    #[test]
    fn unknown_subcommand_with_help_flag_is_not_answered() {
        let args = vec!["--help".to_string()];
        assert!(help_flag_present(&args));
        assert!(low_level_help("bogus").is_none());
    }
}
