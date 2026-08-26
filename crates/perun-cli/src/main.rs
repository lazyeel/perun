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
