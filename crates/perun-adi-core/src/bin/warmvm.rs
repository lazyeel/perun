// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! warmvm: run a lifted ADI warm-OTP case and verify it against the capture.
//!
//! ```text
//! warmvm --program lift/program.bin --case lift/case_tM.bin \
//!        --trace cases/tM/otp-trace.bin [--stop-rec N] [--no-xmm] [--quiet]
//! ```
//!
//! Exit codes: 0 verified + OTP matches the bundle, 1 divergence or error,
//! 2 usage.

use perun_adi_core::warmvm::{self, CaseBundle, Program, RunOptions, TraceReader};
use std::process::ExitCode;

fn usage() -> ! {
    eprintln!(
        "usage: warmvm --program <program.bin> --case <case_*.bin> \
         --trace <otp-trace.bin> [--stop-rec N] [--no-xmm] [--quiet]"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut program_path = None;
    let mut case_path = None;
    let mut trace_path = None;
    let mut opt = RunOptions::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--program" => {
                i += 1;
                program_path = args.get(i).cloned();
            }
            "--case" => {
                i += 1;
                case_path = args.get(i).cloned();
            }
            "--trace" => {
                i += 1;
                trace_path = args.get(i).cloned();
            }
            "--stop-rec" => {
                i += 1;
                opt.stop_rec = args.get(i).and_then(|v| v.parse().ok());
            }
            "--no-xmm" => opt.verify_xmm = false,
            "--quiet" => opt.quiet = true,
            "--progress" => {
                i += 1;
                opt.progress_every = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("warmvm: unknown argument {other}");
                usage();
            }
        }
        i += 1;
    }
    let (Some(program_path), Some(case_path), Some(trace_path)) =
        (program_path, case_path, trace_path)
    else {
        usage();
    };

    let program = match Program::load(&program_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warmvm: {program_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bundle = match CaseBundle::load(&case_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("warmvm: {case_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut trace = match TraceReader::open(&trace_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("warmvm: {trace_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "warmvm: {} instructions, {} modules; case entry {:#x}, stop rec {}",
        program.insns.len(),
        program.modules.len(),
        bundle.entry_ip,
        opt.stop_rec.unwrap_or(bundle.stop_rec)
    );

    let mut vm = warmvm::prepare(&bundle, program);
    let stats = match warmvm::run_verified(&mut vm, &bundle, &mut trace, &opt) {
        Ok(s) => s,
        Err(mm) => {
            eprintln!("warmvm: FAILED\n{mm}");
            return ExitCode::FAILURE;
        }
    };

    let got = match warmvm::otp(&vm, &bundle) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warmvm: otp read: {e}");
            return ExitCode::FAILURE;
        }
    };
    let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "verified: {} records, {} steps, {} libc stubs, tsc {:#x}",
        stats.records, stats.steps, stats.stubs, vm.tsc
    );
    println!("otp: {hex}");
    if got == bundle.otp {
        println!("otp: MATCH ({} bytes)", got.len());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "warmvm: OTP MISMATCH (expected {})",
            bundle
                .otp
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        ExitCode::FAILURE
    }
}
