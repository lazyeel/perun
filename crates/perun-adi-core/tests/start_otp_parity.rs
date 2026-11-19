// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Start/OTP parity gate: the Rust OTP consumer (warmvm) must give the
//! native OTP artifacts on the five-case grid.
//!
//! Grid: `tM`, `tI`, `tE1794862200`, `tE1794863400`, `tE1794865200` —
//! the five native epochs anchored in `/home/admin/rig/lift/meta.json`
//! (`lift/case_<name>.bin` + `cases/<name>/otp-trace.new.bin`). For
//! each case:
//!
//!   - warmvm replays the lifted warm-OTP program against the case's
//!     native trace;
//!   - the VM OTP is compared byte-for-byte with the native artifact
//!     `cases/<name>/cap/otp.bin`;
//!   - the bundle's anchored OTP is checked equal to the native artifact.
//!
//! The bundle embeds the native OTP (verified against
//! `cap/otp.bin` at lift time); the parity gate is warmvm-OTP ==
//! bundle-OTP == native-OTP on the grid.
//!
//! The MID law (`MID = f(state)`, one value across the grid) is pinned
//! by the public Start-state grid in `matrix3`.

use perun_adi_core::warmvm::{self, CaseBundle, Program, RunOptions, TraceReader};

const GRID: [&str; 5] = ["tM", "tI", "tE1794862200", "tE1794863400", "tE1794865200"];

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
#[ignore = "requires the local lift corpus (PERUN_START_PARITY=1, lift dir /home/admin/rig/lift)"]
fn warmvm_otp_matches_native_on_the_five_case_grid() {
    assert_eq!(
        std::env::var("PERUN_START_PARITY").as_deref().unwrap_or(""),
        "1",
        "set PERUN_START_PARITY=1 for the warmvm-vs-native OTP parity run"
    );
    let lift_dir = std::env::var("PERUN_LIFT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/home/admin/rig/lift"));
    let cases_dir = std::env::var("PERUN_GRID_CASES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/home/admin/rig/cases"));

    for name in GRID {
        let bundle_path = lift_dir.join(format!("case_{name}.bin"));
        let trace_path = cases_dir.join(name).join("otp-trace.new.bin");
        let native_path = cases_dir.join(name).join("cap").join("otp.bin");
        for path in [&bundle_path, &trace_path, &native_path] {
            if !path.exists() {
                panic!("{}: required by the parity gate", path.display());
            }
        }
        let bundle =
            CaseBundle::load(&bundle_path.to_string_lossy()).expect("load the warmvm case bundle");
        let program = Program::load(&lift_dir.join("program.bin").to_string_lossy())
            .expect("load the lifted warm-OTP program");
        let mut vm = warmvm::prepare(&bundle, program);
        let mut trace =
            TraceReader::open(&trace_path.to_string_lossy()).expect("open the native trace");
        let opt = RunOptions {
            progress_every: 0,
            ..RunOptions::default()
        };
        let stats = match warmvm::run_verified(&mut vm, &bundle, &mut trace, &opt) {
            Ok(stats) => stats,
            Err(mismatch) => panic!("the VM must verify against the native trace:\n{mismatch}"),
        };
        let got = warmvm::otp(&vm, &bundle).expect("read the warmvm OTP");
        let native = std::fs::read(&native_path).expect("read the native OTP artifact");
        assert_eq!(
            bundle.otp, native,
            "{name}: the lift's anchored OTP must equal the native artifact"
        );
        assert_eq!(
            got, native,
            "{name}: warmvm OTP must equal the native artifact"
        );
        eprintln!(
            "start_otp_parity[{name}]: warmvm OTP = native {} bytes; verified {} records, {} steps, {} libc stubs",
            native.len(),
            stats.records,
            stats.steps,
            stats.stubs
        );
        eprintln!("  otp: {}", hex(&got));
    }
}
