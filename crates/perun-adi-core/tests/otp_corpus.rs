// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent warm-OTP gate: no trace is read and no callee state is replayed.

use perun_adi_core::otp::run_otp;
use perun_adi_core::warmvm::{CaseBundle, Program};
use std::path::PathBuf;

#[test]
fn warm_otp_is_independent_of_recorded_execution() {
    let Some(root) = std::env::var_os("PERUN_OTP_LIFT").map(PathBuf::from) else {
        eprintln!("PERUN_OTP_LIFT unset -- skipping the independent warm-OTP gate");
        return;
    };
    let program_path = root.join("program.bin");
    for (case, epoch) in [
        ("tM", 1794862800),
        ("tI", 1794864600),
        ("tE1794862200", 1794862200),
        ("tE1794863400", 1794863400),
        ("tE1794865200", 1794865200),
        ("tb-end1", 1794862800),
        ("tb-end2", 1794862800),
    ] {
        let mut bundle = CaseBundle::load(root.join(format!("case_{case}.bin")).to_str().unwrap())
            .expect("private warm case");
        let expected = bundle.otp.clone();
        bundle.stop_rec = 0;
        bundle.stubs.clear();
        bundle.mem.clear();
        bundle.otp.fill(0);
        let program = Program::load(program_path.to_str().unwrap()).expect("lifted program");
        let actual = run_otp(program, &bundle, epoch).unwrap_or_else(|error| {
            panic!("{case}: semantic warm-OTP execution failed: {error:?}")
        });
        assert_eq!(actual, expected, "{case}: semantic OTP diverged");
    }
    eprintln!("independent warm OTP: 7 states matched without a trace or recorded call schedule");
}
