// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! THE ORACLE-CAPTURE ASSEMBLY TEST: the public generator API, end to end.
//!
//! OracleCaptureInputs::from_capture_dir assembles the measured inject layer
//! (the tapes and dumps of one capture -- the layer the genesis
//! frontier will replace with pure SPIM math), and assemble_cpim_from_oracle_capture
//! runs the PURE container computation over it. The result must
//! equal the oracle's own 276-byte CPIM byte for byte.
//!
//! This test is intentionally capture-dependent and is not an autonomy
//! test: it compares an assembly using oracle-derived fields and tapes
//! against the reference CPIM from that capture.

use perun_adi_core::body_a::{assemble_cpim_from_oracle_capture, OracleCaptureInputs};

#[test]
#[ignore = "requires same-session live SPIM/tapes/CPIM; run explicitly with PERUN_CPIM_E2E_READY=1"]
fn oracle_capture_assembly_matches_the_reference_cpim() {
    assert_eq!(
        std::env::var("PERUN_CPIM_E2E_READY").as_deref().unwrap_or(""),
        "1",
        "set PERUN_CPIM_E2E_READY=1 only for a complete same-session capture"
    );
    let dir = std::env::var("PERUN_LIVE_DIR")
        .unwrap_or_else(|_| "/opt/data/adi-re".into());
    let inputs = OracleCaptureInputs::from_capture_dir(&dir)
        .expect("the measured inject layer assembles");
    assert_eq!(inputs.captured_spim.len(), 347, "the captured SPIM is retained for session comparison");
    let cpim = assemble_cpim_from_oracle_capture(&inputs);

    let reference = std::fs::read(format!("{dir}/live_prov_out.bin")).expect("the reference");
    assert_eq!(reference.len(), 0x114);
    let mut equal = 0;
    for i in 0..0x114 {
        assert_eq!(cpim[i], reference[i], "container+{i:#05x}");
        equal += 1;
    }
    eprintln!("ORACLE-CAPTURE ASSEMBLY: {equal}/276 bytes through the explicitly oracle-backed API (formula-computed and measured tape outputs remain explicit inputs)");
}
