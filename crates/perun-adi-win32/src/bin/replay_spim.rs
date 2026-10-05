// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Replay the live SPIM captured from the working Android engine through
//! `CoreADI64.dll`, and report what the Windows image did with it.
//!
//! The input is not a reconstruction: it is the bytes the working engine
//! received from `startMachineProvisioning`, captured at the call site of
//! `ADI_ProvisioningStart` where both buffers are named. Whether the Windows
//! image transforms them is the question, and the byte comparison answers it
//! either way.

fn main() {
    let spim_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/data/adi-re/live_prov_in.bin".to_string());
    let cpim_ref = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/opt/data/adi-re/live_prov_out.bin".to_string());
    let image = std::env::args().nth(3);

    let spim = match std::fs::read(&spim_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {spim_path}: {e}");
            std::process::exit(1);
        }
    };
    let reference = std::fs::read(&cpim_ref).ok();

    println!("input  : {spim_path} ({} bytes)", spim.len());
    match &reference {
        Some(r) => println!("oracle : {cpim_ref} ({} bytes)", r.len()),
        None => println!("oracle : absent"),
    }

    match perun_adi_win32::replay(image.as_deref(), &spim, reference.as_deref()) {
        Ok(report) => print!("{report}"),
        Err(e) => {
            eprintln!("replay failed: {e}");
            std::process::exit(1);
        }
    }
}
