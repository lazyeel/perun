// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! THE END-TO-END CPIM TEST: the full 276-byte container, assembled
//! from the generated depot zone plus the measured session fields,
//! compared byte for byte against the live oracle's own CPIM.
//!
//! What is GENERATED here (the crate's own math, live-verified):
//!   - the body A bytes: the sixteen mixers over the one-session
//!     giant tape, the sel-tape backfills, the session-invariant
//!     zones -- all ten rounds, every checkable position;
//!   - the digest: the eight BE sums, all 32 bytes, zero gates;
//!   - the container's structure fields: the version word 5, the
//!     body lengths 0xa0/0x34, the body B version 4 (the measured
//!     anatomy, written by the generator, not copied).
//!
//! What is CARRIED from the reference (the named boundaries, not
//! derivations): the session block (16 bytes), the body B (52),
//! and the ten m15 body rows whose giant hits the pair36 tape did
//! not carry (the next capture closes them; every carried byte is
//! counted and named in the verdict).
//!
//! The verdict line reports the container parity AND the split:
//!   "CPIM e2e: 276/276 container bytes; N generated, M carried"

use perun_adi_core::body_a::generate_body_from_tapes;

#[test]
fn cpim_end_to_end() {
    let dir = std::env::var("PERUN_LIVE_DIR")
        .unwrap_or_else(|_| "/opt/data/adi-re".into());
    if std::env::var("PERUN_CPIM_E2E_READY").is_err() {
        eprintln!("gating: PERUN_CPIM_E2E_READY not set");
        return;
    }
    let Ok(cpim) = std::fs::read(format!("{dir}/live_prov_out.bin")) else {
        eprintln!("gating: no live CPIM under {dir}");
        return;
    };
    assert_eq!(cpim.len(), 0x114, "the live CPIM is 276 bytes");

    // THE GENERATED DEPOT ZONE (192): body A + digest, one session.
    let Ok((depot, body_bytes)) = generate_body_from_tapes(&dir) else {
        panic!("the body-a tapes did not assemble under {dir}");
    };

    // THE CONTAINER, per the measured anatomy:
    //   [0..4) version 5 | [4..0x14) session | [0x14..0x18) 0xa0
    //   [0x18..0xb8) body A | [0xb8..0xd8) digest
    //   [0xd8..0xdc) 0x34 | [0xdc..0xe0) 4 | [0xe0..0x114) body B
    let mut out = [0u8; 0x114];
    out[0..4].copy_from_slice(&5u32.to_be_bytes());          // version: written
    out[4..0x14].copy_from_slice(&cpim[4..0x14]);           // session: carried
    out[0x14..0x18].copy_from_slice(&0xa0u32.to_be_bytes()); // A len: written
    out[0x18..0xb8].copy_from_slice(&depot[0..0xa0]);        // body A: generated
    out[0xb8..0xd8].copy_from_slice(&depot[0xa0..0xc0]);     // digest: generated
    out[0xd8..0xdc].copy_from_slice(&0x34u32.to_be_bytes()); // B len: written
    out[0xdc..0xe0].copy_from_slice(&4u32.to_be_bytes());    // B ver: written
    out[0xe0..0x114].copy_from_slice(&cpim[0xe0..0x114]);    // body B: carried

    // THE COMPARISON: all 276 bytes against the oracle.
    let mut equal = 0;
    for i in 0..0x114 {
        assert_eq!(out[i], cpim[i], "container+{i:#05x}");
        equal += 1;
    }
    // the split: generated positions vs carried
    let carried = 16 + 52 + (160 - body_bytes); // session + body B + the m15 rows
    eprintln!("CPIM e2e: {equal}/276 container bytes; {} generated, {carried} carried (session 16, body B 52, m15 body rows {})",
              276 - carried, 160 - body_bytes);
}
