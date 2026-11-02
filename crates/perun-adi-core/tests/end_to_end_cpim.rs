// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! THE END-TO-END CPIM TEST: the full 276-byte container, assembled
//! from the generated depot zone plus the measured session fields,
//! compared byte for byte against the live oracle's own CPIM.
//!
//! What is reconstructed or computed from same-session measurements:
//!   - 150 body-A bytes: mixer formulas over giant/selector tapes and
//!     the four baked, load-stable zones;
//!   - 10 body-A bytes: M14's completed post-tail outputs, carried
//!     from the same-session giant tape (the tail is not recomputed);
//!   - the 32-byte digest: Rust arithmetic over word-tape candidates,
//!     whose selection is anchored to the live CPIM's eight sums;
//!   - 16 structural bytes: the measured container constants.
//!
//! What is copied unchanged from the reference CPIM: session (16 bytes)
//! and body B (52 bytes). Missing M4/M12/M15 giant-hit inputs are
//! backfilled from the same-session selector tape, not CPIM.
//!
//! This test proves byte-for-byte parity, not SPIM-only autonomy:
//! session data, M14 post-tail values, and digest-word resolution still
//! have measured/oracle-anchored inputs. The accounting keeps those
//! boundaries separate instead of calling all assembled body-A bytes
//! independently formula-generated.

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

    // THE ASSEMBLED DEPOT ZONE (192): body A + digest, one session.
    let Ok((depot, body_bytes)) = generate_body_from_tapes(&dir) else {
        panic!("the body-a tapes did not assemble under {dir}");
    };
    assert_eq!(body_bytes, 160, "the tape assembler must fill all body-A positions");

    // THE CONTAINER, per the measured anatomy:
    //   [0..4) version 5 | [4..0x14) session | [0x14..0x18) 0xa0
    //   [0x18..0xb8) body A | [0xb8..0xd8) digest
    //   [0xd8..0xdc) 0x34 | [0xdc..0xe0) 4 | [0xe0..0x114) body B
    let mut out = [0u8; 0x114];
    out[0..4].copy_from_slice(&5u32.to_be_bytes());          // version: written
    out[4..0x14].copy_from_slice(&cpim[4..0x14]);           // session: carried
    out[0x14..0x18].copy_from_slice(&0xa0u32.to_be_bytes()); // A len: written
    out[0x18..0xb8].copy_from_slice(&depot[0..0xa0]);        // body A: assembled from formulas + M14 tape results
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
    // Separate formula-computed mixer bytes from finalized M14 tape outputs.
    use perun_adi_core::body_a::BODY_A_M14_TAPE_RESULTS;
    let body_a_formula = body_bytes - BODY_A_M14_TAPE_RESULTS;
    let digest_formula = 32; // arithmetic is Rust; word selection is CPIM-sum anchored
    let structure_formula = 16; // four measured constants/length/version words
    let tape_finalized = BODY_A_M14_TAPE_RESULTS;
    let cpim_carried = 16 + 52; // session + body B
    assert_eq!(body_a_formula, 150);
    assert_eq!(body_a_formula + digest_formula + structure_formula
               + tape_finalized + cpim_carried, 276);
    eprintln!(
        "CPIM e2e: {equal}/276 parity; body-A formula={body_a_formula}, digest arithmetic={digest_formula} (word selection CPIM-anchored), structure={structure_formula}; M14 post-tail tape={tape_finalized}; CPIM copied={cpim_carried} (session 16 + body B 52)"
    );
}
