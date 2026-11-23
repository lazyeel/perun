// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Private M14 differential gate. `PERUN_MIXER14_VECTORS` names a local
//! mode-`0600` file of `(value, zone_byte, native_output)` triples. Raw
//! records are neither printed nor committed.

use perun_adi_core::body_a::{mixer14_inputs, mixer_byte, Zones, ZONE_WINDOW};

#[test]
fn mixer14_matches_private_pretail_vectors() {
    let Some(path) = std::env::var_os("PERUN_MIXER14_VECTORS") else {
        eprintln!("PERUN_MIXER14_VECTORS unset -- skipping the private M14 gate");
        return;
    };
    let vectors = std::fs::read(path).expect("read private M14 vectors");
    assert!(!vectors.is_empty() && vectors.len() % 3 == 0);
    let mut checked = 0usize;
    for record in vectors.as_chunks::<3>().0 {
        let (value, zone_byte, expected) = (record[0], record[1], record[2]);
        let mut planter = [0u8; 256];
        planter[0] = value ^ 0x8D;
        let input = mixer14_inputs(0, &planter);
        assert_eq!(input.lane_value, value);
        assert_eq!(input.mul, value.wrapping_mul(value));
        let mut zones = Zones {
            a: [0; ZONE_WINDOW],
            b: [0; ZONE_WINDOW],
            c: [0; ZONE_WINDOW],
            d: [0; ZONE_WINDOW],
            c1a: 0,
            c1b: 0,
            c1c: 0,
            c1d: 0,
        };
        zones.b[value as usize + 0x100] = zone_byte;
        assert_eq!(
            mixer_byte(13, &input, &zones),
            Some(expected),
            "pure-Rust M14 diverged at private record {}",
            checked + 1
        );
        checked += 1;
    }
    assert_eq!(checked, 10);
    eprintln!("pure-Rust M14: {checked} private pre-tail vectors matched");
}
