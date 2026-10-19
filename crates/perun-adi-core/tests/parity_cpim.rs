// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The end-to-end CPIM parity test: a fresh 347-byte SPIM in, the
//! proven chain's word out, and the CPIM reference validated by
//! the anatomy of 2026-10-23.
//!
//! What this test pins, in the order of the campaign's proof:
//!
//! 1. **The SPIM input** parses as the measured 347-byte GSA form.
//! 2. **The chain** (Entry::measured -> conveyor -> word channels
//!    over the real DLL image) reproduces the verdict word
//!    [0x90, 0x58, 0xb9, 0xad] -- with every channel seed derived
//!    from the fold's own r9d, nothing hardcoded.
//! 3. **The CPIM generator** runs against the fresh SPIM and
//!    produces a container the anatomy validator accepts (the
//!    shape is proven by the reference round-trip; the session
//!    crypto body is the documented session-fold boundary).
//! 4. **The reference CPIM** parses and round-trips byte-exact
//!    (the environment carries its path: PERUN_CPIM_REF).
//!
//! All three environment gates are explicit; a missing path skips
//! the corresponding assertion with a message rather than passing
//! silently.

use perun_adi_core::chain::{generate_cpim, validate_cpim, Entry};
use perun_adi_core::cpim::CpimLayout;
use perun_adi_core::word_channels::ImageByRva;

/// The real DLL image, loaded from the env-gated path (never a
/// repository path -- the DLL lives outside the repo).
struct EnvImage {
    data: Vec<u8>,
    secs: Vec<(u64, u64, u64)>, // (vr, vsize, rawoff)
}

impl EnvImage {
    fn load(path: &std::path::Path) -> Self {
        let data = std::fs::read(path).expect("read the DLL");
        let e = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        let nsec = u16::from_le_bytes([data[e + 6], data[e + 7]]) as usize;
        let optsz = u16::from_le_bytes([data[e + 20], data[e + 21]]) as usize;
        let mut secs = Vec::new();
        for i in 0..nsec {
            let s = e + 24 + optsz + i * 40;
            let vs =
                u32::from_le_bytes([data[s + 8], data[s + 9], data[s + 10], data[s + 11]]) as u64;
            let vr =
                u32::from_le_bytes([data[s + 12], data[s + 13], data[s + 14], data[s + 15]]) as u64;
            let rs =
                u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]]) as u64;
            let ro =
                u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]) as u64;
            secs.push((vr, vs.max(rs), ro));
        }
        Self { data, secs }
    }

    fn off(&self, rva: u32) -> Option<usize> {
        let rva = rva as u64;
        for &(vr, vs, ro) in &self.secs {
            if vr <= rva && rva < vr + vs {
                return Some((ro + (rva - vr)) as usize);
            }
        }
        None
    }
}

impl ImageByRva for EnvImage {
    fn byte_at_rva(&self, rva: u32) -> u8 {
        self.off(rva)
            .map_or(0, |o| self.data.get(o).copied().unwrap_or(0))
    }
}

/// 1 + 2: the fresh SPIM parses, and the chain reproduces the
/// verdict word from the measured entry over the real image.
#[test]
fn fresh_spim_drives_the_chain_to_the_word() {
    let (Some(spim_path), Some(dll_path)) = (
        std::env::var_os("PERUN_SPIM_REF"),
        std::env::var_os("PERUN_COREADI_DLL"),
    ) else {
        eprintln!("PERUN_SPIM_REF/PERUN_COREADI_DLL unset -- skipping the SPIM chain test");
        return;
    };
    let spim = std::fs::read(spim_path).expect("read SPIM");
    assert_eq!(spim.len(), 347, "the fresh SPIM is 347 bytes");
    // The measured GSA form: the version word is the first BE u32.
    let ver = u32::from_be_bytes([spim[0], spim[1], spim[2], spim[3]]);
    assert!(
        ver > 0 && ver <= 4,
        "SPIM version word {ver} in the measured range"
    );

    let image = EnvImage::load(std::path::Path::new(&dll_path));
    let entry = Entry::measured();
    let (r9d, word) = entry.run(&image);
    // The full algebra: tape ^ frame5c0 ^ the four table words = the
    // measured cluster-entry r9d, and its four seeds compute the word.
    assert_eq!(
        r9d, 0x73dc_77fa,
        "the conveyor folds to the measured register"
    );
    assert_eq!(
        word,
        [0x90, 0x58, 0xb9, 0xad],
        "the verdict word, byte for byte"
    );
}

/// 3: the generator runs on the fresh SPIM and its container
/// passes the anatomy validator (the shape proven by the
/// reference; the session body is the documented boundary).
#[test]
fn fresh_spim_generates_an_anatomy_valid_container() {
    let (Some(spim_path), Some(dll_path)) = (
        std::env::var_os("PERUN_SPIM_REF"),
        std::env::var_os("PERUN_COREADI_DLL"),
    ) else {
        eprintln!("PERUN_SPIM_REF/PERUN_COREADI_DLL unset -- skipping the generator test");
        return;
    };
    let spim = std::fs::read(spim_path).expect("read SPIM");
    let image = EnvImage::load(std::path::Path::new(&dll_path));
    let (layout, word) = generate_cpim(&spim, &Entry::measured(), &image)
        .expect("the generator must accept the fresh SPIM");
    assert_eq!(word, [0x90, 0x58, 0xb9, 0xad]);
    // The container the generator emits carries the reference's
    // declared anatomy end to end.
    assert_eq!(layout.version, 5);
    assert_eq!(layout.body_a.len(), 160);
    assert_eq!(layout.body_a_digest.len(), 32);
    assert_eq!(layout.body_b.len(), 52);
    let blob = layout.to_bytes();
    assert_eq!(blob.len(), CpimLayout::REFERENCE_LEN);
    let parsed = validate_cpim(&blob).expect("the generated container validates");
    assert_eq!(parsed, layout, "generate -> validate is a fixed point");
    // The honest boundary: the session crypto body is not ours to
    // invent; the test pins that the generator does NOT fill it
    // with the SPIM bytes (the body comes from the session fold).
    assert_ne!(
        &blob[0x18..0xb8],
        &spim[..160],
        "the generator must not smuggle the SPIM into the crypto body"
    );
}

/// 4: the reference CPIM parses, its section lengths pin, and the
/// parse/serialize round-trip is byte-exact.
#[test]
fn reference_cpim_roundtrips_through_the_generator_machinery() {
    let Some(path) = std::env::var_os("PERUN_CPIM_REF") else {
        eprintln!("PERUN_CPIM_REF unset -- skipping the reference test");
        return;
    };
    let blob = std::fs::read(path).expect("read reference");
    let l = validate_cpim(&blob).expect("reference validates");
    assert_eq!(
        l.to_bytes(),
        blob,
        "the generator machinery reproduces the reference byte-exact"
    );
}
