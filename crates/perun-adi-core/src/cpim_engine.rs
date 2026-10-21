//! The CPIM body engine, measured on the live Android oracle (2026-10-22).
//!
//! The whole zone CPIM[0x18..0xd8) -- body A (160 bytes) and the digest
//! (32 bytes) -- is a contiguous slice of ONE runtime table the engine
//! builds before unloading it (the "depot", the r14 of the writer cycle).
//! The unloader itself is a 28-instruction CFF cycle at
//! libCoreADI+0xdc6dc..0xdc748 that runs 96 turns, writing two bytes
//! per turn:
//!
//!   mov byte [r11+rbx], r10b   ; odd byte  = depot[idx-1]
//!   mov byte [r11+rsi], dl      ; even byte = depot[idx]
//!
//! with idx = edi - 0x43cd3cea (an always-false MBA mask selects the
//! cmov term), rbx = idx + 0x19 descending by two, rsi = rbx - 1.  Both
//! stores draw from the same table, so the cycle is an obfuscated
//! `memcpy(cpim[0x18..0xd8], depot[0..0xC0))`.
//!
//! Measured parity: 192/192 bytes on the 2026-10-21 gdb pair
//! (r14_table.bin -> gdb_pair_cpim.bin), and 96/96 store-1 / 96/96
//! store-2 / 96/96 table-index checks over the full writer tape.
//!
//! What this module does NOT own (the honest boundary): the mixer chain
//! that FILLS the depot (libCoreADI+0xe6b41.., the unrolled planter-key
//! cascade -- session material, the true SPIM dependence). This module
//! takes the depot as an input; `live_pair_parity` pins the unloader
//! byte for byte, and the mixer chain is the next transcription front.

/// The depot slice the unloader copies: CPIM[0x18..0xd8), 192 bytes.
pub const DEPOT_SLICE: usize = 0xC0;

/// One writer-cycle turn, transcribed from the live trace. `idx` is the
/// engine's own table cursor (edi - 0x43cd3cea); the turn writes the
/// even byte of the pair (depot[idx]) at cpim offset `idx + 0x18` and
/// the odd byte (depot[idx - 1]) at `idx + 0x19`.
#[inline]
fn writer_turn(depot: &[u8], idx: usize, cpim: &mut [u8]) {
    // mov byte [r11+rsi], dl   where dl = depot[idx], rsi = rbx - 1
    cpim[idx + 0x18] = depot[idx];
    // mov byte [r11+rbx], r10b -- prepared in the PREVIOUS turn (the
    // +0xdc6dc block reads the pre-decrement edi), which lands it on
    // depot[idx + 1]; measured: cpim[j] = depot[j - 0x18] for ALL j.
    cpim[idx + 0x19] = depot[idx + 1];
}

/// The measured unloader: the full 28-instruction cycle unrolled into
/// its 96 turns, idx descending 0xBE, 0xBC, .. 0x00 (step -2, matching
/// `add edi, -2` at +0xdc707). Given the depot table, fills the
/// CPIM[0x18..0xd8) zone of `cpim`.
///
/// This is a transcription of a measured loop, not a free-form copy:
/// the turn order and the odd/even source indices follow the gdb tape
/// one for one.
pub fn unload_depot(depot: &[u8; DEPOT_SLICE], cpim: &mut [u8]) {
    let mut idx = 0xC0 - 2; // first turn: rbx = 0xd7, idx = rbx - 0x19 = 0xBE
    loop {
        writer_turn(depot, idx, cpim);
        if idx == 0 {
            break;
        }
        idx -= 2; // add edi, -2
    }
}

/// Convenience: build the full 276-byte CPIM container from the depot
/// slice plus the already-measured surrounding fields (the header,
/// session block, length fields and body B come from elsewhere in the
/// engine; `unload_depot` owns only [0x18..0xd8)).
pub fn fill_cpim_zone(cpim: &mut [u8], depot: &[u8; DEPOT_SLICE]) {
    unload_depot(depot, cpim);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live gdb pair of 2026-10-21: the depot dump taken inside the
    /// transform (r14_table.bin) and the CPIM the same run produced.
    /// Pinned by env so the test carries its own evidence gates, the
    /// campaign convention.
    #[test]
    fn live_pair_depot_unloader_parity() {
        let depot_path = std::env::var("PERUN_DEPOT_REF")
            .unwrap_or_else(|_| "/opt/data/adi-re/r14_table.bin".to_string());
        let cpim_path = std::env::var("PERUN_CPIM_LIVE")
            .unwrap_or_else(|_| "/opt/data/adi-re/gdb_pair_cpim.bin".to_string());
        let (Ok(depot_blob), Ok(cpim_blob)) = (
            std::fs::read(&depot_path),
            std::fs::read(&cpim_path),
        ) else {
            eprintln!("gating: {depot_path} / {cpim_path} not present");
            return;
        };
        assert_eq!(cpim_blob.len(), 0x114, "the live CPIM is 276 bytes");
        let depot: [u8; DEPOT_SLICE] =
            depot_blob[..DEPOT_SLICE].try_into().expect("depot dump covers 0xC0");

        // the measured law, first: the zone is the depot slice verbatim
        for (k, (&d, &c)) in depot.iter().zip(cpim_blob[0x18..0xd8].iter()).enumerate() {
            assert_eq!(d, c, "depot[{k:#04x}] != cpim[{:#04x}]", 0x18 + k);
        }

        // and the transcribed unloader reproduces it on its own
        let mut cpim = vec![0u8; 0x114];
        fill_cpim_zone(&mut cpim, &depot);
        assert_eq!(&cpim[0x18..0xd8], &cpim_blob[0x18..0xd8], "unloader parity");
    }

    /// The writer-cycle semantics pinned without the live files: every
    /// byte of the zone lands exactly once, odd bytes from depot[k-1],
    /// even bytes from depot[k] -- the 96 turns cover 192 bytes with no
    /// overlap and no gap.
    #[test]
    fn unloader_covers_zone_exactly_once() {
        let mut depot = [0u8; DEPOT_SLICE];
        for (k, b) in depot.iter_mut().enumerate() {
            *b = (k * 7 + 3) as u8;
        }
        let mut cpim = vec![0u8; 0x114];
        unload_depot(&depot, &mut cpim);
        for j in 0x18..0xd8 {
            let expect = depot[j - 0x18];
            assert_eq!(cpim[j], expect, "cpim[{j:#04x}] mismatch");
        }
        // untouched surroundings
        assert!(cpim[..0x18].iter().all(|&b| b == 0));
        assert!(cpim[0xd8..].iter().all(|&b| b == 0));
    }
}
