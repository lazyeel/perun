// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The planter window table: shape and position law (measured 2026-11-19/20).
//!
//! The native planter is a 0x2700-byte session object. Seven 256-byte
//! permutation windows inside it are the key schedule the mixer block reads:
//!
//! ```text
//! role   planter offset   measured
//! fam1   +0x0D60          permutation, c = 0x3B
//! fam4   +0x1390          permutation, c = 0x64
//! fam2   +0x1A00          permutation, c = 0x07
//! fifth  +0x1F30          permutation, c = 0x57
//! fam3   +0x2460          permutation, c = 0x39
//! extra  +0x0C50          permutation, role open
//! extra  +0x1280          permutation, role open
//! ```
//!
//! # The position law
//!
//! Every canonical window is a GF(2)-affine permutation of the position byte:
//!
//! ```text
//! w[i] = c ^ XOR_{k : bit k of i is set} basis[k]
//! ```
//!
//! so a window is nine bytes: its constant `c` and an eight-byte basis. That
//! was verified byte for byte on every captured lineage (A1, A2, B, C, D, E, F).
//! The constant is lineage-invariant for the five canonical windows; the basis
//! is session-dynamic (identical for lineages that share one SPIM).
//!
//! The affine law holds for the five canonical windows on *every* capture of
//! the measured corpus (A1, A2, B, C, D, E, F) and fails for both extras on
//! every one of them, so [`Window`] models a window as a general byte table and
//! [`Window::affine_matches_table`] reports whether the law holds for a given
//! capture. A window whose eight basis bytes are linearly dependent is still
//! written by the same evaluator but is not bijective -- measured on replays
//! of arenas the native code never produced.
//!
//! # The genesis pipeline
//!
//! Measured on the Android x86_64 oracle (`libCoreADI.so`, offline SPIM
//! harness), replaying `gcore` checkpoints at RVA `0xDD511`:
//!
//! ```text
//! arena[0..240] = SPIM[8..248]                     // exact, 240/240 bytes
//!                                                   (unrolled copy at 0xA958D)
//!
//! for b in 0..15:                                 // fifteen block-local rounds
//!     read  all 16 bytes of arena[16b .. 16b+16)  // in a fixed order
//!     write schedule[16b .. 16b+16)              // four dwords, +0,+12,+4,+8
//!
//! tail = schedule[0xB0 .. 0xF0)                  // sixteen dwords, read back
//! for i in 0..256:                               // window loop 0xE1F74..0xE26DE
//!     for each of the seven windows:
//!         window[i] = tau ( tail bits )          // nine affine parameters
//! ```
//!
//! The round read order is identical in every round and every lineage,
//! `01 06 03 0a 00 04 09 0f 08 0b 02 05 07 0c 0e 0d` by position; a
//! single arena byte moves all sixteen bytes of its own block and exactly one
//! byte of the next block -- position `p ^ 3`. Only the last five arena blocks
//! (`arena[160..240]`, i.e. `SPIM[168..248]`) reach the windows, because the
//! window tail stops reading the schedule at `+0xB0`.
//!
//! The tail stage (64 live bytes -> seven 256-byte tables) produces the five
//! canonical windows as affine position laws on every capture measured, and
//! both extras as non-affine tables. The two extras are therefore not filled by
//! the evaluator that fills the canonical five; their role is still open.
//!
//! The map *from the arena bytes to those parameters* is not GF(2)-affine on
//! the full 640-bit input and is not a per-byte XOR bundle: no arena byte is a
//! private input of one parameter (a single suffix byte moves up to 27 of the
//! 45 canonical parameter bytes), and single-bit probes do not compose. That is
//! the remaining unknown substance of the genesis.
//!
//! # What this module owns, and does not
//!
//! Owns: the layout, the offsets, the affine position law both ways (a window
//! is nine [`Params`] bytes; [`Window::from_params`] rebuilds the table and
//! [`Window::params`] recovers it), and parsing a planter image into typed
//! windows.
//!
//! Does **not** own the arena -> parameter map. Measured facts (see
//! `research-runs/planter-arena-law-2026-11-20.md`): the windows do not depend
//! on the 12-byte prefill seed; they depend on the 240-byte arena, and only the
//! arena's last 80 bytes (`SPIM[168..248]`) reach them. Because that map is not
//! affine centre, `expand_planter(spim)` stays gated on the native oracle and this module
//! deliberately exposes no `from_spim` that would pretend otherwise. The
//! five constants, however, are lineage-invariant and are pinned: any candidate
//! producer must reproduce them.

/// Length of a window.
pub const WINDOW_LEN: usize = 256;

/// Length of the native planter object.
pub const PLANTER_LEN: usize = 0x2700;

/// Length of the arena that feeds the windows.
pub const ARENA_LEN: usize = 240;

/// The arena's RVA inside `libCoreADI`'s writable image.
pub const ARENA_RVA: usize = 0x19B600;

/// The arena the planter genesis consumes, taken straight from the SPIM.
///
/// Measured byte for byte on A1, A2, C and D: the arena is exactly
/// `spim[8..248]`, the 240 bytes following the 8-byte SPIM header. No
/// permutation, no relabelling, no seed and no identity enters here -- the
/// native `0xA958D` unrolled copy block only rearranges the dwords it writes.
/// The later windows depend on `arena[160..240]`, i.e. on `spim[168..248]`,
/// but the arena itself is a pure slice of the input and needs no producer.
pub fn arena_from_spim(spim: &crate::spim::Spim) -> [u8; ARENA_LEN] {
    let mut out = [0u8; ARENA_LEN];
    out.copy_from_slice(&spim.to_bytes()[8..248]);
    out
}

/// The four fixed GF(2)-linear masks of the cross-block coupling.
///
/// Schedule byte `q` of block `b` receives one byte of arena block `b-1`, at
/// position `q ^ 3`, through `COUPLING_MASKS[q % 4]`. Each mask is stored as the
/// images of the eight unit bits, so the map is
///
/// ```text
/// M(v) = XOR_{k : bit k of v is set} mask[k]
/// ```
///
/// Measured on 30 (block, q) positions in four unrelated random contexts, and
/// identical on the A1 and C checkpoints: the tables are lineage-invariant and
/// block-invariant, and all four have GF(2) rank 8, i.e. they are byte
/// bijections. Only the additive constant of the coupling is context-dependent
/// (it carries the full-block dependence), which is why the coupling is not a
/// per-byte copy.
pub const COUPLING_MASKS: [[u8; 8]; 4] = [
    [0xCF, 0x66, 0x65, 0xEE, 0x7C, 0xEC, 0x9C, 0xB9],
    [0xC1, 0xEE, 0x7B, 0xE6, 0x79, 0x29, 0xB5, 0x10],
    [0x3B, 0x29, 0x45, 0x6F, 0x48, 0x5B, 0x64, 0xA9],
    [0x9F, 0xDD, 0x71, 0x88, 0x89, 0x75, 0x68, 0xD5],
];

/// The fixed linear part of the block coupling: `x[b-1][q ^ 3]` into `S[b][q]`.
///
/// The affine constant of the coupling is context-dependent and deliberately
/// not modelled here; this is the mask that the measurement found to be
/// invariant across blocks, lineages and random contexts.
pub fn coupling_linear(q: usize, byte: u8) -> u8 {
    let mask = COUPLING_MASKS[q % 4];
    let mut out = 0u8;
    for (k, column) in mask.iter().enumerate() {
        if byte & (1 << k) != 0 {
            out ^= *column;
        }
    }
    out
}

/// The nine bytes that generate one affine window: the constant and the basis.
///
/// This is the whole information content of a canonical window. The native
/// evaluator writes 256 bytes, but every one of them is one XOR of a subset of
/// the basis, so the bytes here reproduce `window` exactly through
/// [`Window::from_params`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The value at position 0, i.e. the constant term.
    pub constant: u8,
    /// `basis[k]`, the contribution of bit `k` of the index byte.
    pub basis: [u8; 8],
}

/// A 256-byte planter window, stored as a byte permutation table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Window {
    bytes: [u8; WINDOW_LEN],
}

/// A malformed window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The table is not bijective: some value repeats or is missing.
    NotAPermutation,
}

impl std::fmt::Display for WindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPermutation => write!(f, "window table is not a permutation"),
        }
    }
}

impl std::error::Error for WindowError {}

impl Window {
    /// Build from a 256-byte table, requiring a complete permutation.
    pub fn from_permutation(bytes: [u8; WINDOW_LEN]) -> Result<Self, WindowError> {
        let mut seen = [false; WINDOW_LEN];
        for byte in bytes {
            if seen[byte as usize] {
                return Err(WindowError::NotAPermutation);
            }
            seen[byte as usize] = true;
        }
        Ok(Self { bytes })
    }

    /// The raw table.
    pub const fn as_bytes(&self) -> &[u8; WINDOW_LEN] {
        &self.bytes
    }

    /// The constant `c`, i.e. the value at position 0.
    pub const fn constant(&self) -> u8 {
        self.bytes[0]
    }

    /// The eight basis bytes, `basis[k] = w[1 << k] ^ w[0]`.
    pub fn basis(&self) -> [u8; 8] {
        let c = self.bytes[0];
        let mut out = [0u8; 8];
        for (k, slot) in out.iter_mut().enumerate() {
            *slot = self.bytes[1 << k] ^ c;
        }
        out
    }

    /// The nine bytes that generate this table, i.e. [`Window::params`]'s result.
    ///
    /// Meaningful for the five canonical windows; for the two extras the
    /// affine law does not hold, so this is a best-effort summary and
    /// [`Window::affine_matches_table`] is the test that says whether the
    /// table can be reproduced from it.
    pub fn params(&self) -> Params {
        Params {
            constant: self.constant(),
            basis: self.basis(),
        }
    }

    /// Rebuild the table from nine bytes through the affine position law.
    pub fn from_params(params: &Params) -> Self {
        let mut bytes = [0u8; WINDOW_LEN];
        for (i, slot) in bytes.iter_mut().enumerate() {
            let mut v = params.constant;
            for (k, b) in params.basis.iter().enumerate() {
                if i & (1 << k) != 0 {
                    v ^= b;
                }
            }
            *slot = v;
        }
        Self { bytes }
    }

    /// Evaluate the affine position law against the stored table at `i`.
    pub fn position(&self, i: u8) -> u8 {
        let c = self.bytes[0];
        let mut v = c;
        let basis = self.basis();
        for (k, b) in basis.iter().enumerate() {
            if i & (1 << k) != 0 {
                v ^= b;
            }
        }
        v
    }

    /// Whether the table agrees with the affine position law everywhere.
    pub fn affine_matches_table(&self) -> bool {
        for (i, value) in self.bytes.iter().enumerate() {
            if self.position(i as u8) != *value {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Debug for Window {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Window")
            .field("constant", &self.constant())
            .field("basis", &self.basis())
            .field("affine", &self.affine_matches_table())
            .finish()
    }
}

/// A window role and its planter offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// `fam1`, offset `+0x0D60`.
    Fam1,
    /// `fam4`, offset `+0x1390`.
    Fam4,
    /// `fam2`, offset `+0x1A00`.
    Fam2,
    /// The fifth window, offset `+0x1F30`.
    Fifth,
    /// `fam3`, offset `+0x2460`.
    Fam3,
    /// Extra permutation at `+0x0C50`; role open.
    ExtraC50,
    /// Extra permutation at `+0x1280`; role open.
    Extra1280,
}

impl Family {
    /// The five canonical windows.
    pub const CANONICAL: [Self; 5] = [Self::Fam1, Self::Fam4, Self::Fam2, Self::Fifth, Self::Fam3];

    /// Every measured window.
    pub const ALL: [Self; 7] = [
        Self::Fam1,
        Self::Fam4,
        Self::Fam2,
        Self::Fifth,
        Self::Fam3,
        Self::ExtraC50,
        Self::Extra1280,
    ];

    /// The planter-relative offset of the window.
    pub const fn offset(self) -> usize {
        match self {
            Self::Fam1 => 0x0D60,
            Self::Fam4 => 0x1390,
            Self::Fam2 => 0x1A00,
            Self::Fifth => 0x1F30,
            Self::Fam3 => 0x2460,
            Self::ExtraC50 => 0x0C50,
            Self::Extra1280 => 0x1280,
        }
    }

    /// The measured lineage-invariant constant, when one is established.
    pub const fn constant(self) -> Option<u8> {
        match self {
            Self::Fam1 => Some(0x3B),
            Self::Fam4 => Some(0x64),
            Self::Fam2 => Some(0x07),
            Self::Fifth => Some(0x57),
            Self::Fam3 => Some(0x39),
            Self::ExtraC50 | Self::Extra1280 => None,
        }
    }

    /// The human name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fam1 => "fam1",
            Self::Fam4 => "fam4",
            Self::Fam2 => "fam2",
            Self::Fifth => "fifth",
            Self::Fam3 => "fam3",
            Self::ExtraC50 => "extra-c50",
            Self::Extra1280 => "extra-1280",
        }
    }
}

/// The seven windows of one planter, parsed from its image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanterWindows {
    windows: [Window; 7],
}

/// A planter image that does not have the measured shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanterError {
    /// The image is shorter than the measured planter object.
    ShortImage {
        /// Observed length.
        len: usize,
    },
    /// One window is not a permutation; the payload is the planter offset.
    BadWindow {
        /// Planter offset of the offending window.
        offset: usize,
    },
}

impl std::fmt::Display for PlanterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortImage { len } => {
                write!(
                    f,
                    "planter image is {len} bytes, need at least {PLANTER_LEN}"
                )
            }
            Self::BadWindow { offset } => {
                write!(f, "planter window at +{offset:#x} is not a permutation")
            }
        }
    }
}

impl std::error::Error for PlanterError {}

impl PlanterWindows {
    /// Parse the seven windows from a planter image.
    pub fn parse(planter: &[u8]) -> Result<Self, PlanterError> {
        if planter.len() < PLANTER_LEN {
            return Err(PlanterError::ShortImage { len: planter.len() });
        }
        let mut windows = [Window {
            bytes: [0u8; WINDOW_LEN],
        }; 7];
        for (slot, family) in windows.iter_mut().zip(Family::ALL) {
            let off = family.offset();
            let mut table = [0u8; WINDOW_LEN];
            table.copy_from_slice(&planter[off..off + WINDOW_LEN]);
            *slot = Window::from_permutation(table)
                .map_err(|_| PlanterError::BadWindow { offset: off })?;
        }
        Ok(Self { windows })
    }

    /// One window by family.
    pub const fn window(&self, family: Family) -> &Window {
        &self.windows[family as usize]
    }

    /// The five canonical windows, in planter order.
    pub fn canonical(&self) -> [&Window; 5] {
        [
            self.window(Family::Fam1),
            self.window(Family::Fam4),
            self.window(Family::Fam2),
            self.window(Family::Fifth),
            self.window(Family::Fam3),
        ]
    }

    /// Every measured window carries its lineage-invariant constant.
    pub fn constants_match_measurements(&self) -> bool {
        Family::ALL.iter().all(|family| match family.constant() {
            Some(expected) => self.window(*family).constant() == expected,
            None => true,
        })
    }

    /// Every canonical window obeys the affine position law.
    pub fn canonical_windows_are_affine(&self) -> bool {
        self.canonical()
            .iter()
            .all(|window| window.affine_matches_table())
    }

    /// The nine-byte parameter blocks of the canonical windows.
    ///
    /// Measured fact: the native stage writes the canonical five through this
    /// law on every captured lineage, while the two extras do not fit it. A
    /// candidate arena producer must therefore reproduce these 45 bytes, not
    /// the 1280-byte tables.
    pub fn canonical_params(&self) -> [Params; 5] {
        let [fam1, fam4, fam2, fifth, fam3] = self.canonical();
        [
            fam1.params(),
            fam4.params(),
            fam2.params(),
            fifth.params(),
            fam3.params(),
        ]
    }

    /// Number of the eight basis bytes per window that are GF(2)-independent.
    ///
    /// Width eight is a bijection. On arenas the native suite did not produce,
    /// the native generator can hand back a dependent basis and the same
    /// evaluator then emits a table with repetitions; that is the measured
    /// failure mode, not a break of the law.
    pub fn canonical_basis_ranks(&self) -> [u8; 5] {
        let mut ranks = [0u8; 5];
        for (slot, window) in self.canonical().iter().enumerate() {
            let mut pivots: [u8; 8] = [0; 8];
            let mut rank = 0u8;
            for &v in &window.basis() {
                let mut x = v;
                while x != 0 {
                    let bit = 7 - x.leading_zeros() as usize;
                    if pivots[bit] == 0 {
                        pivots[bit] = x;
                        rank += 1;
                        break;
                    }
                    x ^= pivots[bit];
                }
            }
            ranks[slot] = rank;
        }
        ranks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offsets and constants measured on seven captured lineages.
    #[test]
    fn layout_is_the_measured_one() {
        let expected = [
            (Family::Fam1, 0x0D60, Some(0x3B)),
            (Family::Fam4, 0x1390, Some(0x64)),
            (Family::Fam2, 0x1A00, Some(0x07)),
            (Family::Fifth, 0x1F30, Some(0x57)),
            (Family::Fam3, 0x2460, Some(0x39)),
            (Family::ExtraC50, 0x0C50, None),
            (Family::Extra1280, 0x1280, None),
        ];
        for (family, offset, constant) in expected {
            assert_eq!(family.offset(), offset, "{}", family.name());
            assert_eq!(family.constant(), constant, "{}", family.name());
        }
        assert_eq!(WINDOW_LEN, 256);
        assert_eq!(PLANTER_LEN, 0x2700);
        assert_eq!(ARENA_LEN, 240);
        assert_eq!(Family::CANONICAL.len(), 5);
    }

    /// The input boundary of the genesis is a slice, not a transform.
    #[test]
    fn arena_is_the_spim_suffix_verbatim() {
        let mut bytes = [0u8; crate::spim::SPIM_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        // the anatomy Start requires: BE u32 Body B length 52, version 4.
        bytes[crate::spim::LENGTH_OFFSET..crate::spim::LENGTH_OFFSET + 4]
            .copy_from_slice(&(crate::spim::BODY_B_LEN as u32).to_be_bytes());
        bytes[crate::spim::VERSION_OFFSET..crate::spim::VERSION_OFFSET + 4]
            .copy_from_slice(&4u32.to_be_bytes());
        let spim = crate::spim::Spim::parse(&bytes).expect("valid 347-byte SPIM");
        let arena = arena_from_spim(&spim);
        assert_eq!(arena.len(), ARENA_LEN);
        assert_eq!(&arena[..], &bytes[8..248]);
        assert_eq!(&arena[160..], &bytes[168..248]);
    }

    fn affine_window(c: u8, basis: [u8; 8]) -> [u8; WINDOW_LEN] {
        let mut out = [0u8; WINDOW_LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            let mut v = c;
            for (k, b) in basis.iter().enumerate() {
                if i & (1 << k) != 0 {
                    v ^= b;
                }
            }
            *slot = v;
        }
        out
    }

    /// The A1 fam1 and fam4 basis bytes, pinned from the gdb capture.
    #[test]
    fn a1_affine_law_reproduces_the_captured_permutation() {
        let fam1 = affine_window(0x3B, [0xcc, 0x19, 0xf4, 0x42, 0xa8, 0x6e, 0x5e, 0xeb]);
        let window = Window::from_permutation(fam1).expect("permutation");
        assert_eq!(window.constant(), 0x3B);
        assert_eq!(
            window.basis(),
            [0xcc, 0x19, 0xf4, 0x42, 0xa8, 0x6e, 0x5e, 0xeb]
        );
        assert!(window.affine_matches_table());

        let fam4 = affine_window(0x64, [0xd6, 0x1b, 0x18, 0x2b, 0x5f, 0xe3, 0x27, 0x25]);
        let window4 = Window::from_permutation(fam4).expect("permutation");
        assert_eq!(window4.constant(), 0x64);
        assert!(window4.affine_matches_table());
    }

    /// The four coupling masks are pinned in the same order the sweep produced
    /// them, and they must stay byte bijections: a dependent column would mean a
    /// transcription slip, because the oracle's four are all rank 8.
    #[test]
    fn coupling_masks_are_bijections_and_match_the_sweep() {
        assert_eq!(
            COUPLING_MASKS,
            [
                [0xCF, 0x66, 0x65, 0xEE, 0x7C, 0xEC, 0x9C, 0xB9],
                [0xC1, 0xEE, 0x7B, 0xE6, 0x79, 0x29, 0xB5, 0x10],
                [0x3B, 0x29, 0x45, 0x6F, 0x48, 0x5B, 0x64, 0xA9],
                [0x9F, 0xDD, 0x71, 0x88, 0x89, 0x75, 0x68, 0xD5],
            ]
        );
        for (r, mask) in COUPLING_MASKS.iter().enumerate() {
            let mut seen = [false; 256];
            for v in 0..=255u8 {
                let img = coupling_linear(r * 4, v);
                assert!(!seen[img as usize], "mask {r} is not injective");
                seen[img as usize] = true;
            }
            // q % 4 selects the mask, the block must not.
            for q in (0..16).step_by(4) {
                assert_eq!(coupling_linear(r + q * 4, 0x5A), coupling_linear(r, 0x5A));
            }
            // And the column convention is the sweep's: M(1 << k) == mask[k].
            for (k, column) in mask.iter().enumerate() {
                assert_eq!(coupling_linear(r, 1 << k), *column);
            }
        }
    }

    #[test]
    fn rejects_non_permutations() {
        let mut table = [0u8; WINDOW_LEN];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let ok = Window::from_permutation(table).expect("identity is a permutation");
        // basis[k] = (1<<k) ^ 0 = 1<<k, and c = 0, so the affine law *does* hold.
        assert!(ok.affine_matches_table());

        let mut bad = table;
        bad[1] = bad[0];
        assert_eq!(
            Window::from_permutation(bad).unwrap_err(),
            WindowError::NotAPermutation
        );
    }

    #[test]
    fn affine_detection_is_sharp() {
        let basis = [0xcc, 0x19, 0xf4, 0x42, 0xa8, 0x6e, 0x5e, 0xeb];
        let mut table = affine_window(0x3B, basis);
        assert!(Window::from_permutation(table)
            .expect("permutation")
            .affine_matches_table());
        table.swap(7, 8);
        let w = Window::from_permutation(table).expect("still a permutation");
        assert!(!w.affine_matches_table());
    }

    /// `from_params` must reproduce the captured tables byte for byte.
    ///
    /// The A1 constants and basis bytes are the ones measured on the native
    /// oracle and pinned in `layout_is_the_measured_one` above.
    #[test]
    fn params_round_trip_reproduces_the_window() {
        let fam1 = affine_window(0x3B, [0xcc, 0x19, 0xf4, 0x42, 0xa8, 0x6e, 0x5e, 0xeb]);
        let fam4 = affine_window(0x64, [0xd6, 0x1b, 0x18, 0x2b, 0x5f, 0xe3, 0x27, 0x25]);
        let fam2 = affine_window(0x07, [0x90, 0x9c, 0x4f, 0x7d, 0xcf, 0x03, 0x1a, 0x52]);
        let fifth = affine_window(0x57, [0x92, 0xb2, 0xe4, 0xe7, 0x15, 0xab, 0x27, 0x14]);
        let fam3 = affine_window(0x39, [0x06, 0x6e, 0x31, 0x5a, 0x9d, 0xf4, 0x91, 0x25]);

        let tables = [
            (Family::Fam1, fam1, 0x3B),
            (Family::Fam4, fam4, 0x64),
            (Family::Fam2, fam2, 0x07),
            (Family::Fifth, fifth, 0x57),
            (Family::Fam3, fam3, 0x39),
        ];
        let mut planter = vec![0u8; PLANTER_LEN];
        for (family, table, constant) in tables {
            planter[family.offset()..family.offset() + WINDOW_LEN].copy_from_slice(&table);
            assert_eq!(table[0], constant, "{}", family.name());
        }
        // The two extras do not obey the law in the native suite preference, so give
        // the parser a permutation that is deliberately not affine.
        let mut extra = affine_window(0x20, [0x73, 0x7c, 0x7d, 0xad, 0xf9, 0x8e, 0x20, 0xca]);
        extra.swap(1, 2);
        for family in [Family::ExtraC50, Family::Extra1280] {
            planter[family.offset()..family.offset() + WINDOW_LEN].copy_from_slice(&extra);
        }

        let windows = PlanterWindows::parse(&planter).expect("valid planter");
        assert!(windows.canonical_windows_are_affine());
        assert_eq!(windows.canonical_basis_ranks(), [8, 8, 8, 8, 8]);

        // Every canonical window must survive params -> from_params unchanged.
        for family in Family::CANONICAL {
            let window = windows.window(family);
            let rebuilt = Window::from_params(&window.params());
            assert_eq!(
                rebuilt.as_bytes(),
                window.as_bytes(),
                "{} did not round-trip through Params",
                family.name()
            );
        }
    }

    /// Dependent basis bytes break bijectivity but not the law.
    ///
    /// Measured on the native oracle: replaying an arena the suite did not
    /// produce hands back a basis with rank below eight, and the same
    /// evaluator then writes a table with repetitions. `from_params` must
    /// reproduce that table exactly, so a downstream consumer sees the
    /// native output rather than a corrected one.
    #[test]
    fn dependent_basis_is_reproduced_verbatim() {
        let degenerate = Params {
            constant: 0,
            basis: [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
        let bytes = Window::from_params(&degenerate).as_bytes().to_owned();
        assert!(!Window::from_permutation(bytes).is_ok());

        let mut planter = vec![0u8; PLANTER_LEN];
        for family in Family::ALL {
            planter[family.offset()..family.offset() + WINDOW_LEN]
                .copy_from_slice(&Window::from_params(&degenerate).as_bytes()[..]);
        }
        assert!(matches!(
            PlanterWindows::parse(&planter),
            Err(PlanterError::BadWindow { .. })
        ));
    }

    #[test]
    fn parse_requires_the_measured_shape() {
        let mut planter = vec![0u8; PLANTER_LEN];
        for family in Family::ALL {
            let basis = [0xcc, 0x19, 0xf4, 0x42, 0xa8, 0x6e, 0x5e, 0xeb];
            let c = family.constant().unwrap_or(0);
            planter[family.offset()..family.offset() + WINDOW_LEN]
                .copy_from_slice(&affine_window(c, basis));
        }
        let windows = PlanterWindows::parse(&planter).expect("valid planter");
        assert!(windows.canonical_windows_are_affine());
        assert!(windows.constants_match_measurements());

        let short = PlanterWindows::parse(&planter[..PLANTER_LEN - 1]);
        assert_eq!(
            short,
            Err(PlanterError::ShortImage {
                len: PLANTER_LEN - 1
            })
        );
    }
}
