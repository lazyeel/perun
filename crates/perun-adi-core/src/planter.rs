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
//! The two extras are only affine on some captures, so [`Window`] models a
//! window as a general byte table and [`Window::affine_matches_table`] reports
//! whether the law holds for a given capture.
//!
//! # What this module owns, and does not
//!
//! Owns: the layout, the offsets, the affine position law, and parsing a
//! planter image into typed windows.
//!
//! Does **not** own the genesis from the SPIM. Measured facts (see
//! `research-runs/planter-arena-law-2026-11-20.md`): the windows do not depend
//! on the 12-byte prefill seed; they depend on the 240-byte arena the native
//! code copies from `SPIM[8..248]` into `libCoreADI`'s writable image, and only
//! the arena's last 80 bytes (`SPIM[168..248]`) reach them. The arena -> window
//! map is a cascade of fifteen separable 16-byte mixers with a one-byte
//! `p ^ 3` feed-forward; it is not GF(2)-affine and not a per-byte XOR bundle.
//! `expand_planter(spim)` therefore stays gated on the native oracle until that
//! cascade is transcribed, and this module deliberately exposes no
//! `from_spim` that would pretend otherwise.

/// Length of a window.
pub const WINDOW_LEN: usize = 256;

/// Length of the native planter object.
pub const PLANTER_LEN: usize = 0x2700;

/// Length of the arena that feeds the windows.
pub const ARENA_LEN: usize = 240;

/// The arena's RVA inside `libCoreADI`'s writable image.
pub const ARENA_RVA: usize = 0x19B600;

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
