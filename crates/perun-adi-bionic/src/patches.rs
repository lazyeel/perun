// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The five binary patches this lane depends on, as data rather than as advice.
//!
//! Each is a specific defect in a specific android-21 binary, located by
//! measurement and recorded so that a rebuild applies it instead of silently
//! reverting it. They share a root cause — a `PTHREAD_MUTEX_ROBUST` word
//! flagged "owner died" with nobody to own it — but they sit in different
//! objects and must be told apart.
//!
//! # Why this is a table and not a comment
//!
//! Patching `linker64`'s `g_dl_mutex` by hand and then rebuilding the stand
//! reverts it, because the rebuild copies a pristine loader over the patched
//! one. That happened, and the lane looked dead for no visible reason. The
//! only reliable way to remember is to have it written down where the rebuild
//! reads it.

/// Which object a patch targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchSite {
    /// The Bionic libc, `libc.so`.
    Libc,
    /// The Bionic loader, `linker64`.
    Linker,
    /// `libLLVM.so`, reached through the platform GUI stack.
    Llvm,
}

/// One patch: where it applies, what it writes, and why.
#[derive(Clone, Copy, Debug)]
pub struct Patch {
    pub site: PatchSite,
    /// Offset within the file.
    pub file_offset: u64,
    /// The bytes the field must hold for this patch to apply.
    pub expect: &'static [u8],
    /// What it must hold afterwards.
    pub write: &'static [u8],
    /// Why, in one line. Read this before changing any offset.
    pub because: &'static str,
}

impl Patch {
    /// Apply to a file image.
    ///
    /// Returns whether anything changed. An image already carrying the patched
    /// bytes is left alone; an image holding something *else* is refused,
    /// because then the offset no longer means what this table claims.
    pub fn apply(&self, image: &mut [u8]) -> Result<bool, PatchError> {
        let at = self.file_offset as usize;
        let end = at + self.expect.len();
        if end > image.len() {
            return Err(PatchError::OutOfRange {
                at,
                len: image.len(),
            });
        }
        // Compare over the length actually written, not the length expected.
        // flockfile's patch covers 13 of the 17 bytes it verifies, so comparing
        // the whole window would report "unexpected" on a file we already
        // patched -- and a rebuild applies the table more than once.
        let wend = at + self.write.len();
        if &image[at..wend] == self.write {
            return Ok(false);
        }
        if &image[at..end] != self.expect {
            return Err(PatchError::Unexpected {
                at,
                found: hex(&image[at..end]),
                expected: hex(self.expect),
            });
        }
        if self.write.len() > self.expect.len() {
            return Err(PatchError::Grows {
                at,
                from: self.expect.len(),
                to: self.write.len(),
            });
        }
        image[at..at + self.write.len()].copy_from_slice(self.write);
        Ok(true)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Why a patch refused to apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// The offset lies past the end of the file.
    OutOfRange { at: usize, len: usize },
    /// The field holds something other than the documented pristine bytes.
    Unexpected {
        at: usize,
        found: String,
        expected: String,
    },
    /// The replacement is longer than the bytes it replaces, which would
    /// shift everything after it. No patch here may do that.
    Grows { at: usize, from: usize, to: usize },
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange { at, len } => {
                write!(f, "offset {at} is past the end of the file ({len} bytes)")
            }
            Self::Unexpected {
                at,
                found,
                expected,
            } => write!(
                f,
                "at {at}: expected {expected}, found {found}; the file is either \
                 already patched or its layout changed"
            ),
            Self::Grows { at, from, to } => write!(
                f,
                "at {at}: the patch would grow the field from {from} to {to} bytes \
                 and shift the rest of the file"
            ),
        }
    }
}

impl std::error::Error for PatchError {}

// The `expect` bytes were read out of the android-21 x86_64 image, not inferred.

// Everything this lane patches, in the order a rebuild must apply them.
pub const PATCHES: &[Patch] = &[
    Patch {
        site: PatchSite::Linker,
        file_offset: 0x16040,
        expect: &[0x00, 0x40, 0x00, 0x00],
        write: &[0x00, 0x00, 0x00, 0x00],
        because: "g_dl_mutex is flagged robust with no owner in the image, so \
                  pthread_mutex_lock loops on it and the FIRST dlopen never returns",
    },
    Patch {
        site: PatchSite::Libc,
        file_offset: 0x23A20,
        // push %rax ; mov 0x58(%rdi),%rdi ; add $0x38,%rdi ; jmp pthread_mutex_lock
        expect: &[
            0x50, 0x48, 0x8b, 0x3f, 0x48, 0x8b, 0x7f, 0x58, 0x48, 0x83, 0xc7, 0x38, 0xe9, 0xae,
            0x1a, 0xff, 0xff,
        ],
        // ret, then nops across the rest of the 26-byte function.
        write: &[
            0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
        because: "flockfile is a tail call into pthread_mutex_lock; ret-ing out clears \
                  every stdio hang at once, including libcurl's BIO_gets on the CA bundle",
    },
    Patch {
        site: PatchSite::Libc,
        file_offset: 0x23A60,
        expect: &[
            0x50, 0x48, 0x8b, 0x3f, 0x48, 0x8b, 0x7f, 0x58, 0x48, 0x83, 0xc7, 0x38, 0xe9, 0xae,
            0x1a, 0xff, 0xff,
        ],
        write: &[
            0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
        because: "funlockfile is flockfile's mirror; leaving it would unlock a mutex \
                  that was never taken",
    },
    Patch {
        site: PatchSite::Libc,
        file_offset: 0x2B230,
        // __sysconf_nprocessors_onln: 41 57 48 8d 35 65 ...
        expect: &[0x41, 0x57, 0x48, 0x8d, 0x35, 0x65],
        // mov $4,%eax ; ret -- breaks the malloc -> sysconf -> fgets cycle, in
        // which the allocator's own initialisation reads /proc/stat through a
        // stdio path that needs the allocator.
        write: &[0xb8, 0x04, 0x00, 0x00, 0x00, 0xc3],
        because: "sysconf(_SC_NPROCESSORS_ONLN) reads /proc/stat through fgets, which \
                  takes the stream lock the allocator is already holding",
    },
    Patch {
        site: PatchSite::Llvm,
        file_offset: 0xB75765,
        // The call to pthread_mutex_lock inside MutexImpl::acquire.
        expect: &[0xe8, 0xa7, 0xff, 0x6f, 0xff],
        write: &[0x90, 0x90, 0x90, 0x90, 0x90],
        because: "llvm::sys::MutexImpl::acquire locks a statically initialised mutex \
                  that never gets released; the stand is single-threaded",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn image_with(p: &Patch) -> Vec<u8> {
        let mut v = vec![0u8; p.file_offset as usize + p.expect.len() + 8];
        let at = p.file_offset as usize;
        v[at..at + p.expect.len()].copy_from_slice(p.expect);
        v
    }

    #[test]
    fn every_patch_is_present_at_its_site() {
        assert_eq!(
            PATCHES
                .iter()
                .filter(|p| p.site == PatchSite::Linker)
                .count(),
            1
        );
        assert_eq!(
            PATCHES.iter().filter(|p| p.site == PatchSite::Libc).count(),
            3
        );
        assert_eq!(
            PATCHES.iter().filter(|p| p.site == PatchSite::Llvm).count(),
            1
        );
    }

    #[test]
    fn applies_once_then_becomes_a_no_op() {
        for p in PATCHES {
            let mut img = image_with(p);
            assert_eq!(p.apply(&mut img), Ok(true), "{}", p.because);
            let at = p.file_offset as usize;
            assert_eq!(&img[at..at + p.write.len()], p.write);
            assert_eq!(p.apply(&mut img), Ok(false));
        }
    }

    #[test]
    fn refuses_a_foreign_image() {
        let p = &PATCHES[0];
        let mut img = vec![0u8; 0x16044];
        img[0x16040..0x16044].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        match p.apply(&mut img) {
            Err(PatchError::Unexpected { at, found, .. }) => {
                assert_eq!(at, 0x16040);
                assert_eq!(found, "efbeadde"); // 0xdeadbeef, little-endian
            }
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }

    #[test]
    fn refuses_an_offset_past_the_end() {
        let p = &PATCHES[0];
        let mut tiny = vec![0u8; 32];
        assert!(matches!(
            p.apply(&mut tiny),
            Err(PatchError::OutOfRange { .. })
        ));
    }

    #[test]
    fn no_patch_grows_its_field() {
        // Growing would shift the rest of the file and corrupt the object;
        // apply() refuses it, and the table must not contain one.
        for p in PATCHES {
            assert!(
                p.write.len() <= p.expect.len(),
                "{:?} would grow the field",
                p.file_offset
            );
        }
    }

    #[test]
    fn the_two_libc_locks_stay_inside_their_own_functions() {
        // flockfile and funlockfile are 26 bytes each and sit 0x40 apart;
        // ftrylockfile lives between them and must not be touched.
        let f = PATCHES.iter().find(|p| p.file_offset == 0x23A20).unwrap();
        let u = PATCHES.iter().find(|p| p.file_offset == 0x23A60).unwrap();
        assert_eq!(u.file_offset - f.file_offset, 0x40);
        assert!(f.file_offset + 26 <= 0x23A40);
        assert!(u.file_offset >= 0x23A60);
    }

    #[test]
    fn every_patch_documents_itself() {
        for p in PATCHES {
            assert!(
                p.because.len() > 40,
                "{:?} needs a real explanation",
                p.file_offset
            );
            assert!(!p.expect.is_empty());
        }
    }
}
