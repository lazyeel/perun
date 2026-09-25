// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! rdtsc execution census (feature `rdtsc-census`).
//!
//! **Research only.** One question: how many of the pinned rdtsc sites does a
//! short SAP session actually execute?
//!
//! Every site is mined to `0xCC` instead of the neutralising replacement.
//! The SIGTRAP handler records the site, zeroes RAX/RDX and resumes just past
//! the idiom, so the guest sees exactly what the real patch gives it.

//! The handler runs in signal context, so the fired set is a bitmap over
//! site indices and the lookup is a binary search. Neither allocates or
//! locks, which is what makes this safe to call from a trap.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// One instrumented site: the guest address range its `0xCC` covers, the
/// base of the image it belongs to, and its offset within that image.
#[derive(Clone)]
pub struct Site {
    pub lo: u64,
    pub hi: u64,
    pub base: u64,
    pub off: u32,
    pub image: &'static str,
}

/// Sorted by `lo`, so the handler can binary search it.
static SITES: Mutex<Vec<Site>> = Mutex::new(Vec::new());
/// One bit per site, 64 sites per word.
const WORDS: usize = (1 << 13) / 64;
static FIRED: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

/// Install the instrumented sites. Called once per image, at load time.
pub fn register(sites: &[Site]) {
    if let Ok(mut v) = SITES.lock() {
        v.extend_from_slice(sites);
        v.sort_by_key(|s| s.lo);
    }
}

/// Mine one site: `0xCC` over the first byte, rest of the idiom intact.
///
/// # Safety
/// `at` must be writable and have at least `len` readable bytes behind it.
pub unsafe fn mine(at: *mut u8, len: usize) {
    unsafe { *at = 0xCC };
    let _ = len;
}

/// Handle a trap at `site_addr` (the byte after the `0xCC`).
///
/// Returns the address to resume at, or `None` when the fault is not one of
/// ours — in which case the caller must fall back to its normal handling.
pub fn on_trap(site_addr: u64) -> Option<u64> {
    let idx = SITES
        .lock()
        .ok()?
        .binary_search_by(|s| {
            if site_addr < s.lo {
                std::cmp::Ordering::Greater
            } else if site_addr >= s.hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()?;
    let resume = SITES.lock().ok()?[idx].hi;
    FIRED[idx / 64].fetch_or(1u64 << (idx % 64), Ordering::Relaxed);
    Some(resume)
}

/// Every site that fired, as `(image, offset)`, sorted.
pub fn fired() -> Vec<(&'static str, u32)> {
    let Ok(v) = SITES.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, s) in v.iter().enumerate() {
        if FIRED[i / 64].load(Ordering::Relaxed) & (1u64 << (i % 64)) != 0 {
            out.push((s.image, s.off));
        }
    }
    out.sort_unstable();
    out
}

/// Total sites registered, for the coverage ratio in the report.
pub fn total() -> usize {
    SITES.lock().map(|v| v.len()).unwrap_or(0)
}
