// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Memory/latency benchmark for the IPA replicator (research only; needs the
//! `rep-bench` feature, so it is never part of a normal build).
//!
//! `perun download` hides two costs in one number: the fetch and the
//! replicate. This runs `replicate()` alone against a package already on
//! disk, so the number it prints is the replicator's own.
//!
//! Usage: rep-bench <src> <dst> [--strategy window|stream] [--window MiB]

#![cfg(feature = "rep-bench")]

mod fetcher;
mod sap;
mod scaffold;
mod store;

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let src = args.get(1).cloned().expect("usage: rep-bench <src> <dst>");
    let dst = args.get(2).cloned().expect("usage: rep-bench <src> <dst>");

    let info = store::appstore::DownloadInfo {
        url: String::new(),
        sinfs: Vec::new(),
        metadata: store::plist::Plist::dict(),
        version: "0".into(),
        artwork_url: String::new(),
        artwork: None,
    };
    let account = store::account::Account::default();

    let before = std::time::Instant::now();
    let r = store::ipa::replicate(&src, &dst, &info, &account);
    let ms = before.elapsed().as_millis();
    match r {
        Ok(true) => println!("replicate ok, {ms} ms, out={}", fsize(&dst)),
        Ok(false) => println!("replicate reported no bundle, {ms} ms"),
        Err(e) => {
            println!("replicate FAILED after {ms} ms: {e}");
            std::process::exit(1);
        }
    }
}

fn fsize(p: &str) -> String {
    std::fs::metadata(p)
        .map(|m| m.len().to_string())
        .unwrap_or_default()
}

/// Keeps the unused-import checker honest about the module tree.
#[allow(dead_code)]
fn _unused(_: &Instant) {}
