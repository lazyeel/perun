// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Live check: does the crate produce real tokens?
//!
//! `cargo test` cannot answer that — its tests are all pure — so this binary
//! calls the public API against the stand that is actually installed and prints
//! what came back. It exits non-zero if no headers appear.

fn main() {
    match perun_adi_bionic::generate_headers() {
        Ok(h) => {
            println!("X-Apple-I-MD:   {}", h.md);
            println!("X-Apple-I-MD-M: {}", h.mdm);
        }
        Err(e) => {
            eprintln!("adi-bionic: {e}");
            std::process::exit(1);
        }
    }
}
