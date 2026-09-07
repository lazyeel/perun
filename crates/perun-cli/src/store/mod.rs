// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! App Store client for the Perun CLI: login via MZFinance with 2FA,
//! search/lookup via the iTunes API, purchase, streaming download with
//! sinf replication, purchase history (DAAP), and version metadata —
//! all request bodies that Apple gates with the action signature signed
//! natively by the runtime's SAP session.
//!
//! Layout:
//! - `plist`   — XML + binary property lists (the store wire format)
//! - `json`    — the iTunes Search API's format
//! - `http`    — curl-backed client with a persistent cookie jar
//! - `bag`     — endpoint configuration from `init.itunes.apple.com`
//! - `signer`  — the SAP action signature over the native runtime
//! - `account` — session state + the encrypted on-disk store
//! - `appstore`— the operations themselves
//! - `ipa`     — zip replication, sinf injection, partial fetch
//! - `dmap`    — the DAAP purchase-history format
//!
//! 2FA note: on this login path Apple's second factor arrives out of
//! band (trusted-device push or SMS fallback) and the code is appended
//! to the password on the retry round. The interactive phone-SMS flow
//! of the GSA layer (selecting which trusted number receives the code)
//! does not exist on MZFinance — there are no GSA tokens here to drive
//! it; Apple sends to the default number on its own.

pub mod account;
pub mod appstore;
pub mod bag;
pub mod cli;
pub mod dmap;
pub mod http;
pub mod ipa;
pub mod json;
pub mod plist;
pub mod signer;
pub mod storefronts;

use std::path::PathBuf;

/// User-Agent the bag requires (Configurator; the exact build string the
/// reference tool sends).
pub const USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

/// The header the SAP signature rides in.
pub const HEADER_ACTION_SIGNATURE: &str = "X-Apple-ActionSignature";

/// Bag endpoint.
pub const BAG_URL: &str = "https://init.itunes.apple.com/bag.xml";

/// Per-user state directory: `$PERUN_STORE_DIR`, else `~/.local/state/perun/`
/// (XDG), holding the cookie jar and the encrypted account file.
pub fn state_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("PERUN_STORE_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
        return Ok(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = std::path::Path::new(&home)
        .join(".local")
        .join("state")
        .join("perun");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

/// The machine MAC as `AA:BB:CC:DD:EE:FF` (Store identity + file binding).
pub fn primary_mac() -> Result<[u8; 6], String> {
    read_first_mac()
}

fn read_first_mac() -> Result<[u8; 6], String> {
    // /sys/class/net: first interface with a non-empty address, loopback
    // excluded — mirrors the reference machine.MacAddress().
    let dir = std::path::Path::new("/sys/class/net");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("net interfaces: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        if name == "lo" {
            continue;
        }
        let addr_path = dir.join(&name).join("address");
        if let Ok(text) = std::fs::read_to_string(&addr_path) {
            let hex: Vec<&str> = text.trim().split(':').collect();
            if hex.len() == 6 && !hex.iter().all(|&h| h == "00") {
                let mut mac = [0u8; 6];
                for (i, part) in hex.iter().enumerate() {
                    mac[i] = u8::from_str_radix(part, 16).map_err(|_| "bad MAC")?;
                }
                return Ok(mac);
            }
        }
    }
    Err("no MAC address found".into())
}

/// MAC as lowercase colon-separated hex (the C++ fork's machine_id).
pub fn primary_mac_hex() -> Result<String, String> {
    let mac = primary_mac()?;
    Ok(mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Resolve the SAP assets (fetcher cache), shared with the bare
/// `perun sap` command.
pub fn ensure_sap_assets() -> Result<crate::sap::SapAssets, String> {
    let dir = crate::fetcher::ensure_cache(true)?;
    crate::sap::SapAssets::load_dir(&dir.display().to_string())
}
