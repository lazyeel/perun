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
///
/// Resolution order:
/// 1. a pinned MAC from `<state>/machine`, if the file exists;
/// 2. the first physical, up interface in `/sys/class/net` (a `device/`
///    symlink in sysfs — virtual links like veth/bridge/tun do not have
///    one; loopback and down links are skipped);
/// 3. a deterministic pseudo-MAC derived from a machine anchor
///    (`/etc/machine-id`, else the hostname): six bytes of SHA-256 with
///    the local bit set, so the address is well-formed regardless of
///    what the host looks like.
///
/// The first resolution is pinned to `<state>/machine`, so a change of
/// NIC, NIC order, or container network namespace cannot silently re-key
/// the encrypted account store or the Store identity Apple sees. The
/// `--mac` CLI flag overrides per-run and never rewrites the pin.
pub fn primary_mac() -> [u8; 6] {
    if let Some(mac) = pinned_mac() {
        return mac;
    }
    let mac = match hardware_mac() {
        Ok(m) => m,
        Err(e) => {
            // No physical interface (containers, minimal VMs). Derive a
            // stable address from the machine anchor instead of failing:
            // Store requests need *a* stable identity, not this exact one.
            eprintln!("[store] {e}; deriving a pseudo-MAC");
            pseudo_mac_from_anchor()
        }
    };
    pin_mac(&mac);
    mac
}

/// The pin file: `<state>/machine`, one MAC, lowercase colon hex.
fn pin_file() -> Result<PathBuf, String> {
    Ok(state_dir()?.join("machine"))
}

/// A colon-separated MAC as bytes, or a short message for the log line
/// when the value is malformed. Also the `--mac` flag parser.
pub fn parse_mac_text(text: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return Err("not a MAC address".into());
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err("not a MAC address".into());
        }
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| "not a MAC address")?;
    }
    Ok(mac)
}

/// The pinned MAC, if a pin file exists and parses.
fn pinned_mac() -> Option<[u8; 6]> {
    let path = match pin_file() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let text = std::fs::read_to_string(&path).ok()?;
    parse_mac_text(&text).ok()
}

/// Best-effort pin write; a read-only state dir must not break the run.
fn pin_mac(mac: &[u8; 6]) {
    if let Ok(path) = pin_file() {
        let text = mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        if let Err(e) = std::fs::write(&path, format!("{text}\n")) {
            eprintln!("[store] pin machine address: {e}");
        }
    }
}

/// MAC of the first physical, up, non-loopback interface.
fn hardware_mac() -> Result<[u8; 6], String> {
    hardware_mac_in(std::path::Path::new("/sys/class/net"))
}

/// The scan behind [`hardware_mac`], parameterized by the sysfs net root
/// so tests can drive it on a synthetic tree.
///
/// The `device` symlink is the physical discriminator: a NIC bound to
/// real hardware (or its driver) carries one, while veth pairs, bridges,
/// tunnels and taps do not. Down interfaces come and go with
/// rfkill/suspend; their MAC is not stable enough to key the account
/// store on. An all-zero address (some virtual and not-yet-provisioned
/// links) is not an identity either.
fn hardware_mac_in(dir: &std::path::Path) -> Result<[u8; 6], String> {
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
        let if_dir = dir.join(&name);
        // Physical check first: skip bridges, veth pairs, tunnels.
        if !if_dir.join("device").exists() {
            continue;
        }
        // Then the up check; an unparseable flags file is a skip, not an
        // abort — one broken interface must not hide the working ones.
        // sysfs writes flags as hex with an 0x prefix ("0x1003").
        match std::fs::read_to_string(if_dir.join("flags")) {
            Ok(text) => match u32::from_str_radix(text.trim().trim_start_matches("0x"), 16) {
                Ok(flags) if flags & 0x1 != 0 => {}
                _ => continue,
            },
            Err(_) => continue,
        }
        match std::fs::read_to_string(if_dir.join("address")).map(|t| parse_mac_text(&t)) {
            Ok(Ok(mac)) if mac != [0u8; 6] => return Ok(mac),
            _ => continue,
        }
    }
    Err("no physical network interface with a MAC address".into())
}

/// A deterministic pseudo-MAC from the machine anchor.
fn pseudo_mac_from_anchor() -> [u8; 6] {
    pseudo_mac_from(&machine_anchor())
}

/// The machine anchor: the systemd machine ID if the host has one, else
/// the hostname, else a constant — whatever survives, in that order.
fn machine_anchor() -> String {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if !id.is_empty() {
            return id.to_string();
        }
    }
    match std::env::var("HOSTNAME") {
        Ok(h) if !h.is_empty() => h,
        _ => "perun".into(),
    }
}

/// Six bytes of SHA-256(`perun-machine-v1:` + anchor) with the
/// locally-administered bit set and the multicast bit clear — a valid
/// unicast source address shape, stable for a given anchor.
fn pseudo_mac_from(anchor: &str) -> [u8; 6] {
    let material = format!("perun-machine-v1:{anchor}");
    let digest = account::Sha256::digest(material.as_bytes());
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&digest[..6]);
    mac[0] = (mac[0] | 0x02) & !0x01; // local bit set, multicast clear
    mac
}

/// MAC as lowercase colon-separated hex (the C++ fork's machine_id).
pub fn primary_mac_hex() -> String {
    let mac = primary_mac();
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Resolve the SAP assets (fetcher cache), shared with the bare
/// `perun sap` command.
pub fn ensure_sap_assets() -> Result<crate::sap::SapAssets, String> {
    let dir = crate::fetcher::ensure_cache(true)?;
    crate::sap::SapAssets::load_dir(&dir.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_N: AtomicUsize = AtomicUsize::new(0);

    /// Build a synthetic sysfs net root: each interface spec is
    /// (name, physical?, flags, address).
    fn synth_tree(specs: &[(&str, bool, &str, &str)]) -> std::path::PathBuf {
        let n = DIR_N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir()
            .join(format!("perun-mac-test-{}-{}", std::process::id(), n));
        for (name, physical, flags, addr) in specs {
            let if_dir = root.join(name);
            std::fs::create_dir_all(&if_dir).unwrap();
            std::fs::write(if_dir.join("flags"), flags).unwrap();
            std::fs::write(if_dir.join("address"), addr).unwrap();
            if *physical {
                std::fs::create_dir_all(if_dir.join("device")).unwrap();
            }
        }
        root
    }

    #[test]
    fn parse_mac_text_forms() {
        assert_eq!(
            parse_mac_text("4e:3b:02:20:13:a8").unwrap(),
            [0x4e, 0x3b, 0x02, 0x20, 0x13, 0xa8]
        );
        assert!(parse_mac_text("4e:3b:02:20:13").is_err()); // five parts
        assert!(parse_mac_text("zz:3b:02:20:13:a8").is_err()); // not hex
        assert!(parse_mac_text("4e3:3b:02:20:13:a8").is_err()); // 3 chars
        assert!(parse_mac_text("").is_err());
    }

    #[test]
    fn pseudo_mac_known_vector() {
        // SHA-256("perun-machine-v1:perun-test-anchor") starts 61 b6 fe
        // ec f3 15; bit 1 of the first byte is set (locally administered,
        // unicast) making it 62.
        assert_eq!(
            pseudo_mac_from("perun-test-anchor"),
            [0x62, 0xb6, 0xfe, 0xec, 0xf3, 0x15]
        );
    }

    #[test]
    fn pseudo_mac_bit_shape_and_stability() {
        for anchor in ["a", "some-hostname", "uuid-like-9147cbb0"] {
            let mac = pseudo_mac_from(anchor);
            assert_eq!(mac, pseudo_mac_from(anchor), "stable for one anchor");
            assert_eq!(mac[0] & 0x01, 0, "multicast bit clear");
            assert_eq!(mac[0] & 0x02, 2, "locally administered bit set");
            assert_ne!(mac, [0u8; 6]);
        }
        // Different anchors give different addresses (with overwhelming
        // probability; the test set is fixed so it cannot flake).
        assert_ne!(pseudo_mac_from("a"), pseudo_mac_from("b"));
    }

    #[test]
    fn hardware_scan_prefers_physical_up() {
        // A veth pair (up, valid MAC, no device link) must lose to the
        // physical NIC even when it sorts first — the container case.
        let tree = synth_tree(&[
            ("eth0", true, "0x1003", "aa:bb:cc:00:11:22\n"),
            ("lo", true, "0x9", "00:00:00:00:00:00\n"),
            ("veth1", false, "0x1003", "e2:48:61:a7:a1:4f\n"),
        ]);
        assert_eq!(
            hardware_mac_in(&tree).unwrap(),
            [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]
        );
    }

    #[test]
    fn hardware_scan_skips_down_and_zero() {
        let tree = synth_tree(&[
            ("eth0", true, "0x1002", "aa:bb:cc:00:11:22\n"), // physical, down
            ("eth1", true, "0x1003", "00:00:00:00:00:00\n"),  // physical, zero
            ("wlan0", true, "0x1003", "11:22:33:44:55:66\n"),
        ]);
        assert_eq!(
            hardware_mac_in(&tree).unwrap(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    #[test]
    fn hardware_scan_container_shape_is_err() {
        // Only virtual links: no hardware MAC exists.
        let tree = synth_tree(&[
            ("lo", true, "0x9", "00:00:00:00:00:00\n"),
            ("eth0", false, "0x1003", "e2:48:61:a7:a1:4f\n"),
        ]);
        assert!(hardware_mac_in(&tree).is_err());
    }

    #[test]
    fn hardware_scan_missing_root_is_err() {
        let tree = std::env::temp_dir().join("perun-mac-test-nonexistent-xyz");
        assert!(hardware_mac_in(&tree).is_err());
    }

    #[test]
    fn hardware_scan_deterministic_order() {
        // Two physical up NICs: the alphabetically first wins, stably.
        let tree = synth_tree(&[
            ("wlan0", true, "0x1003", "11:11:11:11:11:11\n"),
            ("eth0", true, "0x1003", "22:22:22:22:22:22\n"),
        ]);
        assert_eq!(
            hardware_mac_in(&tree).unwrap(),
            [0x22, 0x22, 0x22, 0x22, 0x22, 0x22]
        );
    }
}
