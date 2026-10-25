// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! THE LIVE-NET RUNNER: the crate's CPIM against Apple's GSA backend.
//!
//! The cycle mirrors the measured stand client exactly (the C client's
//! own protocol, headers and bodies -- adi_test.c is the reference):
//!
//!   1. GET  https://gsa.apple.com/grandslam/GsService2/lookup
//!      -> the URL bag (midStartProvisioning / midFinishProvisioning)
//!   2. POST start  (empty plist request)   -> the SPIM (347 bytes, b64)
//!   3. THE CRATE:  generate_cpim(&SessionInputs) -> the 276-byte CPIM
//!      (the inject layer feeds the session inputs; the CPIM itself is
//!      the crate's own container math, byte for byte the oracle's)
//!   4. POST finish (cpim in the plist)     -> ptm / tk / routing info
//!
//! The honest gate: the CPIM is bound to the SPIM the oracle measured.
//! If the fresh start returns the SAME SPIM, the crate's answer is
//! THE answer and the server must take it (ec, ptm, tk). If the SPIM
//! is fresh, the genesis frontier (the planter expand) is the named
//! blocker -- the runner reports the fact and saves the new SPIM for
//! the capture workflow instead of lying.
//!
//! Environment: PERUN_LIVE_DIR (default /opt/data/adi-re) -- the
//! capture directory of the reference pair.

use perun_adi_core::body_a::{generate_cpim, SessionInputs};

const UUID: &str = "1A7DC030-8887-C2D8-F470-E2EA813C70C1";
const MD_LU: &str = "C0308887C2D8F470";
const UA: &str = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";
const CLIENT_INFO: &str =
    "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
const PLIST_HEAD: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"",
    " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    "<plist version=\"1.0\"><dict>"
);
const PLIST_TAIL: &str = "</dict></plist>\n";

/// Minimal base64 (standard alphabet, no padding handling beyond '=').
fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| T.iter().position(|&t| t == c).unwrap_or(0) as u32;
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && c != b'\n').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let n = chunk.iter().fold(0u32, |a, &c| (a << 6) | val(c))
            << (6 * (4 - chunk.len()) as u32);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    out
}

/// The C client's xml_string_after_key: the string right after
/// `<key>key</key><string>` up to `</string>`.
fn string_after_key(xml: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let i = xml.find(&needle)? + needle.len();
    // Apple's bag puts whitespace/newlines between the key and the value.
    let rest = &xml[i..];
    let vs = rest.find("<string>")? + "<string>".len();
    let ve = rest.find("</string>")?;
    Some(rest[vs..ve].trim().to_string())
}

fn agent() -> ureq::Agent {
    // The Apple chain is pinned (the measured stand's own CA strategy:
    // the system store carries no Apple roots on this host). The chain
    // lives with the capture workflow; ureq gets an explicit root store.
    let chain_path = std::env::var("APPLE_CHAIN")
        .unwrap_or_else(|_| "/opt/data/perun/crates/perun-cli/examples/adi-android/apple_chain.pem".into());
    let pem = std::fs::read(&chain_path).expect("read the Apple chain pem");
    let mut roots = rustls::RootCertStore::empty();
    let mut rd = pem.as_slice();
    for cert in rustls_pemfile::certs(&mut rd).flatten() {
        roots.add(cert).expect("add root cert");
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .user_agent(UA)
        .tls_config(std::sync::Arc::new(cfg))
        .build()
}

fn main() {
    let dir = std::env::var("PERUN_LIVE_DIR").unwrap_or_else(|_| "/opt/data/adi-re".into());
    // ureq's default rustls build leaves the CryptoProvider unset.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let a = agent();

    // 1. The URL bag.
    println!("[net] GET lookup ...");
    let lookup = a.get("https://gsa.apple.com/grandslam/GsService2/lookup")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("X-Mme-Device-Id", UUID)
        .set("X-MMe-Client-Info", CLIENT_INFO)
        .set("X-Apple-I-MD-LU", MD_LU)
        .set("X-Apple-Client-App-Name", "Setup")
        .call()
        .expect("lookup call");
    let lookup_xml = lookup.into_string().expect("lookup body");
    println!("[net] lookup: {} bytes", lookup_xml.len());
    let u_start = string_after_key(&lookup_xml, "midStartProvisioning").expect("start url");
    let u_fin = string_after_key(&lookup_xml, "midFinishProvisioning").expect("finish url");
    println!("[net] start={u_start}");
    println!("[net] finish={u_fin}");

    // 2. The fresh SPIM.
    let body = format!("{PLIST_HEAD}<key>Header</key><dict/><key>Request</key><dict/>{PLIST_TAIL}");
    println!("[net] POST start ...");
    let r1 = a.post(&u_start)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("X-Mme-Device-Id", UUID)
        .set("X-MMe-Client-Info", CLIENT_INFO)
        .set("X-Apple-I-MD-LU", MD_LU)
        .set("X-Apple-Client-App-Name", "Setup")
        .send_string(&body)
        .expect("start call");
    let r1_xml = r1.into_string().expect("start body");
    let spim_b64 = string_after_key(&r1_xml, "spim").expect("spim in start response");
    let spim = b64_decode(&spim_b64);
    println!("[net] spim received ({} bytes decoded)", spim.len());
    std::fs::write(format!("{dir}/fresh_spim_live.bin"), &spim).expect("save fresh spim");

    // 3. THE CRATE: the CPIM over the session inputs.
    let inputs = SessionInputs::from_tapes(&dir).expect("the measured inject layer");
    if spim != inputs.spim {
        println!("[verdict] FRESH SPIM: the oracle rotated the challenge ({} bytes).", spim.len());
        println!("[verdict] The crate's CPIM is bound to the reference session's SPIM;");
        println!("[verdict] the planter expand (the genesis frontier) is the named blocker");
        println!("[verdict] for answering a fresh challenge autonomously.");
        println!("[verdict] The fresh SPIM is saved: {dir}/fresh_spim_live.bin");
        return;
    }
    println!("[net] spim MATCHES the reference pair -- the crate's CPIM is THE answer");
    let cpim = generate_cpim(&inputs);
    println!("[prov] cpim ready ({} bytes, crate-generated)", cpim.len());

    // 4. finishMachineProvisioning with the crate's CPIM.
    let cpim_b64 = b64_encode(&cpim);
    let body2 = format!(
        "{PLIST_HEAD}<key>Header</key><dict/>\
         <key>Request</key><dict><key>cpim</key><string>{cpim_b64}</string></dict>{PLIST_TAIL}"
    );
    println!("[net] POST finish ...");
    let r2 = a.post(&u_fin)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("X-Mme-Device-Id", UUID)
        .set("X-MMe-Client-Info", CLIENT_INFO)
        .set("X-Apple-I-MD-LU", MD_LU)
        .set("X-Apple-Client-App-Name", "Setup")
        .send_string(&body2)
        .expect("finish call");
    let r2_xml = r2.into_string().expect("finish body");
    println!("[net] finish response ({} bytes)", r2_xml.len());
    let ptm = string_after_key(&r2_xml, "ptm");
    let tk = string_after_key(&r2_xml, "tk");
    let rinfo = string_after_key(&r2_xml, "X-Apple-I-MD-RINFO");
    println!("[verdict] ptm: {}", ptm.as_deref().map(|s| if s.len() > 48 { format!("{}... ({} bytes)", &s[..48], s.len()) } else { s.to_string() }).unwrap_or_else(|| "NONE".into()));
    println!("[verdict] tk:  {}", tk.as_deref().map(|s| if s.len() > 48 { format!("{}... ({} bytes)", &s[..48], s.len()) } else { s.to_string() }).unwrap_or_else(|| "NONE".into()));
    println!("[verdict] routing info: {}", rinfo.as_deref().unwrap_or("(none)"));
    if ptm.is_some() && tk.is_some() {
        println!("[verdict] *** THE CRATE'S CPIM WAS ACCEPTED BY THE LIVE BACKEND ***");
    } else {
        println!("[verdict] no ptm/tk -- dumping the response head:");
        println!("{}", &r2_xml[..r2_xml.len().min(600)]);
    }
}
