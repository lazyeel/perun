// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The anonymous GSA half of Anisette v3, over `ureq`.
//!
//! This is the network work a real client does itself: Anisette is anonymous
//! machine attestation, so nothing here takes a credential. The library
//! (`CoreADI64.dll`) has no networking imports at all -- KERNEL32, ADVAPI32,
//! SHELL32, SHLWAPI, 103 symbols -- so the round trip has to come from the
//! host, exactly as the Android harness does it with libcurl.
//!
//! The sequence, all of it measured against the live service:
//!
//! 1. `GET  GsService2/lookup`        -> 200, the two MidService URLs
//! 2. `POST startMachineProvisioning`  -> `ec: 0`, a `spim` and a `ptxid`
//! 3. the guest turns the SPIM into a CPIM (see [`crate::adi`])
//! 4. `POST finishMachineProvisioning` -> `ec: 0`, a `ptm` and a `tk`
//!
//! Step 1 is where the chicken-and-egg breaks: the endpoint that hands out the
//! SPIM demands the same Anisette headers the SPIM is used to produce.
//! `X-Apple-I-MD-LU` is not a token -- it is 8 random bytes as 16 uppercase
//! hex with an `X` prefix -- so it can be minted locally before any SPIM
//! exists. Without that header the same URL answers 401.

use std::io::Read as _;
use std::time::Duration;

use perun_shims::machine_id::{collect_linux, modern_id};

/// The lookup service. Its answer carries the provisioning endpoints, so it is
/// fetched rather than hardcoded -- the URLs are configuration from Apple's
/// side and can move.
const LOOKUP: &str = "https://gsa.apple.com/grandslam/GsService2/lookup";

/// AuthKit's own user agent. GSA keys off it.
const UA: &str = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";

/// Client info as AuthKit on Windows sends it. The `<MacBookPro…>` shape the
/// Android harness uses is not what a Windows client presents.
const CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/7.21)>";

const APP_NAME: &str = "iCloud";

/// Routing information Apple returns for this machine class.
const RINFO: &str = "171061";

/// The empty body both provisioning endpoints accept: `Header` and `Request`
/// as empty dicts. GSService answers with XML, whatever the content type says.
const EMPTY_PLIST: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    "<plist version=\"1.0\"><dict>",
    "<key>Header</key><dict/>",
    "<key>Request</key><dict/>",
    "</dict></plist>"
);

/// A client-info string for the host, and the machine identity GSA keys on.
#[derive(Clone, Debug)]
pub struct Identity {
    /// `X-Mme-Device-Id`: the seven hashed components, dotted and upper-case.
    pub device_id: String,
    /// `X-Apple-I-MD-LU`: locally mintable, so first contact is possible.
    pub lu: String,
}

/// Collect this host's Anisette identity.
///
/// `X-Mme-Device-Id` comes from `machine_id`, which implements Blackwood's
/// formula (seven MD5s, first 32 bits each, upper-case hex, dot-joined).
/// `X-Apple-I-MD-LU` is 8 fresh random bytes rendered as 16 upper-case hex
/// with an `X` prefix -- not a token, so it needs no prior provisioning.
pub fn identity() -> Identity {
    let inputs = collect_linux();
    let device_id = modern_id(&inputs);
    let mut lu = String::from("X");
    let mut f = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            let mut b = [0u8; 8];
            f.read_exact(&mut b)?;
            Ok(b)
        })
        .unwrap_or_else(|_| {
            // No /dev/urandom: fall back to the clock. The value only has to
            // be unique enough for one bootstrap round, never a secret.
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0x9E37_79B9_7F4A_7C15);
            n.to_be_bytes()
        });
    for b in &mut f {
        lu.push_str(&format!("{b:02X}"));
    }
    Identity {
        device_id: device_id.to_uppercase().to_string(),
        lu,
    }
}

impl Identity {
    fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("User-Agent".into(), UA.into()),
            ("X-Mme-Device-Id".into(), self.device_id.clone()),
            ("X-Mme-Client-Info".into(), CLIENT_INFO.into()),
            ("X-Apple-I-MD-LU".into(), self.lu.clone()),
            ("X-Apple-Client-App-Name".into(), APP_NAME.into()),
            ("X-Apple-I-SRL-NO".into(), "0".into()),
        ]
    }
}

/// The two provisioning endpoints, as the lookup service named them.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub start: String,
    pub finish: String,
}

/// What `startMachineProvisioning` returns.
#[derive(Clone, Debug)]
pub struct Start {
    /// The server SPIM, base64-decoded.
    pub spim: Vec<u8>,
    /// Provisioning transaction id, echoed back at the finish step.
    pub ptxid: String,
}

/// What `finishMachineProvisioning` returns.
#[derive(Clone, Debug)]
pub struct Finish {
    pub ptm: Vec<u8>,
    pub tk: Vec<u8>,
    pub rinfo: String,
}

/// A rustls agent that trusts the roots this host has.
///
/// Apple Root CA is not in the container's bundle, and `rustls` has no
/// "ignore" knob that would be honest here, so the chain the server actually
/// presented is pinned instead. That is a real trust decision, not a
/// verification bypass: `cert_chain` is checked against the pinned roots on
/// every connection. Set `PERUN_GSA_CA` to a PEM bundle to use the system
/// store instead.
fn agent() -> Result<ureq::Agent, String> {
    let roots = match std::env::var_os("PERUN_GSA_CA") {
        Some(path) => {
            let pem =
                std::fs::read(&path).map_err(|e| format!("{}: {e}", path.to_string_lossy()))?;
            parse_roots(&pem)?
        }
        // Apple's Root CA is not in this container's bundle, and rustls has
        // no "ignore" switch that would be honest, so the chain the server
        // actually presents is pinned and verification stays ON. Obtain it
        // with: openssl s_client -connect gsa.apple.com:443 -showcerts
        // (chain 1 = leaf, 2 = intermediate, 3 = Apple Root CA). The leaf is
        // verified against the intermediate and the root is the anchor.
        None => {
            const INTERMEDIATE: &[u8] = include_bytes!("../../../assets/gsa_intermediate.pem");
            const ROOT: &[u8] = include_bytes!("../../../assets/gsa_root.pem");
            let mut pem = Vec::with_capacity(INTERMEDIATE.len() + ROOT.len());
            pem.extend_from_slice(INTERMEDIATE);
            pem.extend_from_slice(ROOT);
            parse_roots(&pem)?
        }
    };
    // The roots are known now, so the agent can be built with them. They come
    // first because `tls_config` takes the config by value and returns the
    // Agent, so the two calls cannot be split.
    let builder = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build());
    Ok(builder.build().into())
}

/// Turn PEM bytes into the root set rustls verifies against.
fn parse_roots(pem: &[u8]) -> Result<ureq::tls::RootCerts, String> {
    // Only certificates are wanted; a bundle may also carry a key.
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("gsa CA: {e}"))?;
    if certs.is_empty() {
        return Err("gsa CA: no certificate parsed".into());
    }
    Ok(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certs)))
}

/// GET the lookup bag and pull out the two provisioning URLs.
pub fn lookup(id: &Identity) -> Result<Endpoints, String> {
    let a = agent()?;
    let mut r = a.get(LOOKUP);
    for (k, v) in id.headers() {
        r = r.header(&k, &v);
    }
    let mut resp = r.call().map_err(|e| format!("lookup: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("lookup: HTTP {}", resp.status()));
    }
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("lookup body: {e}"))?;
    Ok(Endpoints {
        start: xml_value(&body, "midStartProvisioning").ok_or("lookup: no midStartProvisioning")?,
        finish: xml_value(&body, "midFinishProvisioning")
            .ok_or("lookup: no midFinishProvisioning")?,
    })
}

/// POST the empty provisioning body and return the SPIM and ptxid.
pub fn start_provisioning(id: &Identity, ep: &Endpoints) -> Result<Start, String> {
    let a = agent()?;
    let mut r = a.post(&ep.start);
    for (k, v) in id.headers() {
        r = r.header(&k, &v);
    }
    let mut resp = r.send(EMPTY_PLIST).map_err(|e| format!("start: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("start: HTTP {}", resp.status()));
    }
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("start body: {e}"))?;
    let ec = xml_value(&body, "ec").unwrap_or_default();
    if !ec.is_empty() && ec != "0" {
        return Err(format!("start: ec={ec}"));
    }
    let spim_b64 = xml_value(&body, "spim").ok_or("start: no spim")?;
    let ptxid = xml_value(&body, "ptxid").ok_or("start: no ptxid")?;
    Ok(Start {
        spim: b64_decode(&spim_b64)?,
        ptxid,
    })
}

/// POST the cpim and ptxid, returning ptm, tk and the routing info.
pub fn finish_provisioning(
    id: &Identity,
    ep: &Endpoints,
    cpim: &[u8],
    ptxid: &str,
) -> Result<Finish, String> {
    let a = agent()?;
    let mut r = a.post(&ep.finish);
    for (k, v) in id.headers() {
        r = r.header(&k, &v);
    }
    // The body is a plist whose Request carries the cpim we produced, keyed by
    // the transaction id the start step handed us.
    let body = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\"><dict>",
            "<key>Header</key><dict/>",
            "<key>Request</key><dict>",
            "<key>ptxid</key><string>{}</string>",
            "<key>cpim</key><string>{}</string>",
            "</dict></dict></plist>"
        ),
        ptxid,
        b64_encode(cpim)
    );
    let mut resp = r.send(body.as_str()).map_err(|e| format!("finish: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("finish: HTTP {}", resp.status()));
    }
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("finish body: {e}"))?;
    let ec = xml_value(&text, "ec").unwrap_or_default();
    if !ec.is_empty() && ec != "0" {
        return Err(format!("finish: ec={ec}"));
    }
    // The raw body is the outside oracle: whatever the offline chain
    // produced, the server's answer names the binding it wants. Log it
    // (bounded) before parsing, so an ec=0-with-no-ptm answer is as
    // readable as a rejection.
    eprintln!(
        "[gsa] finish body ({} bytes): {}",
        text.len(),
        &text[..text.len().min(2048)]
    );
    let ptm = b64_decode(&xml_value(&text, "ptm").ok_or("finish: no ptm")?)?;
    let tk = b64_decode(&xml_value(&text, "tk").ok_or("finish: no tk")?)?;
    Ok(Finish {
        ptm,
        tk,
        rinfo: xml_value(&text, "X-Apple-I-MD-RINFO").unwrap_or_else(|| RINFO.into()),
    })
}

/// The `<key>k</key><string>v</string>` that follows `k` in a plist.
///
/// GSService answers in XML even when the request says form-urlencoded, so
/// this is the shape to read, not a plist parser.
fn xml_value(xml: &str, key: &str) -> Option<String> {
    let pat = format!("<key>{key}</key>");
    let i = xml.find(&pat)? + pat.len();
    let rest = &xml[i..];
    let s = rest.find("<string>")? + "<string>".len();
    let e = rest[s..].find("</string>")? + s;
    Some(rest[s..e].to_string())
}

/// Base64 without a new dependency; the alphabet is the standard one.
fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut rev = [255u8; 256];
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i, c) in T.iter().enumerate() {
        rev[*c as usize] = i as u8;
    }
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let v = rev[c as usize];
        if v == 255 {
            return Err(format!("base64: bad byte {c:#x}"));
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Format the header block `perun adi headers` prints.
pub fn header_block(
    id: &Identity,
    mid: &[u8],
    otp: &[u8],
    rinfo: &str,
    client_time: &str,
    tz: &str,
) -> String {
    let mut s = String::new();
    s.push_str(&format!("X-Apple-I-MD: {}\n", b64_encode(otp)));
    s.push_str(&format!("X-Apple-I-MD-M: {}\n", b64_encode(mid)));
    s.push_str(&format!("X-Apple-I-MD-RINFO: {rinfo}\n"));
    s.push_str(&format!("X-Apple-I-MD-LU: {}\n", id.lu));
    s.push_str("X-Apple-I-SRL-NO: 0\n");
    s.push_str(&format!("X-Apple-I-Client-Time: {client_time}\n"));
    s.push_str(&format!("X-Apple-I-TimeZone: {tz}"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for n in 0..64usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let e = b64_encode(&data);
            assert_eq!(b64_decode(&e).ok().unwrap(), data, "n={n}");
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn xml_value_reads_a_string_after_a_key() {
        let x = "<dict><key>ec</key><integer>0</integer>\
                  <key>ptxid</key><string>abc-123</string></dict>";
        assert_eq!(xml_value(x, "ptxid").as_deref(), Some("abc-123"));
        assert_eq!(xml_value(x, "nope"), None);
    }

    #[test]
    fn identity_lu_is_the_documented_shape() {
        let id = identity();
        // `X` plus 16 upper-case hex digits.
        assert_eq!(id.lu.len(), 17, "{}", id.lu);
        assert!(id.lu.starts_with('X'), "{}", id.lu);
        assert!(
            id.lu[1..].chars().all(|c| c.is_ascii_hexdigit()),
            "{}",
            id.lu
        );
        // Seven dotted 8-hex components.
        assert_eq!(id.device_id.split('.').count(), 7, "{}", id.device_id);
    }

    #[test]
    fn header_block_has_the_seven_headers_in_order() {
        let id = Identity {
            device_id: "A".repeat(63),
            lu: "X0123456789ABCDEF".into(),
        };
        let s = header_block(
            &id,
            &[1, 2, 3],
            &[4, 5],
            "171061",
            "2026-10-03T00:00:00Z",
            "UTC",
        );
        let keys: Vec<&str> = s.lines().map(|l| l.split(':').next().unwrap()).collect();
        assert_eq!(
            keys,
            vec![
                "X-Apple-I-MD",
                "X-Apple-I-MD-M",
                "X-Apple-I-MD-RINFO",
                "X-Apple-I-MD-LU",
                "X-Apple-I-SRL-NO",
                "X-Apple-I-Client-Time",
                "X-Apple-I-TimeZone",
            ]
        );
    }
}
