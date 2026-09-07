// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The bag-driven SAP action signer: drives the native `SapRuntime`
//! (CommerceKit guest mapped into this process) through the setup rounds
//! using the endpoints from the live bag, then signs request bodies into
//! `X-Apple-ActionSignature`.

use super::bag::SAPConfig;
use super::http::{self, Request};
use super::plist::{self, Plist};
use crate::sap::SapRuntime;

/// A live SAP signing session. Must live on the dedicated 256 MiB thread
/// the CLI spawns for SAP work (see `main.rs::cmd_sap`); keep instances in
/// that thread only.
pub struct Signer {
    runtime: SapRuntime,
    /// The hardware identity this session signs under (diagnostics).
    #[allow(dead_code)]
    mac: [u8; 6],
}

impl Signer {
    /// Full setup: assets → init → cert exchange → setup exchange.
    /// `mac` seeds the FairPlay hardware identity (6 bytes).
    pub fn new(config: &SAPConfig, mac: [u8; 6]) -> Result<Signer, String> {
        let assets = super::ensure_sap_assets()?;
        let mut runtime = SapRuntime::new(&assets).map_err(|e| format!("SAP runtime: {e}"))?;
        runtime.init(mac).map_err(|e| format!("SAPInit: {e}"))?;

        // Certificate: the bag endpoint serves a plist envelope, not raw DER
        // (unlike the legacy CDN path the bare `perun sap` command uses).
        let cert_res = http::send(Request::new("GET", &config.certificate_url))?;
        if cert_res.status != 200 {
            return Err(format!("setupCert: HTTP {}", cert_res.status));
        }
        let cert_doc =
            plist::parse_xml(&cert_res.body).map_err(|e| format!("setupCert parse: {e}"))?;
        let cert = cert_doc
            .get("sign-sap-setup-cert")
            .and_then(|v| v.as_data())
            .ok_or("setupCert: missing sign-sap-setup-cert data")?
            .to_vec();
        if cert.len() < 64 {
            return Err(format!("setupCert suspiciously short: {}", cert.len()));
        }

        let (req1, st1) = runtime
            .exchange(config.version as u64, mac, &cert)
            .map_err(|e| format!("exchange(cert): {e}"))?;
        if st1 != 1 {
            return Err(format!("exchange(cert) state {st1} != 1"));
        }

        let reply = post_setup_buffer(&config.setup_url, &req1)?;
        let (_req2, st2) = runtime
            .exchange(config.version as u64, mac, &reply)
            .map_err(|e| format!("exchange(setup): {e}"))?;
        if st2 != 0 {
            return Err(format!("exchange(setup) state {st2} != 0"));
        }

        Ok(Signer { runtime, mac })
    }

    /// Sign a request body — the 501-byte action signature, base64 for the
    /// header. Consumes no guest state besides the session keys.
    pub fn sign(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        self.runtime.sign(body).map_err(|e| format!("SAPSign: {e}"))
    }

    /// Sign and produce the header pair, ready to attach.
    pub fn sign_header(&mut self, body: &[u8]) -> Result<(String, String), String> {
        let sig = self.sign(body)?;
        Ok((
            super::HEADER_ACTION_SIGNATURE.to_string(),
            plist::base64_encode(&sig),
        ))
    }

    /// The MAC the session is bound to.
    #[allow(dead_code)]
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

/// POST the round-1 exchange buffer and unwrap the reply buffer.
fn post_setup_buffer(url: &str, buffer: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload = Plist::dict();
    payload.set("sign-sap-setup-buffer", Plist::Data(buffer.to_vec()));
    let res = http::send(
        Request::new("POST", url)
            .header("Content-Type", "application/x-plist")
            .plist_body(plist::to_xml(&payload).into_bytes()),
    )?;
    if res.status != 200 {
        let snippet = String::from_utf8_lossy(&res.body)
            .chars()
            .take(200)
            .collect::<String>();
        return Err(format!("signSapSetup: HTTP {}: {}", res.status, snippet));
    }
    let doc = plist::parse_xml(&res.body).map_err(|e| format!("signSapSetup parse: {e}"))?;
    doc.get("sign-sap-setup-buffer")
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec())
        .ok_or_else(|| "signSapSetup: missing reply buffer".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_buffer_plist_roundtrip() {
        let mut payload = Plist::dict();
        payload.set("sign-sap-setup-buffer", Plist::Data(vec![0xAB, 0xCD]));
        let xml = plist::to_xml(&payload);
        assert!(xml.contains("sign-sap-setup-buffer"));
        let parsed = plist::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(
            parsed.get("sign-sap-setup-buffer").unwrap().as_data(),
            Some(&[0xAB, 0xCD][..])
        );
    }
}
