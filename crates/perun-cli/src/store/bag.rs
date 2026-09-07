// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The Store bag: endpoint configuration served by `init.itunes.apple.com`.
//! The bag is what makes the SAP signer bag-driven — the URLs and version
//! come from Apple, not from constants (only the fallback defaults do).

use super::BAG_URL;
use super::http::{self, Request};
use super::plist;

/// SAP endpoints + the login URL, as advertised by the bag.
#[derive(Clone, Debug)]
pub struct SAPConfig {
    pub auth_endpoint: String,
    pub setup_url: String,
    pub certificate_url: String,
    pub version: u32,
}

#[derive(Clone, Debug)]
pub struct Bag {
    pub sap: SAPConfig,
}

impl Bag {
    /// Fetch and validate the live bag.
    pub fn fetch(guid: &str) -> Result<Bag, String> {
        let url = format!("{BAG_URL}?guid={guid}");
        let res = http::send(Request::new("GET", &url).header("Accept", "application/xml"))?;
        if res.status != 200 {
            return Err(format!("bag: HTTP {}", res.status));
        }
        let doc = plist::parse_xml(&res.body)
            .map_err(|e| format!("bag parse: {e} (status {})", res.status))?;
        // The SAP endpoints live inside the `urlBag` sub-dict (same shape
        // the reference tool decodes via its bagResult.URLBag).
        let bag = doc.get("urlBag").ok_or("bag: missing urlBag")?;
        let auth = bag
            .get("authenticateAccount")
            .and_then(|v| v.as_str())
            .ok_or("bag: missing authenticateAccount")?
            .to_string();
        let setup = bag
            .get("sign-sap-setup")
            .and_then(|v| v.as_str())
            .ok_or("bag: missing sign-sap-setup")?
            .to_string();
        let cert = bag
            .get("sign-sap-setup-cert")
            .and_then(|v| v.as_str())
            .ok_or("bag: missing sign-sap-setup-cert")?
            .to_string();
        let version = bag
            .get("sign-sap-version")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or("bag: missing/invalid sign-sap-version")?;
        if version != 200 {
            return Err(format!("bag: unsupported SAP version {version}"));
        }
        for (label, url) in [
            ("authenticateAccount", &auth),
            ("sign-sap-setup", &setup),
            ("sign-sap-setup-cert", &cert),
        ] {
            if !url.starts_with("https://") {
                return Err(format!("bag: {label} is not HTTPS: {url}"));
            }
        }
        Ok(Bag {
            sap: SAPConfig {
                auth_endpoint: auth,
                setup_url: setup,
                certificate_url: cert,
                version,
            },
        })
    }
}

impl Bag {
    /// Test helper: parse the SAP config out of an already-parsed bag dict
    /// using the same key layout as `fetch`.
    #[cfg(test)]
    fn from_plist_for_test(doc: &plist::Plist) -> Bag {
        let bag = doc.get("urlBag").expect("urlBag");
        let get = |k: &str| {
            bag.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        Bag {
            sap: SAPConfig {
                auth_endpoint: get("authenticateAccount"),
                setup_url: get("sign-sap-setup"),
                certificate_url: get("sign-sap-setup-cert"),
                version: get("sign-sap-version").parse().unwrap_or(0),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bag_fields_present_in_fixture() {
        // Shape check against the structure observed live (2026-09-04):
        // the SAP keys sit inside the urlBag sub-dict.
        let fixture = br#"<?xml version="1.0"?><Document><Protocol><plist version="1.0"><dict>
<key>some-top-level</key><string>noise</string>
<key>urlBag</key><dict>
<key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string>
<key>sign-sap-setup</key><string>https://fpinit.itunes.apple.com/v1/signSapSetup/legacy</string>
<key>sign-sap-setup-cert</key><string>https://s.mzstatic.com/sap/setupCert.plist</string>
<key>sign-sap-version</key><string>200</string>
</dict></dict></plist></Protocol></Document>"#;
        let doc = plist::parse_xml(fixture).unwrap();
        let bag = Bag::from_plist_for_test(&doc);
        assert_eq!(bag.sap.version, 200);
        assert!(bag.sap.auth_endpoint.contains("MZFinance"));
        assert!(bag.sap.setup_url.contains("signSapSetup"));
    }
}
