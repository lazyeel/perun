// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! DAAP/DMAP: the tagged binary format of the purchase-history service.

use super::account::Account;
use super::appstore::App;

/// Walk the DMAP tree, depth-limited, invoking `visit(tag, payload)` on
/// every tag. Container tags recurse.
/// DMAP visitor: `(tag, payload) -> Result`.
type DmapVisit<'a> = dyn FnMut(&str, &[u8]) -> Result<(), String> + 'a;

fn walk_dmap(data: &[u8], depth: usize, visit: &mut DmapVisit) -> Result<(), String> {
    if depth > 16 {
        return Err("DMAP nesting is too deep".into());
    }
    let mut offset = 0usize;
    while offset < data.len() {
        if data.len() - offset < 8 {
            return Err(format!("truncated DMAP tag header at byte {offset}"));
        }
        let tag_bytes = &data[offset..offset + 4];
        if !tag_bytes.iter().all(|&c| (0x20..=0x7e).contains(&c)) {
            return Err(format!("invalid DMAP tag at byte {offset}"));
        }
        let tag = std::str::from_utf8(tag_bytes).unwrap().to_string();
        let length = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if length > data.len() - offset - 8 {
            return Err(format!(
                "DMAP tag {tag} length {length} exceeds remaining response"
            ));
        }
        let end = offset + 8 + length;
        let payload = &data[offset + 8..end];
        visit(&tag, payload)?;
        if is_container(&tag) {
            walk_dmap(payload, depth + 1, visit)?;
        }
        offset = end;
    }
    Ok(())
}

fn is_container(tag: &str) -> bool {
    matches!(
        tag,
        "adbs"
            | "adsr"
            | "aply"
            | "avdb"
            | "mbcl"
            | "mccr"
            | "mcty"
            | "mdcl"
            | "mlcl"
            | "mlit"
            | "mlog"
            | "msrv"
            | "mupd"
    )
}

/// First `tag` whose payload is a 4- or 8-byte big-endian integer.
pub fn first_uint(data: &[u8], tag: &str) -> Option<u64> {
    let mut found: Option<u64> = None;
    let _ = walk_dmap(data, 0, &mut |t, payload| {
        if found.is_none() && t == tag {
            match payload.len() {
                4 => found = Some(u32::from_be_bytes(payload.try_into().unwrap()) as u64),
                8 => found = Some(u64::from_be_bytes(payload.try_into().unwrap())),
                _ => return Err("bad integer length".into()),
            }
        }
        Ok(())
    });
    found
}

/// DAAP status check: `mstt` == 200, else map 401/403 to expired session.
pub fn status_ok(data: &[u8], label: &str) -> Result<(), String> {
    if let Some(status) = first_uint(data, "mstt") {
        if status == 401 || status == 403 {
            return Err(format!(
                "{label}: session expired (DAAP status {status}) — run 'auth login' again"
            ));
        }
        if status != 200 {
            return Err(format!("{label}: DAAP status {status}"));
        }
    }
    Ok(())
}

/// Parse the `mlit` listing into apps (id/bundle/name/version/date).
pub fn parse_owned_apps(data: &[u8]) -> Vec<App> {
    let mut apps: Vec<App> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let _ = walk_dmap(data, 0, &mut |tag, payload| {
        if tag != "mlit" {
            return Ok(());
        }
        let mut app = App::default();
        walk_dmap(payload, 0, &mut |t, body| {
            match t {
                "aeSI" => app.id = read_int(body).unwrap_or(0),
                "aeBI" => app.bundle_id = String::from_utf8_lossy(body).into_owned(),
                "aeLN" => app.name = String::from_utf8_lossy(body).into_owned(),
                "minm" => {
                    if app.name.is_empty() {
                        app.name = String::from_utf8_lossy(body).into_owned();
                    }
                }
                "aePd" => app.version = String::from_utf8_lossy(body).into_owned(),
                "asdp" if body.len() == 4 => {
                    let secs = u32::from_be_bytes(body.try_into().unwrap()) as i64;
                    app.purchase_date = Some(unix_to_iso8601(secs));
                }
                _ => {}
            }
            Ok(())
        })?;
        if app.id != 0 && seen.insert(app.id) {
            apps.push(app);
        }
        Ok(())
    });
    apps
}

fn read_int(payload: &[u8]) -> Option<i64> {
    match payload.len() {
        4 => Some(u32::from_be_bytes(payload.try_into().ok()?) as i64),
        8 => Some(i64::from_be_bytes(payload.try_into().ok()?)),
        _ => None,
    }
}

fn unix_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Headers shared by the DAAP requests (the login one adds nothing more).
pub fn daap_headers(account: &Account, guid: &str) -> Vec<(String, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let rfc_date = unix_to_rfc1123(now);
    let client_time = unix_to_iso8601(now);
    vec![
        ("Accept".into(), "*/*".into()),
        ("Accept-Language".into(), "en-us".into()),
        ("Client-Cloud-DAAP-Request-Reason".into(), "5".into()),
        (
            "Client-Cloud-Purchase-Daap-Version".into(),
            "1.1/Configurator-2.0".into(),
        ),
        ("Client-DAAP-Version".into(), "3.12".into()),
        ("Date".into(), rfc_date),
        ("iCloud-DSID".into(), account.directory_services_id.clone()),
        ("X-Apple-I-Client-Time".into(), client_time),
        ("X-Apple-I-Locale".into(), "en_US".into()),
        ("X-Apple-I-TimeZone".into(), "UTC".into()),
        ("X-Apple-Store-Front".into(), account.store_front.clone()),
        ("X-Apple-TZ".into(), "0".into()),
        ("X-Dsid".into(), account.directory_services_id.clone()),
        ("X-Guid".into(), guid.into()),
        ("X-Token".into(), account.password_token.clone()),
    ]
}

fn unix_to_rfc1123(secs: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let weekday = ((days.rem_euclid(7) + 4) % 7) as usize; // 1970-01-01 = Thursday
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        d,
        MONTHS[(month - 1) as usize],
        year,
        h,
        m,
        s
    )
}

/// Body of the items request: `adsr` wrapping mstc/mlid/mikd/musr/mder/mque/aetl.
pub fn items_body(session_id: u32, revision: u32, query: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    inner.extend_from_slice(&tag_u32("mstc", now));
    inner.extend_from_slice(&tag_u32("mlid", session_id));
    inner.extend_from_slice(&tag_u8("mikd", 2));
    inner.extend_from_slice(&tag_u32("musr", revision));
    inner.extend_from_slice(&tag_u32("mder", 0));
    inner.extend_from_slice(&tag_str("mque", query));
    inner.extend_from_slice(&tag_bytes("aetl", &[]));
    tag_bytes("adsr", &inner)
}

fn tag_bytes(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn tag_str(name: &str, value: &str) -> Vec<u8> {
    tag_bytes(name, value.as_bytes())
}

fn tag_u32(name: &str, value: u32) -> Vec<u8> {
    tag_bytes(name, &value.to_be_bytes())
}

fn tag_u8(name: &str, value: u8) -> Vec<u8> {
    tag_bytes(name, &[value])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_body_shape() {
        let body = items_body(5, 9, "'com.apple.itunes.extended\\-media\\-kind:131072'");
        assert_eq!(&body[..4], b"adsr");
        let len = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
        assert_eq!(body.len(), 8 + len);
        // inner contains mlid and musr
        assert!(body.windows(4).any(|w| w == b"mlid"));
        assert!(body.windows(4).any(|w| w == b"musr"));
    }

    #[test]
    fn dmap_malformed_inputs() {
        // Non-printable tag byte → rejected.
        assert!(
            walk_dmap(
                &[0x01, 0x02, 0x03, 0x04, 0, 0, 0, 1, 0x41],
                0,
                &mut |_, _| Ok(())
            )
            .is_err()
        );
        // Length exceeding the buffer → rejected.
        assert!(walk_dmap(b"mstt\x00\x00\x00\x40", 0, &mut |_, _| Ok(())).is_err());
        // Truncated header → rejected.
        assert!(walk_dmap(b"ms", 0, &mut |_, _| Ok(())).is_err());
        // Empty input is fine.
        assert!(walk_dmap(&[], 0, &mut |_, _| Ok(())).is_ok());
    }

    #[test]
    fn dmap_deep_nesting_bounded() {
        // 20 nested msrv containers exceed the depth cap of 16.
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..20 {
            let inner = data.clone();
            data = tag_bytes("msrv", &inner);
        }
        assert!(walk_dmap(&data, 0, &mut |_, _| Ok(())).is_err());
    }

    #[test]
    fn daap_headers_shape() {
        let acc = Account {
            email: "a@b.c".into(),
            name: String::new(),
            directory_services_id: "12345".into(),
            password_token: "tok".into(),
            store_front: "143441-1,32".into(),
            pod: String::new(),
            password: String::new(),
        };
        let hdrs = daap_headers(&acc, "424CD91586ED");
        let get = |k: &str| hdrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("X-Token").as_deref(), Some("tok"));
        assert_eq!(get("X-Guid").as_deref(), Some("424CD91586ED"));
        assert_eq!(get("X-Dsid").as_deref(), Some("12345"));
        assert_eq!(get("Client-DAAP-Version").as_deref(), Some("3.12"));
        assert!(get("Date").is_some());
        assert!(get("X-Apple-I-Client-Time").is_some());
    }

    #[test]
    fn items_body_shape_matches_reference() {
        // The DAAP items body: adsr { mstc, mlid, mikd=2, musr, mder=0, mque, aetl }.
        let body = items_body(
            0x11223344,
            7,
            "('com.apple.itunes.extended\\-media\\-kind:131072')",
        );
        assert!(body.starts_with(b"adsr"), "{:?}", &body[..8]);
        let total = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
        assert_eq!(body.len(), 8 + total);
        // Spot-check nested tags by walking.
        let mut seen = Vec::new();
        walk_dmap(&body, 0, &mut |tag, _| {
            seen.push(tag.to_string());
            Ok(())
        })
        .unwrap();
        for tag in ["mstc", "mlid", "mikd", "musr", "mder", "mque", "aetl"] {
            assert!(seen.contains(&tag.to_string()), "missing {tag} in {seen:?}");
        }
    }
    #[test]
    fn walk_finds_nested_uint() {
        // msrv { mstt = 200, mlcl { mlit { aeSI = 42 } } } — one container
        // tree, as the real DAAP responses nest.
        let lit = tag_bytes("aeSI", &42u32.to_be_bytes());
        let mlit = tag_bytes("mlit", &lit);
        let lcl = tag_bytes("mlcl", &mlit);
        let mut tree = tag_bytes("mstt", &200u32.to_be_bytes());
        tree.extend_from_slice(&lcl);
        let doc = tag_bytes("msrv", &tree);
        assert_eq!(first_uint(&doc, "mstt"), Some(200));
        let apps = parse_owned_apps(&doc);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, 42);
    }
}
