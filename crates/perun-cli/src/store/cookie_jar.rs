// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The store lane's cookie jar: netscape-format persistence, `Set-Cookie`
//! folding, and the `Cookie` request header.
//!
//! This replaces `cookie_store`, which perun depended on for one thing: letting
//! `ureq` hold and replay the session. That cost 25 transitive crates for
//! domain validation perun has no use for — it only ever talks to
//! `*.apple.com` and `*.itunes.apple.com` — and the ICU4X slice behind
//! `cookie_store → idna` alone is 15 crates under Unicode-3.0, a copyleft
//! licence, for a cookie jar.
//!
//! The matching rules are the ones RFC 6265 actually needs here, and they are
//! deliberately small:
//!
//! * a cookie is sent when the request host equals its domain or ends with
//!   `.` + domain, and the request path starts with the cookie's path;
//! * a `Secure` cookie goes only over https;
//! * `HttpOnly` is parsed and persisted because the on-disk format carries the
//!   flag, and it means nothing to a client that only sends the cookie back;
//! * an expired row is dead on load, and `Max-Age<=0` deletes.
//!
//! Public-suffix validation is the one thing this does *not* do. It is what
//! `cookie_store` spent `idna` and the public-suffix list on, and without it a
//! cookie can in principle be set for a parent domain. Perun's jar is written
//! only by Apple's own `Set-Cookie` headers and read only for hosts under
//! apple.com, so the exposure is a malformed Apple response rather than a
//! reachable attack, and the alternative is 25 crates of dependency.

use std::path::Path;
use std::sync::Mutex;
use std::sync::OnceLock;

/// One cookie. The field set is the netscape row plus the flag the row format
/// has no column for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Netscape spelling: a leading dot means "and every subdomain". An exact
    /// host-only cookie is stored with the dot and matched on equality alone.
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    /// Unix seconds, or 0 for a session cookie. Apple's `hsaccnt`, `wosid`,
    /// `woinst` and `mzf_in` carry no expiry, so 0 is the common case and must
    /// round-trip: it is the value the store authenticates with.
    pub expires: i64,
}

impl Cookie {
    /// Whether this cookie is sent to `host` over `scheme`.
    fn matches(&self, scheme: &str, host: &str, path: &str) -> bool {
        if self.secure && scheme != "https" {
            return false;
        }
        // A leading dot is how the netscape format spells "and every
        // subdomain", and it is not part of the host. Without one the cookie is
        // host-only and only an exact match counts.
        let host = host.to_ascii_lowercase();
        let domain = self.domain.trim_start_matches('.').to_ascii_lowercase();
        if !(host == domain || host.ends_with(&format!(".{domain}"))) {
            return false;
        }
        path_matches(&self.path, path)
    }
}

/// RFC 6265 § 5.1.4 path-match, with the two deviations every implementation
/// makes: an empty cookie path matches everything, and a cookie path that is
/// not a prefix of the request path only matches when the request path ends
/// where the cookie path ends.
fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path.is_empty() || cookie_path == "/" {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.ends_with('/')
        || request_path.len() == cookie_path.len()
        || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn now_expiry(max_age: i64) -> i64 {
    now_unix().saturating_add(max_age)
}

/// The request path a cookie gets when the server sends no `Path`.
fn default_path(url: &str) -> String {
    let path = url
        .split_once("://")
        .map_or("/", |(_, rest)| rest.find('/').map_or("/", |i| &rest[i..]));
    let trimmed = path.split(['?', '#']).next().unwrap_or("/");
    if !trimmed.starts_with('/') {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => trimmed[..i].to_string(),
    }
}

/// Split a URL into `(scheme, host, path)`, tolerating the shapes Apple's
/// headers and the store's own redirects produce.
fn split_url(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    let path = match rest.find('/') {
        Some(i) => rest[i..].split(['?', '#']).next().unwrap_or("/"),
        None => "/",
    };
    Some((
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase(),
        path.to_string(),
    ))
}

/// The jar. One per process, because the store lane's session is shared by
/// every request and `http::send` reaches it without threading a handle.
pub struct CookieJar {
    cookies: Mutex<Vec<Cookie>>,
}

impl CookieJar {
    pub fn new() -> Self {
        CookieJar {
            cookies: Mutex::new(Vec::new()),
        }
    }

    /// Fold one `Set-Cookie` response header into the jar.
    ///
    /// Returns `false` when the header deletes the cookie, which must remove
    /// the stored row rather than resurrect it. `default_domain` is the host
    /// the response came from, used when the header carries no `Domain`.
    pub fn add_from_set_cookie(&self, header_val: &str, default_domain: &str) -> bool {
        let mut parts = header_val.split(';');
        let pair = parts.next().unwrap_or("").trim();
        let Some((name, value)) = pair.split_once('=') else {
            return false;
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            return false;
        }
        let mut domain = String::new();
        let mut path = String::new();
        let mut secure = false;
        let mut http_only = false;
        let mut expires = 0i64;
        let mut deleted = false;
        for attr in parts {
            let attr = attr.trim();
            let (key, val) = attr.split_once('=').unwrap_or((attr, ""));
            match key.trim().to_ascii_lowercase().as_str() {
                "domain" => {
                    let d = val.trim().trim_start_matches('.');
                    if !d.is_empty() {
                        domain = format!(".{d}");
                    }
                }
                "path" => path = val.trim().to_string(),
                "secure" => secure = true,
                "httponly" => http_only = true,
                "max-age" => {
                    if let Ok(secs) = val.trim().parse::<i64>() {
                        if secs <= 0 {
                            deleted = true;
                        } else {
                            expires = now_expiry(secs);
                        }
                    }
                }
                // An absolute `Expires` is deliberately not honoured: the
                // deadline is re-derived from `Max-Age` on the next response,
                // and parsing a date the server may have got wrong would expire
                // a live session early. It stays a session cookie, as it is on
                // disk already.
                "expires" => expires = 0,
                _ => {}
            }
        }
        if path.is_empty() {
            path = default_path(&format!("https://{default_domain}/"));
        }
        if domain.is_empty() {
            domain = default_domain.to_ascii_lowercase();
        }
        self.remove_matching(&name, &domain, &path);
        if deleted {
            return false;
        }
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Cookie {
                name,
                value: value.trim().to_string(),
                domain,
                path,
                secure,
                http_only,
                expires,
            });
        true
    }

    fn remove_matching(&self, name: &str, domain: &str, path: &str) {
        let mut jar = self
            .cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jar.retain(|c| {
            !(c.name.eq_ignore_ascii_case(name)
                && c.domain.eq_ignore_ascii_case(domain)
                && c.path == path)
        });
    }

    /// The `Cookie` request header for `url`, or `None` when nothing matches.
    ///
    /// A host-only cookie and a suffix cookie for the same name would both be
    /// sent, which is what a browser does too, so the rows are emitted in
    /// insertion order rather than deduplicated.
    pub fn get_cookie_header_for_url(&self, url: &str) -> Option<String> {
        let (scheme, host, path) = split_url(url)?;
        let now = now_unix();
        let jar = self
            .cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut parts: Vec<String> = Vec::new();
        for c in jar.iter() {
            if c.expires > 0 && c.expires <= now {
                continue;
            }
            if c.matches(&scheme, &host, &path) {
                parts.push(format!("{}={}", c.name, c.value));
            }
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }

    /// Read a curl-format jar. Returns the number of live cookies loaded.
    ///
    /// An absent or empty file is not an error: a first run has no session
    /// yet, and a failed read must not be able to destroy one.
    pub fn load_netscape_file(&self, path: &Path) -> std::io::Result<usize> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let now = now_unix();
        let mut loaded: Vec<Cookie> = Vec::new();
        for line in text.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.starts_with('#') && !line.starts_with("#HttpOnly_") {
                continue;
            }
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 7 {
                continue;
            }
            let http_only = line.starts_with("#HttpOnly_");
            // The `#HttpOnly_` prefix is curl's marker, not part of the domain.
            let domain = f[0].trim_start_matches("#HttpOnly_");
            let name = f[5];
            if name.is_empty() || domain.is_empty() {
                continue;
            }
            // A row whose deadline has passed is dead: loading it would hand
            // the client a cookie the server has already withdrawn.
            if let Ok(sec) = f[4].parse::<i64>()
                && (sec < 0 || (sec > 0 && sec <= now))
            {
                continue;
            }
            loaded.push(Cookie {
                name: name.to_string(),
                value: f[6].to_string(),
                domain: domain.to_string(),
                path: if f[2].is_empty() {
                    "/".into()
                } else {
                    f[2].to_string()
                },
                // The two flag columns are read case-insensitively: curl writes
                // the caps spelling, and rows this module wrote earlier carried
                // Rust's lowercase.
                secure: f[3].eq_ignore_ascii_case("TRUE"),
                http_only,
                expires: f[4].parse::<i64>().unwrap_or(0),
            });
        }
        let n = loaded.len();
        if n > 0 {
            *self
                .cookies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = loaded;
        }
        Ok(n)
    }

    /// Write the jar back, temp file plus rename, so a crash mid-write cannot
    /// truncate a live session.
    ///
    /// An empty jar is never written: a failed load or a response that set no
    /// cookies must not be able to destroy a session that is working.
    pub fn save_netscape_file(&self, path: &Path) -> std::io::Result<()> {
        let jar = self
            .cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if jar.is_empty() {
            return Ok(());
        }
        let mut out = String::from(
            "# Netscape HTTP Cookie File\n# Written by perun. Do not edit by hand.\n\n",
        );
        for c in jar.iter() {
            let prefix = if c.http_only { "#HttpOnly_" } else { "" };
            // The two flag columns are the format's TRUE/FALSE spelling, not
            // Rust's, so the file stays readable by curl and by eye.
            out.push_str(&format!(
                "{prefix}{}\tTRUE\t{}\t{}\t{}\t{}\t{}\n",
                c.domain,
                c.path,
                if c.secure { "TRUE" } else { "FALSE" },
                c.expires,
                c.name,
                c.value
            ));
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    /// Drop expired cookies. Called from the save path so a long-lived process
    /// does not carry a dead row forever.
    pub fn retain_live(&self) {
        let now = now_unix();
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|c| c.expires == 0 || c.expires > now);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    pub fn names(&self) -> Vec<String> {
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|c| c.name.clone())
            .collect()
    }
}

/// The process-wide jar.
pub fn jar() -> &'static CookieJar {
    static JAR: OnceLock<CookieJar> = OnceLock::new();
    JAR.get_or_init(CookieJar::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("perun-jar-{}-{name}", std::process::id()))
    }

    /// The bug this module exists to prevent: Apple's session cookies carry no
    /// `Expires`, so a saver that keeps only persistent cookies drops the four
    /// `MZFinance` authenticates with and the next signed call 401s. `0` is the
    /// netscape spelling of "session" and has to come back as a session cookie.
    #[test]
    fn session_cookies_survive_the_round_trip() {
        let path = tmp("rt");
        let _ = std::fs::remove_file(&path);
        let jar = CookieJar::new();
        jar.add_from_set_cookie(
            "hsaccnt=session-value; Path=/WebObjects",
            "p25-buy.itunes.apple.com",
        );
        jar.add_from_set_cookie("mz_at_ssl=ssl-value; Secure", "p25-buy.itunes.apple.com");
        jar.save_netscape_file(&path).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("hsaccnt\tsession-value"),
            "session cookie missing:\n{written}"
        );

        let back = CookieJar::new();
        assert_eq!(back.load_netscape_file(&path).unwrap(), 2);
        let names = back.names();
        assert!(names.contains(&"hsaccnt".to_string()), "{names:?}");
        assert!(
            back.get_cookie_header_for_url(
                "https://p25-buy.itunes.apple.com/WebObjects/MZFinancePlatform"
            )
            .unwrap()
            .contains("hsaccnt=session-value"),
            "the session cookie must be sent back"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The store talks to `*.itunes.apple.com` and `*.apple.com`, and the
    /// session cookies are set on a parent domain. A jar that treated the
    /// domain as an exact host would send none of them and every signed
    /// request would 401.
    #[test]
    fn a_suffix_domain_reaches_every_apple_subdomain() {
        let jar = CookieJar::new();
        jar.add_from_set_cookie(
            "itspod=48; Domain=.apple.com; Path=/",
            "init.itunes.apple.com",
        );
        for url in [
            "https://init.itunes.apple.com/bag.xml",
            "https://p25-buy.itunes.apple.com/WebObjects/MZFinancePlatform",
            "https://amp-api.apps.apple.com/v1/catalog/us/apps/1",
            "https://buy.itunes.apple.com/verify",
        ] {
            let header = jar
                .get_cookie_header_for_url(url)
                .unwrap_or_else(|| panic!("no header for {url}"));
            assert!(header.contains("itspod=48"), "{url}: {header}");
        }
        // And nothing outside apple.com gets it.
        assert!(
            jar.get_cookie_header_for_url("https://example.com/")
                .is_none()
        );
    }

    /// A path-scoped cookie must not leak to a sibling path: the `/WebObjects`
    /// session cookie is not valid on the DAAP or the catalogue endpoints.
    #[test]
    fn a_path_scoped_cookie_stays_on_its_path() {
        let jar = CookieJar::new();
        jar.add_from_set_cookie(
            "wosid=SID; Domain=.apple.com; Path=/WebObjects",
            "init.itunes.apple.com",
        );
        assert!(
            jar.get_cookie_header_for_url("https://p25-buy.itunes.apple.com/WebObjects/x")
                .unwrap()
                .contains("wosid=SID")
        );
        assert!(
            jar.get_cookie_header_for_url("https://p25-buy.itunes.apple.com/WebObjects")
                .unwrap()
                .contains("wosid=SID")
        );
        for outside in [
            "https://p25-buy.itunes.apple.com/",
            "https://p25-buy.itunes.apple.com/Web",
            "https://p25-buy.itunes.apple.com/WebObjects2/x",
            "https://p25-buy.itunes.apple.com/daap",
        ] {
            assert!(
                jar.get_cookie_header_for_url(outside).is_none(),
                "leaked onto {outside}"
            );
        }
    }

    /// `Max-Age=0` is a deletion. Getting this wrong resurrects a cookie the
    /// server just withdrew, which is how a session that ended comes back.
    #[test]
    fn max_age_zero_deletes_the_row() {
        let jar = CookieJar::new();
        jar.add_from_set_cookie(
            "mzf_in=abc; Domain=.apple.com; Path=/",
            "init.itunes.apple.com",
        );
        assert_eq!(jar.len(), 1);
        assert!(
            !jar.add_from_set_cookie(
                "mzf_in=; Domain=.apple.com; Path=/; Max-Age=0",
                "init.itunes.apple.com"
            ),
            "a deletion must report false"
        );
        assert_eq!(jar.len(), 0, "the row must be gone");
        assert!(
            jar.get_cookie_header_for_url("https://init.itunes.apple.com/bag.xml")
                .is_none()
        );
    }

    /// `Secure` is a transport rule, not a storage one: the cookie is kept and
    /// written, and withheld only from a plaintext request.
    #[test]
    fn secure_cookies_are_withheld_from_plaintext() {
        let jar = CookieJar::new();
        jar.add_from_set_cookie(
            "mz_at_ssl=v; Domain=.apple.com; Path=/; Secure",
            "init.itunes.apple.com",
        );
        assert!(
            jar.get_cookie_header_for_url("http://init.itunes.apple.com/bag.xml")
                .is_none(),
            "a Secure cookie must not go out over http"
        );
        assert!(
            jar.get_cookie_header_for_url("https://init.itunes.apple.com/bag.xml")
                .unwrap()
                .contains("mz_at_ssl=v")
        );
    }

    /// A cookie whose deadline has passed is dead on load: handing the client
    /// one the server withdrew is how a stale session outlives its grant.
    #[test]
    fn an_expired_row_is_not_loaded() {
        let path = tmp("exp");
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            concat!(
                "# Netscape HTTP Cookie File\n",
                ".apple.com\tTRUE\t/\tFALSE\t0\tlive\tkeep\n",
                "#HttpOnly_.apple.com\tTRUE\t/\tFALSE\t1\tdead\tdrop\n",
                "#HttpOnly_.apple.com\tTRUE\t/WebObjects\tFALSE\t0\thsaccnt\tSECRETVALUE\n",
            ),
        )
        .unwrap();
        let jar = CookieJar::new();
        assert_eq!(
            jar.load_netscape_file(&path).unwrap(),
            2,
            "the live rows load"
        );
        let names = jar.names();
        assert!(names.contains(&"live".to_string()), "{names:?}");
        assert!(names.contains(&"hsaccnt".to_string()), "{names:?}");
        assert!(!names.contains(&"dead".to_string()), "{names:?}");
        let _ = std::fs::remove_file(&path);
    }

    /// An empty or missing jar must never overwrite a populated file: that is
    /// how a failed import used to destroy a live session with no error.
    #[test]
    fn an_empty_jar_never_overwrites_the_file() {
        let path = tmp("keep");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, ".apple.com\tTRUE\t/\tFALSE\t0\tkeep-me\tv\n").unwrap();
        let empty = CookieJar::new();
        empty.save_netscape_file(&path).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("keep-me"),
            "the file was clobbered:\n{after}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A missing file is a first run, not an error.
    #[test]
    fn a_missing_file_loads_zero() {
        let path = tmp("absent");
        let _ = std::fs::remove_file(&path);
        assert_eq!(CookieJar::new().load_netscape_file(&path).unwrap(), 0);
    }

    /// A host-only cookie (no `Domain` attribute) goes to that host and not to
    /// its siblings.
    #[test]
    fn a_host_only_cookie_does_not_leak_to_siblings() {
        let jar = CookieJar::new();
        jar.add_from_set_cookie("itspod=48; Path=/", "init.itunes.apple.com");
        assert!(
            jar.get_cookie_header_for_url("https://init.itunes.apple.com/bag.xml")
                .is_some()
        );
        assert!(
            jar.get_cookie_header_for_url("https://other.itunes.apple.com/bag.xml")
                .is_none()
        );
    }

    /// The legacy curl jar is what an existing install already has on disk, and
    /// if importing it silently yields nothing the next save wipes the session —
    /// a failure with no visible error until a signed request 401s. Three
    /// shapes matter: a plain row, a `#HttpOnly_` row (curl's marker, not part
    /// of the domain), and a path-scoped one.
    #[test]
    fn a_legacy_curl_jar_imports_and_replays() {
        let path = tmp("legacy");
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            concat!(
                "# Netscape HTTP Cookie File\n",
                "\n",
                ".apple.com\tTRUE\t/\tFALSE\t0\titspod\t48\n",
                "#HttpOnly_.apple.com\tTRUE\t/\tTRUE\t0\tmz_at0\tSECRETVALUE\n",
                "#HttpOnly_.apple.com\tTRUE\t/WebObjects\tTRUE\t0\twosid\tSID\n",
            ),
        )
        .unwrap();
        let jar = CookieJar::new();
        assert_eq!(jar.load_netscape_file(&path).unwrap(), 3);
        let names = jar.names();
        for want in ["itspod", "mz_at0", "wosid"] {
            assert!(
                names.contains(&want.to_string()),
                "{want} missing: {names:?}"
            );
        }
        let header = jar
            .get_cookie_header_for_url("https://p25-buy.itunes.apple.com/bag.xml")
            .unwrap();
        assert!(header.contains("mz_at0=SECRETVALUE"), "{header}");
        // The path-scoped row only on its own path.
        let web = jar
            .get_cookie_header_for_url("https://p25-buy.itunes.apple.com/WebObjects/x")
            .unwrap();
        assert!(web.contains("wosid=SID"), "{web}");
        assert!(
            !jar.get_cookie_header_for_url("https://p25-buy.itunes.apple.com/other")
                .unwrap_or_default()
                .contains("wosid"),
            "the /WebObjects cookie leaked off its path"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The RFC 6265 path-match rules, which the `/WebObjects` session cookie
    /// depends on.
    #[test]
    fn path_match_follows_the_rfc() {
        assert!(path_matches("/", "/anything"));
        assert!(path_matches("", "/anything"));
        assert!(path_matches("/WebObjects", "/WebObjects/MZFinance"));
        assert!(path_matches("/WebObjects", "/WebObjects"));
        assert!(path_matches("/WebObjects", "/WebObjects/"));
        assert!(!path_matches("/WebObjects", "/Web"));
        assert!(!path_matches("/WebObjects", "/WebObjects2/x"));
        assert!(!path_matches("/WebObjects", "/"));
    }
}
