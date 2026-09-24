// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! HTTP for the Store lane, over an in-process client (ureq + rustls).
//!
//! One [`ureq::Agent`] is built per process and reused, so connections are
//! pooled and kept alive across requests — the SAP exchange, the login round
//! and the DAAP history now reuse one TLS handshake per host instead of
//! paying a fresh one (plus a `curl` fork) per call.
//!
//! The cookie jar is shared the same way: it is loaded once when the agent is
//! built and written back after every response, because the Store's
//! `mz_at0-*` session cookies must survive across invocations.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use ureq::Agent;

use super::{USER_AGENT, state_dir};

/// A response with status, headers (lower-cased), and body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    }
}

/// One HTTP request.
pub struct Request<'a> {
    pub method: &'a str,
    /// The target URL; retained on the struct for error reporting.
    #[allow(dead_code)]
    pub url: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Return the 3xx response itself instead of following the redirect
    /// (the login flow re-POSTs the original body at the pod).
    pub stop_on_redirect: bool,
    /// When set, the body is streamed to this writer and `Response.body`
    /// stays empty; `progress` is called with `(downloaded, total)`.
    pub sink: Option<&'a mut dyn std::io::Write>,
    /// File variant of `sink` for resumable downloads. When the server
    /// answers a Range resume with 200 (fresh full body) the file is
    /// truncated to 0 and rewritten from the start BEFORE the first body
    /// byte lands — so a 200-after-resume never appends to the partial.
    pub file_sink: Option<&'a mut std::fs::File>,
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>,
    /// Resume gate: when set together with `sink`/`file_sink`, the caller
    /// expects a range continuation starting at this offset. The response
    /// is validated against Content-Range BEFORE any body byte reaches the
    /// sink; a non-matching 206/416 aborts the transfer leaving the sink
    /// untouched (a 200 truncates `file_sink`, or is a fresh body for a
    /// generic `sink`).
    pub range_start: Option<u64>,
}

impl<'a> Request<'a> {
    pub fn new(method: &'a str, url: &'a str) -> Request<'a> {
        Request {
            method,
            url,
            headers: Vec::new(),
            body: None,
            stop_on_redirect: false,
            sink: None,
            file_sink: None,
            progress: None,
            range_start: None,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn header_vec(mut self, pairs: &[(String, String)]) -> Self {
        for (name, value) in pairs {
            self.headers.push((name.clone(), value.clone()));
        }
        self
    }

    pub fn plist_body(mut self, body: Vec<u8>) -> Self {
        // Only set the content type when the caller hasn't picked one
        // already (the SAP endpoints want application/x-plist).
        if !self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        {
            self.headers
                .push(("Content-Type".into(), "application/x-apple-plist".into()));
        }
        self.body = Some(body);
        self
    }

    pub fn form_body(mut self, body: Vec<u8>) -> Self {
        // Only set the content type when the caller hasn't picked one
        // already — the login flow sets its own before attaching the body.
        if !self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        {
            self.headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
        }
        self.body = Some(body);
        self
    }

    pub fn body_bytes(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Return the 3xx response itself instead of following the redirect.
    pub fn stop_on_redirect_marker(mut self) -> Self {
        self.stop_on_redirect = true;
        self
    }

    /// Generic streaming sink (any writer). Retained for callers that stream
    /// to non-file destinations; the localhost e2e test covers it.
    /// Resumable downloads use [`Request::with_file_sink`] instead, so a
    /// 200-after-resume can truncate before streaming.
    #[allow(dead_code)]
    pub fn with_sink(mut self, sink: &'a mut dyn std::io::Write) -> Self {
        self.sink = Some(sink);
        self
    }

    /// File sink for resumable downloads (see `file_sink` docs). Takes
    /// `&mut File` so a 200-after-resume can truncate before streaming.
    pub fn with_file_sink(mut self, file: &'a mut std::fs::File) -> Self {
        self.file_sink = Some(file);
        self
    }

    pub fn with_progress(mut self, progress: &'a mut dyn FnMut(u64, u64)) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Resume gate: stream into the sink only after the server's range
    /// answer validates against `start` (the current partial size).
    pub fn with_range_resume(mut self, start: u64) -> Self {
        self.range_start = Some(start);
        self
    }
}

/// Cookie-jar path shared by all Store requests.
/// Mirror of the reference downloadResponseRange. Validates the status +
/// Content-Range against the local partial size BEFORE any byte is
/// appended. 200 = fresh full body (the file-sink path truncates to 0
/// before streaming); 206 = continuation (start must equal the local
/// size); 416 with matching `bytes */N` = the file is already complete.
fn check_range_response(
    status: u16,
    headers: &HashMap<String, String>,
    local: u64,
) -> Result<(), String> {
    let get = |name: &str| headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str());
    match status {
        200 => Ok(()),
        416 => {
            let range = get("content-range").unwrap_or("");
            let value = range
                .strip_prefix("bytes */")
                .and_then(|v| v.parse::<u64>().ok());
            match value {
                Some(size) if size == local => Ok(()),
                _ => Err(format!(
                    "download range rejected: local size {local} does not match server range {range:?}"
                )),
            }
        }
        206 => {
            let header = get("content-range").unwrap_or("").to_string();
            let value = header.strip_prefix("bytes ").unwrap_or("");
            let (bounds, total_text) = value.split_once('/').ok_or_else(|| {
                format!("invalid download content range {header:?} for local size {local}")
            })?;
            let (start_text, end_text) = bounds.split_once('-').ok_or_else(|| {
                format!("invalid download content range {header:?} for local size {local}")
            })?;
            let start = start_text.parse::<u64>().map_err(|_| {
                format!("invalid download content range {header:?} for local size {local}")
            })?;
            let end = end_text.parse::<u64>().map_err(|_| {
                format!("invalid download content range {header:?} for local size {local}")
            })?;
            let size = total_text.parse::<u64>().map_err(|_| {
                format!("invalid download content range {header:?} for local size {local}")
            })?;
            if start != local || end < start || size <= end {
                return Err(format!(
                    "invalid download content range {header:?} for local size {local}"
                ));
            }
            let length = end - start + 1;
            if let Some(len) = get("content-length").and_then(|v| v.parse::<u64>().ok())
                && len != length
            {
                return Err(format!(
                    "download content length {len} does not match range length {length}"
                ));
            }
            Ok(())
        }
        other => Err(format!("unexpected download response status: {other}")),
    }
}

pub fn cookie_jar_path() -> Result<PathBuf, String> {
    Ok(state_dir()?.join("cookies.txt"))
}

/// 200-after-resume helper: when a Range resume (`range_start > 0`) gets a
/// 200 (server ignored Range, fresh full body), truncate the partial to 0
/// so the fresh body starts at offset 0. Returns true when truncated.
fn truncate_file_for_fresh(
    file: &mut std::fs::File,
    status: u16,
    range_start: Option<u64>,
) -> Result<bool, String> {
    if status == 200 && range_start.unwrap_or(0) > 0 {
        file.set_len(0)
            .map_err(|e| format!("truncate resume file: {e}"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek resume file: {e}"))?;
        return Ok(true);
    }
    Ok(false)
}

/// The one agent for the whole process, built on first use and reused.
///
/// Strictly one. Two agents meant two in-memory cookie jars, and whichever
/// served the last request would overwrite the file and drop what the other
/// learned — the session lost its `mz_at0-*` cookies after a single successful
/// call. One jar, one store, one truth.
///
/// Redirects are off at the agent level (`max_redirects(0)`): the agent never
/// jumps on its own. A call that wants a hop follows it itself, in
/// [`send`], through this same agent, so a redirect can never become a second,
/// cookie-less client. The login is the deliberate exception and keeps its own
/// handling: its 302 to a pod carries the credentials, and re-posting the
/// original body there is part of the protocol, not a blind follow.
static AGENT: OnceLock<Agent> = OnceLock::new();

fn agent() -> Result<&'static Agent, String> {
    if let Some(a) = AGENT.get() {
        return Ok(a);
    }
    // Build before publishing, so a failure is not cached for the process.
    let a = build_agent(&cookie_jar_path()?)?;
    Ok(AGENT.get_or_init(|| a))
}

/// Apply the caller's headers. `header()` is on the unconstrained impl of the
/// typestate parameter, so this works for both the with-body and no-body
/// builders.
fn with_headers<Any>(
    mut b: ureq::RequestBuilder<Any>,
    headers: &[(String, String)],
) -> ureq::RequestBuilder<Any> {
    for (name, value) in headers {
        b = b.header(name, value);
    }
    b
}

fn build_agent(jar: &PathBuf) -> Result<Agent, String> {
    let builder = Agent::config_builder()
        .user_agent(USER_AGENT)
        .max_redirects(0)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .timeout_send_body(Some(Duration::from_secs(60)))
        .http_status_as_error(false);
    let agent: Agent = builder.build().into();
    load_cookies(&agent, jar);
    Ok(agent)
}

/// Read the shared jar into the agent, and keep the rows for the writer.
fn load_cookies(agent: &Agent, jar: &PathBuf) {
    let Ok(text) = std::fs::read_to_string(jar) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut guard = agent.cookie_jar_lock();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') && !line.starts_with("#HttpOnly_") {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let (domain, include_sub, path, secure, expires, name, value) =
            (f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
        if name.is_empty() {
            continue;
        }
        // A row whose deadline has passed is dead: loading it would hand the
        // agent a cookie Apple has already withdrawn.
        if let Ok(sec) = expires.parse::<i64>()
            && (sec < 0 || (sec > 0 && sec <= now_unix()))
        {
            continue;
        }
        let _ = include_sub;
        // curl prefixes HttpOnly rows with `#HttpOnly_`. It is not part of the
        // domain, and leaving it in makes the Domain attribute unparseable, so
        // the row is dropped. The flag only restricts script access, which has
        // no meaning for a client that just sends the cookie back.
        let domain = domain.trim_start_matches("#HttpOnly_");
        // The netscape domain carries a leading dot (".apple.com"), which is
        // not a URI host; the cookie's Domain attribute keeps the dot.
        let host = domain.trim_start_matches('.');
        let Ok(uri) = format!("https://{host}").parse::<ureq::http::Uri>() else {
            continue;
        };
        // The Domain attribute is what makes this a suffix cookie: without it
        // the jar would treat every cookie as host-only for `apple.com` and
        // send none of them to the `*.itunes.apple.com` hosts.
        let mut set = format!("{name}={value}; Domain={domain}; Path={path}");
        if secure == "TRUE" {
            set.push_str("; Secure");
        }
        if let Ok(cookie) = ureq::Cookie::parse(set, &uri)
            && guard.insert(cookie, &uri).is_err()
        {
            eprintln!("[store:http] cookie import failed for {name} on {host}");
        }
        rows.push(vec![
            domain.to_string(),
            include_sub.to_string(),
            path.to_string(),
            secure.to_string(),
            expires.to_string(),
            name.to_string(),
            value.to_string(),
        ]);
    }
    drop(guard);
    *JAR_LINES.lock().unwrap_or_else(|e| e.into_inner()) = rows;
}

/// The on-disk jar, in curl's netscape format, held in memory for the process.
///
/// This is the persistence layer, and it is deliberately NOT enumerated from
/// the in-memory jar: `ureq::Cookie` exposes only `name()` and `value()`, so
/// the domain, path and expiry needed for the format cannot be read back out of
/// it. Nor can we use ureq's own JSON saver — `cookie_store`'s JSON writer keeps
/// only `is_persistent()` cookies, and Apple's `hsaccnt`, `wosid`, `woinst` and
/// `mzf_in` carry no `Expires`, so every save dropped the four cookies
/// MZFinance authenticates with and DAAP answered 401. The netscape format has
/// an explicit expiry column, so a session cookie is written as `0` and comes
/// back as a session cookie.
static JAR_LINES: Mutex<Vec<Vec<String>>> = Mutex::new(Vec::new());

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

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

/// Fold one `Set-Cookie` header into a netscape row for `url`.
///
/// Returns `None` when the header deletes the cookie (`Max-Age` zero or
/// negative), which must remove the stored row rather than resurrect it: an
/// Apple session cookie dropped this way is what makes the next authenticated
/// call fail.
fn set_cookie_line(set: &str, url: &str) -> Option<Vec<String>> {
    let mut parts = set.split(';');
    let pair = parts.next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    let host = format!("{scheme}://{host}")
        .parse::<ureq::http::Uri>()
        .ok()
        .and_then(|u| u.host().map(|h| h.to_string()))?;
    let mut domain = String::new();
    let mut path = String::new();
    let mut secure = false;
    let mut expires = String::from("0");
    for attr in parts {
        let attr = attr.trim();
        let (key, val) = attr.split_once('=').unwrap_or((attr, ""));
        match key.trim().to_ascii_lowercase().as_str() {
            "domain" => domain = format!(".{}", val.trim().trim_start_matches('.')),
            "path" => path = val.trim().to_string(),
            "secure" => secure = true,
            "max-age" => {
                if let Ok(secs) = val.trim().parse::<i64>() {
                    if secs <= 0 {
                        return None;
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    expires = (now + secs).to_string();
                }
            }
            "expires" => {
                // Left as 0 (session): the absolute date is re-derived on the
                // next response anyway, and a wrong one would expire early.
                expires = String::from("0");
            }
            _ => {}
        }
    }
    if path.is_empty() {
        path = default_path(url);
    }
    if domain.is_empty() {
        domain = host;
    }
    Some(vec![
        domain,
        "FALSE".to_string(),
        path,
        secure.to_string(),
        expires,
        name.to_string(),
        value.trim().to_string(),
    ])
}

/// Record the `Set-Cookie` headers of one response, replacing any row of the
/// same name, domain and path.
fn record_set_cookies(sets: &[String], url: &str) {
    let mut rows = JAR_LINES.lock().unwrap_or_else(|e| e.into_inner());
    for set in sets {
        // The name identifies the row being set or deleted; the domain and path
        // only say which of several same-named cookies it applies to.
        let name = set.split(';').next().unwrap_or("").trim();
        let Some((name, _)) = name.split_once('=') else {
            continue;
        };
        let existing = |r: &Vec<String>| r[5] == name;
        match set_cookie_line(set, url) {
            Some(row) => match rows
                .iter()
                .position(|r| r[0] == row[0] && existing(r) && r[2] == row[2])
            {
                Some(i) => rows[i] = row,
                None => rows.push(row),
            },
            None => rows.retain(|r| !existing(r)),
        }
    }
}

/// Write the jar back. Temp file plus rename, so a crash mid-write cannot
/// truncate a live session.
fn save_cookies(jar: &PathBuf) {
    let rows = JAR_LINES.lock().unwrap_or_else(|e| e.into_inner());
    if rows.is_empty() {
        // Never replace a populated file with nothing: a failed load or a
        // request that set no cookies must not destroy a live session.
        return;
    }
    let mut out =
        String::from("# Netscape HTTP Cookie File\n# Written by perun. Do not edit by hand.\n\n");
    for r in rows.iter() {
        out.push_str(&r.join("\t"));
        out.push('\n');
    }
    let tmp = jar.with_extension("tmp");
    if std::fs::write(&tmp, out).is_ok() && std::fs::rename(&tmp, jar).is_ok() {
        return;
    }
    let _ = std::fs::remove_file(&tmp);
}

/// Issue one request, and follow hops ourselves when the caller wants them.
///
/// The agent is built with redirects off, so every hop goes through this same
/// agent and the same cookie jar — the IPA URL answers with a 302 onto Apple's
/// CDN, and the second hop must arrive as the same client, cookie scoping
/// included. The caller's headers are carried over unchanged, `Range` among
/// them: dropping it on the CDN hop would defeat resumable downloads, which
/// exist precisely to survive that redirect.
fn dispatch(
    agent: &Agent,
    req: &Request<'_>,
    url: String,
) -> Result<ureq::http::Response<ureq::Body>, String> {
    const MAX_HOPS: usize = 8;
    let mut url = url;
    let mut hop = 0usize;
    loop {
        // `call()` exists only on the no-body builder, `send()` only on the
        // with-body one, so the two shapes are dispatched separately; the
        // header application is shared through with_headers().
        let res = match (req.method, req.body.as_ref()) {
            ("GET", _) | ("DELETE", _) => with_headers(agent.get(&url), &req.headers).call(),
            ("POST", Some(body)) | ("PUT", Some(body)) => {
                with_headers(agent.post(&url), &req.headers).send(body.clone())
            }
            // A POST with no payload still needs Content-Length: 0, or Apple's
            // front (Tomcat) answers 411 Length Required.
            ("POST", None) => with_headers(agent.post(&url), &req.headers).send(Vec::new()),
            (other, _) => {
                return Err(format!(
                    "unsupported method {other:?}: the agent exposes GET/POST/PUT/DELETE only"
                ));
            }
        };
        let res = res.map_err(|e| format!("{url} {}", describe(&e)))?;

        let status = res.status().as_u16();
        let location = res
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        // The login stops on the first hop: its 302 carries the credentials and
        // re-posting the original body to the pod is its own protocol step.
        if req.stop_on_redirect || !(300..400).contains(&status) || status == 304 {
            return Ok(res);
        }
        let Some(next) = location else {
            return Ok(res);
        };
        let Ok(next) = url_join(&url, &next) else {
            return Err(format!("{url}: unusable redirect target {next:?}"));
        };
        hop += 1;
        if hop > MAX_HOPS {
            return Err(format!("{url}: more than {MAX_HOPS} redirects"));
        }
        // Drain so the pooled connection can be reused for the next hop.
        let _ = res.into_body().into_reader();
        eprintln!("[store:http] {status} {url} -> {next}");
        url = next;
    }
}

/// Resolve a `Location` against the URL it came from (RFC 3986 §5.3, the
/// subset that shows up here: absolute, rooted, and plain-relative).
fn url_join(base: &str, location: &str) -> Result<String, String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let b = ureq::http::Uri::from_str(base).map_err(|e| e.to_string())?;
    let host = b.authority().ok_or("no authority in base URL")?.to_string();
    if let Some(rooted) = location.strip_prefix('/') {
        return Ok(format!(
            "{}://{host}/{rooted}",
            b.scheme_str().unwrap_or("https")
        ));
    }
    // Relative: replace the last path segment of the base.
    let path = b.path();
    let dir = match path.rfind('/') {
        Some(i) => &path[..i + 1],
        None => "/",
    };
    let resolved = if dir.ends_with('/') {
        format!("{dir}{location}")
    } else {
        format!("{dir}/{location}")
    };
    Ok(format!(
        "{}://{host}{resolved}",
        b.scheme_str().unwrap_or("https")
    ))
}

/// Execute a request through the shared agent.
pub fn send(mut req: Request) -> Result<Response, String> {
    let agent = agent()?;
    let debug = std::env::var("PERUN_STORE_HTTP_DEBUG").is_ok();

    let mut res = dispatch(agent, &req, req.url.to_string())?;

    if debug {
        eprintln!(
            "[store:http] {} {} ({} header(s), {} body)",
            req.method,
            req.url,
            req.headers.len(),
            req.body.as_ref().map_or(0, |b| b.len())
        );
    }

    let status = res.status().as_u16();
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut set_cookies: Vec<String> = Vec::new();
    for (name, value) in res.headers() {
        if let Ok(v) = value.to_str() {
            let lower = name.as_str().to_ascii_lowercase();
            if lower == "set-cookie" {
                set_cookies.push(v.to_string());
            }
            headers.insert(lower, v.to_string());
        }
    }
    record_set_cookies(&set_cookies, req.url);
    save_cookies(&cookie_jar_path().unwrap_or_default());

    // The resume gate runs before a single body byte can reach a sink.
    let mut file_buf: Option<std::io::BufWriter<&mut std::fs::File>> =
        req.file_sink.as_mut().map(|f| {
            let f: &mut std::fs::File = f;
            std::io::BufWriter::with_capacity(1 << 20, f)
        });
    let has_sink = req.sink.is_some() || file_buf.is_some();
    if has_sink && let Some(start) = req.range_start {
        check_range_response(status, &headers, start)?;
        if let Some(buf) = file_buf.as_mut() {
            truncate_file_for_fresh(buf.get_mut(), status, req.range_start)?;
        }
    }
    let total_hint = headers
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok());

    let mut body: Vec<u8> = Vec::new();
    let mut downloaded: u64 = 0;
    let mut chunk = [0u8; 64 * 1024];
    // One reader for the whole body: re-creating it per chunk restarts the
    // gzip decoder and truncates the response.
    let mut reader = res.body_mut().as_reader();
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        let window = &chunk[..n];
        downloaded += window.len() as u64;
        if let Some(buf) = file_buf.as_mut() {
            buf.write_all(window)
                .map_err(|e| format!("sink write: {e}"))?;
            // Flush per chunk so a crash mid-download leaves a resumable tail.
            buf.flush().ok();
        } else if let Some(sink) = req.sink.as_mut() {
            sink.write_all(window)
                .map_err(|e| format!("sink write: {e}"))?;
            sink.flush().ok();
        } else {
            body.extend_from_slice(window);
        }
        if let Some(progress) = req.progress.as_mut() {
            progress(downloaded, total_hint.unwrap_or(0));
        }
    }
    if let Some(buf) = file_buf.as_mut() {
        buf.flush().map_err(|e| format!("sink flush: {e}"))?;
    }

    save_cookies(&cookie_jar_path()?);

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// A second agent for the SAP lane.
///
/// The Store agent carries the shared cookie jar; the FairPlay handshake must
/// not receive the `mz_at0-*` session cookies, so this one has none. It still
/// pools connections, which is where the SAP win comes from.
static SAP_AGENT: OnceLock<Agent> = OnceLock::new();

fn sap_agent() -> &'static Agent {
    SAP_AGENT.get_or_init(|| {
        Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_body(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .build()
            .into()
    })
}

/// One request on the cookie-less SAP agent.
///
/// `user_agent` is a parameter because the SAP lane deliberately identifies as
/// a different Configurator build than the Store lane does.
pub fn raw_request(
    method: &str,
    url: &str,
    user_agent: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let agent = sap_agent();
    let res = match (method, body) {
        ("GET", _) => {
            let mut b = agent.get(url).header("User-Agent", user_agent);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.call()
        }
        (_, Some(data)) => {
            let mut b = agent.post(url).header("User-Agent", user_agent);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.send(data.to_vec())
        }
        _ => {
            let mut b = agent.post(url).header("User-Agent", user_agent);
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.send(Vec::new())
        }
    }
    .map_err(|e| format!("{method} {url}: {}", describe(&e)))?;

    let status = res.status().as_u16();
    let mut out: HashMap<String, String> = HashMap::new();
    for (name, value) in res.headers() {
        if let Ok(v) = value.to_str() {
            out.insert(name.as_str().to_ascii_lowercase(), v.to_string());
        }
    }
    let mut buf = Vec::new();
    let mut res = res;
    res.body_mut()
        .as_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body: {e}"))?;
    Ok(Response {
        status,
        headers: out,
        body: buf,
    })
}

/// A short, human-readable reason for a transport error.
fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_hdrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn range_gate_fresh_200() {
        assert!(check_range_response(200, &range_hdrs(&[]), 0).is_ok());
        // 200 with a partial on disk: allowed, the file-sink path truncates
        // to 0 before streaming the fresh body.
        assert!(check_range_response(200, &range_hdrs(&[]), 1000).is_ok());
    }

    #[test]
    fn fresh_200_truncates_partial_before_streaming() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir();
        let path = dir.join(format!("perun-resume-{}.tmp", std::process::id()));
        // Partial on disk.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"partial-bytes").unwrap();
        }
        // 200 with a resume offset: truncate to 0.
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            assert!(truncate_file_for_fresh(&mut f, 200, Some(13)).unwrap());
            assert_eq!(f.metadata().unwrap().len(), 0);
        }
        // 206 continuation: untouched.
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all(b"partial-bytes").unwrap();
            assert!(!truncate_file_for_fresh(&mut f, 206, Some(13)).unwrap());
            assert_eq!(f.metadata().unwrap().len(), 13);
        }
        // Fresh download (no resume): untouched even on 200.
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            assert!(!truncate_file_for_fresh(&mut f, 200, None).unwrap());
            assert!(!truncate_file_for_fresh(&mut f, 200, Some(0)).unwrap());
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn range_gate_partial_206_validates_start() {
        let h = range_hdrs(&[
            ("content-range", "bytes 1000-28410/28411"),
            ("content-length", "27411"),
        ]);
        assert!(check_range_response(206, &h, 1000).is_ok());
        assert!(check_range_response(206, &h, 999).is_err());
        assert!(check_range_response(206, &h, 0).is_err());
    }

    #[test]
    fn range_gate_partial_206_rejects_malformed() {
        let no_total = range_hdrs(&[("content-range", "bytes 1000-28410")]);
        assert!(check_range_response(206, &no_total, 1000).is_err());
        let reversed = range_hdrs(&[("content-range", "bytes 5000-1000/28411")]);
        assert!(check_range_response(206, &reversed, 5000).is_err());
        let len_mismatch = range_hdrs(&[
            ("content-range", "bytes 1000-28410/28411"),
            ("content-length", "12345"),
        ]);
        assert!(check_range_response(206, &len_mismatch, 1000).is_err());
    }

    #[test]
    fn range_gate_not_satisfiable_416() {
        let h = range_hdrs(&[("content-range", "bytes */28411")]);
        assert!(check_range_response(416, &h, 28411).is_ok());
        assert!(check_range_response(416, &h, 28410).is_err());
        assert!(check_range_response(416, &range_hdrs(&[]), 28411).is_err());
    }

    #[test]
    fn range_gate_unexpected_status() {
        assert!(check_range_response(403, &range_hdrs(&[]), 0).is_err());
        assert!(check_range_response(500, &range_hdrs(&[]), 0).is_err());
        assert!(check_range_response(302, &range_hdrs(&[]), 0).is_err());
    }

    /// The legacy curl jar is what an existing install has on disk. If this
    /// import silently yields nothing, the next save wipes the session — the
    /// failure is invisible until a signed request 401s.
    #[test]
    fn legacy_netscape_jar_is_imported() {
        let scratch = std::env::temp_dir().join(format!("perun-cj-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let jar = scratch.join("cookies.txt");
        std::fs::write(
            &jar,
            concat!(
                "# Netscape HTTP Cookie File\n",
                "\n",
                ".apple.com\tTRUE\t/\tFALSE\t0\titspod\t48\n",
                "#HttpOnly_.apple.com\tTRUE\t/\tTRUE\t0\tmz_at0\tSECRETVALUE\n",
                "#HttpOnly_.apple.com\tTRUE\t/WebObjects\tTRUE\t0\twosid\tSID\n",
            ),
        )
        .unwrap();

        let agent: Agent = Agent::config_builder().build().into();
        load_cookies(&agent, &jar);
        let guard = agent.cookie_jar_lock();
        let names: Vec<String> = guard.iter().map(|c| c.name().to_string()).collect();
        assert!(
            names.contains(&"itspod".to_string()),
            "plain cookie: {names:?}"
        );
        assert!(
            names.contains(&"mz_at0".to_string()),
            "HttpOnly cookie: {names:?}"
        );
        assert!(
            names.contains(&"wosid".to_string()),
            "path-scoped cookie: {names:?}"
        );
        assert!(
            guard.iter().any(|c| c.value() == "SECRETVALUE"),
            "cookie value must survive the import"
        );
        drop(guard);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// The bug this file exists to prevent: `cookie_store`'s JSON saver keeps
    /// only `is_persistent()` cookies, so Apple's session cookies — `hsaccnt`,
    /// `wosid`, `woinst`, `mzf_in`, none of which carry an `Expires` — were
    /// dropped on every save, and DAAP answered 401. The netscape format has an
    /// explicit expiry column, so `0` (session) must survive the round trip.
    #[test]
    fn session_cookies_survive_the_jar_round_trip() {
        let scratch = std::env::temp_dir().join(format!("perun-cj-rt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let jar = scratch.join("cookies.txt");

        {
            let mut rows = JAR_LINES.lock().unwrap();
            rows.clear();
            rows.push(vec![
                ".apple.com".into(),
                "TRUE".into(),
                "/WebObjects".into(),
                "FALSE".into(),
                "0".into(),
                "hsaccnt".into(),
                "session-value".into(),
            ]);
            rows.push(vec![
                ".apple.com".into(),
                "TRUE".into(),
                "/".into(),
                "TRUE".into(),
                "0".into(),
                "mz_at_ssl-1".into(),
                "ssl-value".into(),
            ]);
        }
        save_cookies(&jar);

        let written = std::fs::read_to_string(&jar).unwrap();
        assert!(
            written.contains("hsaccnt\tsession-value"),
            "session cookie missing from the jar file:\n{written}"
        );

        // Reload into a fresh agent: the row must come back as a real cookie.
        {
            let mut rows = JAR_LINES.lock().unwrap();
            rows.clear();
        }
        let agent: Agent = Agent::config_builder().build().into();
        load_cookies(&agent, &jar);
        let names: Vec<String> = agent
            .cookie_jar_lock()
            .iter()
            .map(|c| c.name().to_string())
            .collect();
        assert!(
            names.contains(&"hsaccnt".to_string()),
            "hsaccnt did not come back: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// An empty jar must never overwrite a populated file: that is how a failed
    /// import used to destroy a live session with no error anywhere.
    #[test]
    fn empty_jar_does_not_overwrite_a_populated_file() {
        let scratch = std::env::temp_dir().join(format!("perun-cj2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let jar = scratch.join("cookies.txt");
        let original =
            b"# Netscape HTTP Cookie File\n.apple.com\tTRUE\t/\tFALSE\t0\thsaccnt\tkeep-me\n";
        std::fs::write(&jar, original).unwrap();

        let mut rows = JAR_LINES.lock().unwrap();
        rows.clear();
        drop(rows);
        save_cookies(&jar);
        assert_eq!(
            std::fs::read(&jar).unwrap(),
            original,
            "the on-disk jar must survive an empty in-memory one"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// End-to-end through the real curl binary against a localhost server:
    /// `/full` ignores Range (the 200-after-resume case), `/part` honors it
    /// (206). Proves the file on disk ends up byte-identical to the fresh
    /// body in both cases, and that the generic sink still streams.
    #[test]
    fn resume_against_localhost_200_truncates_and_206_appends() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::net::TcpListener;

        // Isolate the cookie jar + header tmp from real user state.
        let scratch = std::env::temp_dir().join(format!("perun-http-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        unsafe {
            std::env::set_var("PERUN_STORE_DIR", &scratch);
            std::env::set_var("no_proxy", "127.0.0.1,localhost");
        }

        let full: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_full = full.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            head.extend_from_slice(&buf[..n]);
                            if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() > 8192 {
                                break;
                            }
                        }
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let target = text.lines().next().unwrap_or("").to_string();
                let range: Option<u64> = text
                    .lines()
                    .skip(1)
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        if name.trim().eq_ignore_ascii_case("range") {
                            Some(value.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .and_then(|v| v.strip_prefix("bytes=").map(str::to_string))
                    .and_then(|v| v.trim_end_matches('-').parse().ok());
                let total = server_full.len() as u64;
                let (status, start) = if target.contains("/part") {
                    match range {
                        Some(s) if s < total => ("206 Partial Content", s),
                        _ => ("200 OK", 0),
                    }
                } else {
                    ("200 OK", 0) // ignores Range entirely
                };
                let body = &server_full[start as usize..];
                let mut resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                if status.starts_with("206") {
                    resp.push_str(&format!(
                        "Content-Range: bytes {start}-{}/{total}\r\n",
                        total - 1
                    ));
                }
                resp.push_str("\r\n");
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });

        let base = format!("http://127.0.0.1:{port}");

        // Case A: 200-after-resume. A stale 14-byte partial plus a server
        // that ignores Range must yield exactly the fresh body.
        let file_a = scratch.join("resume-200.bin");
        std::fs::write(&file_a, b"STALE-PARTIAL!").unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&file_a)
                .unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            let url = format!("{base}/full");
            let res = send(
                Request::new("GET", &url)
                    .header("Range", "bytes=14-")
                    .with_range_resume(14)
                    .with_file_sink(&mut f),
            )
            .expect("localhost 200 download");
            assert_eq!(res.status, 200);
        }
        assert_eq!(std::fs::read(&file_a).unwrap(), full);

        // Case B: an honest 206 continuation appends at the tail.
        let file_b = scratch.join("resume-206.bin");
        std::fs::write(&file_b, &full[..100]).unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&file_b)
                .unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            let url = format!("{base}/part");
            let res = send(
                Request::new("GET", &url)
                    .header("Range", "bytes=100-")
                    .with_range_resume(100)
                    .with_file_sink(&mut f),
            )
            .expect("localhost 206 download");
            assert_eq!(res.status, 206);
        }
        assert_eq!(std::fs::read(&file_b).unwrap(), full);

        // Case C: the generic sink still streams (keeps with_sink covered).
        {
            let url = format!("{base}/full");
            let mut out = Vec::new();
            let res = send(Request::new("GET", &url).with_sink(&mut out))
                .expect("localhost sink download");
            assert_eq!(res.status, 200);
            assert!(res.body.is_empty());
            assert_eq!(out, full);
        }

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
