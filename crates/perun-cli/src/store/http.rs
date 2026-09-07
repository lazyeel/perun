// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! HTTP for the Store lane, backed by the curl binary (same discipline as
//! the SAP fetcher: no TLS stack in the binary, the system curl provides
//! one). The cookie jar is a netscape-format file shared across requests
//! and invocations — the Store's `mz_at0-*` session cookies live there.
//!
//! Streams: curl writes response headers to a temp file (`-D`) and the
//! body to stdout, so the body stream stays clean even when `-L` follows
//! several hops (each hop's header block would otherwise interleave with
//! the body). The status is parsed from the header file afterwards; a
//! body-streaming download can read the file mid-flight for the
//! Content-Length progress hint.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    pub progress: Option<&'a mut dyn FnMut(u64, u64)>,
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
            progress: None,
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

    pub fn with_sink(mut self, sink: &'a mut dyn std::io::Write) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn with_progress(mut self, progress: &'a mut dyn FnMut(u64, u64)) -> Self {
        self.progress = Some(progress);
        self
    }
}

/// Cookie-jar path shared by all Store requests.
pub fn cookie_jar_path() -> Result<PathBuf, String> {
    Ok(state_dir()?.join("cookies.txt"))
}

/// Execute a request through curl.
pub fn send(mut req: Request) -> Result<Response, String> {
    let jar = cookie_jar_path()?;
    let hdr_path = state_dir()?.join(".headers.tmp");
    let _ = std::fs::remove_file(&hdr_path);

    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--connect-timeout")
        .arg("20")
        .arg("--max-time")
        .arg("600")
        .arg("-H")
        .arg(format!("User-Agent: {USER_AGENT}"))
        .arg("-b")
        .arg(&jar)
        .arg("-c")
        .arg(&jar)
        .arg("-D")
        .arg(&hdr_path)
        .arg("-o")
        .arg("-"); // body to stdout
    if !req.stop_on_redirect {
        cmd.arg("-L").arg("--max-redirs").arg("8");
    }
    for (name, value) in &req.headers {
        cmd.arg("-H").arg(format!("{name}: {value}"));
    }
    if req.body.is_some() {
        cmd.arg("-X").arg(req.method).arg("--data-binary").arg("@-");
    } else if req.method != "GET" {
        // A POST without a payload still needs Content-Length: 0, or Apple's
        // front (Tomcat) answers 411 Length Required.
        cmd.arg("-X")
            .arg(req.method)
            .arg("-H")
            .arg("Content-Length: 0");
    }
    cmd.arg(req.url);
    if std::env::var("PERUN_STORE_HTTP_DEBUG").is_ok() {
        eprintln!("[store:http] {cmd:?}");
    }

    let mut child = cmd
        .stdin(if req.body.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn curl: {e}"))?;

    if let Some(body) = req.body.take() {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or("curl stdin closed")?;
        let mut off = 0usize;
        while off < body.len() {
            let n = stdin
                .write(&body[off..])
                .map_err(|e| format!("curl stdin: {e}"))?;
            off += n;
        }
        drop(stdin);
    }

    let mut out = child.stdout.take().ok_or("curl stdout closed")?;
    let mut err = child.stderr.take().ok_or("curl stderr closed")?;
    let mut body: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    let mut total_hint: Option<u64> = None;
    let mut hint_read = false;
    loop {
        let n = out
            .read(&mut chunk)
            .map_err(|e| format!("curl read: {e}"))?;
        if n == 0 {
            break;
        }
        let window = &chunk[..n];
        downloaded += window.len() as u64;
        // curl writes the response headers to the file before the first
        // body byte arrives — read the progress hint once, lazily.
        if !hint_read && req.sink.is_some() {
            if let Ok(raw) = std::fs::read(&hdr_path)
                && let Some(len) = content_length_of_last_hop(&raw)
            {
                total_hint = Some(len);
            }
            hint_read = true;
        }
        if let Some(sink) = req.sink.as_mut() {
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

    let mut stderr = Vec::new();
    err.read_to_end(&mut stderr).ok();
    let exit = child.wait().map_err(|e| format!("curl wait: {e}"))?.code();
    let raw_headers = std::fs::read(&hdr_path).unwrap_or_default();
    let _ = std::fs::remove_file(&hdr_path);

    let (status, headers) = parse_header_file(&raw_headers);
    if status == 0 {
        let msg = String::from_utf8_lossy(&stderr).trim().to_string();
        return Err(format!("curl exit {exit:?}: {msg}"));
    }

    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Parse the concatenated header blocks curl wrote (one per hop with -L).
/// The status comes from the last hop; a header set by a later hop wins.
fn parse_header_file(raw: &[u8]) -> (u16, HashMap<String, String>) {
    let text = String::from_utf8_lossy(raw);
    let mut status: u16 = 0;
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("HTTP/") {
            // rest looks like "1.1 200 OK" — pick the numeric status.
            let code = rest.split_whitespace().nth(1).unwrap_or("");
            status = code.parse().unwrap_or(status);
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            // Later hops override; X-Set-Apple-Store-Front must come from
            // the final response, not an intermediate bounce.
            headers.insert(name, value);
        }
    }
    (status, headers)
}

fn content_length_of_last_hop(raw: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(raw);
    let mut len: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("HTTP/") {
            len = None; // a new hop resets the length
        } else if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            len = value.trim().parse().ok();
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_file_edge_cases() {
        // Single hop, no headers.
        let raw = b"HTTP/1.1 204 No Content\r\n";
        let (status, headers) = parse_header_file(raw);
        assert_eq!(status, 204);
        assert!(headers.is_empty());
        // Three hops: last status wins, later header overrides.
        let raw = b"HTTP/1.1 302\r\nLocation: /a\r\nHTTP/1.1 301\r\nLocation: /b\r\nHTTP/1.1 200\r\nX-Last: 3\r\n";
        let (status, headers) = parse_header_file(raw);
        assert_eq!(status, 200);
        assert_eq!(headers.get("location").map(|s| s.as_str()), Some("/b"));
        assert_eq!(headers.get("x-last").map(|s| s.as_str()), Some("3"));
        // Non-numeric status keeps the previous value.
        let raw = b"HTTP/1.1 xyz\r\n";
        let (status, _) = parse_header_file(raw);
        assert_eq!(status, 0);
        // content_length_of_last_hop resets per hop.
        let raw = b"HTTP/1.1 302\r\nContent-Length: 999\r\nHTTP/1.1 200\r\n";
        assert_eq!(content_length_of_last_hop(raw), None);
    }
    #[test]
    fn header_file_two_hops() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: https://p25-buy/\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Set-Apple-Store-Front: 143441-1,32\r\n";
        let (status, headers) = parse_header_file(raw);
        assert_eq!(status, 200);
        assert_eq!(
            headers.get("x-set-apple-store-front").map(|s| s.as_str()),
            Some("143441-1,32")
        );
        assert_eq!(content_length_of_last_hop(raw), Some(5));
    }
}
