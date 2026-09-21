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
use std::io::{Read, Seek, SeekFrom};
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
fn check_range_response(status: u16, headers: &HashMap<String, String>, local: u64) -> Result<(), String> {
    let get = |name: &str| {
        headers
            .get(&name.to_ascii_lowercase())
            .map(|s| s.as_str())
    };
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
            let (start_text, end_text) =
                bounds.split_once('-').ok_or_else(|| {
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
    // File sink is buffered here (1 MiB) so the resume path keeps the
    // caller's large-write behavior without the caller owning a BufWriter
    // across the truncate point.
    let mut file_buf: Option<std::io::BufWriter<&mut std::fs::File>> =
        req.file_sink.as_mut().map(|f| {
            let f: &mut std::fs::File = f;
            std::io::BufWriter::with_capacity(1 << 20, f)
        });
    let has_sink = req.sink.is_some() || file_buf.is_some();
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
        if !hint_read && has_sink {
            if let Ok(raw) = std::fs::read(&hdr_path) {
                let (st, hdrs) = parse_header_file(&raw);
                if let Some(start) = req.range_start {
                    // Validate the range answer before the first byte
                    // reaches the sink.
                    check_range_response(st, &hdrs, start)?;
                    // 200-after-resume: the server ignored Range and sends
                    // the full body. Truncate the partial BEFORE streaming
                    // so the fresh body starts at offset 0.
                    if let Some(buf) = file_buf.as_mut() {
                        truncate_file_for_fresh(buf.get_mut(), st, req.range_start)?;
                    }
                }
                if let Some(len) = content_length_of_last_hop(&raw) {
                    total_hint = Some(len);
                }
            }
            hint_read = true;
        }
        if let Some(buf) = file_buf.as_mut() {
            use std::io::Write;
            buf.write_all(window)
                .map_err(|e| format!("sink write: {e}"))?;
            // Flush once per chunk so a crash mid-download leaves the tail
            // on disk and resumable.
            buf.flush().ok();
        } else if let Some(sink) = req.sink.as_mut() {
            sink.write_all(window)
                .map_err(|e| format!("sink write: {e}"))?;
            // Flush once per chunk so a crash mid-download leaves the tail
            // on disk and resumable. The BufWriter on the caller side
            // already coalesces the tiny writes, so this is a single
            // buffered flush() — acceptable for now.
            sink.flush().ok();
        } else {
            body.extend_from_slice(window);
        }
        if let Some(progress) = req.progress.as_mut() {
            progress(downloaded, total_hint.unwrap_or(0));
        }
    }
    if let Some(buf) = file_buf.as_mut() {
        use std::io::Write;
        buf.flush().map_err(|e| format!("sink flush: {e}"))?;
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
        let h = range_hdrs(&[("content-range", "bytes 1000-28410/28411"), ("content-length", "27411")]);
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
