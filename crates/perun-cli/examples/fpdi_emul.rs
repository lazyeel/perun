// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! fpdi/init+setup protocol emulator: a faithful local stand-in for
//! `https://fpinit.itunes.apple.com/v1/fpdi/*`, captured live and frozen.
//!
//! Measured taxonomy (every cell probed against the live endpoints; only the
//! Content-Type gates the backend, bodies never discriminate):
//!
//! | method | known path (`init`/`setup`) | unknown path |
//! |---|---|---|
//! | GET | 405 + JSON envelope | 404 + JSON envelope |
//! | POST, no CT or `application/json*` | 500 + Jersey HTML (URI echoed) | 404 + JSON envelope |
//! | POST, any other CT | 415 + JSON envelope | 404 + JSON envelope |
//! | other (PUT/DELETE observed) | 403 + Akamai HTML | 403 + Akamai HTML (inferred: the edge filters the method first) |
//!
//! Modes:
//! ```sh
//! fpdi-emul stub [--port P]              # serve the taxonomy on 127.0.0.1
//! fpdi-emul probe --base URL             # run the matrix via curl, print it
//! fpdi-emul check                        # self-contained: stub thread + assert
//! ```
//!
//! Pure `std`, no dependencies. Like the SAP fetcher, the live side shells
//! out to `curl`. Unit tests pin the decision table and the exact bodies.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;

const PATHS: [&str; 2] = ["/v1/fpdi/init", "/v1/fpdi/setup"];

const JSON_405: &str = "{\"code\":405,\"message\":\"HTTP 405 Method Not Allowed\"}";
const JSON_404: &str = "{\"code\":404,\"message\":\"HTTP 404 Not Found\"}";
const JSON_415: &str = "{\"code\":415,\"message\":\"HTTP 415 Unsupported Media Type\"}";
const HTML_403: &str = "<HTML>\n<HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD>\n\n<BODY BGCOLOR=\"white\" FGCOLOR=\"black\">\n<H1>Access Denied</H1>\n<HR>\n\n<FONT FACE=\"Helvetica,Arial\"><B>\nDescription: You are not allowed to access the document you requested.\n</B></FONT>\n<HR>\n</BODY>\n";

fn html_500(uri: &str) -> String {
    format!(
        "<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html;charset=ISO-8859-1\"/>\n<title>Error 500 Internal Server Error</title>\n</head>\n<body><h2>HTTP ERROR 500 Internal Server Error</h2>\n<table>\n<tr><th>URI:</th><td>{uri}</td></tr>\n<tr><th>STATUS:</th><td>500</td></tr>\n<tr><th>MESSAGE:</th><td>Internal Server Error</td></tr>\n<tr><th>SERVLET:</th><td>jersey</td></tr>\n</table>\n\n</body>\n</html>\n"
    )
}

/// The frozen taxonomy: (method, path, content-type) -> (status, type, body).
///
/// Content-Type is the only header that matters, and only on POST to a known
/// path: missing or `application/json*` reaches the backend (500); anything
/// else is refused at the edge (415). Probed live cell by cell.
fn decide(method: &str, path: &str, ctype: Option<&str>) -> (u16, &'static str, String) {
    let known = PATHS.contains(&path);
    match (method, known) {
        ("GET", true) => (405, "application/json", JSON_405.to_string()),
        ("GET", false) => (404, "application/json", JSON_404.to_string()),
        ("POST", true) => match ctype {
            None => (500, "text/html", html_500(path)),
            Some(ct) if ct.split(';').next().unwrap_or("").trim() == "application/json" => {
                (500, "text/html", html_500(path))
            }
            Some(_) => (415, "application/json", JSON_415.to_string()),
        },
        ("POST", false) => (404, "application/json", JSON_404.to_string()),
        (_, _) => (403, "text/html", HTML_403.to_string()),
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

fn serve_conn(stream: TcpStream) {
    let mut r = BufReader::new(stream);
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        head.extend_from_slice(&line);
        if head.len() > 8192 {
            return;
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let mut stream = r.into_inner();
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let mut parts = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut ctype: Option<String> = None;
    for h in lines {
        let h = h.trim_end_matches('\r');
        if h.is_empty() {
            break;
        }
        if let Some(v) = h.strip_prefix("Content-Type:") {
            ctype = Some(v.trim().to_string());
        } else if let Some(v) = h.strip_prefix("content-type:") {
            ctype = Some(v.trim().to_string());
        }
    }
    if method.is_empty() || path.is_empty() {
        let _ = stream.write_all(
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let (code, ctype_out, body) = decide(method, path, ctype.as_deref());
    let resp = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype_out}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason(code),
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
}

/// Run the stub forever on 127.0.0.1:port (port 0 = ephemeral, prints addr).
fn run_stub(port: u16) -> i32 {
    let l = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind 127.0.0.1:{port}: {e}");
            return 1;
        }
    };
    eprintln!("[fpdi-emul] stub on {}", l.local_addr().unwrap());
    for c in l.incoming() {
        match c {
            Ok(s) => serve_conn(s),
            Err(e) => eprintln!("[fpdi-emul] accept: {e}"),
        }
    }
    0
}

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    ctype: Option<&'static str>,
    body: Option<Vec<u8>>,
}

fn matrix() -> Vec<Case> {
    let filler: Vec<u8> = (0u8..128).collect();
    let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>".to_vec();
    vec![
        Case {
            name: "get-init",
            method: "GET",
            path: "/v1/fpdi/init",
            ctype: None,
            body: None,
        },
        Case {
            name: "get-setup",
            method: "GET",
            path: "/v1/fpdi/setup",
            ctype: None,
            body: None,
        },
        Case {
            name: "get-unknown",
            method: "GET",
            path: "/v1/fpdi/nope",
            ctype: None,
            body: None,
        },
        Case {
            name: "post-empty",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: None,
            body: None,
        },
        Case {
            name: "post-noct-bytes",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: None,
            body: Some(filler.clone()),
        },
        Case {
            name: "post-json",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: Some("application/json"),
            body: Some(b"{}".to_vec()),
        },
        Case {
            name: "post-plist",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: Some("application/x-plist"),
            body: Some(plist.clone()),
        },
        Case {
            name: "post-octet",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: Some("application/octet-stream"),
            body: Some(filler.clone()),
        },
        Case {
            name: "post-setup-noct",
            method: "POST",
            path: "/v1/fpdi/setup",
            ctype: None,
            body: Some(filler.clone()),
        },
        Case {
            name: "post-unknown",
            method: "POST",
            path: "/v1/fpdi/nope",
            ctype: None,
            body: Some(filler),
        },
        Case {
            name: "put-init",
            method: "PUT",
            path: "/v1/fpdi/init",
            ctype: None,
            body: None,
        },
        Case {
            name: "post-urlencoded",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: Some("application/x-www-form-urlencoded"),
            body: Some(b"a=b".to_vec()),
        },
        Case {
            name: "post-json-charset",
            method: "POST",
            path: "/v1/fpdi/init",
            ctype: Some("application/json; charset=utf-8"),
            body: Some(b"{}".to_vec()),
        },
        Case {
            name: "put-unknown",
            method: "PUT",
            path: "/v1/fpdi/nope",
            ctype: None,
            body: None,
        },
        Case {
            name: "delete-init",
            method: "DELETE",
            path: "/v1/fpdi/init",
            ctype: None,
            body: None,
        },
        Case {
            name: "delete-unknown",
            method: "DELETE",
            path: "/v1/fpdi/nope",
            ctype: None,
            body: None,
        },
    ]
}

fn run_curl(base: &str, c: &Case, dir: &std::path::Path) -> (String, Vec<u8>) {
    let body_in = dir.join(format!("{}-in.bin", c.name));
    if let Some(b) = &c.body {
        std::fs::write(&body_in, b).unwrap();
    }
    let body_out = dir.join(format!("{}-out.bin", c.name));
    let mut cmd = Command::new("curl");
    cmd.args(["-s", "--max-time", "20", "-X", c.method]);
    if let Some(ct) = c.ctype {
        cmd.args(["-H", &format!("Content-Type: {ct}")]);
    } else if c.method == "POST" && c.body.is_some() {
        // Mirror the no-Content-Type probe: strip curl's default.
        cmd.args(["-H", "Content-Type:"]);
    }
    if c.body.is_some() {
        cmd.args(["--data-binary", &format!("@{}", body_in.display())]);
    }
    cmd.args([
        "-o",
        &body_out.to_string_lossy(),
        "-w",
        "%{http_code} %{size_download}",
    ]);
    cmd.arg(format!("{base}{}", c.path));
    let out = cmd.output().expect("curl missing from PATH");
    let meta = String::from_utf8_lossy(&out.stdout).into_owned();
    let body = std::fs::read(&body_out).unwrap_or_default();
    (meta, body)
}

fn probe(base: &str) -> i32 {
    let dir: PathBuf = std::env::temp_dir().join(format!("fpdi-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    println!(
        "{:<16} {:<6} {:<16} {:<28} {:<14} {}",
        "case", "method", "path", "content-type", "result", "body-head"
    );
    for c in matrix() {
        let (meta, body) = run_curl(base, &c, &dir);
        let head = String::from_utf8_lossy(&body[..body.len().min(64)]).replace('\n', "\\n");
        println!(
            "{:<16} {:<6} {:<16} {:<28} {:<14} {}",
            c.name,
            c.method,
            c.path,
            c.ctype.unwrap_or("(none)"),
            meta.trim(),
            head
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    0
}

/// Self-contained check: stub on a thread, matrix against it, assert all.
fn check() -> i32 {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            if let Ok(s) = c {
                serve_conn(s);
            }
        }
    });
    let base = format!("http://127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            break;
        }
        if std::time::Instant::now() > deadline {
            eprintln!("error: stub did not come up");
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let dir: PathBuf = std::env::temp_dir().join(format!("fpdi-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut failed = 0;
    for c in matrix() {
        let (meta, body) = run_curl(&base, &c, &dir);
        let (code, _, want) = decide(c.method, c.path, c.ctype);
        let want_meta = format!("{code} {}", want.len());
        let ok = meta.trim() == want_meta && body == want.as_bytes();
        println!(
            "{} {} -> {} {}",
            if ok { "PASS" } else { "FAIL" },
            c.name,
            meta.trim(),
            body.len()
        );
        if !ok {
            failed += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    if failed > 0 {
        eprintln!("{failed} case(s) mismatched");
        1
    } else {
        println!("all cases match the frozen taxonomy");
        0
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rc = match args.first().map(String::as_str) {
        Some("stub") => {
            let port = args
                .windows(2)
                .find(|w| w[0] == "--port")
                .and_then(|w| w[1].parse().ok())
                .unwrap_or(18080);
            run_stub(port)
        }
        Some("probe") => {
            let base = args
                .windows(2)
                .find(|w| w[0] == "--base")
                .map(|w| w[1].clone())
                .unwrap_or_else(|| "https://fpinit.itunes.apple.com".to_string());
            probe(&base)
        }
        Some("check") => check(),
        _ => {
            eprintln!("usage: fpdi-emul (stub [--port P] | probe [--base URL] | check)");
            2
        }
    };
    std::process::exit(rc);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_get() {
        assert_eq!(decide("GET", "/v1/fpdi/init", None).0, 405);
        assert_eq!(decide("GET", "/v1/fpdi/setup", None).0, 405);
        assert_eq!(decide("GET", "/v1/fpdi/nope", None).0, 404);
    }

    #[test]
    fn taxonomy_post() {
        assert_eq!(decide("POST", "/v1/fpdi/init", None).0, 500);
        assert_eq!(decide("POST", "/v1/fpdi/setup", None).0, 500);
        assert_eq!(decide("POST", "/x", None).0, 404);
    }

    #[test]
    fn taxonomy_post_content_type_gate() {
        // Missing or application/json* reaches the backend; anything else 415.
        assert_eq!(
            decide("POST", "/v1/fpdi/init", Some("application/json")).0,
            500
        );
        assert_eq!(
            decide(
                "POST",
                "/v1/fpdi/init",
                Some("application/json; charset=utf-8")
            )
            .0,
            500
        );
        for ct in [
            "application/x-plist",
            "application/octet-stream",
            "application/x-www-form-urlencoded",
            "text/xml",
            "text/plain",
        ] {
            let (code, _, body) = decide("POST", "/v1/fpdi/init", Some(ct));
            assert_eq!(code, 415, "ct={ct}");
            assert_eq!(body, JSON_415);
        }
    }

    #[test]
    fn taxonomy_other_methods() {
        for m in ["PUT", "DELETE", "PATCH", "HEAD"] {
            assert_eq!(decide(m, "/v1/fpdi/init", None).0, 403);
        }
    }

    #[test]
    fn bodies_byte_exact() {
        assert_eq!(
            JSON_405,
            "{\"code\":405,\"message\":\"HTTP 405 Method Not Allowed\"}"
        );
        assert_eq!(
            JSON_404,
            "{\"code\":404,\"message\":\"HTTP 404 Not Found\"}"
        );
        assert!(HTML_403.contains("Access Denied"));
        assert_eq!(HTML_403.len(), 249);
        let b = html_500("/v1/fpdi/init");
        assert_eq!(b.len(), 410);
        assert!(b.contains("<td>/v1/fpdi/init</td>"));
        assert!(b.contains("SERVLET:</th><td>jersey</td>"));
    }

    #[test]
    fn matrix_covers_taxonomy_cells() {
        let m = matrix();
        // every (method-class, path-class) cell appears at least once
        for method in ["GET", "POST", "PUT", "DELETE"] {
            for path in ["/v1/fpdi/init", "/v1/fpdi/nope"] {
                assert!(
                    m.iter().any(|c| c.method == method && c.path == path),
                    "missing {method} {path}"
                );
            }
        }
    }
}
