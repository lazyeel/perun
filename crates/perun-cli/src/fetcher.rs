// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Zero-config asset fetcher for the SAP runtime.
//!
//! On first run (or when the cache is invalid), this module downloads the four
//! Apple commerce images the runtime needs, directly from Apple's public
//! software-update distribution — without fetching the full 1.28 GB package:
//!
//! 1. `GET` the xar header + TOC of `OSXUpd10.9.pkg` (a few KB) and locate the
//!    `Payload` heap object.
//! 2. Range-request the compressed payload **tail** starting at the measured
//!    block boundary, prepend the synthesized bzip2 stream header `"BZh9"`,
//!    and decompress with the pure-Rust `bzip2-rs` decoder.
//! 3. Skip the 932-byte prefix inside the decompressed stream and walk the
//!    `odc` cpio archive until all four pinned files are extracted.
//! 4. Verify each file's size and SHA-256 against the pinned constants (the
//!    same digests the loader checks), then store them in the cache directory.
//!
//! The same initialization also fetches the SAP setup certificate once; it is
//! served with `Last-Modified: 2016` and effectively never changes, so the
//! hot path performs zero network round-trips to the CDN on cache hits.
//!
//! All network I/O shells out to `curl` (same model as the protocol module):
//! no TLS stack is linked into the binary.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Apple software update package (public, 2013; URL pinned like the reference
/// implementations). Layout measurements below were taken against exactly
/// this file on 2026-09-02; the constants are re-validated at runtime by
/// digest checks, so a changed layout fails loudly instead of silently.
const UPDATE_URL: &str = "https://swcdn.apple.com/content/downloads/27/34/041-98128-A_SYPWICN3KH/5dqkl4rqgbsr18yzy61yeie9g3cmjc5hiv/OSXUpd10.9.pkg";

/// Offset (inside the compressed `Payload` heap object) of the bzip2 block
/// boundary that opens the archive slice containing the commerce images. The
/// stream header `"BZh9"` is synthesized in front of it; the bytes at this
/// offset start with the block magic `31 41 59 26 53 59` (`"1AY&SY"`).
const PAYLOAD_BZ_OFFSET: u64 = 0x352F_40D5;

/// Bytes to discard in the decompressed stream before the first cpio entry.
const PAYLOAD_CPIO_SKIP: u64 = 0x3A4;

/// Setup certificate URL and cache file name. Served with
/// `last-modified: 2016`; re-validated at most once a day (TTL below).
const SETUP_CERT_URL: &str = "https://s.mzstatic.com/sap/setup.crt";
pub const SETUP_CERT_FILE: &str = "setup.crt";
const SETUP_CERT_TTL: u64 = 24 * 60 * 60;
const SETUP_CERT_MIN_LEN: usize = 64;

/// (name, expected size, pinned sha256) — kept byte-identical with the loader's
/// validation, which re-checks whatever this fetcher writes.
const PINNED: &[(&str, u64, &str)] = &[
    (
        "CoreFP",
        29_014_912,
        "f19141336be4198d0f8991bb00017c915efc7aeaece36c345f7faa1237ea6074",
    ),
    (
        "CoreFP.icxs",
        5_288_352,
        "473e78af86979f5bd4f6269561caf770b3d16c098d918846eeac8cdd2fe6566a",
    ),
    (
        "CommerceKit",
        3_271_840,
        "b84ff12c21987856c0a17b78f1ad82b73195a6dec5f3b208a17d245555a2c8a2",
    ),
    (
        "CommerceCore",
        207_744,
        "c5401e57402230f3c876409d295319ddf1e61287bc882683c5d61277be7bc1f2",
    ),
];

/// Full cpio paths of the pinned files inside the update payload.
const CPIO_PATHS: &[(&str, &str)] = &[
    // (pinned name, archive path)
    (
        "CommerceKit",
        "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/CommerceKit",
    ),
    (
        "CommerceCore",
        "./System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Frameworks/CommerceCore.framework/Versions/A/CommerceCore",
    ),
    (
        "CoreFP",
        "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
    ),
    (
        "CoreFP.icxs",
        "./System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP.icxs",
    ),
];

const PROGRESS_EVERY: u64 = 16 << 20;

// ── cache directory ───────────────────────────────────────────────────────

/// Resolve the asset cache directory: `$PERUN_SAP_DIR` if set, else
/// `~/.cache/perun/sap/` (XDG-style). The directory is created on demand.
pub fn cache_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("PERUN_SAP_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
        return Ok(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = Path::new(&home).join(".cache").join("perun").join("sap");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

fn sha256_hex(data: &[u8]) -> String {
    // Minimal SHA-256 (FIPS 180-4); avoids pulling a crypto crate for four
    // digests per initialization.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

// ── curl plumbing (same model as the protocol module) ─────────────────────

fn curl_range(url: &str, start: u64, end_inclusive: u64) -> Result<Vec<u8>, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "--max-time",
            "60",
            "-H",
            "User-Agent: Configurator/2.15 (Macintosh; OS X 14.2; 16C68)",
            "-r",
            &format!("{start}-{end_inclusive}"),
            url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl range {start}-{end_inclusive} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Sequential `Read` over the network tail via `curl`, internally buffered in
/// large windows: one curl process per 8 MiB, serving small `read()` calls
/// (the bzip2 decoder pulls ~1 KB at a time) from the in-memory window.
struct RangeTailReader {
    url: String,
    pos: u64,
    window: Vec<u8>,
    fetched: u64,
}

impl RangeTailReader {
    fn new(url: &str, start: u64) -> Self {
        Self {
            url: url.to_string(),
            pos: start,
            window: Vec::new(),
            fetched: 0,
        }
    }

    /// Fetch the next window into memory. On success, `window` is non-empty.
    fn refill(&mut self) -> std::io::Result<()> {
        if !self.window.is_empty() {
            return Ok(());
        }
        const WINDOW: u64 = 8 << 20;
        let data = curl_range(&self.url, self.pos, self.pos + WINDOW - 1)
            .map_err(std::io::Error::other)?;
        self.window = data;
        self.fetched += self.window.len() as u64;
        Ok(())
    }
}

impl Read for RangeTailReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.window.is_empty() {
            self.refill()?;
            if self.window.is_empty() {
                return Ok(0); // tail exhausted
            }
        }
        let take = self.window.len().min(buf.len());
        buf[..take].copy_from_slice(&self.window[..take]);
        self.window.drain(..take);
        self.pos += take as u64;
        Ok(take)
    }
}

// ── xar TOC (zlib via a minimal in-tree inflate is overkill; TOC is small
//    enough to shell out) ──────────────────────────────────────────────────

fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, String> {
    // The xar TOC is a few KB of zlib data; pipe through python3 (present on
    // every Linux this targets) to avoid linking a TLS-stack-sized inflate.
    use std::io::Write;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg("import sys,zlib;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn python3 (zlib): {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(data)
        .map_err(|e| format!("zlib stdin: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("zlib wait: {e}"))?;
    if !out.status.success() {
        return Err("zlib decompress failed".into());
    }
    Ok(out.stdout)
}

/// Absolute byte range of the `Payload` heap object inside the package.
fn payload_range(url: &str) -> Result<(u64, u64), String> {
    let head = curl_range(url, 0, 8191)?;
    if head.len() < 24 || &head[..4] != b"xar!" {
        return Err("update package is not a xar container".into());
    }
    let hlen = u16::from_be_bytes(head[4..6].try_into().unwrap()) as u64;
    let toc_cl = u64::from_be_bytes(head[8..16].try_into().unwrap());
    let toc_raw = curl_range(url, hlen, hlen + toc_cl - 1)?;
    let toc = inflate_zlib(&toc_raw)?;
    let text = String::from_utf8_lossy(&toc);
    let mut heap = hlen + toc_cl;
    for block in text.split("<file ").skip(1) {
        let name = tag(block, "name");
        if name.as_deref() != Some("Payload") {
            continue;
        }
        let off = tag(block, "offset").and_then(|v| v.parse::<u64>().ok());
        let len = tag(block, "length").and_then(|v| v.parse::<u64>().ok());
        if let (Some(off), Some(len)) = (off, len) {
            heap += off;
            return Ok((heap, len));
        }
    }
    Err("Payload not found in package TOC".into())
}

fn tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = block.find(&open)? + open.len();
    let j = block[i..].find(&close)? + i;
    Some(block[i..j].to_string())
}

// ── cpio walk ─────────────────────────────────────────────────────────────

const CPIO_MAGIC: &[u8; 6] = b"070707";
const CPIO_HEADER: usize = 76;
const CPIO_NAMESIZE_AT: usize = 59;
const CPIO_FILESIZE_AT: usize = 65;
const CPIO_FILESIZE_LEN: usize = 11; // odc: 11 octal digits, space-padded

fn octal_field(hdr: &[u8], at: usize, len: usize) -> Result<u64, String> {
    let raw = &hdr[at..at + len];
    let s = String::from_utf8_lossy(raw);
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| format!("bad octal field {s:?}"))
}

/// Read exactly `n` bytes or fail.
fn read_exact(reader: &mut dyn Read, n: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; n];
    let mut done = 0usize;
    while done < n {
        let got = reader
            .read(&mut out[done..])
            .map_err(|e| format!("archive read: {e}"))?;
        if got == 0 {
            let missing = n - done;
            return Err(format!("archive ended {missing} bytes early"));
        }
        done += got;
    }
    Ok(out)
}

fn skip(reader: &mut dyn Read, mut n: u64) -> Result<(), String> {
    let mut sink = vec![0u8; 1 << 20];
    while n > 0 {
        let take = sink.len().min(n as usize);
        let got = reader
            .read(&mut sink[..take])
            .map_err(|e| format!("archive skip: {e}"))?;
        if got == 0 {
            return Err("archive ended during skip".into());
        }
        n -= got as u64;
    }
    Ok(())
}

// ── top-level API ─────────────────────────────────────────────────────────

/// `BZh9` prefix followed by the network tail.
struct PrefixedTailReader {
    prefix: std::io::Cursor<Vec<u8>>,
    tail: RangeTailReader,
}

impl Read for PrefixedTailReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Prefix first (exactly once); then the tail.
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            return self.prefix.read(buf);
        }
        self.tail.read(buf)
    }
}

/// Ensure the asset cache is complete; download what is missing. Returns the
/// directory holding the four images (`test-sap` layout compatible).
pub fn ensure_cache(verbose: bool) -> Result<PathBuf, String> {
    let dir = cache_dir()?;

    // Fast path: everything cached and pinned.
    if cache_complete(&dir) {
        if verbose {
            eprintln!("[fetcher] assets cached at {}", dir.display());
        }
        return Ok(dir);
    }

    eprintln!(
        "[fetcher] first run: fetching Apple commerce assets (~32 MB of the 1.28 GB update package)…"
    );
    let t0 = std::time::Instant::now();
    let (p_abs, p_len) = payload_range(UPDATE_URL)?;
    if verbose {
        eprintln!(
            "[fetcher] payload at {p_abs:#x}, {p_len} bytes; tail from {:#x}",
            p_abs + PAYLOAD_BZ_OFFSET
        );
    }

    // Synthesized header + network tail: the reader equivalent of the
    // reference implementation's `io.MultiReader` (stream-header synthesis).
    let tail = RangeTailReader::new(UPDATE_URL, p_abs + PAYLOAD_BZ_OFFSET);
    let mut stream = bzip2_rs::DecoderReader::new(PrefixedTailReader {
        prefix: std::io::Cursor::new(b"BZh9".to_vec()),
        tail,
    });
    skip(&mut stream, PAYLOAD_CPIO_SKIP)?;

    let mut wanted: Vec<(&str, &str, u64, &str)> = CPIO_PATHS
        .iter()
        .filter_map(|(name, path)| {
            PINNED
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, size, sha)| (*name, *path, *size, *sha))
        })
        .collect();
    let total = wanted.len();
    let mut found = 0usize;
    let mut walked: u64 = 0;

    while found < total {
        let hdr = read_exact(&mut stream, CPIO_HEADER)?;
        if &hdr[..6] != CPIO_MAGIC {
            return Err(format!("cpio desync after {walked} decompressed bytes"));
        }
        let name_size = octal_field(&hdr, CPIO_NAMESIZE_AT, 6)? as usize;
        let file_size = octal_field(&hdr, CPIO_FILESIZE_AT, CPIO_FILESIZE_LEN)?;
        let name_b = read_exact(&mut stream, name_size)?;
        walked += (CPIO_HEADER + name_size) as u64;
        if name_b.is_empty() || name_b[name_b.len() - 1] != 0 {
            return Err("cpio entry name is not NUL-terminated".into());
        }
        let name = String::from_utf8_lossy(&name_b[..name_b.len() - 1]).to_string();
        if name == "TRAILER!!!" {
            return Err("reached cpio trailer before all assets were found".into());
        }

        if let Some(idx) = wanted.iter().position(|(_, p, _, _)| *p == name) {
            let (name, _, exp_size, pin) = wanted[idx];
            let mut body = Vec::with_capacity(exp_size as usize);
            let mut rem = file_size;
            while rem > 0 {
                let take = (1 << 20).min(rem as usize);
                let chunk = read_exact(&mut stream, take)?;
                body.extend_from_slice(&chunk);
                rem -= chunk.len() as u64;
            }
            let (ok_size, ok_sha) = (body.len() as u64 == exp_size, sha256_hex(&body) == pin);
            if !(ok_size && ok_sha) {
                return Err(format!(
                    "asset {name} failed validation (size {} vs {exp_size}, digest {})",
                    body.len(),
                    if ok_sha { "ok" } else { "MISMATCH" }
                ));
            }
            let tmp = dir.join(format!(".{name}.part"));
            std::fs::write(&tmp, &body).map_err(|e| format!("write {tmp:?}: {e}"))?;
            std::fs::rename(&tmp, dir.join(name)).map_err(|e| format!("rename {name}: {e}"))?;
            let elapsed = t0.elapsed().as_secs_f64();
            eprintln!(
                "[fetcher] {name}: {} bytes, digest ok ({}/{}), {elapsed:.0}s",
                body.len(),
                found + 1,
                total,
            );
            found += 1;
            wanted.remove(idx);
            walked += file_size;
            continue;
        }

        skip(&mut stream, file_size)?;
        walked += file_size;
        if walked > PROGRESS_EVERY && walked % PROGRESS_EVERY < (8 << 20) {
            eprintln!("[fetcher] walking archive: {walked} decompressed bytes…",);
        }
    }

    eprintln!(
        "[fetcher] all {total} assets fetched and pinned in {:.1}s",
        t0.elapsed().as_secs_f64()
    );
    Ok(dir)
}

fn cache_complete(dir: &Path) -> bool {
    for (name, size, sha) in PINNED {
        let path = dir.join(name);
        let Ok(data) = std::fs::read(&path) else {
            return false;
        };
        if data.len() as u64 != *size || sha256_hex(&data) != *sha {
            return false;
        }
    }
    true
}

/// Ensure the setup certificate is cached (fetched at most once per day).
/// Returns the path to the cached certificate.
pub fn ensure_cert() -> Result<PathBuf, String> {
    let dir = cache_dir()?;
    let path = dir.join(SETUP_CERT_FILE);
    if let Ok(meta) = std::fs::metadata(&path) {
        let fresh = meta
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_none_or(|age| age.as_secs() < SETUP_CERT_TTL);
        if fresh && meta.len() as usize >= SETUP_CERT_MIN_LEN {
            return Ok(path);
        }
    }
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "--max-time",
            "30",
            "-H",
            "User-Agent: Configurator/2.15 (Macintosh; OS X 14.2; 16C68)",
            SETUP_CERT_URL,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "certificate fetch failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.len() < SETUP_CERT_MIN_LEN {
        return Err(format!(
            "certificate suspiciously short: {}",
            out.stdout.len()
        ));
    }
    let tmp = dir.join(".setup.crt.part");
    std::fs::write(&tmp, &out.stdout).map_err(|e| format!("write {tmp:?}: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename cert: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_fips_vectors() {
        // FIPS 180-4 / NIST reference digests.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn pinned_corefp_digest_matches_test_assets() {
        // Ground truth tie-in: the pinned digest constant must equal the real
        // file when the test corpus is present (it is gitignored; skip is fine).
        if let Ok(data) = std::fs::read("test-sap/CoreFP") {
            assert_eq!(sha256_hex(&data), PINNED[0].2);
        }
    }
}
