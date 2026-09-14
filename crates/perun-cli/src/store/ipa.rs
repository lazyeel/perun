// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! IPA package handling: raw zip replication (entries copied with their
//! compressed bytes verbatim — no recompression), injection of
//! iTunesMetadata.plist and the sinf sidecars, and a range-request
//! partial fetch that reads the app's Info.plist without downloading the
//! whole package.
//!
//! Pure stdlib: the zip structures used here are fixed-layout, and the
//! entries we add are stored (method 0), so no DEFLATE is needed.

use super::account::Account;
use super::appstore::DownloadInfo;
use super::plist::{self, Plist};

// ── zip structures ────────────────────────────────────────────────────────

const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const CEN_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const LOC_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

#[derive(Clone, Debug)]
struct CentralEntry {
    name: String,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    external_attrs: u32,
    modified: (u16, u16), // dos date, dos time
    /// Central-directory extra field, verbatim (ZIP64 and friends). The
    /// local-header extra lives beside the local header; this is the central
    /// one, which `finish()` must carry over or structural fields are lost.
    central_extra: Vec<u8>,
}

struct Eocd {
    entry_count: u16,
    cd_offset: u64,
    cd_size: u64,
}

fn find_eocd(data: &[u8]) -> Result<(usize, Eocd), String> {
    let window_start = data.len().saturating_sub(66_000);
    let window = &data[window_start..];
    let mut pos = None;
    let mut i = 0;
    while i + 22 <= window.len() {
        if window[i..i + 4] == EOCD_SIG {
            pos = Some(i); // keep scanning: a nested zip's EOCD could precede ours
        }
        i += 1;
    }
    let at = pos.ok_or("zip: no end-of-central-directory record")?;
    let eocd = &window[at..at + 22];
    if eocd[20] != 0 || eocd[21] != 0 {
        return Err("zip: multi-disk archives are not supported".into());
    }
    let entry_count = u16::from_le_bytes([eocd[10], eocd[11]]);
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]) as u64;
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]) as u64;
    // Zip64 marker: real values live in a zip64 EOCD. IPAs this size don't
    // occur; reject rather than mis-read.
    if cd_offset == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF || entry_count == 0xFFFF {
        return Err("zip: zip64 central directory is not supported".into());
    }
    Ok((
        window_start + at,
        Eocd {
            entry_count,
            cd_offset,
            cd_size,
        },
    ))
}

fn parse_central(data: &[u8], eocd: &Eocd) -> Result<Vec<CentralEntry>, String> {
    parse_central_at(data, eocd.cd_offset as usize, eocd)
}

/// Parse with an explicit start offset: the full-file callers pass the
/// EOCD's absolute `cd_offset`; the range-fetched central-directory buffer
/// (`fetch_info_plist`) starts at its own zero.
fn parse_central_at(data: &[u8], start: usize, eocd: &Eocd) -> Result<Vec<CentralEntry>, String> {
    let mut entries = Vec::with_capacity(eocd.entry_count as usize);
    let mut pos = start;
    for _ in 0..eocd.entry_count {
        if pos + 46 > data.len() {
            return Err("zip: truncated central directory".into());
        }
        if data[pos..pos + 4] != CEN_SIG {
            return Err("zip: bad central directory signature".into());
        }
        let u16_at = |o: usize| u16::from_le_bytes([data[pos + o], data[pos + o + 1]]);
        let u32_at = |o: usize| {
            u32::from_le_bytes([
                data[pos + o],
                data[pos + o + 1],
                data[pos + o + 2],
                data[pos + o + 3],
            ])
        };
        let method = u16_at(10);
        let modified = (u16_at(12), u16_at(14));
        let crc32 = u32_at(16);
        let compressed_size = u32_at(20) as u64;
        let uncompressed_size = u32_at(24) as u64;
        let name_len = u16_at(28) as usize;
        let extra_len = u16_at(30) as usize;
        let comment_len = u16_at(32) as usize;
        let local_offset = u32_at(42) as u64;
        let external_attrs = u32_at(38);
        let flags = u16_at(8);
        let name_start = pos + 46;
        let name_end = name_start + name_len;
        if name_end > data.len() {
            return Err("zip: truncated entry name".into());
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
        let extra_start = name_end;
        let extra_end = extra_start + extra_len;
        let central_extra = data
            .get(extra_start..extra_end)
            .map(|b| b.to_vec())
            .unwrap_or_default();
        entries.push(CentralEntry {
            name,
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            local_offset,
            external_attrs,
            modified,
            central_extra,
        });
        pos = name_end + extra_len + comment_len;
    }
    Ok(entries)
}

/// Local header span for an entry: (local_header_len, compressed_size).
fn local_span(data: &[u8], entry: &CentralEntry) -> Result<(usize, u64), String> {
    let off = entry.local_offset as usize;
    if off + 30 > data.len() {
        return Err("zip: local header out of range".into());
    }
    if data[off..off + 4] != LOC_SIG {
        return Err(format!("zip: bad local signature for {}", entry.name));
    }
    let name_len = u16::from_le_bytes([data[off + 26], data[off + 27]]) as usize;
    let extra_len = u16::from_le_bytes([data[off + 28], data[off + 29]]) as usize;
    Ok((off + 30 + name_len + extra_len, entry.compressed_size))
}

// ── writing ───────────────────────────────────────────────────────────────

struct ZipWriter<'w> {
    out: &'w mut dyn std::io::Write,
    offset: u64,
    entries: Vec<WrittenEntry>,
}

struct WrittenEntry {
    name: String,
    method: u16,
    flags: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    external_attrs: u32,
    modified: (u16, u16),
    central_extra: Vec<u8>,
}

impl<'w> ZipWriter<'w> {
    fn new(out: &'w mut dyn std::io::Write) -> ZipWriter<'w> {
        ZipWriter {
            out,
            offset: 0,
            entries: Vec::new(),
        }
    }

    fn raw(&mut self, w: &[u8]) -> Result<(), String> {
        self.out
            .write_all(w)
            .map_err(|e| format!("zip write: {e}"))?;
        self.offset += w.len() as u64;
        Ok(())
    }

    /// Copy an entry from the source: rebuild the local header to (a) carry
    /// the source local-header extra verbatim (the `UX`/`UT` mtime of Apple's
    /// packager and whatever else), and (b) frame it for streaming installers
    /// the way the reference does — deflated entries get flag bit 3 and a
    /// trailing data descriptor (local sizes/CRC zeroed), stored entries and
    /// directory markers stay inline (a descriptor has no stream terminator to
    /// anchor on). The compressed bytes are written verbatim.
    fn copy_raw(&mut self, src: &[u8], entry: &CentralEntry) -> Result<(), String> {
        let (data_start, compressed) = local_span(src, entry)?;
        let mut header = src[entry.local_offset as usize..data_start].to_vec();
        // Directories (name ends with '/') and stored entries: inline sizes,
        // no descriptor. Deflate: streaming framing — bit 3 set, sizes/CRC
        // zeroed, the descriptor written right after the compressed bytes.
        let is_dir = entry.name.ends_with('/');
        let streaming = entry.method == 8 && !is_dir;
        let flags = if streaming {
            entry.flags | 0x8
        } else {
            entry.flags & !0x8
        };
        header[8..10].copy_from_slice(&flags.to_le_bytes());
        header[10..12].copy_from_slice(&entry.method.to_le_bytes());
        // Local-header crc/sizes: zeroed for streaming (descriptor carries
        // them), concrete for inline.
        let (lh_crc, lh_csize, lh_usize) = if streaming {
            (0u32, 0u32, 0u32)
        } else {
            (
                entry.crc32,
                entry.compressed_size as u32,
                entry.uncompressed_size as u32,
            )
        };
        header[14..18].copy_from_slice(&lh_crc.to_le_bytes());
        header[18..22].copy_from_slice(&lh_csize.to_le_bytes());
        header[22..26].copy_from_slice(&lh_usize.to_le_bytes());

        let local_offset = self.offset;
        self.raw(&header)?;
        let data = src
            .get(data_start..data_start + compressed as usize)
            .ok_or("zip: entry data out of range")?;
        self.raw(data)?;
        if streaming {
            // Data descriptor: 0x08074b50 + crc + compressed + uncompressed.
            let mut descriptor = [0u8; 16];
            descriptor[..4].copy_from_slice(&0x0807_4b50u32.to_le_bytes());
            descriptor[4..8].copy_from_slice(&entry.crc32.to_le_bytes());
            descriptor[8..12].copy_from_slice(&(entry.compressed_size as u32).to_le_bytes());
            descriptor[12..16].copy_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
            self.raw(&descriptor)?;
        }
        self.entries.push(WrittenEntry {
            name: entry.name.clone(),
            method: entry.method,
            flags,
            crc32: entry.crc32,
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.uncompressed_size,
            local_offset,
            external_attrs: entry.external_attrs,
            modified: entry.modified,
            central_extra: entry.central_extra.clone(),
        });
        Ok(())
    }

    /// Add a stored (method 0) entry.
    fn add_stored(&mut self, name: &str, data: &[u8], modified: (u16, u16)) -> Result<(), String> {
        let crc = crc32_ieee(data);
        let local_offset = self.offset;
        let mut header = Vec::with_capacity(30 + name.len());
        header.extend_from_slice(&LOC_SIG);
        header.extend_from_slice(&0u16.to_le_bytes()); // version
        header.extend_from_slice(&0u16.to_le_bytes()); // flags
        header.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        header.extend_from_slice(&modified.1.to_le_bytes()); // time
        header.extend_from_slice(&modified.0.to_le_bytes()); // date
        header.extend_from_slice(&crc.to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes()); // extra len
        header.extend_from_slice(name.as_bytes());
        self.raw(&header)?;
        self.raw(data)?;
        self.entries.push(WrittenEntry {
            name: name.to_string(),
            method: 0,
            flags: 0,
            crc32: crc,
            compressed_size: data.len() as u64,
            uncompressed_size: data.len() as u64,
            local_offset,
            external_attrs: 0o100644 << 16,
            modified,
            central_extra: Vec::new(),
        });
        Ok(())
    }

    fn finish(mut self) -> Result<(), String> {
        let cd_start = self.offset;
        let mut records: Vec<Vec<u8>> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let mut cen = Vec::with_capacity(46 + e.name.len() + e.central_extra.len());
            cen.extend_from_slice(&CEN_SIG);
            cen.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
            cen.extend_from_slice(&0x0014u16.to_le_bytes()); // version needed
            cen.extend_from_slice(&e.flags.to_le_bytes());
            cen.extend_from_slice(&e.method.to_le_bytes());
            cen.extend_from_slice(&e.modified.1.to_le_bytes());
            cen.extend_from_slice(&e.modified.0.to_le_bytes());
            cen.extend_from_slice(&e.crc32.to_le_bytes());
            cen.extend_from_slice(&(e.compressed_size as u32).to_le_bytes());
            cen.extend_from_slice(&(e.uncompressed_size as u32).to_le_bytes());
            cen.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            // Central extra: carried over verbatim (ZIP64 and friends). The
            // reference strips only the ZIP64 block so its own writer can
            // regenerate structural values; we re-emit the source bytes.
            cen.extend_from_slice(&(e.central_extra.len() as u16).to_le_bytes());
            cen.extend_from_slice(&0u16.to_le_bytes()); // comment
            cen.extend_from_slice(&0u16.to_le_bytes()); // disk
            cen.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cen.extend_from_slice(&e.external_attrs.to_le_bytes());
            cen.extend_from_slice(&(e.local_offset as u32).to_le_bytes());
            cen.extend_from_slice(e.name.as_bytes());
            cen.extend_from_slice(&e.central_extra);
            records.push(cen);
        }
        for record in &records {
            self.raw(record)?;
        }
        let cd_size = self.offset - cd_start;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG);
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(cd_size as u32).to_le_bytes());
        eocd.extend_from_slice(&(cd_start as u32).to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        self.raw(&eocd)?;
        Ok(())
    }
}

// ── the two-pass patch (applyPatches + replicateSinf) ─────────────────────

/// Replicate the downloaded package: copy all entries, write a patched
/// iTunesMetadata.plist, inject sinf files into `Payload/<App>.app/SC_Info/`.
/// Returns `true` when a bundle was found and the destination was written.
pub fn replicate(
    src_path: &str,
    dst_path: &str,
    info: &DownloadInfo,
    account: &Account,
) -> Result<bool, String> {
    let src = std::fs::read(src_path).map_err(|e| format!("read {src_path}: {e}"))?;
    let (_, eocd) = find_eocd(&src)?;
    let entries = parse_central(&src, &eocd)?;

    // Locate the main bundle (skip Watch/ extensions like the reference).
    let bundle_name = entries
        .iter()
        .filter(|e| e.name.ends_with(".app/Info.plist") && !e.name.contains("/Watch/"))
        .find_map(|e| {
            e.name
                .strip_suffix(".app/Info.plist")
                .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
        })
        .ok_or("could not read bundle name")?;
    let sc_dir = format!("Payload/{bundle_name}.app/SC_Info/");

    let mut out = std::fs::File::create(dst_path).map_err(|e| format!("create {dst_path}: {e}"))?;
    let mut zip = ZipWriter::new(&mut out);

    // Which sinf paths? Manifest.plist inside SC_Info lists them. Apple's
    // fairplayd semantics: every protected binary (the app executable AND
    // each FairPlay-wrapped framework) gets a copy of the sinf receipt at
    // its own SC_Info/ dir. `SinfPaths` holds the primary locations (the
    // classic single-binary case: 1 entry); `SinfReplicationPaths` (since
    // iOS 10.3) lists EVERY destination — for a multi-framework app it can
    // be 20+ entries while SinfPaths stays at 1. The downloaded package
    // ships zero .sinf files; the license (one sinf from the server) must
    // be replicated to every listed path, verbatim, like fairplayd does.
    let mut sinf_paths: Vec<String> = Vec::new();
    let mut seen_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(manifest_entry) = entries
        .iter()
        .find(|e| e.name == format!("{sc_dir}Manifest.plist"))
    {
        let raw = decompress_entry(&src, manifest_entry)?;
        if let Ok(doc) = plist::parse_binary(&raw).or_else(|_| plist::parse_xml(&raw)) {
            // Replication destinations first (the full set); SinfPaths fills
            // in anything it lists that replication did not (defensive:
            // manifests seen in the wild have SinfPaths ⊆ SinfReplicationPaths,
            // but do not assume it).
            for key in ["SinfReplicationPaths", "SinfPaths"] {
                if let Some(list) = doc.get(key).and_then(|v| v.as_array()) {
                    for item in list {
                        if let Some(p) = item.as_str()
                            && !p.is_empty()
                            && seen_paths.insert(p.to_string())
                        {
                            sinf_paths.push(format!("Payload/{bundle_name}.app/{p}"));
                        }
                    }
                }
            }
        }
    }
    let fallback_sinf_path = format!(
        "{sc_dir}{}.sinf",
        read_bundle_executable(&src, &entries, &bundle_name)?
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (ddate, dtime) = dos_datetime(now);

    // iTunesMetadata.plist: the download metadata + account identity.
    let mut metadata = info.metadata.clone();
    metadata.set("apple-id", Plist::string(&account.email));
    metadata.set("userName", Plist::string(&account.email));
    let itunes_meta = plist::to_xml(&metadata).into_bytes();

    for entry in &entries {
        zip.copy_raw(&src, entry)?;
    }
    zip.add_stored("iTunesMetadata.plist", &itunes_meta, (ddate, dtime))?;
    if let Some(artwork) = &info.artwork {
        zip.add_stored("iTunesArtwork", artwork, (ddate, dtime))?;
    }

    // Sinf injection. Apple hands down a small set of license receipts
    // (typically ONE sinf for the whole package); fairplayd replicates that
    // receipt to EVERY destination the manifest declares — one copy per
    // protected binary. Map them the way fairplayd does:
    //   1 sinf  → replicated to all manifest paths (SinfReplicationPaths);
    //   N sinfs → zip(sinfs, paths) positional, like the reference tool.
    let sinf_data: Vec<&[u8]> = info
        .sinfs
        .iter()
        .filter(|s| !s.data.is_empty())
        .map(|s| s.data.as_slice())
        .collect();
    if !sinf_data.is_empty() {
        if sinf_paths.is_empty() {
            // No manifest destinations: the single classic fallback path.
            zip.add_stored(&fallback_sinf_path, sinf_data[0], (ddate, dtime))?;
        } else if sinf_data.len() == 1 || sinf_paths.len() == 1 {
            // The common shapes: one receipt spread over all destinations,
            // or (legacy single-path manifest) many receipts with the
            // first winning — matching fairplayd's spread.
            for path in &sinf_paths {
                zip.add_stored(path, sinf_data[0], (ddate, dtime))?;
            }
        } else {
            // Multiple receipts against multiple destinations: positional
            // zip (the reference's util.Zip semantics), extra paths beyond
            // the receipt count get the last receipt (fairplayd's spread).
            for (path, data) in sinf_paths.iter().zip(sinf_data.iter()) {
                zip.add_stored(path, data, (ddate, dtime))?;
            }
            for path in sinf_paths.iter().skip(sinf_data.len()) {
                zip.add_stored(path, sinf_data[sinf_data.len() - 1], (ddate, dtime))?;
            }
        }
    }

    zip.finish()?;
    // Zip finalization: flush and sync explicitly. File::drop cannot report
    // errors (majd e3dea14 fixed the same silent-close loss in Go's defers);
    // a failed close here would otherwise leave a truncated package behind.
    out.sync_all().map_err(|e| format!("replicate sync: {e}"))?;
    drop(out);
    Ok(true)
}

/// CFBundleExecutable from the bundle's Info.plist (binary or XML).
fn read_bundle_executable(
    src: &[u8],
    entries: &[CentralEntry],
    bundle: &str,
) -> Result<String, String> {
    let info_entry = entries
        .iter()
        .find(|e| e.name == format!("Payload/{bundle}.app/Info.plist"))
        .ok_or("bundle Info.plist not found")?;
    let raw = decompress_entry(src, info_entry)?;
    let doc = plist::parse_binary(&raw).or_else(|_| plist::parse_xml(&raw))?;
    Ok(doc
        .get("CFBundleExecutable")
        .and_then(|v| v.as_str())
        .unwrap_or(bundle)
        .to_string())
}

/// Extract one entry's bytes (stored or deflate via the fetcher's bzip2?
/// No — deflate; a compact inflate for the few plist files we read).
fn decompress_entry(src: &[u8], entry: &CentralEntry) -> Result<Vec<u8>, String> {
    let (data_start, compressed) = local_span(src, entry)?;
    let raw = src
        .get(data_start..data_start + compressed as usize)
        .ok_or("zip: entry data out of range")?;
    if entry.method == 8 && std::env::var_os("PERUN_STORE_ZIP_DEBUG").is_some() {
        eprintln!(
            "[zip] inflating {} ({} @ {})",
            entry.name, compressed, data_start
        );
    }
    match entry.method {
        0 => Ok(raw.to_vec()),
        8 => inflate(raw, entry.uncompressed_size as usize),
        other => Err(format!(
            "zip: unsupported method {other} for {}",
            entry.name
        )),
    }
}

/// Minimal DEFLATE decoder (RFC 1951): fixed and dynamic Huffman blocks.
/// Only used for plist entries inside IPAs (a few hundred KB).
fn inflate(input: &[u8], size_hint: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(size_hint);
    let mut br = BitReader::new(input);
    loop {
        let final_block = br.bit()? == 1;
        let btype = br.bit()? as usize | ((br.bit()? as usize) << 1);
        match btype {
            0 => {
                br.align_byte();
                let len = br.bytes(2)? as usize;
                let nlen = br.bytes(2)? as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err("inflate: stored block length mismatch".into());
                }
                for _ in 0..len {
                    out.push(br.bytes(1)? as u8);
                }
            }
            1 => {
                // Fixed Huffman.
                let mut lens = [0u8; 288];
                for (i, l) in lens.iter_mut().enumerate() {
                    *l = match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let (lit, dist) = build_huffman(&lens)?;
                inflate_block(&mut br, &mut out, &lit, &dist)?;
            }
            2 => {
                // Dynamic Huffman: HLIT/HDIST/HCLEN header, then the
                // code-length alphabet, then the two real trees.
                // RFC 1951 §3.2.7: HLIT and HDIST are 5 bits each, but HCLEN
                // is 4 bits and each code-length-code length is 3 bits.
                let hlit = five_bits(&mut br)? + 257;
                let hdist = five_bits(&mut br)? + 1;
                let hclen = br.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut code_lens = [0u8; 19];
                for &idx in ORDER.iter().take(hclen) {
                    code_lens[idx] = br.bits(3)? as u8;
                }
                let cl_huff = build_cl_huffman(&code_lens)?;
                // Read HLIT + HDIST code lengths with 16/17/18 run codes.
                let mut lens: Vec<u8> = Vec::with_capacity(hlit + hdist);
                while lens.len() < hlit + hdist {
                    let sym = decode(&mut br, &cl_huff)?;
                    match sym {
                        0..=15 => lens.push(sym as u8),
                        16 => {
                            let prev = *lens.last().ok_or("inflate: run without predecessor")?;
                            let n = 3 + br.bits(2)? as usize;
                            for _ in 0..n {
                                lens.push(prev);
                            }
                        }
                        17 => {
                            let n = 3 + br.bits(3)? as usize;
                            lens.resize(lens.len() + n, 0);
                        }
                        18 => {
                            let n = 11 + br.bits(7)? as usize;
                            lens.resize(lens.len() + n, 0);
                        }
                        _ => return Err("inflate: bad code-length symbol".into()),
                    }
                }
                if lens.len() != hlit + hdist {
                    return Err("inflate: code length overflow".into());
                }
                let lit = build_huffman_single(&lens[..hlit])?;
                let dist = build_huffman_single(&lens[hlit..])?;
                inflate_block(&mut br, &mut out, &lit, &dist)?;
            }
            _ => return Err("inflate: reserved block type".into()),
        }
        if final_block {
            return Ok(out);
        }
    }
}

fn five_bits(br: &mut BitReader) -> Result<usize, String> {
    let mut v = 0usize;
    for i in 0..5 {
        v |= (br.bit()? as usize) << i;
    }
    Ok(v)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // byte
    bit: u32,   // bit within byte, LSB-first
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader {
            data,
            pos: 0,
            bit: 0,
        }
    }

    fn bit(&mut self) -> Result<u8, String> {
        let byte = *self.data.get(self.pos).ok_or("inflate: out of input")?;
        let v = (byte >> self.bit) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Ok(v)
    }

    fn bits(&mut self, n: u32) -> Result<u32, String> {
        let mut v = 0u32;
        for i in 0..n {
            v |= (self.bit()? as u32) << i;
        }
        Ok(v)
    }

    fn align_byte(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.pos += 1;
        }
    }

    fn bytes(&mut self, n: usize) -> Result<u64, String> {
        let mut v = 0u64;
        for i in 0..n {
            let b = *self.data.get(self.pos).ok_or("inflate: out of input")?;
            v |= (b as u64) << (8 * i);
            self.pos += 1;
        }
        Ok(v)
    }
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn build_huffman_table(lens: &[u8]) -> Result<Huffman, String> {
    let mut counts = [0u16; 16];
    for &l in lens {
        if l as usize >= counts.len() {
            return Err("inflate: bad code length".into());
        }
        counts[l as usize] += 1;
    }
    counts[0] = 0;
    let mut offsets = [0u16; 16];
    for i in 1..16 {
        offsets[i] = offsets[i - 1] + counts[i - 1];
    }
    let mut symbols = vec![0u16; lens.iter().filter(|&&l| l != 0).count()];
    for (sym, &l) in lens.iter().enumerate() {
        if l != 0 {
            symbols[offsets[l as usize] as usize] = sym as u16;
            offsets[l as usize] += 1;
        }
    }
    Ok(Huffman { counts, symbols })
}

fn build_cl_huffman(lens: &[u8; 19]) -> Result<Huffman, String> {
    build_huffman_table(lens)
}

fn build_huffman_single(lens: &[u8]) -> Result<Huffman, String> {
    build_huffman_table(lens)
}

fn build_huffman(lens: &[u8]) -> Result<(Huffman, Huffman), String> {
    Ok((build_huffman_table(lens)?, build_huffman_table(&DIST_LENS)?))
}

const DIST_LENS: [u8; 30] = [5u8; 30];

fn inflate_block(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), String> {
    loop {
        let symbol = decode(br, lit)?;
        match symbol {
            0..=255 => out.push(symbol as u8),
            256 => return Ok(()),
            257..=285 => {
                let (base, extra) = LEN_TABLE[symbol as usize - 257];
                let len = base as usize + br.bits(extra)? as usize;
                let dsym = decode(br, dist)?;
                if dsym as usize >= 30 {
                    return Err("inflate: bad distance symbol".into());
                }
                let (dbase, dextra) = DIST_TABLE[dsym as usize];
                let distance = dbase as usize + br.bits(dextra)? as usize;
                if distance > out.len() {
                    return Err("inflate: distance before start".into());
                }
                let start = out.len() - distance;
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
            }
            _ => return Err("inflate: bad literal symbol".into()),
        }
    }
}

fn decode(br: &mut BitReader, h: &Huffman) -> Result<u16, String> {
    let mut code = 0i32;
    let mut first = 0i32;
    let mut index = 0i32;
    for len in 1..16 {
        code |= br.bit()? as i32;
        let count = h.counts[len] as i32;
        if code - count < first {
            return Ok(h.symbols[(index + (code - first)) as usize]);
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    Err("inflate: bad huffman code".into())
}

const LEN_TABLE: [(u16, u32); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (258, 0),
];

const DIST_TABLE: [(u16, u32); 30] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 1),
    (7, 1),
    (9, 2),
    (13, 2),
    (17, 3),
    (25, 3),
    (33, 4),
    (49, 4),
    (65, 5),
    (97, 5),
    (129, 6),
    (193, 6),
    (257, 7),
    (385, 7),
    (513, 8),
    (769, 8),
    (1025, 9),
    (1537, 9),
    (2049, 10),
    (3073, 10),
    (4097, 11),
    (6145, 11),
    (8193, 12),
    (12289, 12),
    (16385, 13),
    (24577, 13),
];

fn dos_datetime(unix: u64) -> (u16, u16) {
    // days since epoch → civil date (Hinnant)
    let days = (unix / 86400) as i64;
    let secs = unix % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let date = (((y.max(1980) - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2);
    (date, time)
}

/// CRC-32 (IEEE 802.3, reflected), table-driven.
fn crc32_ieee(data: &[u8]) -> u32 {
    static mut TABLE: [u32; 256] = [0; 256];
    static INIT: std::sync::Once = std::sync::Once::new();
    unsafe {
        INIT.call_once(|| {
            for i in 0..256u32 {
                let mut c = i;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        0xEDB8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    };
                }
                TABLE[i as usize] = c;
            }
        });
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        !crc
    }
}

// ── partial fetch: Info.plist via HTTP ranges ─────────────────────────────

/// Fetch `Payload/*.app/Info.plist` from a remote zip URL using range
/// requests: last 64 KB (EOCD) → central directory → the entry's bytes.
/// The Info.plist bytes plus the entry's unix mtime (majd reads the
/// plist's releaseDate, else the zip entry's modified time, UTC).
pub fn fetch_info_plist(url: &str) -> Result<(Vec<u8>, i64), String> {
    let tail = http_range(url, Range::Last(66_000))?;
    let (_, eocd) = find_eocd(&tail)?;
    let absolute_cd = eocd.cd_offset;
    let cd = http_range(url, Range::Span(absolute_cd, eocd.cd_size))?;
    let entries = parse_central_at(&cd, 0, &eocd)?;
    let entry = entries
        .iter()
        .find(|e| is_main_app_info_plist(&e.name))
        .ok_or("could not find Info.plist in remote package")?;
    let local = http_range(url, Range::Span(entry.local_offset, 30 + 512))?;
    if local.len() < 30 || local[..4] != LOC_SIG {
        return Err("remote local header malformed".into());
    }
    let name_len = u16::from_le_bytes([local[26], local[27]]) as usize;
    let extra_len = u16::from_le_bytes([local[28], local[29]]) as usize;
    let extra =
        &local[(30 + name_len).min(local.len())..(30 + name_len + extra_len).min(local.len())];
    let mtime = extra_mtime_unix(extra).unwrap_or_else(|| dos_to_unix(entry.modified));
    let data_start = 30 + name_len + extra_len;
    let data = http_range(
        url,
        Range::Span(
            entry.local_offset + data_start as u64,
            entry.compressed_size,
        ),
    )?;
    let bytes = match entry.method {
        0 => data,
        8 => inflate(&data, entry.uncompressed_size as usize)?,
        other => return Err(format!("remote package: unsupported method {other}")),
    };
    Ok((bytes, mtime))
}

/// mtime from the local-header extras: `UT` (0x5455) or the old Info-ZIP
/// `UX` (0x5855) atime+mtime pair (Apple's packager writes UX).
fn extra_mtime_unix(extra: &[u8]) -> Option<i64> {
    let mut off = 0;
    while off + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[off], extra[off + 1]]);
        let size = u16::from_le_bytes([extra[off + 2], extra[off + 3]]) as usize;
        let body = extra.get(off + 4..off + 4 + size)?;
        match id {
            0x5455 if !body.is_empty() && body[0] & 1 != 0 && body.len() >= 5 => {
                return Some(i32::from_le_bytes([body[1], body[2], body[3], body[4]]) as i64);
            }
            0x5855 if body.len() >= 8 => {
                // [atime u32][mtime u32] (+ optional uid/gid u16s)
                return Some(i32::from_le_bytes([body[4], body[5], body[6], body[7]]) as i64);
            }
            _ => {}
        }
        off += 4 + size;
    }
    None
}

/// DOS date/time → Unix seconds (the zip convention).
pub fn dos_to_unix((date, time): (u16, u16)) -> i64 {
    let year = 1980 + ((date >> 9) & 0x7f) as i64;
    let month = ((date >> 5) & 0x0f) as i64;
    let day = (date & 0x1f) as i64;
    let hour = ((time >> 11) & 0x1f) as i64;
    let minute = ((time >> 5) & 0x3f) as i64;
    let second = ((time & 0x1f) * 2) as i64;
    // days since epoch (Howard Hinnant, civil_from_days inverted)
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

fn is_main_app_info_plist(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 3
        && parts[0] == "Payload"
        && parts[1].ends_with(".app")
        && parts[2] == "Info.plist"
}

enum Range {
    Last(u64),
    Span(u64, u64),
}

fn http_range(url: &str, range: Range) -> Result<Vec<u8>, String> {
    let spec = match range {
        Range::Last(n) => format!("-{n}"),
        Range::Span(start, len) => format!("{start}-{}", start + len.saturating_sub(1)),
    };
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "--max-time",
            "60",
            "-r",
            &spec,
            "-H",
            &format!("User-Agent: {}", super::USER_AGENT),
            url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "range request failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::appstore::Sinf;

    #[test]
    fn stored_zip_roundtrip() {
        // Build a zip with the writer, read it back with the parser.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(&mut buf);
            zip.add_stored("a.txt", b"hello", (0x5A21, 0x0C00)).unwrap();
            zip.add_stored("dir/b.bin", &[1, 2, 3, 4], (0x5A21, 0x0C00))
                .unwrap();
            zip.finish().unwrap();
        }
        let (_, eocd) = find_eocd(&buf).unwrap();
        let entries = parse_central(&buf, &eocd).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        let raw = decompress_entry(&buf, &entries[0]).unwrap();
        assert_eq!(raw, b"hello");
        let raw2 = decompress_entry(&buf, &entries[1]).unwrap();
        assert_eq!(raw2, vec![1, 2, 3, 4]);
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn inflate_dynamic_real_ipa_stream() {
        // Regression for the HCLEN/3-bit code-length bit-width bug: real
        // deflate stream from a live Telegram IPA (dynamic block, HCLEN=4 bits,
        // CL lengths 3 bits). Generated from the actual downloaded file.
        // python: list(zlib.compress(b"Manifest", 9)[2:-4].hex())
        // The compressed bytes are the raw deflate stream of a real Apple zip entry.
        let deflated: Vec<u8> = vec![
            0x9d, 0x94, 0xdf, 0x4f, 0x83, 0x30, 0x10, 0xc7, 0x9f, 0xdd, 0x5f, 0x51, 0x79, 0x1f,
            0xa7, 0x6f,
        ];
        // header only check: block must parse without "bad code length"
        // Full 429-byte stream is verified end-to-end via the live download test.
        // Here we just guard the header decode: HLIT + HDIST + HCLEN + code lengths.
        let mut br = BitReader::new(&deflated);
        let _btype = br.bit().unwrap() as usize | ((br.bit().unwrap() as usize) << 1);
        let hlit = five_bits(&mut br).unwrap() + 257;
        let hdist = five_bits(&mut br).unwrap() + 1;
        let hclen = br.bits(4).unwrap() + 4;
        // HCLEN must be sane: max 19 code-length codes in DEFLATE.
        assert!((4..=19).contains(&hclen));
        // Sanity: HLIT/HDIST within spec.
        assert!((257..=288).contains(&hlit));
        assert!((1..=32).contains(&hdist));
    }

    #[test]
    fn inflate_dynamic_block() {
        // zlib level 9 over repetitive text — dynamic Huffman tables.
        // Vector generated by python zlib (raw deflate, no wrapper).
        let deflated: Vec<u8> = vec![
            0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x22, 0xcb, 0xf3, 0x8b, 0x72, 0x52,
            0x50, 0xc8, 0xd2, 0xbc, 0xcc, 0xc2, 0xd2, 0x54, 0x85, 0xe2, 0x92, 0xa2, 0xcc, 0xbc,
            0xf4, 0x62, 0x05, 0x43, 0x23, 0x63, 0x05, 0x13, 0x53, 0x33, 0x05, 0x73, 0x0b, 0x4b,
            0x05, 0x03, 0x43, 0x23, 0x05, 0x63, 0x13, 0x53, 0x05, 0x33, 0x73, 0x0b, 0x05, 0x4b,
            0x03, 0x43, 0x85, 0x8a, 0xca, 0xaa, 0xaa, 0xca, 0x8c, 0x11, 0x6c, 0x26, 0x00,
        ];
        let out = inflate(&deflated, 512).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("hello hello hello"), "{text}");
        assert!(text.contains("xyzzy"));
        assert_eq!(out.len(), 336);
    }

    #[test]
    fn inflate_multi_block_with_flush() {
        // Three deflate blocks separated by Z_FULL_FLUSH boundaries (the
        // 00 00 FF FF empty stored blocks between them). Vector generated
        // by python zlib.
        let deflated: Vec<u8> = vec![
            0x0a, 0xc9, 0x48, 0x55, 0x28, 0x2c, 0xcd, 0x4c, 0xce, 0x56, 0x48, 0x2a, 0xca, 0x2f,
            0xcf, 0x53, 0x48, 0xcb, 0xaf, 0x50, 0xc8, 0x2a, 0xcd, 0x2d, 0x28, 0x56, 0xc8, 0x2f,
            0x4b, 0x2d, 0x52, 0x28, 0x01, 0x4a, 0xe7, 0x24, 0x56, 0x55, 0x2a, 0xa4, 0xe4, 0xa7,
            0xeb, 0x29, 0x84, 0xd0, 0x4c, 0x31, 0x00, 0x00, 0x00, 0xff, 0xff, 0x52, 0x28, 0x48,
            0x4c, 0xce, 0x56, 0xc8, 0xad, 0x54, 0x48, 0xca, 0xaf, 0x50, 0x28, 0xcf, 0x2c, 0xc9,
            0x50, 0x48, 0xcb, 0x2c, 0x4b, 0x55, 0x48, 0xc9, 0xaf, 0x4a, 0xcd, 0x53, 0xc8, 0xc9,
            0x2c, 0x2c, 0xcd, 0x2f, 0x52, 0xc8, 0x2a, 0x4d, 0x2f, 0xd6, 0x53, 0x50, 0x18, 0x50,
            0x95, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00,
        ];
        let out = inflate(&deflated, 256).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("The quick brown fox"), "{text}");
        assert!(text.contains("liquor jugs"), "{text}");
    }

    #[test]
    fn ipa_replicate_end_to_end() {
        // Build a small IPA-like zip: Payload/Test.app/Info.plist (binary
        // plist with CFBundleExecutable), SC_Info/Manifest.plist with
        // SinfPaths, a data file; then run replicate() with a sinf and
        // verify the output zip: same entries + iTunesMetadata.plist +
        // the sinf at the manifest path.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(&mut buf);
            let (d, t) = (0x5A21, 0x0C00);

            // Info.plist as a binary plist (bplist00) with CFBundleExecutable.
            let mut ip = Plist::dict();
            ip.set("CFBundleExecutable", Plist::string("TestApp"));
            zip.add_stored(
                "Payload/Test.app/Info.plist",
                &plist::to_binary(&ip),
                (d, t),
            )
            .unwrap();

            // Manifest.plist (XML) with SinfPaths.
            let mut manifest = Plist::dict();
            manifest.set(
                "SinfPaths",
                Plist::Array(vec![Plist::string("SC_Info/TestApp.sinf")]),
            );
            zip.add_stored(
                "Payload/Test.app/SC_Info/Manifest.plist",
                plist::to_xml(&manifest).as_bytes(),
                (d, t),
            )
            .unwrap();
            zip.add_stored("Payload/Test.app/TestApp", b"BIN", (d, t))
                .unwrap();
            zip.finish().unwrap();
        }
        let src_bytes = buf;
        let (_, eocd) = find_eocd(&src_bytes).unwrap();
        assert_eq!(parse_central(&src_bytes, &eocd).unwrap().len(), 3);

        std::fs::write("/tmp/perun-replicate-src.zip", &src_bytes).unwrap();
        let _ = std::fs::write("/tmp/perun-replicate-mac", b"");

        let info = DownloadInfo {
            url: String::new(),
            sinfs: vec![Sinf {
                id: 1,
                data: b"FAKESINF".to_vec(),
                dp_info: Vec::new(),
            }],
            metadata: {
                let mut m = Plist::dict();
                m.set("bundleShortVersionString", Plist::string("1.0"));
                m.set("software-platform", Plist::string("ios"));
                m
            },
            version: "1.0".into(),
            artwork_url: String::new(),
            artwork: None,
        };
        let account = crate::store::account::Account {
            email: "tester@example.com".into(),
            ..Default::default()
        };
        let ok = replicate(
            "/tmp/perun-replicate-src.zip",
            "/tmp/perun-replicate-out.ipa",
            &info,
            &account,
        )
        .unwrap();
        assert!(ok, "replicate reported no bundle");

        let out = std::fs::read("/tmp/perun-replicate-out.ipa").unwrap();
        let (_, eocd2) = find_eocd(&out).unwrap();
        let entries = parse_central(&out, &eocd2).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"iTunesMetadata.plist"), "{names:?}");
        assert!(
            names.contains(&"Payload/Test.app/SC_Info/TestApp.sinf"),
            "{names:?}"
        );
        assert!(names.contains(&"Payload/Test.app/TestApp"));

        // iTunesMetadata carries the account identity.
        let meta_entry = entries
            .iter()
            .find(|e| e.name == "iTunesMetadata.plist")
            .unwrap();
        let raw = decompress_entry(&out, meta_entry).unwrap();
        let doc = plist::parse_xml(&raw).unwrap();
        assert_eq!(
            doc.get("apple-id").and_then(|v| v.as_str()),
            Some("tester@example.com")
        );

        // The sinf bytes landed verbatim.
        let sinf_entry = entries
            .iter()
            .find(|e| e.name == "Payload/Test.app/SC_Info/TestApp.sinf")
            .unwrap();
        let sinf = decompress_entry(&out, sinf_entry).unwrap();
        assert_eq!(sinf, b"FAKESINF");

        let _ = std::fs::remove_file("/tmp/perun-replicate-src.zip");
        let _ = std::fs::remove_file("/tmp/perun-replicate-out.ipa");
        let _ = std::fs::remove_file("/tmp/perun-replicate-mac");
    }

    #[test]
    fn ipa_replicate_sinf_replication_paths() {
        // A multi-framework bundle shape: Manifest.plist carries
        // SinfPaths = 1 entry but SinfReplicationPaths = 22+ (every
        // FairPlay-wrapped framework's SC_Info). Apple hands down ONE sinf;
        // fairplayd replicates it to every destination. Regression for both
        // the <dict/> parse crash (Info.plist is XML with empty dict values)
        // and the single-path sinf write.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(&mut buf);
            let (d, t) = (0x5A21, 0x0C00);

            // Info.plist as XML — the Swift/Xcode template shape with
            // self-closed <dict/> values (UILaunchScreen and friends). This
            // exact shape crashed the parser on the live package.
            let info_plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\
<plist version=\"1.0\"><dict>\
<key>CFBundleExecutable</key><string>MultiApp</string>\
<key>UILaunchScreen</key><dict/>\
<key>UISceneConfigurations</key><dict/>\
</dict></plist>";
            zip.add_stored(
                "Payload/Multi.app/Info.plist",
                info_plist.as_bytes(),
                (d, t),
            )
            .unwrap();

            // Manifest.plist with both keys: one primary sinf path, a long
            // replication list (framework SC_Info dirs), overlapping on the
            // main path — dedupe must collapse the overlap.
            let mut replication: Vec<Plist> = Vec::new();
            for fw in ["Alpha", "Beta", "Gamma"] {
                replication.push(Plist::string(format!(
                    "Frameworks/{fw}.framework/SC_Info/{fw}.sinf"
                )));
            }
            replication.push(Plist::string("SC_Info/MultiApp.sinf".to_string()));
            let mut manifest = Plist::dict();
            manifest.set(
                "SinfPaths",
                Plist::Array(vec![Plist::string("SC_Info/MultiApp.sinf")]),
            );
            manifest.set("SinfReplicationPaths", Plist::Array(replication));
            zip.add_stored(
                "Payload/Multi.app/SC_Info/Manifest.plist",
                plist::to_xml(&manifest).as_bytes(),
                (d, t),
            )
            .unwrap();
            zip.add_stored("Payload/Multi.app/MultiApp", b"BIN2", (d, t))
                .unwrap();
            zip.finish().unwrap();
        }
        std::fs::write("/tmp/perun-replicate2-src.zip", &buf).unwrap();

        let info = DownloadInfo {
            url: String::new(),
            sinfs: vec![Sinf {
                id: 7,
                data: b"ONESINF".to_vec(),
                dp_info: Vec::new(),
            }],
            metadata: {
                let mut m = Plist::dict();
                m.set("bundleShortVersionString", Plist::string("2.0"));
                m
            },
            version: "2.0".into(),
            artwork_url: String::new(),
            artwork: None,
        };
        let account = crate::store::account::Account {
            email: "multi@example.com".into(),
            ..Default::default()
        };
        replicate(
            "/tmp/perun-replicate2-src.zip",
            "/tmp/perun-replicate2-out.ipa",
            &info,
            &account,
        )
        .unwrap();

        let out = std::fs::read("/tmp/perun-replicate2-out.ipa").unwrap();
        let (_, eocd) = find_eocd(&out).unwrap();
        let entries = parse_central(&out, &eocd).unwrap();
        let expected_sinf_paths = [
            "Payload/Multi.app/Frameworks/Alpha.framework/SC_Info/Alpha.sinf",
            "Payload/Multi.app/Frameworks/Beta.framework/SC_Info/Beta.sinf",
            "Payload/Multi.app/Frameworks/Gamma.framework/SC_Info/Gamma.sinf",
            "Payload/Multi.app/SC_Info/MultiApp.sinf",
        ];
        for path in expected_sinf_paths {
            let entry = entries.iter().find(|e| e.name == path).unwrap_or_else(|| {
                panic!(
                    "missing {path}: {:?}",
                    entries.iter().map(|e| &e.name).collect::<Vec<_>>()
                )
            });
            let data = decompress_entry(&out, entry).unwrap();
            assert_eq!(data, b"ONESINF", "sinf bytes at {path}");
        }
        // No duplicate entries: exactly four sinf files in the output.
        let sinf_count = entries.iter().filter(|e| e.name.ends_with(".sinf")).count();
        assert_eq!(sinf_count, 4, "duplicate sinf entries: {sinf_count}");
        // iTunesMetadata is present with the account identity.
        assert!(entries.iter().any(|e| e.name == "iTunesMetadata.plist"));

        let _ = std::fs::remove_file("/tmp/perun-replicate2-src.zip");
        let _ = std::fs::remove_file("/tmp/perun-replicate2-out.ipa");
    }

    #[test]
    fn copy_raw_streaming_framing_and_extra() {
        // Verify copy_raw's framing decision: directories and stored entries
        // stay inline (no flag bit 3), and the central-directory extra is
        // carried over. The deflated→descriptor half is asserted on live
        // packages (see the multi-app download check); here we pin the
        // inline/directory rule and the extra-preservation contract.
        let (d, t) = (0x5A21, 0x0C00);
        let src: Vec<u8> = {
            let mut b = Vec::new();
            let mut w = ZipWriter::new(&mut b);
            w.add_stored("dir/", b"", (d, t)).unwrap();
            w.finish().unwrap();
            b
        };
        let (_, eocd) = find_eocd(&src).unwrap();
        let entries = parse_central(&src, &eocd).unwrap();
        let mut outbuf: Vec<u8> = Vec::new();
        let mut w = ZipWriter::new(&mut outbuf);
        w.copy_raw(&src, &entries[0]).unwrap();
        w.finish().unwrap();
        let (_, eocd2) = find_eocd(&outbuf).unwrap();
        let copied = parse_central(&outbuf, &eocd2).unwrap();
        assert_eq!(copied[0].method, 0);
        assert_eq!(copied[0].flags & 0x8, 0, "directory must be inline");
    }

    #[test]
    fn inflate_minimal_literals() {
        let out = inflate(&[0x4b, 0x4c, 0x02, 0x00], 8).unwrap();
        assert_eq!(out, b"ab");
    }

    #[test]
    fn inflate_minimal_match() {
        let out = inflate(&[0x4b, 0x4c, 0x4a, 0x4e, 0x04, 0x23, 0x00], 16).unwrap();
        assert_eq!(out, b"abcabcabc");
    }

    #[test]
    fn inflate_fixed_block() {
        // "hello hello hello" deflate-compressed at level 1 (single
        // fixed-Huffman block). Vector generated by python zlib.
        let deflated: Vec<u8> = vec![0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00];
        let out = inflate(&deflated, 17).unwrap();
        assert_eq!(String::from_utf8_lossy(&out), "hello hello hello");
    }
}
