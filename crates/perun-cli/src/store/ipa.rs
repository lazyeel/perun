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
const ZIP64_EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x06];
const ZIP64_LOC_SIG: [u8; 4] = [0x50, 0x4B, 0x06, 0x07];
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// iOS 18 on A17 Pro and the M-series run with 16 KiB pages, so a Mach-O's
/// payload has to start on a 16 KiB boundary inside the package. That lets
/// the installer map the code straight out of the zip; an unaligned payload
/// forces a copy through an aligned bounce buffer, and on those devices the
/// copy is what breaks.
///
/// This is only the container half of the requirement. The Mach-O's own
/// `__TEXT` has to have been linked with a 16 KiB segment alignment, which is
/// a property of the binary and not something a repackager can change.
const CODE_ALIGNMENT: u64 = 16 * 1024;
/// Extra-field id used purely as alignment padding. 0x0000 is unassigned in
/// APPNOTE, and a parser that does not recognise a field skips it by its
/// declared size like any other.
const PAD_EXTRA_ID: u16 = 0x0000;
const ZIP64_SUB: u32 = 0xFFFF_FFFF;
const ZIP64_SUB16: u16 = 0xFFFF;

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

/// Locate the end-of-central-directory record.
///
/// `data` is a window onto the archive that ends at the archive's end, and
/// `base` is that window's offset within the archive. Every offset this
/// returns is absolute, which matters because the offsets inside the record
/// are: a 66 KB tail of a 3 GB package starts three gigabytes into the file.
fn find_eocd_at(data: &[u8], base: u64) -> Result<(u64, Eocd), String> {
    let mut pos = None;
    let mut i = 0;
    while i + 22 <= data.len() {
        let at = base + i as u64;
        if data[i..i + 4] == EOCD_SIG && candidate_is_plausible(&data[i..i + 22], at) {
            // Keep scanning: a nested zip's own record can precede ours, and a
            // comment or entry body can carry the signature bytes. Only a
            // candidate whose directory ends at or before the record is
            // believed, and the last believed candidate is the archive's.
            pos = Some(i);
        }
        i += 1;
    }
    let at = pos.ok_or("zip: no end-of-central-directory record")?;
    let eocd = &data[at..at + 22];
    // Bytes 4..8 are the two disk numbers. Bytes 20..22 are the comment
    // length, which says nothing about validity — reading it as a disk number
    // rejected every archive carrying a comment and named the wrong cause.
    if u16::from_le_bytes([eocd[4], eocd[5]]) != 0 || u16::from_le_bytes([eocd[6], eocd[7]]) != 0 {
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
        base + at as u64,
        Eocd {
            entry_count,
            cd_offset,
            cd_size,
        },
    ))
}

fn find_eocd(data: &[u8]) -> Result<(usize, Eocd), String> {
    let (at, eocd) = find_eocd_at(data, 0)?;
    Ok((at as usize, eocd))
}

/// Whether a 22-byte record found at absolute offset `at` can be an archive's
/// own end-of-central-directory record.
///
/// The central directory it names must start inside the archive and end at or
/// before the record itself. A ZIP64 archive carries 0xFFFF_FFFF placeholders
/// here and its real numbers live in the zip64 record, so it is left to the
/// caller's explicit zip64 rejection rather than judged here.
fn candidate_is_plausible(eocd: &[u8], at: u64) -> bool {
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]) as u64;
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]) as u64;
    if cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF {
        return true;
    }
    cd_offset + cd_size <= at
}

#[cfg(test)]
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
        // The tuple is (date, time) everywhere else in this module: that is
        // the order `add_stored` and `finish` write, and the order the callers
        // pass. Reading the record as (time, date) made every copied entry
        // land its two halves in each other's field.
        let modified = (u16_at(14), u16_at(12));
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
#[cfg(test)]
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

// ── streaming package source ───────────────────────────────────────────────

/// A package read through the file rather than a whole-file mapping.
///
/// The replicator used to `mmap` the entire archive and lean on
/// `MADV_SEQUENTIAL` to keep the resident set down, which only *asks* the
/// reclaimer to keep up: measured peak RSS on 3.6 GiB swung 532..1012 MiB
/// between identical runs. Here nothing is mapped at all, so the resident set
/// is the largest single read — the central directory, a few MiB — and nothing
/// else. Bulk entry bodies are moved through a fixed buffer.
struct Pkg {
    file: std::fs::File,
    len: u64,
}

impl Pkg {
    fn open(path: &str) -> Result<Pkg, String> {
        let file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let len = file
            .metadata()
            .map_err(|e| format!("stat {path}: {e}"))?
            .len();
        Ok(Pkg { file, len })
    }

    /// Positional read. Callers use this only for metadata-sized ranges.
    fn read_at(&self, off: u64, len: u64) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; len as usize];
        let mut done = 0usize;
        while done < out.len() {
            let n = read_at(&self.file, &mut out[done..], off + done as u64)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("zip: unexpected end of file".into());
            }
            done += n;
        }
        Ok(out)
    }

    /// Stream `len` bytes at `off` through a fixed buffer into the writer.
    fn copy_range_to(
        &mut self,
        off: u64,
        len: u64,
        out: &mut dyn std::io::Write,
    ) -> Result<u64, String> {
        use std::io::{Read, Seek, SeekFrom};
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("seek: {e}"))?;
        let mut left = len;
        let mut buf = [0u8; 512 * 1024];
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = self
                .file
                .read(&mut buf[..want])
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("zip: unexpected end of file".into());
            }
            out.write_all(&buf[..n])
                .map_err(|e| format!("zip write: {e}"))?;
            left -= n as u64;
        }
        Ok(len)
    }
}

fn read_at(f: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    f.read_at(buf, off)
}

/// Where an entry's payload starts, and how long it is — from the 30-byte
/// local header alone, so no body bytes are touched to find out.
fn local_span_file(pkg: &Pkg, entry: &CentralEntry) -> Result<(u64, u64), String> {
    let off = entry.local_offset;
    if off + 30 > pkg.len {
        return Err("zip: local header out of range".into());
    }
    let h = pkg.read_at(off, 30)?;
    if h[..4] != LOC_SIG {
        return Err(format!("zip: bad local signature for {}", entry.name));
    }
    let name_len = u16::from_le_bytes([h[26], h[27]]) as u64;
    let extra_len = u16::from_le_bytes([h[28], h[29]]) as u64;
    Ok((off + 30 + name_len + extra_len, entry.compressed_size))
}

/// Read and inflate one entry straight from the file. Only the compressed
/// body of a small archive member is materialised here (Info.plist, the
/// manifest), never an entry-sized blob of the whole package.
fn decompress_entry_pkg(pkg: &mut Pkg, entry: &CentralEntry) -> Result<Vec<u8>, String> {
    let (data_start, compressed) = local_span_file(pkg, entry)?;
    let body = pkg.read_at(data_start, compressed)?;
    decompress_bytes(&body, entry)
}

/// Strip ZIP64 extra blocks (id 0x0001) so the writer can regenerate
/// structural values instead of re-emitting stale ones.
fn decompress_bytes(body: &[u8], entry: &CentralEntry) -> Result<Vec<u8>, String> {
    if entry.method == 0 {
        return Ok(body.to_vec());
    }
    inflate(body, entry.uncompressed_size as usize)
}

fn strip_zip64_extra(extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra.len());
    let mut i = 0;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[i], extra[i + 1]]);
        let size = u16::from_le_bytes([extra[i + 2], extra[i + 3]]) as usize;
        let end = i + 4 + size;
        if end > extra.len() {
            // Truncated block: keep the tail verbatim rather than dropping.
            out.extend_from_slice(&extra[i..]);
            break;
        }
        if id != ZIP64_EXTRA_ID {
            out.extend_from_slice(&extra[i..end]);
        }
        i = end;
    }
    if i < extra.len() {
        out.extend_from_slice(&extra[i..]);
    }
    out
}

/// Build a ZIP64 extra block for the central directory. Fields appear in
/// spec order, only for values that overflow 32 bits: uncompressed,
/// compressed, local-header offset.
fn zip64_central_extra(uncompressed: u64, compressed: u64, offset: u64) -> Vec<u8> {
    let mut fields = Vec::with_capacity(24);
    if uncompressed >= ZIP64_SUB as u64 {
        fields.extend_from_slice(&uncompressed.to_le_bytes());
    }
    if compressed >= ZIP64_SUB as u64 {
        fields.extend_from_slice(&compressed.to_le_bytes());
    }
    if offset >= ZIP64_SUB as u64 {
        fields.extend_from_slice(&offset.to_le_bytes());
    }
    if fields.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(4 + fields.len());
    out.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    out.extend_from_slice(&fields);
    out
}

/// Build a ZIP64 extra block for a local header (sizes only).
fn zip64_local_extra(uncompressed: u64, compressed: u64) -> Vec<u8> {
    let mut fields = Vec::with_capacity(16);
    if uncompressed >= ZIP64_SUB as u64 {
        fields.extend_from_slice(&uncompressed.to_le_bytes());
    }
    if compressed >= ZIP64_SUB as u64 {
        fields.extend_from_slice(&compressed.to_le_bytes());
    }
    if fields.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(4 + fields.len());
    out.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    out.extend_from_slice(&fields);
    out
}

/// True when `name` is a Mach-O the installer has to be able to map directly:
/// the bundle's own binary, or one nested in a framework or an app extension.
///
/// The test is by name, not by magic, and deliberately so: a deflated
/// executable's bytes are still compressed at pack time, so sniffing a magic
/// number would either be impossible for most entries or force a decompress
/// pass that defeats the streaming design. Inside a bundle the executable
/// always repeats the bundle's own name, which makes the shape unambiguous —
/// `Frameworks/Networking.framework/Networking`, not `.../Resources/blob`.
fn is_executable_macho(name: &str) -> bool {
    if name.is_empty() || name.ends_with('/') {
        return false;
    }
    // Only ever inside an app bundle.
    if !name.starts_with("Payload/") {
        return false;
    }
    let Some((parent, file)) = name.rsplit_once('/') else {
        return false;
    };
    // The enclosing bundle directory, e.g. "Foo.app" / "Bar.framework".
    let bundle_dir = parent.rsplit('/').next().unwrap_or(parent);
    let Some((stem, ext)) = bundle_dir.rsplit_once('.') else {
        return false;
    };
    if !matches!(ext, "app" | "framework" | "appex") {
        return false;
    }
    // The binary inside a bundle always repeats the bundle's own name, which
    // is what keeps `Frameworks/Networking.framework/Resources/blob` and
    // `en.lproj/Localizable.strings` out. Watch apps and any deeper nesting
    // need no special case: the shape is identical.
    file == stem && !stem.is_empty()
}

/// Pad the local extra field so this entry's payload lands on a
/// `CODE_ALIGNMENT` boundary.
///
/// The payload offset is `local_offset + 30 + name_len + extra_len`, so the
/// local extra is the only lever. Nothing else has to move: the central
/// directory records the *local header* offset, not the payload offset, and
/// APPNOTE lets the two extra fields differ in length, so this needs no
/// central-directory change to keep offsets consistent.
///
/// A field is a four-byte header plus data, so a pad of 1..3 cannot form a
/// field of its own. Overshooting by one whole alignment unit keeps the
/// result aligned and costs 16 KiB on roughly one entry in five thousand.
fn align_payload_extra(extra: &mut Vec<u8>, local_offset: u64, name_len: usize) -> bool {
    let base = local_offset + 30 + name_len as u64 + extra.len() as u64;
    let residue = base % CODE_ALIGNMENT;
    if residue == 0 {
        return false;
    }
    let pad = (CODE_ALIGNMENT - residue) as usize;
    let total = if pad < 4 {
        pad + CODE_ALIGNMENT as usize
    } else {
        pad
    };
    debug_assert!(total >= 4);
    debug_assert!(total <= usize::from(u16::MAX));
    extra.extend_from_slice(&PAD_EXTRA_ID.to_le_bytes());
    extra.extend_from_slice(&((total - 4) as u16).to_le_bytes());
    extra.resize(extra.len() + (total - 4), 0);
    true
}

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
    /// Build the rebuilt local header for one entry, plus the framing flags
    /// the tail of `copy_raw` needs. Shared by the slice path (tests) and the
    /// file path (production) so the bytes cannot drift apart.
    fn build_local_header(
        &self,
        src_header: &[u8],
        entry: &CentralEntry,
    ) -> Result<(Vec<u8>, bool, bool), String> {
        if src_header.len() < 30 {
            return Err("zip: local header too short".into());
        }
        let name_len = u16::from_le_bytes([src_header[26], src_header[27]]) as usize;
        let src_extra = src_header.get(30 + name_len..).unwrap_or(&[]);
        let name_bytes = src_header.get(30..30 + name_len).unwrap_or(&[]);
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
        let need64 = entry.compressed_size >= ZIP64_SUB as u64
            || entry.uncompressed_size >= ZIP64_SUB as u64;
        // Local-header crc/sizes: zeroed for streaming (descriptor carries
        // them), concrete for inline (0xFFFFFFFF + ZIP64 extra when large).
        let (lh_crc, lh_csize, lh_usize) = if streaming {
            (0u32, 0u32, 0u32)
        } else if need64 {
            (entry.crc32, ZIP64_SUB, ZIP64_SUB)
        } else {
            (
                entry.crc32,
                entry.compressed_size as u32,
                entry.uncompressed_size as u32,
            )
        };
        // Rebuild the local header so a ZIP64 extra can grow it: fixed
        // 30-byte prefix + name + (stripped source extra + ZIP64 sizes).
        let mut local_extra = strip_zip64_extra(src_extra);
        if !streaming {
            local_extra.extend_from_slice(&zip64_local_extra(
                entry.uncompressed_size,
                entry.compressed_size,
            ));
        }
        // 16 KiB payload alignment for executable Mach-O (iOS 18 / A17 Pro /
        // M-series). `self.offset` is still this entry's local header offset
        // here, and the padding only lengthens the local extra, so the
        // central directory's local_offset stays valid untouched.
        if is_executable_macho(&entry.name) {
            align_payload_extra(&mut local_extra, self.offset, name_bytes.len());
        }
        if local_extra.len() > 0xFFFF {
            return Err("zip: local extra too long".into());
        }
        if name_bytes.len() > 0xFFFF {
            return Err("zip: entry name too long".into());
        }
        let mut header = Vec::with_capacity(30 + name_bytes.len() + local_extra.len());
        header.extend_from_slice(&LOC_SIG);
        // Version needed: 45 for ZIP64 entries, else copy source.
        let version_needed: u16 = if need64 && !streaming {
            45
        } else {
            u16::from_le_bytes([src_header[4], src_header[5]])
        };
        header.extend_from_slice(&version_needed.to_le_bytes());
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&entry.method.to_le_bytes());
        // mtime/mdate: copy source verbatim.
        header.extend_from_slice(&src_header[12..16]);
        header.extend_from_slice(&lh_crc.to_le_bytes());
        header.extend_from_slice(&lh_csize.to_le_bytes());
        header.extend_from_slice(&lh_usize.to_le_bytes());
        header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        header.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
        header.extend_from_slice(name_bytes);
        header.extend_from_slice(&local_extra);
        Ok((header, streaming, need64))
    }

    /// Write the data descriptor a streaming (bit 3) entry needs.
    fn write_descriptor(&mut self, entry: &CentralEntry, need64: bool) -> Result<(), String> {
        let mut descriptor = if need64 {
            let mut d = [0u8; 24].to_vec();
            d[8..16].copy_from_slice(&entry.compressed_size.to_le_bytes());
            d[16..24].copy_from_slice(&entry.uncompressed_size.to_le_bytes());
            d
        } else {
            let mut d = [0u8; 16].to_vec();
            d[8..12].copy_from_slice(&(entry.compressed_size as u32).to_le_bytes());
            d[12..16].copy_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
            d
        };
        descriptor[..4].copy_from_slice(&0x0807_4b50u32.to_le_bytes());
        descriptor[4..8].copy_from_slice(&entry.crc32.to_le_bytes());
        self.raw(&descriptor)
    }

    /// Remember a written entry for the central directory. `local_offset` is
    /// captured by the caller *before* the header is written, because
    /// `self.offset` advances with every byte.
    fn record_entry(&mut self, entry: &CentralEntry, streaming: bool, local_offset: u64) {
        let flags = if streaming {
            entry.flags | 0x8
        } else {
            entry.flags & !0x8
        };
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
    }

    /// Slice path, used by the tests and by anything already holding bytes.
    #[cfg(test)]
    fn copy_raw(&mut self, src: &[u8], entry: &CentralEntry) -> Result<(), String> {
        let (data_start, compressed) = local_span(src, entry)?;
        let src_header = src
            .get(entry.local_offset as usize..data_start)
            .ok_or("zip: entry header out of range")?;
        let (header, streaming, need64) = self.build_local_header(src_header, entry)?;
        let local_offset = self.offset;
        self.raw(&header)?;
        let data = src
            .get(data_start..data_start + compressed as usize)
            .ok_or("zip: entry data out of range")?;
        self.raw(data)?;
        if streaming {
            self.write_descriptor(entry, need64)?;
        }
        self.record_entry(entry, streaming, local_offset);
        Ok(())
    }

    /// File path: header from a small read, body streamed in fixed chunks, so
    /// nothing proportional to the package is ever resident.
    fn copy_raw_from_file(&mut self, pkg: &mut Pkg, entry: &CentralEntry) -> Result<(), String> {
        let (data_start, compressed) = local_span_file(pkg, entry)?;
        let hlen = data_start - entry.local_offset;
        let src_header = pkg.read_at(entry.local_offset, hlen)?;
        let (header, streaming, need64) = self.build_local_header(&src_header, entry)?;
        let local_offset = self.offset;
        self.raw(&header)?;
        let wrote = pkg.copy_range_to(data_start, compressed, &mut *self.out)?;
        // copy_range_to writes straight to the sink, so the writer's own
        // offset bookkeeping (self.raw) never saw these bytes.
        self.offset += wrote;
        if streaming {
            self.write_descriptor(entry, need64)?;
        }
        self.record_entry(entry, streaming, local_offset);
        Ok(())
    }

    /// Add a stored (method 0) entry.
    fn add_stored(&mut self, name: &str, data: &[u8], modified: (u16, u16)) -> Result<(), String> {
        if name.len() > 0xFFFF {
            return Err("zip: entry name too long".into());
        }
        let crc = crc32_ieee(data);
        let size = data.len() as u64;
        let need64 = size >= ZIP64_SUB as u64;
        let local_offset = self.offset;
        let local_extra = zip64_local_extra(size, size);
        if local_extra.len() > 0xFFFF {
            return Err("zip: local extra too long".into());
        }
        let mut header = Vec::with_capacity(30 + name.len() + local_extra.len());
        header.extend_from_slice(&LOC_SIG);
        header.extend_from_slice(&(if need64 { 45u16 } else { 0u16 }).to_le_bytes()); // version
        header.extend_from_slice(&0u16.to_le_bytes()); // flags
        header.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        header.extend_from_slice(&modified.1.to_le_bytes()); // time
        header.extend_from_slice(&modified.0.to_le_bytes()); // date
        header.extend_from_slice(&crc.to_le_bytes());
        if need64 {
            header.extend_from_slice(&ZIP64_SUB.to_le_bytes());
            header.extend_from_slice(&ZIP64_SUB.to_le_bytes());
        } else {
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        header.extend_from_slice(&local_extra);
        self.raw(&header)?;
        self.raw(data)?;
        self.entries.push(WrittenEntry {
            name: name.to_string(),
            method: 0,
            flags: 0,
            crc32: crc,
            compressed_size: size,
            uncompressed_size: size,
            local_offset,
            external_attrs: 0o100644 << 16,
            modified,
            central_extra: Vec::new(),
        });
        Ok(())
    }

    fn finish(mut self) -> Result<(), String> {
        let cd_start = self.offset;
        // ZIP64 triggers: entry count, CD size/offset, or any entry's
        // sizes/offset overflowing 32 bits. Previously these truncated via
        // `as u16/as u32`; now they emit real ZIP64 structures.
        let mut need64 = self.entries.len() >= ZIP64_SUB16 as usize;
        for e in &self.entries {
            if e.compressed_size >= ZIP64_SUB as u64
                || e.uncompressed_size >= ZIP64_SUB as u64
                || e.local_offset >= ZIP64_SUB as u64
            {
                need64 = true;
                break;
            }
        }
        let mut records: Vec<Vec<u8>> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            if e.name.len() > 0xFFFF {
                return Err("zip: entry name too long".into());
            }
            // Central extra: source bytes with stale ZIP64 stripped, plus a
            // fresh ZIP64 block when this entry overflows 32 bits.
            let mut extra = strip_zip64_extra(&e.central_extra);
            extra.extend_from_slice(&zip64_central_extra(
                e.uncompressed_size,
                e.compressed_size,
                e.local_offset,
            ));
            if extra.len() > 0xFFFF {
                return Err("zip: central extra too long".into());
            }
            let entry64 = e.compressed_size >= ZIP64_SUB as u64
                || e.uncompressed_size >= ZIP64_SUB as u64
                || e.local_offset >= ZIP64_SUB as u64;
            let version_needed: u16 = if entry64 { 45 } else { 0x0014 };
            let mut cen = Vec::with_capacity(46 + e.name.len() + extra.len());
            cen.extend_from_slice(&CEN_SIG);
            cen.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
            cen.extend_from_slice(&version_needed.to_le_bytes());
            cen.extend_from_slice(&e.flags.to_le_bytes());
            cen.extend_from_slice(&e.method.to_le_bytes());
            cen.extend_from_slice(&e.modified.1.to_le_bytes());
            cen.extend_from_slice(&e.modified.0.to_le_bytes());
            cen.extend_from_slice(&e.crc32.to_le_bytes());
            cen.extend_from_slice(
                &(if e.compressed_size >= ZIP64_SUB as u64 {
                    ZIP64_SUB
                } else {
                    e.compressed_size as u32
                })
                .to_le_bytes(),
            );
            cen.extend_from_slice(
                &(if e.uncompressed_size >= ZIP64_SUB as u64 {
                    ZIP64_SUB
                } else {
                    e.uncompressed_size as u32
                })
                .to_le_bytes(),
            );
            cen.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            cen.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            cen.extend_from_slice(&0u16.to_le_bytes()); // comment
            cen.extend_from_slice(&0u16.to_le_bytes()); // disk
            cen.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cen.extend_from_slice(&e.external_attrs.to_le_bytes());
            cen.extend_from_slice(
                &(if e.local_offset >= ZIP64_SUB as u64 {
                    ZIP64_SUB
                } else {
                    e.local_offset as u32
                })
                .to_le_bytes(),
            );
            cen.extend_from_slice(e.name.as_bytes());
            cen.extend_from_slice(&extra);
            records.push(cen);
        }
        for record in &records {
            self.raw(record)?;
        }
        let cd_size = self.offset - cd_start;
        if cd_size >= ZIP64_SUB as u64 || cd_start >= ZIP64_SUB as u64 {
            need64 = true;
        }
        if need64 {
            // ZIP64 end-of-central-directory record + locator, then the
            // regular EOCD with placeholder values.
            let zip64_eocd_offset = self.offset;
            let count = self.entries.len() as u64;
            let mut z64 = Vec::with_capacity(56);
            z64.extend_from_slice(&ZIP64_EOCD_SIG);
            z64.extend_from_slice(&44u64.to_le_bytes()); // size of remaining record
            z64.extend_from_slice(&0x0014u16.to_le_bytes()); // version made by
            z64.extend_from_slice(&45u16.to_le_bytes()); // version needed
            z64.extend_from_slice(&0u32.to_le_bytes()); // disk
            z64.extend_from_slice(&0u32.to_le_bytes()); // cd disk
            z64.extend_from_slice(&count.to_le_bytes()); // entries this disk
            z64.extend_from_slice(&count.to_le_bytes()); // entries total
            z64.extend_from_slice(&cd_size.to_le_bytes());
            z64.extend_from_slice(&cd_start.to_le_bytes());
            self.raw(&z64)?;
            let mut loc = Vec::with_capacity(20);
            loc.extend_from_slice(&ZIP64_LOC_SIG);
            loc.extend_from_slice(&0u32.to_le_bytes()); // cd disk
            loc.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
            loc.extend_from_slice(&1u32.to_le_bytes()); // disks
            self.raw(&loc)?;
        }
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG);
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        if need64 {
            eocd.extend_from_slice(&ZIP64_SUB16.to_le_bytes());
            eocd.extend_from_slice(&ZIP64_SUB16.to_le_bytes());
            eocd.extend_from_slice(&ZIP64_SUB.to_le_bytes());
            eocd.extend_from_slice(&ZIP64_SUB.to_le_bytes());
        } else {
            eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            eocd.extend_from_slice(&(cd_size as u32).to_le_bytes());
            eocd.extend_from_slice(&(cd_start as u32).to_le_bytes());
        }
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
    // The destination is only ever created by an atomic rename, so a failure
    // anywhere in the copy loop cannot leave a truncated package at the path
    // the caller was told would hold a finished one. Same filesystem, so
    // `rename` is atomic; the temp name sits beside the destination to keep it
    // that way.
    let partial = format!("{dst_path}.partial");
    match replicate_to(&partial, src_path, info, account) {
        Ok(true) => {
            std::fs::rename(&partial, dst_path).map_err(|e| {
                let _ = std::fs::remove_file(&partial);
                format!("finish {dst_path}: {e}")
            })?;
            Ok(true)
        }
        Ok(false) => {
            // No bundle found (rare): the caller decides what to keep.
            let _ = std::fs::remove_file(&partial);
            Ok(false)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(e)
        }
    }
}

/// Write the replicated package to `dst_path`. The caller owns publication:
/// see `replicate`, which renames this file into place only on success.
fn replicate_to(
    dst_path: &str,
    src_path: &str,
    info: &DownloadInfo,
    account: &Account,
) -> Result<bool, String> {
    // Stream the source through a File: nothing is mapped, so the resident
    // set is the largest single read (the central directory) and not the
    // package. Entry bodies move through a fixed 512 KiB buffer.
    let mut pkg = Pkg::open(src_path)?;
    // The EOCD lives in the last 66 KB; nothing before it is needed to
    // locate the central directory, which is then read as one block. The
    // window's own offset has to travel with it: the offsets inside the
    // record are absolute, and this package is 3 GB long.
    let tail_at = pkg.len.saturating_sub(66_000);
    let tail = pkg.read_at(tail_at, pkg.len - tail_at)?;
    let (_, eocd) = find_eocd_at(&tail, tail_at)?;
    let cd = pkg.read_at(eocd.cd_offset, eocd.cd_size)?;
    let entries = parse_central_at(&cd, 0, &eocd)?;
    drop(tail);
    drop(cd);
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

    let out_file =
        std::fs::File::create(dst_path).map_err(|e| format!("create {dst_path}: {e}"))?;
    let mut out = std::io::BufWriter::with_capacity(1 << 20, out_file);
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
        let raw = decompress_entry_pkg(&mut pkg, manifest_entry)?;
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
        read_bundle_executable_pkg(&mut pkg, &entries, &bundle_name)?
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
        zip.copy_raw_from_file(&mut pkg, entry)?;
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
    // Zip finalization: flush the coalescing buffer, then sync explicitly.
    // File::drop cannot report errors (majd e3dea14 fixed the same
    // silent-close loss in Go defers); a failed close would otherwise
    // leave a truncated package with no error.
    std::io::Write::flush(&mut out).map_err(|e| format!("replicate flush: {e}"))?;
    let out_file = out
        .into_inner()
        .map_err(|e| format!("replicate buffer: {e}"))?;
    out_file
        .sync_all()
        .map_err(|e| format!("replicate sync: {e}"))?;
    Ok(true)
}

/// CFBundleExecutable from the bundle's Info.plist (binary or XML).
fn read_bundle_executable_pkg(
    pkg: &mut Pkg,
    entries: &[CentralEntry],
    bundle: &str,
) -> Result<String, String> {
    let info_entry = entries
        .iter()
        .find(|e| e.name == format!("Payload/{bundle}.app/Info.plist"))
        .ok_or("bundle Info.plist not found")?;
    let raw = decompress_entry_pkg(pkg, info_entry)?;
    let doc = plist::parse_binary(&raw).or_else(|_| plist::parse_xml(&raw))?;
    Ok(doc
        .get("CFBundleExecutable")
        .and_then(|v| v.as_str())
        .unwrap_or(bundle)
        .to_string())
}

/// Extract one entry's bytes (stored or deflate via the fetcher's bzip2?
/// No — deflate; a compact inflate for the few plist files we read).
#[cfg(test)]
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
    // Same spellings curl's -r produced: a bare `start-end` span, or `-n` for
    // the last n bytes. The artwork endpoint is public, so this stays off the
    // Store agent's cookie jar exactly as the curl call was.
    let spec = match range {
        Range::Last(n) => format!("-{n}"),
        Range::Span(start, len) => format!("{start}-{}", start + len.saturating_sub(1)),
    };
    let res =
        crate::store::http::raw_request("GET", url, super::USER_AGENT, &[("Range", &spec)], None)?;
    if res.status != 206 && res.status != 200 {
        return Err(format!("range request failed: HTTP {}", res.status));
    }
    Ok(res.body)
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
        // Header-only check: the block must parse without "bad code length".
        // This guards the header decode (HLIT + HDIST + HCLEN + code
        // lengths); the full-stream inflate path is covered by the
        // round-trip tests below.
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

    #[test]
    fn zip64_extra_helpers() {
        // Small values: no block. Large values: placeholder-gated fields in
        // spec order (uncompressed, compressed, offset).
        assert!(zip64_central_extra(10, 20, 30).is_empty());
        let big = ZIP64_SUB as u64;
        let block = zip64_central_extra(big, 20, 30);
        assert_eq!(&block[..4], &[0x01, 0x00, 0x08, 0x00]);
        assert_eq!(&block[4..], &big.to_le_bytes());
        let block = zip64_central_extra(10, big + 1, big + 2);
        // compressed + offset, 16 bytes of fields.
        assert_eq!(u16::from_le_bytes([block[2], block[3]]), 16);
        // strip removes only id-0x0001 blocks, keeps the rest verbatim.
        let mut extra = vec![0x55, 0x54, 0x02, 0x00, 0xAA, 0xBB];
        extra.extend_from_slice(&block);
        extra.extend_from_slice(&[0x58, 0x55, 0x01, 0x00, 0xCC]);
        let stripped = strip_zip64_extra(&extra);
        assert_eq!(
            stripped,
            vec![
                0x55, 0x54, 0x02, 0x00, 0xAA, 0xBB, 0x58, 0x55, 0x01, 0x00, 0xCC
            ]
        );
    }

    #[test]
    fn zip64_finish_emits_structures_only_when_needed() {
        // Small archive: plain EOCD, no ZIP64 sigs.
        let small: Vec<u8> = {
            let mut b = Vec::new();
            let mut w = ZipWriter::new(&mut b);
            w.add_stored("a.txt", b"hi", (0x5A21, 0x0C00)).unwrap();
            w.finish().unwrap();
            b
        };
        assert!(!small.windows(4).any(|w| w == ZIP64_EOCD_SIG));
        assert!(!small.windows(4).any(|w| w == ZIP64_LOC_SIG));
        // Synthetic large entry: sizes/offset overflow 32 bits without
        // allocating gigabytes (entries are pushed directly).
        let big: Vec<u8> = {
            let mut b = Vec::new();
            let mut w = ZipWriter::new(&mut b);
            w.entries.push(WrittenEntry {
                name: "big.bin".into(),
                method: 0,
                flags: 0,
                crc32: 0,
                compressed_size: ZIP64_SUB as u64 + 10,
                uncompressed_size: ZIP64_SUB as u64 + 10,
                local_offset: ZIP64_SUB as u64 + 5,
                external_attrs: 0o100644 << 16,
                modified: (0x5A21, 0x0C00),
                central_extra: Vec::new(),
            });
            w.finish().unwrap();
            b
        };
        assert!(big.windows(4).any(|w| w == ZIP64_EOCD_SIG));
        assert!(big.windows(4).any(|w| w == ZIP64_LOC_SIG));
        // Regular EOCD carries placeholders when ZIP64 is in play (the
        // reader rejects ZIP64 inputs explicitly, so parse the tail by
        // hand instead of find_eocd).
        let at = big
            .windows(4)
            .rposition(|w| w == EOCD_SIG)
            .expect("regular EOCD present");
        let eocd = &big[at..at + 22];
        assert_eq!(u16::from_le_bytes([eocd[8], eocd[9]]), 0xFFFF);
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 0xFFFF);
        assert_eq!(
            u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]),
            0xFFFF_FFFF
        );
        assert_eq!(
            u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]),
            0xFFFF_FFFF
        );
        // The single central record uses 0xFFFFFFFF placeholders and owns
        // a ZIP64 extra block carrying the real 64-bit sizes.
        assert!(big.windows(4).any(|w| w == CEN_SIG));
        let huge = (ZIP64_SUB as u64 + 10).to_le_bytes();
        assert!(big.windows(8).any(|w| w == huge));
    }

    /// The executable predicate is the whole contract: get it wrong in either
    /// direction and the package is either unaligned or padded for nothing.
    #[test]
    fn executable_macho_predicate_covers_every_bundle_shape() {
        for yes in [
            "Payload/Telegram.app/Telegram",
            "Payload/Foo.app/Frameworks/Networking.framework/Networking",
            "Payload/Foo.app/PlugIns/Widget.appex/Widget",
            "Payload/Foo.app/Watch/WatchApp.app/WatchApp",
            "Payload/Foo.app/Frameworks/A/B.framework/B",
        ] {
            assert!(
                is_executable_macho(yes),
                "must be treated as executable: {yes}"
            );
        }
        for no in [
            "",
            "Payload/",
            "Payload/Foo.app/",
            "Payload/Foo.app/Info.plist",
            "Payload/Foo.app/Frameworks/Networking.framework/Resources/blob",
            "Payload/Foo.app/PlugIns/Widget.appex/Assets.car",
            "Payload/Foo.app/en.lproj/Localizable.strings",
            "iTunesMetadata.plist",
            "Payload/Foo.app/Other/Helper",
            "Payload/Foo.app/Frameworks/Networking.framework/Headers/NNetworking.h",
        ] {
            assert!(
                !is_executable_macho(no),
                "must NOT be treated as executable: {no}"
            );
        }
    }

    /// Padding has to land exactly on the boundary, including the 1..3 byte
    /// case that cannot form a field on its own.
    #[test]
    fn payload_extra_alignment_hits_the_boundary_exactly() {
        for name_len in [1usize, 7, 20, 63, 300, 4095] {
            for offset in [0u64, 1, 4095, 4096, 8191, 16383, 16384, 1_000_003] {
                for seed in [0usize, 4, 9, 17, 64] {
                    let mut extra = vec![0xAB; seed];
                    // A plausible pre-existing field, so growth is exercised
                    // on a non-empty extra too.
                    if seed >= 9 {
                        extra[0..2].copy_from_slice(&0x5455u16.to_le_bytes());
                        extra[2..4].copy_from_slice(&((seed - 4) as u16).to_le_bytes());
                    }
                    let base_len = extra.len();
                    let padded = align_payload_extra(&mut extra, offset, name_len);
                    let data_offset = offset + 30 + name_len as u64 + extra.len() as u64;
                    assert_eq!(
                        data_offset % CODE_ALIGNMENT,
                        0,
                        "offset={offset} name={name_len} seed={seed} extra={}",
                        extra.len()
                    );
                    if padded {
                        assert!(extra.len() > base_len, "padding must grow the extra");
                        // The tail is exactly one well-formed field.
                        let d = &extra[base_len..];
                        let id = u16::from_le_bytes([d[0], d[1]]);
                        let sz = u16::from_le_bytes([d[2], d[3]]) as usize;
                        assert_eq!(id, PAD_EXTRA_ID);
                        assert_eq!(sz + 4, d.len(), "field length must match its header");
                    } else {
                        assert_eq!(data_offset, offset + 30 + name_len as u64 + base_len as u64);
                    }
                }
            }
        }
    }

    /// End-to-end: replicate a package carrying an app binary, a framework
    /// binary and an appex binary, then walk the output's local headers and
    /// assert every executable Mach-O payload sits on a 16 KiB boundary —
    /// and that the archive is still a readable zip afterwards.
    #[test]
    fn ipa_replicate_aligns_executables_to_16k() {
        const BIN: &[u8] = b"\xcf\xfa\xed\xfeEXECUTABLE";
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut zip = ZipWriter::new(&mut buf);
            let (d, t) = (0x5A21, 0x0C00);
            let mut ip = Plist::dict();
            ip.set("CFBundleExecutable", Plist::string("TestApp"));
            zip.add_stored(
                "Payload/TestApp.app/Info.plist",
                &plist::to_binary(&ip),
                (d, t),
            )
            .unwrap();
            zip.add_stored("Payload/TestApp.app/TestApp", BIN, (d, t))
                .unwrap();
            zip.add_stored(
                "Payload/TestApp.app/Frameworks/Net.framework/Net",
                BIN,
                (d, t),
            )
            .unwrap();
            zip.add_stored(
                "Payload/TestApp.app/PlugIns/Widget.appex/Widget",
                BIN,
                (d, t),
            )
            .unwrap();
            // Non-executable neighbours must be left alone.
            zip.add_stored(
                "Payload/TestApp.app/Frameworks/Net.framework/Resources/x",
                b"data",
                (d, t),
            )
            .unwrap();
            zip.add_stored(
                "Payload/TestApp.app/Watch/WatchApp.app/WatchApp",
                BIN,
                (d, t),
            )
            .unwrap();
            zip.finish().unwrap();
        }

        let src_path =
            std::env::temp_dir().join(format!("perun-align-src-{}.zip", std::process::id()));
        let out_path =
            std::env::temp_dir().join(format!("perun-align-out-{}.ipa", std::process::id()));
        std::fs::write(&src_path, &buf).unwrap();

        let info = DownloadInfo {
            url: String::new(),
            sinfs: Vec::new(),
            metadata: Plist::dict(),
            version: "1.0".into(),
            artwork_url: String::new(),
            artwork: None,
        };
        let account = crate::store::account::Account {
            email: "tester@example.com".into(),
            ..Default::default()
        };
        replicate(
            src_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            &info,
            &account,
        )
        .unwrap();

        let out = std::fs::read(&out_path).unwrap();
        let (_, eocd) = find_eocd(&out).unwrap();
        let entries = parse_central(&out, &eocd).unwrap();

        let mut checked = 0;
        for e in &entries {
            let (data_start, _) = local_span(&out, e).unwrap();
            if is_executable_macho(&e.name) {
                assert_eq!(
                    data_start as u64 % CODE_ALIGNMENT,
                    0,
                    "unaligned executable payload: {} at {data_start}",
                    e.name
                );
                // Content survived the padding.
                assert_eq!(decompress_entry(&out, e).unwrap(), BIN, "{}", e.name);
                checked += 1;
            }
        }
        assert_eq!(
            checked, 4,
            "expected app, framework, appex and watch binaries"
        );

        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&out_path);
    }

    /// `Pkg` is the only thing standing between the writer and a 3.6 GiB
    /// mapping, so its positional read gets checked against a real file
    /// rather than trusted.
    #[test]
    fn pkg_reads_ranges_and_local_spans() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut buf);
            let (d, t) = (0x5A21, 0x0C00);
            let mut big = vec![0xABu8; 300_000];
            for (i, b) in big.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            z.add_stored("Payload/Big.app/Big", &big, (d, t)).unwrap();
            z.add_stored("Payload/Big.app/Small", b"hi", (d, t))
                .unwrap();
            z.finish().unwrap();
        }
        let path = std::env::temp_dir().join(format!("perun-pkg-{}.zip", std::process::id()));
        std::fs::write(&path, &buf).unwrap();
        let pkg = Pkg::open(path.to_str().unwrap()).unwrap();

        assert_eq!(pkg.len, buf.len() as u64);
        // whole-file read, then a range in the middle
        assert_eq!(pkg.read_at(0, pkg.len).unwrap(), buf);
        let mid = pkg.len / 2;
        let off = 37u64.min(mid);
        assert_eq!(
            pkg.read_at(off, 64).unwrap(),
            &buf[off as usize..off as usize + 64]
        );

        // the CD is reachable and parses from a CD-only buffer. The tail is a
        // window, so its offset inside the package travels with it: a 300 KB
        // file's last 66 KB start at 234 KB, and every offset in the record
        // is absolute.
        let tail_at = pkg.len.saturating_sub(66_000);
        let tail = pkg.read_at(tail_at, pkg.len - tail_at).unwrap();
        let (eocd_at, eocd) = find_eocd_at(&tail, tail_at).unwrap();
        assert_eq!(
            eocd_at,
            pkg.len - 22,
            "the record is the file's last 22 bytes"
        );
        let cd = pkg.read_at(eocd.cd_offset, eocd.cd_size).unwrap();
        let entries = parse_central_at(&cd, 0, &eocd).unwrap();
        assert_eq!(entries.len(), 2);

        // and a local header is found without touching the body
        let small = entries.iter().find(|e| e.name.ends_with("/Small")).unwrap();
        let (data_start, compressed) = local_span_file(&pkg, small).unwrap();
        assert_eq!(compressed, 2);
        assert!(data_start < small.local_offset + 64);
        let _ = std::fs::remove_file(&path);
    }

    // ── regression: EOCD comment length read as the disk number (F4) ────────
    //
    // The end-of-central-directory record ends with a 2-byte comment length.
    // Reading that as "disk number must be zero" rejects every valid archive
    // that carries a comment, and reports the cause as a multi-disk archive,
    // which it is not.
    #[test]
    fn eocd_with_a_comment_is_accepted() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut buf);
            z.add_stored("Payload/Comment.app/Comment", b"hi", (0x5A21, 0x0C00))
                .unwrap();
            z.finish().unwrap();
        }
        let plain = find_eocd(&buf).is_ok();
        assert!(plain, "control: a comment-free archive must be found");

        // Append a comment the way APPNOTE describes: the length goes in the
        // last two bytes of the record, the text follows it.
        let mut commented = buf.clone();
        let at = commented.len() - 22;
        let text = b"an archive comment";
        let n = text.len() as u16;
        commented[at + 20..at + 22].copy_from_slice(&n.to_le_bytes());
        commented.extend_from_slice(text);

        let (off, eocd) =
            find_eocd(&commented).expect("an archive with a comment must be located, not rejected");
        assert_eq!(off, commented.len() - 22 - text.len());
        assert_eq!(eocd.entry_count, 1);
        assert!(eocd.cd_offset + eocd.cd_size <= off as u64);

        // A real multi-disk archive must still be refused, and named as such.
        let mut multidisk = buf.clone();
        let at = multidisk.len() - 22;
        multidisk[at + 4..at + 6].copy_from_slice(&1u16.to_le_bytes());
        let err = match find_eocd(&multidisk) {
            Err(e) => e,
            Ok(_) => panic!("a multi-disk archive must be refused"),
        };
        assert!(err.contains("multi-disk"), "{err}");
    }

    // ── regression: a signature inside the comment is not the record (F7) ───
    //
    // `PK\x05\x06` also occurs inside entry data and inside a comment. A
    // candidate is only believed when the directory it points at ends at or
    // before the candidate itself, which is what stops a forgery sitting in a
    // comment from displacing the archive's own record.
    #[test]
    fn eocd_scan_ignores_a_forged_record_in_the_comment() {
        // 22 bytes that look exactly like a record. The numbers are ordinary
        // 32-bit values on purpose: the ZIP64 0xFFFF_FFFF placeholders are
        // deliberately let through by the filter (their real numbers live in
        // the zip64 record, which the caller rejects by name), so a forgery
        // carrying them would be believed and would test the wrong thing.
        let mut forged = Vec::new();
        forged.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        forged.extend_from_slice(&0u16.to_le_bytes()); // disk
        forged.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        forged.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        forged.extend_from_slice(&1u16.to_le_bytes()); // entries total
        forged.extend_from_slice(&0x100u32.to_le_bytes()); // cd size
        forged.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // cd offset
        forged.extend_from_slice(&0u16.to_le_bytes()); // comment length

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut buf);
            z.add_stored("Payload/Forge.app/Forge", b"hi", (0x5A21, 0x0C00))
                .unwrap();
            z.finish().unwrap();
        }
        // Control: an archive with no forgery at all is still found.
        let mut clean: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut clean);
            z.add_stored("Payload/Forge.app/Forge", b"hi", (0x5A21, 0x0C00))
                .unwrap();
            z.finish().unwrap();
        }
        find_eocd(&clean).expect("control");

        // The forgery goes in the comment, i.e. *after* the real record, so
        // "the last candidate wins" is exactly what has to reject it. Without
        // the filter it is believed, it is last, and the archive's own
        // directory offsets are lost.
        let mut commented = buf.clone();
        let at = commented.len() - 22;
        let n = forged.len() as u16;
        commented[at + 20..at + 22].copy_from_slice(&n.to_le_bytes());
        commented.extend_from_slice(&forged);

        let (off, eocd) =
            find_eocd(&commented).expect("the archive's own record must win over the forgery");
        assert_eq!(off, buf.len() - 22, "the real record, not the forgery");
        assert_eq!(eocd.entry_count, 1);
        assert_ne!(eocd.cd_offset, 0xDEAD_BEEF);
        // And the directory it names is the real one.
        let (_, real) = find_eocd(&buf).unwrap();
        assert_eq!(eocd.cd_offset, real.cd_offset);
        assert_eq!(eocd.cd_size, real.cd_size);
    }

    // ── regression: DOS time and date kept in their own fields (F1) ─────────
    //
    // The central record stores the modification time at offset 12 and the
    // modification date at offset 14. The pair is a tuple in the writer, and
    // a transposition there silently rewrites every timestamp in the package.
    #[test]
    fn central_records_preserve_dos_time_and_date_order() {
        const TIME: u16 = 0x0C5D; // 06:11:00
        const DATE: u16 = 0x5A21; // 2022-09-01
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut buf);
            let mut ip = Plist::dict();
            ip.set("CFBundleExecutable", Plist::string("Stamp"));
            z.add_stored(
                "Payload/Stamp.app/Info.plist",
                &plist::to_binary(&ip),
                (DATE, TIME),
            )
            .unwrap();
            z.add_stored("Payload/Stamp.app/Stamp", b"hi", (DATE, TIME))
                .unwrap();
            z.add_stored("Payload/Stamp.app/Second", b"ho", (DATE, TIME))
                .unwrap();
            z.finish().unwrap();
        }
        let out = replicate_bytes(&buf);
        let (_, eocd) = find_eocd(&out).unwrap();
        let records = central_records(&out, &eocd);
        // Info.plist, two copied bodies, and the metadata sidecar.
        assert_eq!(
            records.len(),
            4,
            "{:?}",
            records.iter().map(|(_, e)| &e.name).collect::<Vec<_>>()
        );
        for (at, e) in &records {
            if e.name == "iTunesMetadata.plist" {
                continue;
            }
            let time = u16::from_le_bytes([out[at + 12], out[at + 13]]);
            let date = u16::from_le_bytes([out[at + 14], out[at + 15]]);
            assert_eq!(time, TIME, "{}: the time field holds the date", e.name);
            assert_eq!(date, DATE, "{}: the date field holds the time", e.name);
        }
        // The injected sidecar is written by a different code path and must
        // keep the same field order: a real DOS date, not the time value.
        let (at, _) = records
            .iter()
            .find(|(_, e)| e.name == "iTunesMetadata.plist")
            .expect("metadata record");
        let time = u16::from_le_bytes([out[at + 12], out[at + 13]]);
        let date = u16::from_le_bytes([out[at + 14], out[at + 15]]);
        let year = 1980 + ((date >> 9) & 0x7f);
        assert!(
            (2020..2100).contains(&year),
            "injected date must be a real date, got {date:#06x} (year {year})"
        );
        assert_ne!(time, date, "injected time and date must not be transposed");
    }

    /// Every central record as `(offset in blob, parsed record)`, walked from
    /// the directory's own start rather than by scanning for the signature.
    fn central_records(blob: &[u8], eocd: &Eocd) -> Vec<(usize, CentralEntry)> {
        let mut out = Vec::with_capacity(eocd.entry_count as usize);
        let mut at = eocd.cd_offset as usize;
        let end = at + eocd.cd_size as usize;
        while at + 46 <= end {
            if blob[at..at + 4] != CEN_SIG {
                break;
            }
            let nl = u16::from_le_bytes([blob[at + 28], blob[at + 29]]) as usize;
            let el = u16::from_le_bytes([blob[at + 30], blob[at + 31]]) as usize;
            let cl = u16::from_le_bytes([blob[at + 32], blob[at + 33]]) as usize;
            let mut rec = CentralEntry {
                name: String::from_utf8_lossy(&blob[at + 46..at + 46 + nl]).into_owned(),
                method: 0,
                flags: 0,
                crc32: 0,
                compressed_size: 0,
                uncompressed_size: 0,
                local_offset: 0,
                external_attrs: 0,
                modified: (0, 0),
                central_extra: Vec::new(),
            };
            rec.modified = (
                u16::from_le_bytes([blob[at + 12], blob[at + 13]]),
                u16::from_le_bytes([blob[at + 14], blob[at + 15]]),
            );
            out.push((at, rec));
            at += 46 + nl + el + cl;
        }
        out
    }

    /// Replicate an in-memory package through the file-backed path, which is
    /// the only path the tests for the fixes below can exercise.
    fn replicate_bytes(src: &[u8]) -> Vec<u8> {
        let id = std::process::id();
        let src_path = std::env::temp_dir().join(format!("perun-byt-src-{id}.zip"));
        let out_path = std::env::temp_dir().join(format!("perun-byt-out-{id}.ipa"));
        let _ = std::fs::remove_file(&out_path);
        std::fs::write(&src_path, src).unwrap();
        replicate(
            src_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            &DownloadInfo {
                url: String::new(),
                sinfs: Vec::new(),
                metadata: Plist::dict(),
                version: "1.0".into(),
                artwork_url: String::new(),
                artwork: None,
            },
            &crate::store::account::Account {
                email: "tester@example.com".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let out = std::fs::read(&out_path).unwrap();
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&out_path);
        out
    }

    // ── regression: a failed replication leaves no destination (F3) ─────────
    //
    // The destination used to be created before the copy loop, so an error
    // inside the loop left a truncated package sitting at the path the caller
    // was told would hold a finished one.
    #[test]
    fn failed_replicate_leaves_no_destination_file() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut z = ZipWriter::new(&mut buf);
            // A bundle Info.plist: `replicate` resolves the bundle name from
            // it, so without one the run stops before the copy loop and the
            // test would not exercise the failure path it is about.
            let mut ip = Plist::dict();
            ip.set("CFBundleExecutable", Plist::string("Break"));
            z.add_stored(
                "Payload/Break.app/Info.plist",
                &plist::to_binary(&ip),
                (0x5A21, 0x0C00),
            )
            .unwrap();
            z.add_stored(
                "Payload/Break.app/Break",
                &vec![b'B'; 20_000],
                (0x5A21, 0x0C00),
            )
            .unwrap();
            z.add_stored(
                "Payload/Break.app/Late",
                &vec![b'L'; 20_000],
                (0x5A21, 0x0C00),
            )
            .unwrap();
            z.finish().unwrap();
        }
        // Point the last record's local offset 7 bytes into the first entry's
        // header: the range check passes, the signature check does not, and the
        // failure lands inside the copy loop with one entry already written.
        let mut broken = buf.clone();
        let mut at = broken.len() - 22;
        let cd_off = u32::from_le_bytes([
            broken[at + 16],
            broken[at + 17],
            broken[at + 18],
            broken[at + 19],
        ]) as usize;
        at = cd_off;
        let mut last = None;
        while at + 46 <= broken.len() && broken[at..at + 4] == CEN_SIG {
            last = Some(at);
            let nl = u16::from_le_bytes([broken[at + 28], broken[at + 29]]) as usize;
            let el = u16::from_le_bytes([broken[at + 30], broken[at + 31]]) as usize;
            let cl = u16::from_le_bytes([broken[at + 32], broken[at + 33]]) as usize;
            at += 46 + nl + el + cl;
        }
        let last = last.expect("at least one central record");
        broken[last + 42..last + 46].copy_from_slice(&7u32.to_le_bytes());

        let id = std::process::id();
        let src_path = std::env::temp_dir().join(format!("perun-f3-src-{id}.zip"));
        let out_path = std::env::temp_dir().join(format!("perun-f3-out-{id}.ipa"));
        let _ = std::fs::remove_file(&out_path);
        std::fs::write(&src_path, &broken).unwrap();

        let err = replicate(
            src_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            &DownloadInfo {
                url: String::new(),
                sinfs: Vec::new(),
                metadata: Plist::dict(),
                version: "1.0".into(),
                artwork_url: String::new(),
                artwork: None,
            },
            &crate::store::account::Account {
                email: "tester@example.com".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.contains("zip:"), "{err}");
        assert!(
            !out_path.exists(),
            "a failed replication must not leave a file at the destination"
        );
        let _ = std::fs::remove_file(&src_path);
    }
}
