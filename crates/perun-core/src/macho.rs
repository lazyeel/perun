// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Minimal Mach-O (x86_64) header parsing, fat-universal dispatch, and the
//! classic `LC_DYLD_INFO(_ONLY)` rebase/bind stream interpreter.
//!
//! The 2013 CoreFP/CommerceKit pair Apple ships in the OS X 10.9 update
//! package uses the classic dyld info format (no chained fixups), so this
//! module deliberately covers only that generation: enough to relocate the
//! images natively, nothing speculative.
//!
//! Everything is read with explicit offsets from the byte stream, mirroring
//! `image.rs`; no `#[repr(C)]` alignment traps.

/// Mach-O 64-bit magic (little-endian file).
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
/// Fat (universal) file magic.
pub const FAT_MAGIC: u32 = 0xcafebabe;
/// CPU type x86_64.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_DYLD_INFO: u32 = 0x22;

/// One load command, kept as (cmd, offset-in-file) for lazy inspection.
#[derive(Debug, Clone, Copy)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    /// Offset of the command payload in the file.
    pub off: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Segment64 {
    pub name: [u8; 16],
    /// VM address of the segment in the file's preferred layout.
    pub vmaddr: u64,
    pub vmsize: u64,
    /// File offset and size of initialized data.
    pub fileoff: u64,
    pub filesize: u64,
    pub initprot: i32,
    pub maxprot: i32,
}

impl Segment64 {
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

/// Fixup kinds we interpret. Classic dyld info opcode families collapse to
/// these two entry shapes.
#[derive(Debug, Clone)]
pub struct RebaseEntry {
    pub segment: [u8; 16],
    pub seg_off: u64,
    /// Target address in the file's preferred layout (segment vmaddr + off).
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct BindEntry {
    pub segment: [u8; 16],
    pub seg_off: u64,
    /// Symbol name, leading underscore included.
    pub name: String,
    pub addend: i64,
}

/// Symtab entry (nlist64) — defined symbols with a value are collected.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    /// Address in the file's preferred layout.
    pub addr: u64,
}

/// Parsed Mach-O x86_64 image (one slice of a fat file, or a thin file).
#[derive(Debug, Clone)]
pub struct MachInfo {
    /// Executable __text section bounds in the x86_64 slice, as
    /// (file_offset, size). Code-only patching (rdtsc neutralization)
    /// must stay inside these; __const holds crypto constants where the
    /// idiom bytes appear as data.
    pub text_section: Option<(u64, u64)>,
    /// The x86_64 slice bytes (owned copy when sliced out of a fat file).
    pub data: Vec<u8>,
    /// Preferred base: lowest `vmaddr` across non-__PAGEZERO segments.
    pub base: u64,
    pub segments: Vec<Segment64>,
    pub commands: Vec<LoadCommand>,
    pub rebases: Vec<RebaseEntry>,
    pub binds: Vec<BindEntry>,
    /// Defined symbols from the classic symtab.
    pub symbols: Vec<Symbol>,
}

#[derive(Debug)]
pub enum MachError {
    NotMachO,
    NoX86Slice,
    Truncated,
    BadLoadCommands,
    UnsupportedFixup { kind: &'static str, value: u8 },
    BadSegment { name: String },
    MissingSegment { name: String },
    Io(String),
}

impl core::fmt::Display for MachError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotMachO => write!(f, "not a Mach-O image"),
            Self::NoX86Slice => write!(f, "universal binary has no x86_64 slice"),
            Self::Truncated => write!(f, "file truncated"),
            Self::BadLoadCommands => write!(f, "malformed load command table"),
            Self::UnsupportedFixup { kind, value } => {
                write!(f, "unsupported {kind} type {value}")
            }
            Self::BadSegment { name } => write!(f, "malformed segment {name}"),
            Self::MissingSegment { name } => write!(f, "fixup references unknown segment {name}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for MachError {}

impl From<std::io::Error> for MachError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

fn u16_at(d: &[u8], off: usize) -> Result<u16, MachError> {
    if off + 2 > d.len() {
        return Err(MachError::Truncated);
    }
    Ok(u16::from_le_bytes(d[off..off + 2].try_into().unwrap()))
}
fn u32_at(d: &[u8], off: usize) -> Result<u32, MachError> {
    if off + 4 > d.len() {
        return Err(MachError::Truncated);
    }
    Ok(u32::from_le_bytes(d[off..off + 4].try_into().unwrap()))
}
fn u64_at(d: &[u8], off: usize) -> Result<u64, MachError> {
    if off + 8 > d.len() {
        return Err(MachError::Truncated);
    }
    Ok(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()))
}

/// ULEB128 reader returning (value, offset after the last byte read).
fn read_uleb(d: &[u8], mut p: usize) -> Result<(u64, usize), MachError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if p >= d.len() {
            return Err(MachError::Truncated);
        }
        let b = d[p];
        p += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(MachError::Truncated);
        }
    }
    Ok((result, p))
}

/// SLEB128 reader returning (value, offset after the last byte read).
fn read_sleb(d: &[u8], mut p: usize) -> Result<(i64, usize), MachError> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    loop {
        if p >= d.len() {
            return Err(MachError::Truncated);
        }
        let b = d[p];
        p += 1;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if b & 0x40 != 0 && shift < 64 {
                result |= -1i64 << shift;
            }
            break;
        }
        if shift > 63 {
            return Err(MachError::Truncated);
        }
    }
    Ok((result, p))
}

fn cstr_at(d: &[u8], mut p: usize) -> Result<String, MachError> {
    let start = p;
    while p < d.len() && d[p] != 0 {
        p += 1;
    }
    if p >= d.len() {
        return Err(MachError::Truncated);
    }
    Ok(String::from_utf8_lossy(&d[start..p]).into_owned())
}

/// Detect a fat container and return the x86_64 slice, or the input back if
/// the file is a thin Mach-O.
pub fn x86_slice(input: &[u8]) -> Result<Vec<u8>, MachError> {
    if input.len() < 4 {
        return Err(MachError::Truncated);
    }
    if u32::from_be_bytes(input[0..4].try_into().unwrap()) == FAT_MAGIC {
        let narch = u32::from_be_bytes(input[4..8].try_into().unwrap()) as usize;
        if input.len() < 8 + narch * 20 {
            return Err(MachError::Truncated);
        }
        for i in 0..narch {
            let rec = &input[8 + i * 20..8 + (i + 1) * 20];
            let cputype = u32::from_be_bytes(rec[0..4].try_into().unwrap());
            let offset = u32::from_be_bytes(rec[8..12].try_into().unwrap()) as usize;
            let size = u32::from_be_bytes(rec[12..16].try_into().unwrap()) as usize;
            if cputype == CPU_TYPE_X86_64 {
                if offset + size > input.len() {
                    return Err(MachError::Truncated);
                }
                return Ok(input[offset..offset + size].to_vec());
            }
        }
        return Err(MachError::NoX86Slice);
    }
    Ok(input.to_vec())
}

/// Both classic streams share one opcode encoding; one decoder, two modes.
/// Opcode tables per Apple's `mach-o/rebase.h` / `mach-o/bind.h`:
/// rebase: 0x00 DONE, 0x10 SET_TYPE_IMM, 0x20 SET_SEGMENT_AND_OFFSET_ULEB,
///         0x30 ADD_ADDR_ULEB, 0x40 ADD_ADDR_IMM_SCALED, 0x50 DO_REBASE_IMM_TIMES,
///         0x60 DO_REBASE_ULEB_TIMES, 0x70 DO_REBASE_ADD_ADDR_ULEB,
///         0x80 DO_REBASE_ULEB_TIMES_SKIPPING_ULEB.
/// bind:   0x00 DONE, 0x10/0x20/0x30 SET_DYLIB_ORDINAL, 0x40 SET_SYMBOL_TRAILING_FLAGS,
///         0x50 SET_TYPE_IMM, 0x60 SET_ADDEND_SLEB, 0x70 SET_SEGMENT_AND_OFFSET_ULEB,
///         0x80 ADD_ADDR_ULEB, 0x90 DO_BIND, 0xA0 DO_BIND_ADD_ADDR_LEB,
///         0xB0 DO_BIND_ADD_ADDR_IMM_SCALED, 0xC0 DO_BIND_ULEB_TIMES_SKIPPING_ULEB.
#[allow(clippy::type_complexity)]
fn decode_stream(
    d: &[u8],
    off: usize,
    size: usize,
    binds: bool,
    is_lazy: bool,
) -> Result<Vec<(usize, u64, Option<(String, i64)>)>, MachError> {
    if off + size > d.len() {
        return Err(MachError::Truncated);
    }
    let s = &d[off..off + size];
    let mut out = Vec::new();
    if s.is_empty() {
        return Ok(out);
    }
    let mut p = 0usize;
    let mut seg_idx: usize = 0;
    let mut cursor: u64 = 0;
    let mut addend: i64 = 0;
    let mut done = false;
    while !done && p < s.len() {
        let op = s[p];
        p += 1;
        let opcode = op & 0xF0;
        let imm = op & 0x0F;
        match (binds, opcode) {
            (_, 0x00) => {
                // DONE terminates the classic bind stream; in the lazy
                // stream it only flushes the current record and parsing
                // continues (each lazy entry is self-contained).
                if !is_lazy {
                    done = true;
                } else {
                    // Reset per-record state, mirroring dyld.
                    seg_idx = 0;
                    cursor = 0;
                    addend = 0;
                    // Symbol name persists across records in lazy streams
                    // only until the next SET_SYMBOL; reset it too.
                    clear_symbol();
                }
            }
            // ── rebase stream ──
            (false, 0x10) => {
                // SET_TYPE_IMM — only pointer (1) supported.
                if imm != 1 {
                    return Err(MachError::UnsupportedFixup {
                        kind: "rebase",
                        value: imm,
                    });
                }
            }
            (false, 0x20) | (true, 0x70) => {
                // SET_SEGMENT_AND_OFFSET_ULEB
                seg_idx = imm as usize;
                let (v, np) = read_uleb(s, p)?;
                cursor = v;
                p = np;
            }
            (false, 0x30) | (true, 0x80) => {
                // ADD_ADDR_ULEB
                let (v, np) = read_uleb(s, p)?;
                cursor = cursor.wrapping_add(v);
                p = np;
            }
            (false, 0x40) => {
                // ADD_ADDR_IMM_SCALED — advance only, no fixup emitted.
                // Apple dyld: segOffset += immediate*ptrSize.
                cursor = cursor.wrapping_add(8 * imm as u64);
            }
            (false, 0x50) => {
                // DO_REBASE_IMM_TIMES
                for _ in 0..imm {
                    push(&mut out, seg_idx, cursor, None);
                    cursor += 8;
                }
            }
            (false, 0x60) => {
                // DO_REBASE_ULEB_TIMES
                let (times, np) = read_uleb(s, p)?;
                p = np;
                for _ in 0..times {
                    push(&mut out, seg_idx, cursor, None);
                    cursor += 8;
                }
            }
            (false, 0x70) => {
                // DO_REBASE_ADD_ADDR_ULEB
                push(&mut out, seg_idx, cursor, None);
                let (v, np) = read_uleb(s, p)?;
                cursor = cursor.wrapping_add(v + 8);
                p = np;
            }
            (false, 0x80) => {
                // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB. Apple dyld:
                // segOffset += skip + ptrSize per iteration.
                let (times, np) = read_uleb(s, p)?;
                let (skip, np2) = read_uleb(s, np)?;
                p = np2;
                for _ in 0..times {
                    push(&mut out, seg_idx, cursor, None);
                    cursor = cursor.wrapping_add(skip + 8);
                }
            }
            // ── bind stream ──
            (true, 0x10) => {
                // SET_DYLIB_ORDINAL_IMM — irrelevant (single flat table).
            }
            (true, 0x20) => {
                // SET_DYLIB_ORDINAL_ULEB — irrelevant.
                let (_v, np) = read_uleb(s, p)?;
                p = np;
            }
            (true, 0x30) => {
                // SET_DYLD_SPECIAL_IMM — irrelevant.
            }
            (true, 0x40) => {
                // SET_SYMBOL_TRAILING_FLAGS_IMM: NUL-terminated name follows.
                let name = cstr_at(s, p)?;
                p += name.len() + 1;
                set_symbol(name);
            }
            (true, 0x50) => {
                // SET_TYPE_IMM — pointer (1) or lazy-absent (0); else reject.
                if imm != 1 && imm != 0 {
                    return Err(MachError::UnsupportedFixup {
                        kind: "bind",
                        value: imm,
                    });
                }
            }
            (true, 0x60) => {
                // SET_ADDEND_SLEB
                let (v, np) = read_sleb(s, p)?;
                addend = v;
                p = np;
            }
            (true, 0x90) => {
                // DO_BIND
                let name = take_symbol();
                push(&mut out, seg_idx, cursor, Some((name, addend)));
                cursor += 8;
            }
            (true, 0xA0) => {
                // DO_BIND_ADD_ADDR_LEB
                let name = take_symbol();
                push(&mut out, seg_idx, cursor, Some((name, addend)));
                let (v, np) = read_uleb(s, p)?;
                cursor = cursor.wrapping_add(v + 8);
                p = np;
            }
            (true, 0xB0) => {
                // DO_BIND_ADD_ADDR_IMM_SCALED
                let name = take_symbol();
                push(&mut out, seg_idx, cursor, Some((name, addend)));
                cursor += 8 * (imm as u64 + 1);
            }
            (true, 0xC0) => {
                // DO_BIND_ULEB_TIMES_SKIPPING_ULEB. Apple dyld:
                // segmentOffset += skip + ptrSize per iteration.
                let (times, np) = read_uleb(s, p)?;
                let (skip, np2) = read_uleb(s, np)?;
                p = np2;
                let name = take_symbol();
                for _ in 0..times {
                    push(&mut out, seg_idx, cursor, Some((name.clone(), addend)));
                    cursor = cursor.wrapping_add(skip + 8);
                }
            }
            (_, other) => {
                return Err(MachError::UnsupportedFixup {
                    kind: if binds { "bind" } else { "rebase" },
                    value: other,
                });
            }
        }
        if p >= s.len() {
            break;
        }
    }
    Ok(out)
}

// The bind stream's symbol name is streaming state shared across DO_BIND
// opcodes; a decoder-local cell keeps the main loop flat.
thread_local! {
    static STREAM_SYMBOL: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}
fn set_symbol(name: String) {
    STREAM_SYMBOL.with(|s| *s.borrow_mut() = name);
}
fn take_symbol() -> String {
    STREAM_SYMBOL.with(|s| s.borrow().clone())
}

fn clear_symbol() {
    STREAM_SYMBOL.with(|s| *s.borrow_mut() = String::new());
}

/// One decoded dyld-info stream op: (segment index, offset, optional bind
/// target with addend).
type StreamEntry = (usize, u64, Option<(String, i64)>);

fn push(out: &mut Vec<StreamEntry>, seg_idx: usize, cursor: u64, bind: Option<(String, i64)>) {
    out.push((seg_idx, cursor, bind));
}

impl MachInfo {
    /// Parse an x86_64 Mach-O, accepting a thin file or a fat container.
    pub fn parse(input: &[u8]) -> Result<MachInfo, MachError> {
        let data = x86_slice(input)?;
        Self::parse_thin(&data)
    }

    /// Parse from an owned buffer. Thin files (all five SAP images) are
    /// parsed in place with no intermediate copy; fat containers keep the
    /// `x86_slice` extraction. Callers that read the image from disk purely
    /// to load it should hand the buffer over instead of holding a copy.
    pub fn parse_owned(buffer: Vec<u8>) -> Result<MachInfo, MachError> {
        if buffer.len() >= 4 && u32::from_be_bytes(buffer[0..4].try_into().unwrap()) == FAT_MAGIC {
            let data = x86_slice(&buffer)?;
            return Self::parse_thin(&data);
        }
        Self::parse_thin_owned(buffer)
    }

    /// Parse metadata straight from a file handle without ever materializing
    /// the full image in memory: the header/load-commands are read into a
    /// small buffer, and the dyld rebase/bind streams plus the symbol table
    /// are fetched with targeted reads (they live together in `__LINKEDIT`,
    /// typically the last few hundred KB of the file). The returned `MachInfo`
    /// carries an empty `data` buffer; segment contents are streamed into the
    /// mapping by `MachImage::load_file`.
    pub fn parse_reader<R: std::io::Read + std::io::Seek>(
        r: &mut R,
    ) -> Result<MachInfo, MachError> {
        // Fat container? Find the x86_64 slice offset.
        let mut magic4 = [0u8; 4];
        r.read_exact(&mut magic4)?;
        r.seek(std::io::SeekFrom::Start(0))?;
        let slice_off: u64 = if u32::from_be_bytes(magic4) == FAT_MAGIC {
            let mut hdr = [0u8; 8];
            r.read_exact(&mut hdr)?;
            let narch = u32::from_be_bytes(hdr[4..8].try_into().unwrap()) as usize;
            let mut found = None;
            for _ in 0..narch {
                let mut rec = [0u8; 20];
                r.read_exact(&mut rec)?;
                let cputype = u32::from_be_bytes(rec[0..4].try_into().unwrap());
                let offset = u32::from_be_bytes(rec[8..12].try_into().unwrap()) as u64;
                if cputype == CPU_TYPE_X86_64 {
                    found = Some(offset);
                }
            }
            found.ok_or(MachError::NoX86Slice)?
        } else {
            0
        };

        // Header + load commands.
        r.seek(std::io::SeekFrom::Start(slice_off))?;
        let mut mach_hdr = [0u8; 32];
        r.read_exact(&mut mach_hdr)?;
        if u32::from_le_bytes(mach_hdr[0..4].try_into().unwrap()) != MH_MAGIC_64 {
            return Err(MachError::NotMachO);
        }
        if u32::from_le_bytes(mach_hdr[4..8].try_into().unwrap()) != CPU_TYPE_X86_64 {
            return Err(MachError::NoX86Slice);
        }
        let ncmd = u16::from_le_bytes(mach_hdr[16..18].try_into().unwrap()) as usize;
        let sizeofcmds = u32::from_le_bytes(mach_hdr[20..24].try_into().unwrap()) as usize;
        if ncmd == 0 || sizeofcmds == 0 || sizeofcmds > 1 << 20 {
            return Err(MachError::BadLoadCommands);
        }
        let mut d = vec![0u8; 32 + sizeofcmds];
        d[..32].copy_from_slice(&mach_hdr);
        r.read_exact(&mut d[32..])?;

        // First pass over load commands: collect segments/commands and note
        // the stream/symtab byte ranges we must fetch.
        let mut segments = Vec::new();
        let mut commands = Vec::new();
        let mut symtab: Option<(u32, u32, u32, u32)> = None;
        let mut dyld: Option<[u32; 10]> = None;
        let mut fetch_ranges: Vec<(usize, usize)> = Vec::new(); // (off, size) slice-relative

        let mut off = 32usize;
        for _ in 0..ncmd {
            if off + 8 > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            let cmd = u32_at(&d, off)?;
            let cmdsize = u32_at(&d, off + 4)? as usize;
            if cmdsize < 8 || off + cmdsize > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            commands.push(LoadCommand {
                cmd,
                cmdsize: cmdsize as u32,
                off,
            });
            match cmd {
                LC_SEGMENT_64 => {
                    if cmdsize < 72 {
                        return Err(MachError::BadLoadCommands);
                    }
                    let mut name = [0u8; 16];
                    name.copy_from_slice(&d[off + 8..off + 24]);
                    segments.push(Segment64 {
                        name,
                        vmaddr: u64_at(&d, off + 24)?,
                        vmsize: u64_at(&d, off + 32)?,
                        fileoff: u64_at(&d, off + 40)?,
                        filesize: u64_at(&d, off + 48)?,
                        initprot: i32::from_le_bytes(d[off + 56..off + 60].try_into().unwrap()),
                        maxprot: i32::from_le_bytes(d[off + 60..off + 64].try_into().unwrap()),
                    });
                }
                LC_SYMTAB => {
                    symtab = Some((
                        u32_at(&d, off + 8)?,
                        u32_at(&d, off + 12)?,
                        u32_at(&d, off + 16)?,
                        u32_at(&d, off + 20)?,
                    ));
                }
                LC_DYLD_INFO_ONLY | LC_DYLD_INFO => {
                    let mut fields = [0u32; 10];
                    for (i, item) in fields.iter_mut().enumerate() {
                        *item = u32_at(&d, off + 8 + i * 4)?;
                    }
                    dyld = Some(fields);
                }
                _ => {}
            }
            off += cmdsize;
        }

        if let Some((symoff, nsyms, stroff, strsize)) = symtab {
            if nsyms > 0 && strsize > 0 {
                fetch_ranges.push((symoff as usize, nsyms as usize * 16));
                fetch_ranges.push((stroff as usize, strsize as usize));
            }
        }
        if let Some(f) = dyld {
            for idx in [0usize, 2, 4, 6] {
                if f[idx + 1] > 0 {
                    fetch_ranges.push((f[idx] as usize, f[idx + 1] as usize));
                }
            }
        }

        // Fetch the metadata ranges into one tail buffer; keep a (off -> pos)
        // map so stream decoding addresses the tail buffer with the ORIGINAL
        // file offsets. Ranges in these images are contiguous in the tail.
        let mut tail = Vec::new();
        let mut tail_map: std::collections::BTreeMap<usize, usize> = Default::default();
        if !fetch_ranges.is_empty() {
            let start = fetch_ranges.iter().map(|(o, _)| *o).min().unwrap();
            let end = fetch_ranges.iter().map(|(o, s)| o + s).max().unwrap();
            let size = end - start;
            if size > 8 << 20 {
                return Err(MachError::BadLoadCommands);
            }
            r.seek(std::io::SeekFrom::Start(slice_off + start as u64))?;
            tail = vec![0u8; size];
            r.read_exact(&mut tail)?;
            for (o, _) in &fetch_ranges {
                tail_map.insert(*o, *o - start);
            }
        }

        let fetch = |off: usize, len: usize| -> Result<&[u8], MachError> {
            if off + len > tail.len() {
                return Err(MachError::Truncated);
            }
            Ok(&tail[off..off + len])
        };

        let mut base = None;
        for s in &segments {
            if s.name_str() == "__PAGEZERO" || s.vmsize == 0 {
                continue;
            }
            if base.is_none() || s.vmaddr < base.unwrap() {
                base = Some(s.vmaddr);
            }
        }
        let base = base.ok_or(MachError::Truncated)?;

        let mut rebases = Vec::new();
        let mut binds = Vec::new();
        if let Some(f) = dyld {
            for (idx, is_bind) in [(0usize, false), (2, true), (4, true), (6, true)] {
                let size = f[idx + 1] as usize;
                if size == 0 {
                    continue;
                }
                let pos = tail_map
                    .get(&(f[idx] as usize))
                    .copied()
                    .ok_or(MachError::Truncated)?;
                let s = fetch(pos, size)?;
                let entries = decode_stream(s, 0, size, is_bind, idx == 6)?;
                for (seg_idx, cursor, bind) in entries {
                    let seg = segments[seg_idx];
                    if let Some((name, addend)) = bind {
                        binds.push(BindEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            name,
                            addend,
                        });
                    } else {
                        rebases.push(RebaseEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            value: 0,
                        });
                    }
                }
            }
        }

        let symbols = symtab
            .map(|(symoff, nsyms, stroff, strsize)| {
                let spos = tail_map
                    .get(&(symoff as usize))
                    .copied()
                    .ok_or(MachError::Truncated)?;
                let strpos = tail_map
                    .get(&(stroff as usize))
                    .copied()
                    .ok_or(MachError::Truncated)?;
                let sym_bytes = fetch(spos, nsyms as usize * 16)?;
                let str_bytes = fetch(strpos, strsize as usize)?;
                // Reuse the same nlist decode as read_symtab but from slices.
                let strtab = str_bytes;
                let mut out = Vec::new();
                for i in 0..nsyms as usize {
                    let e = &sym_bytes[i * 16..(i + 1) * 16];
                    let n_strx = u32::from_le_bytes(e[0..4].try_into().unwrap());
                    let n_type = e[4];
                    let n_value = u64::from_le_bytes(e[8..16].try_into().unwrap());
                    if n_type & 0x0e == 0x0e && n_value != 0 {
                        let soff = n_strx as usize;
                        if soff >= strtab.len() {
                            continue;
                        }
                        let name = cstr_at(strtab, soff).unwrap_or_default();
                        if name.is_empty() {
                            continue;
                        }
                        out.push(Symbol {
                            name,
                            addr: n_value,
                        });
                    }
                }
                Ok::<Vec<Symbol>, MachError>(out)
            })
            .transpose()?
            .unwrap_or_default();

        // __TEXT,__text bounds (offsets are slice-relative; __TEXT starts at
        // the slice start for these images, so the section file offset is
        // directly usable as a mapping offset by the loader).
        let mut text_section = None;
        for lc in &commands {
            if lc.cmd != LC_SEGMENT_64 {
                continue;
            }
            let seg_name = &d[lc.off + 8..lc.off + 24];
            if !seg_name.starts_with(b"__TEXT") {
                continue;
            }
            let nsects =
                u32::from_le_bytes(d[lc.off + 64..lc.off + 68].try_into().unwrap()) as usize;
            for i in 0..nsects {
                let so = lc.off + 72 + i * 80;
                let sname = &d[so..so + 16];
                if &sname[..6] == b"__text" {
                    let size = u64::from_le_bytes(d[so + 40..so + 48].try_into().unwrap());
                    let off = u32::from_le_bytes(d[so + 48..so + 52].try_into().unwrap());
                    text_section = Some((off as u64, size));
                }
            }
        }

        Ok(MachInfo {
            data: Vec::new(),
            base,
            segments,
            commands,
            rebases,
            binds,
            symbols,
            text_section,
        })
    }

    fn parse_thin(d: &[u8]) -> Result<MachInfo, MachError> {
        if d.len() < 32 || u32::from_le_bytes(d[0..4].try_into().unwrap()) != MH_MAGIC_64 {
            return Err(MachError::NotMachO);
        }
        let cputype = u32::from_le_bytes(d[4..8].try_into().unwrap());
        if cputype != CPU_TYPE_X86_64 {
            return Err(MachError::NoX86Slice);
        }
        let ncmd = u16_at(d, 16)? as usize;
        let sizeofcmds = u32_at(d, 20)? as usize;
        if 32 + sizeofcmds > d.len() {
            return Err(MachError::BadLoadCommands);
        }

        let mut segments = Vec::new();
        let mut commands = Vec::new();
        let mut symtab: Option<(u32, u32, u32, u32)> = None; // off, nsyms, stroff, strsize
        let mut dyld: Option<[u32; 10]> = None;

        let mut off = 32usize;
        for _ in 0..ncmd {
            if off + 8 > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            let cmd = u32_at(d, off)?;
            let cmdsize = u32_at(d, off + 4)? as usize;
            if cmdsize < 8 || off + cmdsize > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            commands.push(LoadCommand {
                cmd,
                cmdsize: cmdsize as u32,
                off,
            });
            match cmd {
                LC_SEGMENT_64 => {
                    if cmdsize < 72 {
                        return Err(MachError::BadLoadCommands);
                    }
                    let mut name = [0u8; 16];
                    name.copy_from_slice(&d[off + 8..off + 24]);
                    segments.push(Segment64 {
                        name,
                        vmaddr: u64_at(d, off + 24)?,
                        vmsize: u64_at(d, off + 32)?,
                        fileoff: u64_at(d, off + 40)?,
                        filesize: u64_at(d, off + 48)?,
                        initprot: i32::from_le_bytes(d[off + 56..off + 60].try_into().unwrap()),
                        maxprot: i32::from_le_bytes(d[off + 60..off + 64].try_into().unwrap()),
                    });
                }
                LC_SYMTAB => {
                    symtab = Some((
                        u32_at(d, off + 8)?,
                        u32_at(d, off + 12)?,
                        u32_at(d, off + 16)?,
                        u32_at(d, off + 20)?,
                    ));
                }
                LC_DYLD_INFO_ONLY | LC_DYLD_INFO => {
                    let mut fields = [0u32; 10];
                    for (i, item) in fields.iter_mut().enumerate() {
                        *item = u32_at(d, off + 8 + i * 4)?;
                    }
                    dyld = Some(fields);
                }
                _ => {}
            }
            off += cmdsize;
        }

        // Preferred base: lowest vmaddr of loadable segments (skip __PAGEZERO).
        let mut base = None;
        for s in &segments {
            if s.name_str() == "__PAGEZERO" || s.vmsize == 0 {
                continue;
            }
            if base.is_none() || s.vmaddr < base.unwrap() {
                base = Some(s.vmaddr);
            }
        }
        let base = base.ok_or(MachError::Truncated)?;

        // Classic streams: rebase = fields[0..2], bind = fields[2..4],
        // weak = [4..6] (absent in these images), lazy = [6..8]. The bind
        // family all decode with bind semantics; the lazy stream carries no
        // SET_TYPE opcodes, which our decoder tolerates (defaults accepted).
        let mut rebases = Vec::new();
        let mut binds = Vec::new();
        if let Some(f) = dyld {
            for (idx, is_bind) in [(0usize, false), (2, true), (4, true), (6, true)] {
                let off = f[idx] as usize;
                let size = f[idx + 1] as usize;
                if size == 0 {
                    continue;
                }
                let entries = decode_stream(d, off, size, is_bind, idx == 6)?;
                for (seg_idx, cursor, bind) in entries {
                    let seg = segments[seg_idx];
                    if let Some((name, addend)) = bind {
                        binds.push(BindEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            name,
                            addend,
                        });
                    } else {
                        rebases.push(RebaseEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            // Value stays 0 here; the actual target is the
                            // slot's existing file content, read at patch
                            // time (dyld semantics: old_value + slide).
                            value: 0,
                        });
                    }
                }
            }
        }

        let symbols = symtab
            .map(|(off, nsyms, stroff, strsize)| {
                Self::read_symtab(
                    d,
                    off as usize,
                    nsyms as usize,
                    stroff as usize,
                    strsize as usize,
                )
            })
            .transpose()?
            .unwrap_or_default();

        // Record the __TEXT,__text section bounds for code-only patching.
        let mut text_section = None;
        for lc in &commands {
            if lc.cmd != LC_SEGMENT_64 {
                continue;
            }
            let seg_name = &d[lc.off + 8..lc.off + 24];
            if !seg_name.starts_with(b"__TEXT") {
                continue;
            }
            let nsects =
                u32::from_le_bytes(d[lc.off + 64..lc.off + 68].try_into().unwrap()) as usize;
            for i in 0..nsects {
                let so = lc.off + 72 + i * 80;
                let sname = &d[so..so + 16];
                if &sname[..6] == b"__text" {
                    // Section addr == its file offset in these images; only
                    // size and offset matter here.
                    let size = u64::from_le_bytes(d[so + 40..so + 48].try_into().unwrap());
                    let off = u32::from_le_bytes(d[so + 48..so + 52].try_into().unwrap());
                    // In these images section addr == its file offset within
                    // the slice; guard anyway.
                    text_section = Some((off as u64, size));
                }
            }
        }

        Ok(MachInfo {
            data: d.to_vec(),
            base,
            segments,
            commands,
            rebases,
            binds,
            symbols,
            text_section,
        })
    }

    fn parse_thin_owned(buffer: Vec<u8>) -> Result<MachInfo, MachError> {
        let d = &buffer[..];
        if d.len() < 32 || u32::from_le_bytes(d[0..4].try_into().unwrap()) != MH_MAGIC_64 {
            return Err(MachError::NotMachO);
        }
        let cputype = u32::from_le_bytes(d[4..8].try_into().unwrap());
        if cputype != CPU_TYPE_X86_64 {
            return Err(MachError::NoX86Slice);
        }
        let ncmd = u16_at(d, 16)? as usize;
        let sizeofcmds = u32_at(d, 20)? as usize;
        if 32 + sizeofcmds > d.len() {
            return Err(MachError::BadLoadCommands);
        }

        let mut segments = Vec::new();
        let mut commands = Vec::new();
        let mut symtab: Option<(u32, u32, u32, u32)> = None; // off, nsyms, stroff, strsize
        let mut dyld: Option<[u32; 10]> = None;

        let mut off = 32usize;
        for _ in 0..ncmd {
            if off + 8 > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            let cmd = u32_at(d, off)?;
            let cmdsize = u32_at(d, off + 4)? as usize;
            if cmdsize < 8 || off + cmdsize > d.len() {
                return Err(MachError::BadLoadCommands);
            }
            commands.push(LoadCommand {
                cmd,
                cmdsize: cmdsize as u32,
                off,
            });
            match cmd {
                LC_SEGMENT_64 => {
                    if cmdsize < 72 {
                        return Err(MachError::BadLoadCommands);
                    }
                    let mut name = [0u8; 16];
                    name.copy_from_slice(&d[off + 8..off + 24]);
                    segments.push(Segment64 {
                        name,
                        vmaddr: u64_at(d, off + 24)?,
                        vmsize: u64_at(d, off + 32)?,
                        fileoff: u64_at(d, off + 40)?,
                        filesize: u64_at(d, off + 48)?,
                        initprot: i32::from_le_bytes(d[off + 56..off + 60].try_into().unwrap()),
                        maxprot: i32::from_le_bytes(d[off + 60..off + 64].try_into().unwrap()),
                    });
                }
                LC_SYMTAB => {
                    symtab = Some((
                        u32_at(d, off + 8)?,
                        u32_at(d, off + 12)?,
                        u32_at(d, off + 16)?,
                        u32_at(d, off + 20)?,
                    ));
                }
                LC_DYLD_INFO_ONLY | LC_DYLD_INFO => {
                    let mut fields = [0u32; 10];
                    for (i, item) in fields.iter_mut().enumerate() {
                        *item = u32_at(d, off + 8 + i * 4)?;
                    }
                    dyld = Some(fields);
                }
                _ => {}
            }
            off += cmdsize;
        }

        // Preferred base: lowest vmaddr of loadable segments (skip __PAGEZERO).
        let mut base = None;
        for s in &segments {
            if s.name_str() == "__PAGEZERO" || s.vmsize == 0 {
                continue;
            }
            if base.is_none() || s.vmaddr < base.unwrap() {
                base = Some(s.vmaddr);
            }
        }
        let base = base.ok_or(MachError::Truncated)?;

        // Classic streams: rebase = fields[0..2], bind = fields[2..4],
        // weak = [4..6] (absent in these images), lazy = [6..8]. The bind
        // family all decode with bind semantics; the lazy stream carries no
        // SET_TYPE opcodes, which our decoder tolerates (defaults accepted).
        let mut rebases = Vec::new();
        let mut binds = Vec::new();
        if let Some(f) = dyld {
            for (idx, is_bind) in [(0usize, false), (2, true), (4, true), (6, true)] {
                let off = f[idx] as usize;
                let size = f[idx + 1] as usize;
                if size == 0 {
                    continue;
                }
                let entries = decode_stream(d, off, size, is_bind, idx == 6)?;
                for (seg_idx, cursor, bind) in entries {
                    let seg = segments[seg_idx];
                    if let Some((name, addend)) = bind {
                        binds.push(BindEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            name,
                            addend,
                        });
                    } else {
                        rebases.push(RebaseEntry {
                            segment: seg.name,
                            seg_off: cursor,
                            // Value stays 0 here; the actual target is the
                            // slot's existing file content, read at patch
                            // time (dyld semantics: old_value + slide).
                            value: 0,
                        });
                    }
                }
            }
        }

        let symbols = symtab
            .map(|(off, nsyms, stroff, strsize)| {
                Self::read_symtab(
                    d,
                    off as usize,
                    nsyms as usize,
                    stroff as usize,
                    strsize as usize,
                )
            })
            .transpose()?
            .unwrap_or_default();

        // Record the __TEXT,__text section bounds for code-only patching.
        let mut text_section = None;
        for lc in &commands {
            if lc.cmd != LC_SEGMENT_64 {
                continue;
            }
            let seg_name = &d[lc.off + 8..lc.off + 24];
            if !seg_name.starts_with(b"__TEXT") {
                continue;
            }
            let nsects =
                u32::from_le_bytes(d[lc.off + 64..lc.off + 68].try_into().unwrap()) as usize;
            for i in 0..nsects {
                let so = lc.off + 72 + i * 80;
                let sname = &d[so..so + 16];
                if &sname[..6] == b"__text" {
                    // Section addr == its file offset in these images; only
                    // size and offset matter here.
                    let size = u64::from_le_bytes(d[so + 40..so + 48].try_into().unwrap());
                    let off = u32::from_le_bytes(d[so + 48..so + 52].try_into().unwrap());
                    // In these images section addr == its file offset within
                    // the slice; guard anyway.
                    text_section = Some((off as u64, size));
                }
            }
        }

        Ok(MachInfo {
            data: buffer,
            base,
            segments,
            commands,
            rebases,
            binds,
            symbols,
            text_section,
        })
    }

    /// Classic symtab: collect defined symbols with a nonzero value.
    fn read_symtab(
        d: &[u8],
        symoff: usize,
        nsyms: usize,
        stroff: usize,
        strsize: usize,
    ) -> Result<Vec<Symbol>, MachError> {
        if stroff + strsize > d.len() || symoff + nsyms * 16 > d.len() {
            return Err(MachError::Truncated);
        }
        let strtab = &d[stroff..stroff + strsize];
        let mut out = Vec::new();
        for i in 0..nsyms {
            let e = &d[symoff + i * 16..symoff + (i + 1) * 16];
            let n_strx = u32::from_le_bytes(e[0..4].try_into().unwrap());
            let n_type = e[4];
            let n_sect = e[5];
            let n_desc = u16::from_le_bytes(e[6..8].try_into().unwrap());
            let n_value = u64::from_le_bytes(e[8..16].try_into().unwrap());
            // N_SECT (0x0e): defined in this image. N_EXT (0x01) optional;
            // local symbols cost nothing to keep and the obfuscated SAP
            // entry points in CommerceKit are plain externals anyway.
            if n_type & 0x0e == 0x0e && n_value != 0 {
                let soff = n_strx as usize;
                if soff >= strtab.len() {
                    continue;
                }
                let name = cstr_at(strtab, soff).unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                out.push(Symbol {
                    name,
                    addr: n_value,
                });
            }
            let _ = (n_sect, n_desc);
        }
        Ok(out)
    }

    /// File offset of a fixup located at `seg_off` inside the named segment.
    ///
    /// Fixups may legally target the zero-fill tail of a segment
    /// (`filesize < vmsize`); dyld maps the whole `vmsize`. For such slots
    /// there is no file backing — the caller patches post-map memory
    /// instead, so we report `None` rather than an error. Only offsets
    /// beyond `vmsize` (or past the file data when backed) are malformed.
    pub fn segment_file_offset(
        &self,
        seg_name: &[u8; 16],
        seg_off: u64,
        data_len: usize,
    ) -> Result<Option<usize>, MachError> {
        for s in &self.segments {
            if &s.name != seg_name {
                continue;
            }
            if seg_off + 8 > s.vmsize {
                return Err(MachError::BadSegment { name: s.name_str() });
            }
            if seg_off + 8 > s.filesize {
                // Zero-fill tail: no file offset, patch in mapped memory.
                return Ok(None);
            }
            let file = s.fileoff + seg_off;
            if file + 8 > data_len as u64 {
                return Err(MachError::Truncated);
            }
            return Ok(Some(file as usize));
        }
        Err(MachError::MissingSegment {
            name: String::from_utf8_lossy(seg_name)
                .trim_end_matches('\0')
                .to_string(),
        })
    }

    /// Offset of a fixup located at `seg_off` inside the named segment,
    /// expressed in the LOADED MAPPING (vmaddr - preferred base). Same
    /// zero-fill-tail semantics as `segment_file_offset`: slots beyond the
    /// segment's file content are still addressable (the mapping's anon
    /// pages start zeroed), so they yield `Some` here and the caller patches
    /// them directly.
    pub fn segment_map_offset(
        &self,
        seg_name: &[u8; 16],
        seg_off: u64,
        span: usize,
    ) -> Result<Option<usize>, MachError> {
        for s in &self.segments {
            if &s.name != seg_name {
                continue;
            }
            if seg_off + 8 > s.vmsize {
                return Err(MachError::BadSegment { name: s.name_str() });
            }
            let off = (s.vmaddr - self.base) as usize + seg_off as usize;
            if off + 8 > span {
                return Err(MachError::Truncated);
            }
            return Ok(Some(off));
        }
        Err(MachError::MissingSegment {
            name: String::from_utf8_lossy(seg_name)
                .trim_end_matches('\0')
                .to_string(),
        })
    }
}
