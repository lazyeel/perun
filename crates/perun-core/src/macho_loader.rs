// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Native projection of a Mach-O x86_64 image into Linux process memory,
//! the mirror of `loader.rs` for Apple binaries.
//!
//! Same shape as the PE path: parse → map → copy segments → rebase → bind →
//! expose exports. The 2013 OS X 10.9 CoreFP/CommerceKit pair uses classic
//! dyld info (no chained fixups), which `macho.rs` decodes into plain
//! (segment, offset, value) lists, so relocation is direct patching.
//!
//! After `MachImage::load`, guest code runs natively on the CPU under the
//! SysV AMD64 calling convention — no emulation.

use crate::macho::{MachError, MachInfo};

/// Host-side import resolver. Returns `Some(ptr)` when a shim exists for the
/// symbol (leading underscore included, e.g. `_malloc`).
pub trait MachImportResolver {
    fn resolve(&self, symbol: &str) -> Option<usize>;
}

/// Bindings are patched in a private copy of the slice bytes before
/// mapping, mirroring how dyld conceptually relocates file pages on the way
/// into memory. Keeps the original file untouched.
pub struct MachImage {
    info: MachInfo,
    base: *mut u8,
    size: usize,
    /// Loaded base minus preferred base.
    slide: u64,
}

#[derive(Debug)]
pub enum MachLoadError {
    Parse(MachError),
    MapFailed { size: usize },
    SegmentOutOfBounds { name: String },
}

impl From<MachError> for MachLoadError {
    fn from(e: MachError) -> Self {
        Self::Parse(e)
    }
}

impl core::fmt::Display for MachLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse failed: {e}"),
            Self::MapFailed { size } => write!(f, "mmap of {size} bytes failed"),
            Self::SegmentOutOfBounds { name } => write!(f, "segment {name} exceeds image"),
        }
    }
}

impl std::error::Error for MachLoadError {}

impl MachImage {
    /// Load a Mach-O (thin or fat) at `load_base`, binding imports through
    /// `resolver`. Unresolved imports land on trap micro-stubs exactly like
    /// the PE path, so the first guest call reports instead of crashing.
    pub fn load(
        input: &[u8],
        load_base: u64,
        resolver: &mut dyn MachImportResolver,
    ) -> Result<MachImage, MachLoadError> {
        let info = MachInfo::parse(input)?;
        Self::load_parsed(info, load_base, resolver)
    }

    /// Load from an owned buffer: thin images parse in place with no copy of
    /// the file content beyond the final mapping.
    pub fn load_owned(
        buffer: Vec<u8>,
        load_base: u64,
        resolver: &mut dyn MachImportResolver,
    ) -> Result<MachImage, MachLoadError> {
        let info = MachInfo::parse_owned(buffer)?;
        Self::load_parsed(info, load_base, resolver)
    }

    /// Load an already-parsed image. Callers that need metadata from the
    /// image before mapping it (export addresses) can parse once and hand
    /// the same `MachInfo` here, avoiding a second read of the file.
    pub fn load_parsed(
        mut info: MachInfo,
        load_base: u64,
        resolver: &mut dyn MachImportResolver,
    ) -> Result<MachImage, MachLoadError> {
        // Span of the image in memory: from the preferred base to the end of
        // the highest segment.
        let mut span: u64 = 0;
        for s in &info.segments {
            if s.name_str() == "__PAGEZERO" || s.vmsize == 0 {
                continue;
            }
            let end = (s.vmaddr - info.base) + s.vmsize;
            if end > span {
                span = end;
            }
        }
        let span = ((span + 0xFFF) & !0xFFF) as usize;
        if span == 0 {
            return Err(MachLoadError::MapFailed { size: 0 });
        }

        // Patch fixups in the parsed buffer in place (rebase to load_base,
        // bind to shim addresses) — no second copy of the image is made; the
        // buffer is released right after the segments are copied into the
        // mapping. The buffer is temporarily taken out of `info` so the
        // fixup passes can borrow `info`'s parsed tables freely.
        let mut data = core::mem::take(&mut info.data);
        Self::apply_rebases(&info, &mut data, load_base)?;
        Self::apply_binds(&info, &mut data, resolver)?;
        Self::neutralize_rdtsc(&info, &mut data);
        let work = &data[..];

        let base = unsafe {
            libc::mmap(
                load_base as *mut libc::c_void,
                span,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(MachLoadError::MapFailed { size: span });
        }
        let base = base as *mut u8;

        // Zero-fill-tail fixups: patch directly in mapped memory.
        let deferred: Vec<([u8; 16], u64, u64)> =
            DEFERRED_FIXUPS.with(|d| std::mem::take(&mut *d.borrow_mut()));
        unsafe {
            for (seg_name, seg_off, value) in deferred {
                for s in &info.segments {
                    if s.name == seg_name {
                        let dst = base.add((s.vmaddr - info.base) as usize + seg_off as usize);
                        dst.cast::<u64>().write_unaligned(value);
                    }
                }
            }
        }

        unsafe {
            for s in &info.segments {
                if s.name_str() == "__PAGEZERO" || s.filesize == 0 {
                    continue;
                }
                let src_end = s.fileoff as usize + s.filesize as usize;
                if src_end > work.len() {
                    return Err(MachLoadError::SegmentOutOfBounds { name: s.name_str() });
                }
                let dst_off = (s.vmaddr - info.base) as usize;
                let n = (s.filesize as usize).min(span - dst_off);
                std::ptr::copy_nonoverlapping(
                    work.as_ptr().add(s.fileoff as usize),
                    base.add(dst_off),
                    n,
                );
            }
        }

        // All file content now lives in the mapping; the parsed buffer is no
        // longer needed (post-load reads go through the mapping, and the
        // symbol table / fixup lists are owned separately). Release it so a
        // loaded image costs its mmap span, not span + file size.
        drop(data);

        Ok(MachImage {
            slide: (base as u64).wrapping_sub(load_base),
            info,
            base,
            size: span,
        })
    }
    /// Load a Mach-O straight from a file path, never materializing the
    /// image outside its mapping: metadata comes from `parse_reader`
    /// (header + targeted tail reads), segment contents are pread directly
    /// into the mapping, and fixups/rdtsc run against the mapped bytes.
    pub fn load_file(
        path: &std::path::Path,
        load_base: u64,
        resolver: &mut dyn MachImportResolver,
    ) -> Result<MachImage, MachLoadError> {
        let mut file = std::fs::File::open(path).map_err(|e| MachLoadError::Parse(e.into()))?;
        let info = MachInfo::parse_reader(&mut file)?;

        // Mapping span (same computation as load_parsed).
        let mut span: u64 = 0;
        for s in &info.segments {
            if s.name_str() == "__PAGEZERO" || s.vmsize == 0 {
                continue;
            }
            let end = (s.vmaddr - info.base) + s.vmsize;
            if end > span {
                span = end;
            }
        }
        let span = ((span + 0xFFF) & !0xFFF) as usize;
        if span == 0 {
            return Err(MachLoadError::MapFailed { size: 0 });
        }

        let base = unsafe {
            libc::mmap(
                load_base as *mut libc::c_void,
                span,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(MachLoadError::MapFailed { size: span });
        }
        let base = base as *mut u8;
        let img = unsafe { Self::map_and_fixup(file, info, base, span, load_base, resolver)? };
        Ok(img)
    }

    /// Shared tail of the streaming path: stream segments into the mapping,
    /// then apply rebases/binds/rdtsc against mapped memory.
    ///
    /// # Safety
    /// `base..base+span` must be a writable mapping owned by the caller.
    unsafe fn map_and_fixup(
        mut file: std::fs::File,
        info: MachInfo,
        base: *mut u8,
        span: usize,
        load_base: u64,
        resolver: &mut dyn MachImportResolver,
    ) -> Result<MachImage, MachLoadError> {
        use std::os::unix::fs::FileExt;

        // Segment contents: pread straight into the mapping (fat slice offset
        // first, then the slice-relative segment fileoff).
        let slice_off = Self::fat_slice_offset(&mut file)?;
        for s in &info.segments {
            if s.name_str() == "__PAGEZERO" || s.filesize == 0 {
                continue;
            }
            let dst_off = (s.vmaddr - info.base) as usize;
            let n = (s.filesize as usize).min(span.saturating_sub(dst_off));
            if n == 0 {
                continue;
            }
            let mut done = 0usize;
            while done < n {
                let got = file
                    .read_at(
                        std::slice::from_raw_parts_mut(base.add(dst_off + done), n - done),
                        slice_off + s.fileoff + done as u64,
                    )
                    .map_err(|e| MachLoadError::Parse(e.into()))?;
                if got == 0 {
                    return Err(MachLoadError::Parse(MachError::Truncated));
                }
                done += got;
            }
        }

        // Rebases against mapped memory.
        let slide = load_base.wrapping_sub(info.base);
        for r in &info.rebases {
            // dyld semantics: slot holds its preferred-layout value; add slide.
            let off = info
                .segment_map_offset(&r.segment, r.seg_off, span)?
                .ok_or(MachLoadError::Parse(MachError::MissingSegment {
                    name: String::from_utf8_lossy(&r.segment)
                        .trim_end_matches('\0')
                        .to_string(),
                }))?;
            unsafe {
                let slot = base.add(off).cast::<u64>();
                let old = slot.read_unaligned();
                slot.write_unaligned(old.wrapping_add(slide));
            }
        }

        // Binds against mapped memory.
        let zero_page = zero_data_page();
        for b in &info.binds {
            let value = resolver
                .resolve(&b.name)
                .map(|p| (p as u64).wrapping_add(b.addend as u64))
                .or_else(|| {
                    if is_data_symbol(&b.name) {
                        Some(zero_page as u64)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    let label = b.name.clone();
                    crate::stub_pool_sysv().allocate(label) as u64
                });
            let off = info
                .segment_map_offset(&b.segment, b.seg_off, span)?
                .ok_or(MachLoadError::Parse(MachError::MissingSegment {
                    name: String::from_utf8_lossy(&b.segment)
                        .trim_end_matches('\0')
                        .to_string(),
                }))?;
            unsafe {
                base.add(off).cast::<u64>().write_unaligned(value);
            }
        }

        // rdtsc neutralization against mapped __TEXT,__text.
        Self::neutralize_rdtsc_mapped(&info, base, span);

        Ok(MachImage {
            slide,
            info,
            base,
            size: span,
        })
    }

    /// x86_64 slice offset of a fat container, 0 for thin files.
    fn fat_slice_offset(file: &mut std::fs::File) -> Result<u64, MachLoadError> {
        use std::io::{Read, Seek, SeekFrom};
        // Rewind first: the file position is arbitrary at this point.
        file.seek(SeekFrom::Start(0))
            .map_err(|e| MachLoadError::Parse(e.into()))?;
        let mut magic4 = [0u8; 4];
        file.read_exact(&mut magic4)
            .map_err(|e| MachLoadError::Parse(e.into()))?;
        if u32::from_be_bytes(magic4) != crate::macho::FAT_MAGIC {
            return Ok(0);
        }
        // The fat header after the magic is exactly one u32 (nfat); arch
        // records start right after it.
        let mut nfat = [0u8; 4];
        file.read_exact(&mut nfat)
            .map_err(|e| MachLoadError::Parse(e.into()))?;
        let narch = u32::from_be_bytes(nfat) as usize;
        for _ in 0..narch {
            let mut rec = [0u8; 20];
            file.read_exact(&mut rec)
                .map_err(|e| MachLoadError::Parse(e.into()))?;
            let cputype = u32::from_be_bytes(rec[0..4].try_into().unwrap());
            let offset = u32::from_be_bytes(rec[8..12].try_into().unwrap()) as u64;
            if cputype == crate::macho::CPU_TYPE_X86_64 {
                return Ok(offset);
            }
        }
        Err(MachLoadError::Parse(MachError::NoX86Slice))
    }

    /// In-mapping variant of `neutralize_rdtsc`: same three idioms, same
    /// two-byte prefilter, same patch bytes — written into mapped memory.
    fn neutralize_rdtsc_mapped(info: &MachInfo, base: *mut u8, span: usize) {
        let Some((off, size)) = info.text_section else {
            return;
        };
        let start = off as usize;
        let end = start + size as usize;
        if end > span {
            return;
        }
        const IDIOM_A: [u8; 9] = [0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xC2];
        const REPL_A: [u8; 9] = [0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90];
        const IDIOM_B: [u8; 12] = [
            0x0F, 0x31, 0x48, 0x89, 0xD1, 0x48, 0xC1, 0xE1, 0x20, 0x48, 0x09, 0xC1,
        ];
        const REPL_B: [u8; 12] = [
            0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        const IDIOM_C: [u8; 10] = [0x0F, 0x31, 0x48, 0xC1, 0xE0, 0x04, 0x48, 0x83, 0xE0, 0x70];
        const REPL_C: [u8; 10] = [0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];

        unsafe {
            let work = std::slice::from_raw_parts_mut(base, span);
            let mut i = start;
            while i + 12 <= end {
                if work[i] != 0x0F || work[i + 1] != 0x31 {
                    i += 1;
                    continue;
                }
                if work[i..i + 9] == IDIOM_A {
                    work[i..i + 9].copy_from_slice(&REPL_A);
                    i += 9;
                } else if work[i..i + 12] == IDIOM_B {
                    work[i..i + 12].copy_from_slice(&REPL_B);
                    i += 12;
                } else if work[i..i + 10] == IDIOM_C {
                    work[i..i + 10].copy_from_slice(&REPL_C);
                    i += 10;
                } else {
                    i += 1;
                }
            }
        }
    }

    fn apply_rebases(
        info: &MachInfo,
        work: &mut [u8],
        load_base: u64,
    ) -> Result<(), MachLoadError> {
        let slide = load_base.wrapping_sub(info.base);
        let mut deferred: Vec<([u8; 16], u64, u64)> = Vec::new(); // (segment, seg_off, value)
        for r in &info.rebases {
            // dyld rebase semantics: the slot already holds its preferred-
            // layout address; add the slide. Read, add, write back.
            match info.segment_file_offset(&r.segment, r.seg_off, work.len())? {
                Some(off) => {
                    if off + 8 > work.len() {
                        return Err(MachLoadError::Parse(MachError::Truncated));
                    }
                    let old = u64::from_le_bytes(work[off..off + 8].try_into().unwrap());
                    let target = old.wrapping_add(slide);
                    work[off..off + 8].copy_from_slice(&target.to_le_bytes());
                }
                None => {
                    // Zero-fill tail: no file content; the slot starts at 0,
                    // so the rebased value is just the slide.
                    deferred.push((r.segment, r.seg_off, slide));
                }
            }
        }
        DEFERRED_FIXUPS.with(|d| d.borrow_mut().extend(deferred));
        Ok(())
    }

    fn apply_binds(
        info: &MachInfo,
        work: &mut [u8],
        resolver: &mut dyn MachImportResolver,
    ) -> Result<usize, MachLoadError> {
        let mut stubs = 0usize;
        let mut deferred: Vec<([u8; 16], u64, u64)> = Vec::new();
        // Zero page for data symbols the SAP path never dereferences on the
        // signing path (ObjC class refs, constant strings, ivar caches).
        // These vastly outnumber real function imports in the 2013
        // CommerceKit; handing each a trap stub would exhaust the pool and
        // add nothing: the guest only reads them as inert pointers.
        let zero_page = zero_data_page();
        for b in &info.binds {
            let resolved = resolver
                .resolve(&b.name)
                .map(|p| (p as u64).wrapping_add(b.addend as u64))
                .or_else(|| {
                    if is_data_symbol(&b.name) {
                        Some(zero_page as u64)
                    } else {
                        // Trap micro-stub, same shape as the PE path: the
                        // first guest call reports the missing symbol and
                        // returns 0.
                        let label = b.name.clone();
                        let stub = crate::stub_pool_sysv().allocate(label);
                        stubs += 1;
                        Some(stub as u64)
                    }
                });
            let value = resolved.unwrap_or(0);
            match info.segment_file_offset(&b.segment, b.seg_off, work.len())? {
                Some(off) => {
                    if off + 8 > work.len() {
                        return Err(MachLoadError::Parse(MachError::Truncated));
                    }
                    work[off..off + 8].copy_from_slice(&value.to_le_bytes());
                }
                None => deferred.push((b.segment, b.seg_off, value)),
            }
        }
        DEFERRED_FIXUPS.with(|d| d.borrow_mut().extend(deferred));
        Ok(stubs)
    }

    /// Exported symbol address by name (leading underscore included), in the
    /// loaded layout. Symbols from the classic symtab; the 10.9 images do
    /// not use the export trie for the entry points we need.
    pub fn symbol(&self, name: &str) -> Option<u64> {
        let sym = self.info.symbols.iter().find(|s| s.name == name)?;
        Some((self.base as u64).wrapping_add(sym.addr.wrapping_sub(self.info.base)))
    }

    pub fn base(&self) -> *mut u8 {
        self.base
    }

    pub fn slide(&self) -> u64 {
        self.slide
    }

    pub fn info(&self) -> &MachInfo {
        &self.info
    }

    /// Size of the mapped span in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Copy `data` into the guest at `addr` (already inside the mapped
    /// image region or an explicitly mapped scratch buffer).
    ///
    /// # Safety
    /// `addr..addr+len` must be writable guest memory.
    pub unsafe fn write(&self, addr: u64, data: &[u8]) {
        std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }

    /// Read `len` bytes of guest memory.
    ///
    /// # Safety
    /// `addr..addr+len` must be mapped.
    pub unsafe fn read(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), len);
        out
    }
}

impl MachImage {
    /// Rewrite rdtsc-based timing idioms to constant-zero sequences in the
    /// __TEXT working copy. Idioms observed across the 2013 SAP binaries:
    ///
    /// A (9B) `rdtsc; shl rdx,32; or rdx,rax` -> `xor eax,eax; xor edx,edx; nops`
    /// B (12B) `rdtsc; mov rcx,rdx; shl rcx,32; or rcx,rax` -> same, 12 bytes
    /// C (10B) `rdtsc; shl rax,4; and rax,0x70` -> `xor eax,eax` + nops
    ///
    /// The result matches the emulator-side rdtsc hook (RAX=RDX=0) exactly.
    fn neutralize_rdtsc(info: &MachInfo, work: &mut [u8]) {
        // Patch ONLY the executable __text section: the rdtsc idiom bytes
        // also occur inside __const crypto material, where rewriting them
        // corrupts the SAP engine's constants (observed: 6269 raw-segment
        // hits in CoreFP vs a few hundred genuine code sites).
        let Some((off, size)) = info.text_section else {
            return;
        };
        let start = off as usize;
        let end = start + size as usize;
        if end > work.len() {
            return;
        }
        // Idiom A: 0F 31 48 C1 E2 20 48 09 C2
        let idiom_a: [u8; 9] = [0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xC2];
        let repl_a: [u8; 9] = [0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90];
        // Idiom B: 0F 31 48 89 D1 48 C1 E1 20 48 09 C1
        let idiom_b: [u8; 12] = [
            0x0F, 0x31, 0x48, 0x89, 0xD1, 0x48, 0xC1, 0xE1, 0x20, 0x48, 0x09, 0xC1,
        ];
        let repl_b: [u8; 12] = [
            0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        // Idiom C: 0F 31 48 C1 E0 04 48 83 E0 70
        let idiom_c: [u8; 10] = [0x0F, 0x31, 0x48, 0xC1, 0xE0, 0x04, 0x48, 0x83, 0xE0, 0x70];
        let repl_c: [u8; 10] = [0x31, 0xC0, 0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];

        let mut i = start;
        while i + 12 <= end {
            // Fast path: all three idioms begin `0F 31` (rdtsc). A plain
            // two-byte prefilter rejects ~99.97% of positions without a
            // slice compare; only candidates reaching the full comparison.
            if work[i] != 0x0F || work[i + 1] != 0x31 {
                i += 1;
                continue;
            }
            if work[i..i + 9] == idiom_a {
                work[i..i + 9].copy_from_slice(&repl_a);
                i += 9;
            } else if work[i..i + 12] == idiom_b {
                work[i..i + 12].copy_from_slice(&repl_b);
                i += 12;
            } else if work[i..i + 10] == idiom_c {
                work[i..i + 10].copy_from_slice(&repl_c);
                i += 10;
            } else {
                i += 1;
            }
        }
    }
}

impl Drop for MachImage {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base.cast(), self.size);
        }
    }
}

// Fixups that target zero-fill segment tails cannot be written to the file
// copy; they are staged here between the patch phase and the map phase of
// `MachImage::load`.
thread_local! {
    static DEFERRED_FIXUPS: std::cell::RefCell<Vec<([u8; 16], u64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// ── data-symbol classification ─────────────────────────────────────────────

static ZERO_DATA_PAGE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Address of the zero page for inert data imports. FIXED, not mmap'd
/// anywhere: data slots carry bind addends, and slot values end up in
/// the guest's key material, so an ASLR-random page address would make
/// every run produce different signatures. The reference interposer pins
/// its data symbols at small fixed addresses for the same reason.
const ZERO_DATA_PAGE_ADDR: usize = 0x1000_0000;

/// A read-only all-zero page used for data imports that the SAP path never
/// dereferences meaningfully (ObjC runtime refs, constant strings). Reading
/// from it returns zeros; writing is not attempted by these paths.
fn zero_data_page() -> usize {
    *ZERO_DATA_PAGE.get_or_init(|| unsafe {
        let p = libc::mmap(
            ZERO_DATA_PAGE_ADDR as *mut libc::c_void,
            0x1000,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            // Catastrophic but honest: fall back to a low fixed address that
            // will fault loudly if ever dereferenced as code.
            return 0x1000;
        }
        p as usize
    })
}

/// Does this import name look like inert data rather than callable code?
/// The SAP path through CommerceKit/CoreFP touches none of these.
fn is_data_symbol(name: &str) -> bool {
    name.starts_with("_OBJC_CLASS_$_")
        || name.starts_with("_OBJC_METACLASS_$_")
        || name.starts_with("_OBJC_SELECTOR_REFERENCES")
        || name.starts_with("_OBJC_IVAR_$_")
        || name.starts_with("_NSConstant")
        || name.starts_with("_kNS")
        || name.starts_with("_kCF")
        || name.starts_with("_kIO")
        || name.starts_with("_kDA")
        || name.starts_with("_NS")
        || name == "___stack_chk_guard"
}
