// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Native projection of a PE32+ image into process memory.
//!
//! Steps, mirroring what Windows' own loader does (and what the C prototype
//! validated): parse → map → copy headers/sections → relocate → patch IAT →
//! expose exports. After loading, guest code runs natively on the CPU.

use crate::image::{dir_index, ParseError, PeInfo};

/// Function pointer stored into an IAT slot.
pub type ExternPtr = usize;

/// Host-side import resolver. Returns `Some(ptr)` when an implementation
/// exists for `(dll, func)`.
pub trait ImportResolver {
    fn resolve(&self, dll: &str, func: &str) -> Option<ExternPtr>;
}

/// A loaded image.
pub struct Image {
    info: PeInfo,
    base: *mut u8,
    size: u32,
    /// Actual base minus preferred base (0 when mapped at preferred address).
    slide: u64,
    exports: Exports,
    stub_count: usize,
}

struct Exports {
    num_functions: u32,
    num_names: u32,
    addr_table_rva: u32,
    name_table_rva: u32,
    ordinal_table_rva: u32,
}

/// `DllMain(HINSTANCE, reason, reserved)` under the Win64 convention.
pub type DllMainFn = unsafe extern "win64" fn(*mut u8, u32, *mut u8) -> i32;

pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

#[derive(Debug)]
pub enum LoadError {
    Parse(ParseError),
    MapFailed { size: u32 },
    BadImportRva { rva: u32 },
    BadExportRva { rva: u32 },
    RvaOutOfBounds { rva: u32 },
    UnsupportedMachine { machine: u16 },
}

impl From<ParseError> for LoadError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse failed: {e}"),
            Self::MapFailed { size } => write!(f, "mmap of {size} bytes failed"),
            Self::BadImportRva { rva } => write!(f, "import directory points outside image: rva={rva:#x}"),
            Self::BadExportRva { rva } => write!(f, "export directory points outside image: rva={rva:#x}"),
            Self::RvaOutOfBounds { rva } => write!(f, "image too small for rva={rva:#x}"),
            Self::UnsupportedMachine { machine } => write!(f, "unsupported machine: {machine:#06x}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl Image {
    /// Load a PE32+ image from its file bytes.
    pub fn load(file: &[u8], resolver: &mut dyn ImportResolver) -> Result<Image, LoadError> {
        let info = PeInfo::parse(file)?;
        let size = info.opt.size_of_image;

        // 1. Reserve address space, preferring the image's preferred base.
        let base = unsafe {
            libc::mmap(
                info.opt.image_base as *mut libc::c_void,
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        let base = if base == libc::MAP_FAILED {
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size as usize,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            }
        } else {
            base
        };
        if base == libc::MAP_FAILED {
            return Err(LoadError::MapFailed { size });
        }
        let base = base as *mut u8;
        let slide = (base as u64).wrapping_sub(info.opt.image_base);

        // SAFETY: `base` covers `size` bytes we just mapped; all copies below
        // stay within `[0, size_of_image)` verified against section bounds.
        unsafe {
            // 2. Headers.
            let hdr_len = info.opt.size_of_headers.min(size) as usize;
            std::ptr::copy_nonoverlapping(file.as_ptr(), base, hdr_len);

            // 3. Sections (raw data only; the rest stays zero-filled).
            for s in &info.sections {
                if s.size_of_raw_data == 0 || s.pointer_to_raw_data == 0 {
                    continue;
                }
                let src_end = s.pointer_to_raw_data as usize + s.size_of_raw_data as usize;
                if src_end > file.len() {
                    continue;
                }
                let dst = base.add(s.virtual_address as usize);
                let n = s.size_of_raw_data.min(size - s.virtual_address) as usize;
                std::ptr::copy_nonoverlapping(file.as_ptr().add(s.pointer_to_raw_data as usize), dst, n);
            }
        }

        let mut img = Image {
            info,
            base,
            size,
            slide,
            exports: Exports {
                num_functions: 0,
                num_names: 0,
                addr_table_rva: 0,
                name_table_rva: 0,
                ordinal_table_rva: 0,
            },
            stub_count: 0,
        };

        // 4. Relocations.
        if img.slide != 0 {
            if let Some((rva, cb)) = img.info.opt.data_dirs[dir_index::BASE_RELOC] {
                unsafe { img.apply_relocations(rva, cb) };
            }
        }

        // 5. Imports.
        if let Some((rva, _cb)) = img.info.opt.data_dirs[dir_index::IMPORT] {
            img.resolve_imports(rva, resolver)?;
        }

        // 6. Export table bookkeeping.
        if let Some((rva, _cb)) = img.info.opt.data_dirs[dir_index::EXPORT] {
            img.read_export_directory(rva)?;
        }

        // 7. Enforce per-section protections now that patching is done.
        for s in &img.info.sections {
            if s.virtual_size == 0 {
                continue;
            }
            unsafe {
                let addr = img.base.add(page_down(s.virtual_address));
                let len = round_up_page(s.virtual_size.max(s.size_of_raw_data)) as usize;
                libc::mprotect(addr.cast(), len, s.prot());
            }
        }

        Ok(img)
    }

    pub fn base(&self) -> *mut u8 {
        self.base
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn slide(&self) -> u64 {
        self.slide
    }

    pub fn info(&self) -> &PeInfo {
        &self.info
    }

    /// Number of imports that fell back to trap stubs during load.
    pub fn stubbed_imports(&self) -> usize {
        self.stub_count
    }

    /// Entry point as `DllMain` (Win64 calling convention).
    ///
    /// # Safety
    /// The caller must guarantee the runtime environment (TEB/GS, shims)
    /// is prepared before invoking guest code.
    pub unsafe fn entry_dll_main(&self) -> Option<DllMainFn> {
        let rva = self.info.opt.address_of_entry_point;
        if rva == 0 {
            return None;
        }
        Some(std::mem::transmute(self.base.add(rva as usize)))
    }

    /// Raw pointer to an export by name.
    pub fn get_export_by_name(&self, name: &str) -> Option<*const u8> {
        if self.exports.num_names == 0 {
            return None;
        }
        let names = self.slice_at::<u32>(self.exports.name_table_rva, self.exports.num_names)?;
        let ords = self.slice_at::<u16>(self.exports.ordinal_table_rva, self.exports.num_names)?;
        let addrs = self.slice_at::<u32>(self.exports.addr_table_rva, self.exports.num_functions)?;

        for i in 0..self.exports.num_names as usize {
            let name_rva = names[i];
            let cstr = self.cstr_at(name_rva)?;
            if cstr == name.as_bytes() {
                let ord_idx = ords[i] as usize;
                let func_rva = addrs.get(ord_idx).copied()?;
                // Export forwarding: an RVA pointing inside the export
                // directory itself is a forwarded string ("other.dll.fn").
                if let Some((erva, ecb)) = self.info.opt.data_dirs[dir_index::EXPORT] {
                    if func_rva >= erva && func_rva < erva + ecb {
                        return None; // forwarders not followed in phase 1
                    }
                }
                return Some(unsafe { self.base.add(func_rva as usize) } as *const u8);
            }
        }
        None
    }

    /// List of exported function names.
    pub fn export_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let (Some(names), Some(_ords)) = (
            self.slice_at::<u32>(self.exports.name_table_rva, self.exports.num_names),
            self.slice_at::<u16>(self.exports.ordinal_table_rva, self.exports.num_names),
        ) {
            for name_rva in names.iter().take(self.exports.num_names as usize) {
                if let Some(s) = self.cstr_at(*name_rva) {
                    out.push(String::from_utf8_lossy(s).into_owned());
                }
            }
        }
        out
    }

    // ── internals ────────────────────────────────────────────────────────

    fn check_rva(&self, rva: u32, len: u32) -> Result<(), LoadError> {
        if rva as u64 + len as u64 > self.size as u64 {
            Err(LoadError::RvaOutOfBounds { rva })
        } else {
            Ok(())
        }
    }

    /// Typed slice view into mapped memory at an RVA.
    fn slice_at<T>(&self, rva: u32, count: u32) -> Option<&[T]> {
        let bytes = std::mem::size_of::<T>();
        if count == 0 || bytes == 0 {
            return None;
        }
        self.check_rva(rva, count * bytes as u32).ok()?;
        unsafe {
            Some(std::slice::from_raw_parts(
                self.base.add(rva as usize) as *const T,
                count as usize,
            ))
        }
    }

    /// NUL-terminated byte string view at an RVA.
    fn cstr_at(&self, rva: u32) -> Option<&[u8]> {
        if self.check_rva(rva, 1).is_err() {
            return None;
        }
        unsafe {
            let start = self.base.add(rva as usize);
            let mut len = 0usize;
            while *start.add(len) != 0 {
                len += 1;
                if rva as usize + len >= self.size as usize {
                    return None;
                }
            }
            Some(std::slice::from_raw_parts(start, len))
        }
    }

    /// # Safety
    /// Caller guarantees relocation dir fits in the image.
    unsafe fn apply_relocations(&mut self, rva: u32, total_size: u32) {
        self.check_rva(rva, total_size)
            .expect("relocation dir bounds checked by caller");
        let mut off = 0u32;
        while off + 8 <= total_size {
            let block = self.base.add((rva + off) as usize) as *const u32;
            let page_rva = block.read_unaligned();
            let block_size = block.add(1).read_unaligned();
            if block_size < 8 || off + block_size > total_size {
                break;
            }
            let count = (block_size - 8) / 2;
            let entries = self.base.add((rva + off + 8) as usize) as *const u16;
            for j in 0..count as usize {
                let entry = entries.add(j).read_unaligned();
                let ty = entry >> 12;
                let in_page = (entry & 0x0FFF) as u32;
                let target_rva = page_rva + in_page;
                if target_rva + 8 > self.size {
                    continue;
                }
                match ty {
                    10 => {
                        // IMAGE_REL_BASED_DIR64
                        let p = self.base.add(target_rva as usize) as *mut u64;
                        let v = p.read_unaligned();
                        p.write_unaligned(v.wrapping_add(self.slide));
                    }
                    3 => {
                        // IMAGE_REL_BASED_HIGHLOW (rare in PE32+, kept for safety)
                        let p = self.base.add(target_rva as usize) as *mut u32;
                        let v = p.read_unaligned();
                        p.write_unaligned(v.wrapping_add(self.slide as u32));
                    }
                    _ => {}
                }
            }
            off += block_size;
        }
    }

    fn resolve_imports(
        &mut self,
        dir_rva: u32,
        resolver: &mut dyn ImportResolver,
    ) -> Result<(), LoadError> {
        let mut desc_rva = dir_rva;
        loop {
            self.check_rva(desc_rva, 20)?;
            let d = unsafe {
                let p = self.base.add(desc_rva as usize) as *const u32;
                (
                    p.read_unaligned(),
                    p.add(1).read_unaligned(),
                    p.add(2).read_unaligned(),
                    p.add(3).read_unaligned(),
                    p.add(4).read_unaligned(),
                )
            };
            let (_lookup, _ts, _fwd, name_rva, iat_rva) = d;
            if lookup_rva_is_zero(d.0) && iat_rva == 0 {
                break;
            }
            let dll_name = self
                .cstr_at(name_rva)
                .map(String::from_utf8_lossy)
                .unwrap_or_else(|| std::borrow::Cow::Borrowed("?"));
            let dll_upper = dll_name.to_ascii_uppercase();

            let lookup_rva = d.0;
            let mut idx = 0u32;
            loop {
                let thunk_rva = if lookup_rva != 0 { lookup_rva } else { iat_rva };
                self.check_rva(thunk_rva + idx * 8, 8)?;
                let entry = unsafe {
                    (self.base.add((thunk_rva + idx * 8) as usize) as *const u64).read_unaligned()
                };
                if entry == 0 {
                    break;
                }
                let resolved: Option<ExternPtr> = if entry & (1 << 63) != 0 {
                    // Ordinal import: no name to dispatch on.
                    None
                } else {
                    let fname_rva = (entry & 0x7FFF_FFFF) as u32;
                    let fname = self
                        .cstr_at(fname_rva.wrapping_add(2))
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default();
                    resolver.resolve(&dll_upper, &fname)
                };

                self.check_rva(iat_rva + idx * 8, 8)?;
                let slot =
                    unsafe { self.base.add((iat_rva + idx * 8) as usize) as *mut ExternPtr };
                match resolved {
                    Some(ptr) => unsafe { slot.write(ptr) },
                    None => {
                        // Unimplemented: point at a named trap micro-stub so
                        // the first guest call reports instead of crashing.
                        let dll_owned = dll_upper.clone();
                        let fname_owned = self
                            .cstr_at(((entry & 0x7FFF_FFFF) as u32).wrapping_add(2))
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .unwrap_or_default();
                        let stub = crate::stub_pool()
                            .allocate(format!("{dll_owned}!{fname_owned}"));
                        unsafe { slot.write(stub as ExternPtr) };
                        self.stub_count += 1;
                    }
                }
                idx += 1;
                if idx > 100_000 {
                    break; // malformed import table guard
                }
            }
            desc_rva += 20;
            if desc_rva > self.size {
                break;
            }
        }
        Ok(())
    }

    fn read_export_directory(&mut self, rva: u32) -> Result<(), LoadError> {
        self.check_rva(rva + 40, 0)?;
        let f = unsafe {
            let p = self.base.add(rva as usize) as *const u32;
            (
                p.add(4).read_unaligned(),  // +16: ordinal base (skip chars/ts/ver)
                p.add(5).read_unaligned(),  // +20: number of functions
                p.add(6).read_unaligned(),  // +24: number of names
                p.add(7).read_unaligned(),  // +28: address table RVA
                p.add(8).read_unaligned(),  // +32: name table RVA
                p.add(9).read_unaligned(),  // +36: ordinal table RVA
            )
        };
        self.exports = Exports {
            num_functions: f.1,
            num_names: f.2,
            addr_table_rva: f.3,
            name_table_rva: f.4,
            ordinal_table_rva: f.5,
        };
        Ok(())
    }
}

fn lookup_rva_is_zero(v: u32) -> bool {
    v == 0
}

fn page_down(v: u32) -> usize {
    (v & !0xFFF) as usize
}

fn round_up_page(v: u32) -> u32 {
    (v + 0xFFF) & !0xFFF
}

impl Drop for Image {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base.cast(), self.size as usize);
        }
    }
}
