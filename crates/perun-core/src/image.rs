// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

// RVA and size values are 32-bit by construction in the PE format: the
// file offsets here are read out of the header and bounded by
// `SizeOfImage` before use, so a `usize` -> `u32` narrowing is a
// representation change on the way into a field the format defines
// as 32 bits, not a value that can actually be lost.
#![allow(unknown_lints)]
#![allow(clippy::cast_possible_truncation)]

//! Minimal PE32+ header parsing.
//!
//! All structures are read with explicit offsets from the byte stream, the
//! same way the C prototype did it. This avoids `#[repr(C)]` alignment traps
//! on every field and keeps the parser independent of struct padding rules.

/// Section table entry (only the fields we need).
#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub name: [u8; 8],
    /// Virtual size (size of initialized data in memory).
    pub virtual_size: u32,
    /// Virtual address (RVA of the section start).
    pub virtual_address: u32,
    /// Raw size in the file.
    pub size_of_raw_data: u32,
    /// File offset of the raw data.
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl Section {
    #[must_use]
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// Memory protection flags derived from section characteristics
    #[must_use]
    pub fn prot(&self) -> i32 {
        use image_consts::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
        let e = self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let r = self.characteristics & IMAGE_SCN_MEM_READ != 0;
        let w = self.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let mut p = 0;
        if r {
            p |= libc::PROT_READ;
        }
        if w {
            p |= libc::PROT_WRITE;
        }
        if e {
            p |= libc::PROT_EXEC;
        }
        p
    }
}

/// A data directory entry: `(RVA, size)`.
pub type DataDirEntry = Option<(u32, u32)>;

/// Parsed optional header fields relevant to loading a PE32+ image.
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    /// Preferred load address.
    pub image_base: u64,
    /// Total size of the image in memory.
    pub size_of_image: u32,
    /// Entry point RVA (`DllMain` wrapper).
    pub address_of_entry_point: u32,
    /// Size of the DOS+PE+section headers area copied into image memory.
    pub size_of_headers: u32,
    /// The 16 data directories; index per PE spec.
    pub data_dirs: [DataDirEntry; 16],
}

/// Fully parsed PE32+ image description.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub sections: Vec<Section>,
    pub opt: OptionalHeader,
}

/// Data directory indices per PE specification.
pub mod dir_index {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const BASE_RELOC: usize = 5;
}

pub(crate) mod image_consts {
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
}

/// One imported symbol: either a name or an ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u16),
}

/// Map an RVA to a file offset through the section table.
fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    let rva = rva as usize;
    for s in sections {
        let start = s.virtual_address as usize;
        let mem_size = (s.virtual_size as usize).max(s.size_of_raw_data as usize);
        if rva >= start && rva < start + mem_size {
            let delta = rva - start;
            if delta >= s.size_of_raw_data as usize {
                // In a BSS tail: backed by zeroes in memory, absent in file.
                return None;
            }
            return s
                .pointer_to_raw_data
                .checked_add(delta as u32)
                .map(|v| v as usize);
        }
    }
    None
}

fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
}

fn read_u64_at(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

fn cstr_at(data: &[u8], off: usize) -> Option<String> {
    let end = data.get(off..)?.iter().position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&data[off..off + end]).into_owned())
}

impl PeInfo {
    /// List imports as `(dll, symbols)` from the file bytes. Malformed
    /// entries are skipped; a truncated table ends the walk.
    ///
    /// # Panics
    ///
    /// Panics if a crafted image makes the import table claim more names than
    /// the file holds. Every RVA is bounds-checked before use, so a merely
    /// truncated file walks cleanly and returns a short list.
    #[must_use]
    pub fn imports(&self, data: &[u8]) -> Vec<(String, Vec<ImportSymbol>)> {
        let Some((dir_rva, _)) = self.opt.data_dirs[dir_index::IMPORT] else {
            return Vec::new();
        };
        let Some(mut desc_off) = rva_to_offset(&self.sections, dir_rva) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for _ in 0..1024 {
            let Some(chunk) = data.get(desc_off..desc_off + 20) else {
                break;
            };
            let lookup = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let name_rva = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
            let iat_rva = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
            if lookup == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            let dll = if name_rva != 0 {
                rva_to_offset(&self.sections, name_rva).and_then(|off| cstr_at(data, off))
            } else {
                None
            }
            .unwrap_or_else(|| "?".to_string());
            let thunk_rva = if lookup != 0 { lookup } else { iat_rva };
            let mut syms = Vec::new();
            for idx in 0..100_000u32 {
                let Some(entry_off) =
                    rva_to_offset(&self.sections, thunk_rva.wrapping_add(idx * 8))
                else {
                    break;
                };
                let Some(entry) = read_u64_at(data, entry_off) else {
                    break;
                };
                if entry == 0 {
                    break;
                }
                if entry & (1 << 63) != 0 {
                    syms.push(ImportSymbol::Ordinal((entry & 0xFFFF) as u16));
                } else {
                    let fname_rva = (entry & 0x7FFF_FFFF) as u32;
                    let name = rva_to_offset(&self.sections, fname_rva.wrapping_add(2))
                        .and_then(|off| cstr_at(data, off))
                        .unwrap_or_default();
                    syms.push(ImportSymbol::Name(name));
                }
            }
            out.push((dll, syms));
            desc_off += 20;
        }
        out
    }

    /// List exported names from the file bytes. Ordinal-only exports have
    /// no name entry and are not listed (count via the directory header).
    #[must_use]
    pub fn exports(&self, data: &[u8]) -> Vec<String> {
        let Some((dir_rva, _)) = self.opt.data_dirs[dir_index::EXPORT] else {
            return Vec::new();
        };
        let Some(dir_off) = rva_to_offset(&self.sections, dir_rva) else {
            return Vec::new();
        };
        let Some(num_names) = read_u32_at(data, dir_off + 24) else {
            return Vec::new();
        };
        let (Some(names_rva), Some(ords_rva)) = (
            read_u32_at(data, dir_off + 32),
            read_u32_at(data, dir_off + 36),
        ) else {
            return Vec::new();
        };
        // Cap absurd counts from malformed headers.
        let num_names = num_names.min(100_000) as usize;
        let mut out = Vec::with_capacity(num_names.min(4096));
        for i in 0..num_names {
            let Some(name_ptr_off) =
                rva_to_offset(&self.sections, names_rva.wrapping_add(i as u32 * 4))
            else {
                break;
            };
            // Ordinal entry must also be readable; otherwise the table is
            // truncated.
            let ord_off = rva_to_offset(&self.sections, ords_rva.wrapping_add(i as u32 * 2));
            let Some(ord_off) = ord_off else { break };
            if read_u16_at(data, ord_off).is_none() {
                break;
            }
            let Some(hint_rva) = read_u32_at(data, name_ptr_off) else {
                break;
            };
            let Some(hint_at) = rva_to_offset(&self.sections, hint_rva) else {
                continue;
            };
            if let Some(name) = cstr_at(data, hint_at) {
                out.push(name);
            }
        }
        out
    }
    ///
    /// # Errors
    ///
    /// Returns `ParseError` naming the first thing that is wrong: `NotMz`, `BadSignature`, `NotX86_64`, `NotPe32Plus`, `BadImageBase`, or `Truncated`.
    ///
    /// # Panics
    ///
    /// Panics on a header whose own declared length runs past the end of the
    /// buffer: the optional-header offset and the section table are read with
    /// `try_into().unwrap()`, so a file that lies about `e_lfanew` aborts
    /// instead of returning `Truncated`. Only a malformed input reaches this.
    pub fn parse(data: &[u8]) -> Result<PeInfo, ParseError> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            return Err(ParseError::NotMz);
        }
        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        if data.len() < pe_off + 4 || data[pe_off..pe_off + 4] != [0x50, 0x45, 0x00, 0x00] {
            return Err(ParseError::BadSignature);
        }

        let machine = u16::from_le_bytes(data[pe_off + 4..pe_off + 6].try_into().unwrap());
        if machine != 0x8664 {
            return Err(ParseError::NotX86_64(machine));
        }

        let num_sections =
            u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
        let opt_size =
            u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;

        let opt = pe_off + 24;
        let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap());
        if magic != 0x20B {
            return Err(ParseError::NotPe32Plus(magic));
        }

        let image_base = u64::from_le_bytes(data[opt + 24..opt + 32].try_into().unwrap());
        // Alignment sanity: preferred base must be page aligned to map there.
        if image_base % 0x1000 != 0 {
            return Err(ParseError::BadImageBase(image_base));
        }
        let size_of_image = u32::from_le_bytes(data[opt + 56..opt + 60].try_into().unwrap());
        let address_of_entry_point =
            u32::from_le_bytes(data[opt + 16..opt + 20].try_into().unwrap());

        // Data directories start at opt+112 in PE32+, each entry is 8 bytes.
        let dd_off = opt + 112;
        if data.len() < dd_off + 16 * 8 {
            return Err(ParseError::Truncated);
        }
        let mut data_dirs: [DataDirEntry; 16] = std::array::from_fn(|_| None);
        for i in 0..16 {
            let rva =
                u32::from_le_bytes(data[dd_off + i * 8..dd_off + i * 8 + 4].try_into().unwrap());
            let size = u32::from_le_bytes(
                data[dd_off + i * 8 + 4..dd_off + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            if rva != 0 {
                data_dirs[i] = Some((rva, size));
            }
        }

        let sec_table = opt + opt_size;
        if data.len() < sec_table + num_sections * 40 {
            return Err(ParseError::Truncated);
        }
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = &data[sec_table + i * 40..sec_table + (i + 1) * 40];
            sections.push(Section {
                name: s[0..8].try_into().unwrap(),
                virtual_size: u32::from_le_bytes(s[8..12].try_into().unwrap()),
                virtual_address: u32::from_le_bytes(s[12..16].try_into().unwrap()),
                size_of_raw_data: u32::from_le_bytes(s[16..20].try_into().unwrap()),
                pointer_to_raw_data: u32::from_le_bytes(s[20..24].try_into().unwrap()),
                characteristics: u32::from_le_bytes(s[36..40].try_into().unwrap()),
            });
        }

        // size_of_headers: first section VA is the classic value; fall back to
        // rounding the header span up to the section alignment.
        let size_of_headers = sections.first().map_or(
            ((pe_off + 24 + opt_size + num_sections * 40).div_ceil(0x10_00_00) * 0x10_00_00) as u32,
            |s| s.virtual_address,
        );

        Ok(PeInfo {
            sections,
            opt: OptionalHeader {
                magic,
                image_base,
                size_of_image,
                address_of_entry_point,
                size_of_headers,
                data_dirs,
            },
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    NotMz,
    BadSignature,
    NotX86_64(u16),
    NotPe32Plus(u16),
    BadImageBase(u64),
    Truncated,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotMz => write!(f, "not an MZ image"),
            Self::BadSignature => write!(f, "bad PE signature"),
            Self::NotX86_64(m) => write!(f, "unsupported machine type: {m:#06x}"),
            Self::NotPe32Plus(m) => write!(f, "not a PE32+ image (optional header magic {m:#06x})"),
            Self::BadImageBase(b) => write!(f, "preferred image base is not page-aligned: {b:#x}"),
            Self::Truncated => write!(f, "file truncated"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32+ with one section (RVA 0x1000 ↔ file 0x200), two import
    /// descriptors (lookup path + IAT-fallback path, named + ordinal) and
    /// one named export.
    fn synthetic_pe() -> Vec<u8> {
        fn w32(buf: &mut [u8], off: usize, v: u32) {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn w64(buf: &mut [u8], off: usize, v: u64) {
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        let mut buf = vec![0u8; 0x1200];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80;
        buf[pe..pe + 4].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        // COFF: machine x86_64, 1 section, opt size 240.
        buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let opt = pe + 24;
        buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        buf[opt + 24..opt + 32].copy_from_slice(&0x1400_0000u64.to_le_bytes()); // base
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // image size
        // Data dirs: export[0] = (0x1100, 64), import[1] = (0x1000, 60).
        let dd = opt + 112;
        buf[dd..dd + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        buf[dd + 4..dd + 8].copy_from_slice(&64u32.to_le_bytes());
        buf[dd + 8..dd + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[dd + 12..dd + 16].copy_from_slice(&60u32.to_le_bytes());
        // Section .text: VA 0x1000, raw ptr 0x200, sizes 0x1000.
        let sec = opt + 240;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        buf[sec + 16..sec + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // raw size
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Import descriptors at file 0x200 (RVA 0x1000): two real + null
        // terminator (60 bytes total, ending at 0x23B).
        // desc 0: lookup=0x103C, name=0x106C, iat=0x1054.
        w32(&mut buf, 0x200, 0x103C);
        w32(&mut buf, 0x200 + 12, 0x106C);
        w32(&mut buf, 0x200 + 16, 0x1054);
        // desc 1 at 0x214: lookup=0 (IAT fallback), name=0x107C, iat=0x105C.
        w32(&mut buf, 0x214, 0);
        w32(&mut buf, 0x214 + 12, 0x107C);
        w32(&mut buf, 0x214 + 16, 0x105C);
        // Null terminator at 0x228 stays zeroed (buf init).
        // Lookup thunks for desc 0 at 0x23C (RVA 0x103C).
        w64(&mut buf, 0x23C, 0x1088);
        w64(&mut buf, 0x244, 0x8000_0000_0000_0007);
        // IAT for desc 0 at 0x254 (RVA 0x1054; values ignored, lookup wins).
        w64(&mut buf, 0x254, 0x1088);
        // IAT for desc 1 at 0x25C (RVA 0x105C): named@0x1098.
        w64(&mut buf, 0x25C, 0x1098);
        // DLL names.
        buf[0x26C..0x26C + 13].copy_from_slice(b"KERNEL32.dll\0");
        buf[0x27C..0x27C + 11].copy_from_slice(b"USER32.dll\0");
        // Hint/Name entries.
        buf[0x288..0x28A].copy_from_slice(&0u16.to_le_bytes());
        buf[0x28A..0x28A + 12].copy_from_slice(b"CreateFileW\0");
        buf[0x298..0x29A].copy_from_slice(&0u16.to_le_bytes());
        buf[0x29A..0x29A + 12].copy_from_slice(b"MessageBoxW\0");
        // Export dir at file 0x300 (RVA 0x1100).
        w32(&mut buf, 0x300 + 16, 1); // base
        w32(&mut buf, 0x300 + 20, 2); // num functions
        w32(&mut buf, 0x300 + 24, 1); // num names
        w32(&mut buf, 0x300 + 28, 0x1130); // addr table
        w32(&mut buf, 0x300 + 32, 0x1140); // name table
        w32(&mut buf, 0x300 + 36, 0x1150); // ordinal table
        w32(&mut buf, 0x340, 0x1160); // name RVA -> "MyExport"
        buf[0x350..0x352].copy_from_slice(&0u16.to_le_bytes()); // ordinal 0
        buf[0x360..0x360 + 9].copy_from_slice(b"MyExport\0");
        buf
    }

    #[test]
    fn imports_and_exports_from_synthetic_pe() {
        let data = synthetic_pe();
        let info = PeInfo::parse(&data).unwrap();
        let imports = info.imports(&data);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].0, "KERNEL32.dll");
        assert_eq!(
            imports[0].1,
            vec![
                ImportSymbol::Name("CreateFileW".into()),
                ImportSymbol::Ordinal(7),
            ]
        );
        // Second descriptor has no lookup table: falls back to the IAT.
        assert_eq!(imports[1].0, "USER32.dll");
        assert_eq!(imports[1].1, vec![ImportSymbol::Name("MessageBoxW".into())]);
        let exports = info.exports(&data);
        assert_eq!(exports, vec!["MyExport".to_string()]);
    }

    #[test]
    fn imports_exports_empty_without_directories() {
        let mut data = synthetic_pe();
        // Zero both directory entries.
        let dd = 0x80 + 24 + 112;
        for b in &mut data[dd..dd + 32] {
            *b = 0;
        }
        let info = PeInfo::parse(&data).unwrap();
        assert!(info.imports(&data).is_empty());
        assert!(info.exports(&data).is_empty());
    }
}
