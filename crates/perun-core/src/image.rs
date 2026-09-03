// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

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
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// Memory protection flags derived from section characteristics
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

impl PeInfo {
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
        let size_of_headers = sections.first().map(|s| s.virtual_address).unwrap_or(
            ((pe_off + 24 + opt_size + num_sections * 40).div_ceil(0x100000) * 0x100000) as u32,
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
