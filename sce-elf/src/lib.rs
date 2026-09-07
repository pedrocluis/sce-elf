//! Parser for Sony's SELF/ELF binary format (PS4/PS5).
//!
//! Handles the optional SELF signing wrapper, the ELF64 header and program
//! headers (including `PT_SCE_*` segment types), and NID hashing. See
//! [`nid::hash`] for symbol-name-to-NID hashing.

pub mod dynamic;
pub mod elf;
pub mod error;
pub mod nid;
pub mod self_file;

pub use dynamic::{DynEntry, DynTag, Relocation, Symbol};
pub use elf::{ElfHeader, ElfType, ProgramHeader, ProgramType};
pub use error::{Error, Result};
pub use self_file::{SelfHeader, SelfSegmentHeader};

use binrw::BinRead;
use std::io::{Cursor, Seek, SeekFrom};

/// A parsed SELF/ELF binary: the outer SELF wrapper (if present), the ELF
/// header, and its program headers.
pub struct Image {
    pub self_header: Option<SelfHeader>,
    pub self_segments: Vec<SelfSegmentHeader>,
    pub elf_header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    /// Offset of the ELF header within `data` (0 for a raw ELF, or past the
    /// SELF wrapper for a `.self`/`.sprx`).
    pub elf_offset: u64,
    data: Vec<u8>,
}

impl Image {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let mut cursor = Cursor::new(data.as_slice());

        let (self_header, self_segments, elf_offset) = match SelfHeader::read(&mut cursor) {
            Ok(header) => {
                let segments = (0..header.segment_count)
                    .map(|_| SelfSegmentHeader::read(&mut cursor))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let offset = header.header_size as u64;
                (Some(header), segments, offset)
            }
            Err(_) => {
                cursor.seek(SeekFrom::Start(0))?;
                (None, Vec::new(), 0u64)
            }
        };

        cursor.seek(SeekFrom::Start(elf_offset))?;
        let elf_header = ElfHeader::read(&mut cursor)?;

        cursor.seek(SeekFrom::Start(elf_offset + elf_header.e_phoff))?;
        let program_headers = (0..elf_header.e_phnum)
            .map(|_| ProgramHeader::read(&mut cursor))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(Self {
            self_header,
            self_segments,
            elf_header,
            program_headers,
            elf_offset,
            data,
        })
    }

    pub fn is_self(&self) -> bool {
        self.self_header.is_some()
    }

    pub fn elf_type(&self) -> ElfType {
        self.elf_header.e_type.into()
    }

    /// The raw file bytes, for reading segment/section contents at their
    /// recorded offsets.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
