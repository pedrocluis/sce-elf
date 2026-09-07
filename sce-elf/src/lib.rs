//! Parser for Sony's SELF/ELF binary format (PS4/PS5).
//!
//! Handles the optional SELF signing wrapper, the ELF64 header and program
//! headers (including `PT_SCE_*` segment types), the dynamic segment, and NID
//! hashing. See [`Image::imports`] for the imported `(module, library, nid)`
//! triples and [`nid::hash`] for symbol-name-to-NID hashing.

pub mod compat;
pub mod dynamic;
pub mod elf;
pub mod error;
pub mod load;
pub mod nid;
pub mod self_file;

pub use compat::{CompatReport, ImplementedNids, NidSet};
pub use dynamic::{
    DynEntry, DynSymbol, DynTag, Dynamic, DynlibData, LibraryInfo, ModuleInfo, Relocation, Symbol,
    TableSource,
};
pub use elf::{ElfHeader, ElfType, ProgramHeader, ProgramType};
pub use error::{Error, Result};
pub use load::{LoadedImage, RelocationReport, UnresolvedSymbol};
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
                // The ELF header follows the segment table immediately. It is
                // *not* at `header_size`, which measures the whole header
                // block right through to where the segment payloads start —
                // `elf_header_pos = Tell()` in shadPS4's `Elf::Open`.
                let offset = cursor.stream_position()?;
                (Some(header), segments, offset)
            }
            Err(_) => {
                cursor.seek(SeekFrom::Start(0))?;
                (None, Vec::new(), 0u64)
            }
        };

        cursor.seek(SeekFrom::Start(elf_offset))?;
        let elf_header = ElfHeader::read(&mut cursor)?;

        // A malformed e_phoff must not overflow into a wrapped seek — in a
        // debug build the addition itself panics.
        let phoff = elf_offset
            .checked_add(elf_header.e_phoff)
            .ok_or(Error::OutOfBounds {
                what: "program header table",
                region: "the file",
                offset: elf_header.e_phoff,
                size: 0,
                limit: data.len() as u64,
            })?;
        cursor.seek(SeekFrom::Start(phoff))?;
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

    /// The index of the first program header of the given type.
    pub fn segment_index(&self, ty: ProgramType) -> Option<usize> {
        self.program_headers
            .iter()
            .position(|ph| ProgramType::from(ph.p_type) == ty)
    }

    /// The `p_filesz` bytes backing a program header.
    ///
    /// For a raw ELF that's just `p_offset`. In a SELF the program headers
    /// describe the *unwrapped* image, so the bytes actually live wherever
    /// the SELF segment table put them: each "blocked" SELF segment carries
    /// the index of the program header it provides in its flags, and its
    /// `file_offset` is where that program header's contents really start.
    /// (Matches `Elf::LoadSegment` in shadPS4's `src/core/loader/elf.cpp`.)
    pub fn segment_data(&self, index: usize) -> Result<&[u8]> {
        let ph = self
            .program_headers
            .get(index)
            .ok_or(Error::NoSuchSegment(index))?;

        if !self.is_self() {
            return self.file_slice(ph.p_offset, ph.p_filesz, "program header");
        }

        // A blocked SELF segment carries the payload of the program header
        // its id names — but a header whose contents merely *live inside*
        // that one (PT_DYNAMIC sitting within a PT_LOAD, say) has no segment
        // of its own. So match on containment, not on the id, and read at the
        // same relative position within the payload.
        let (i, seg, delta) = self
            .self_segments
            .iter()
            .enumerate()
            .filter(|(_, seg)| seg.is_blocked())
            .find_map(|(i, seg)| {
                let owner = self.program_headers.get(seg.id() as usize)?;
                let delta = ph.p_offset.checked_sub(owner.p_offset)?;
                (delta < owner.p_filesz).then_some((i, seg, delta))
            })
            .ok_or(Error::UnmappedSegment(index))?;

        // Both transforms need the segment's own bytes decoded first; see the
        // decompression item in TODO.md.
        if seg.is_encrypted() {
            return Err(Error::OpaqueSegment {
                index: i,
                reason: "encrypted",
            });
        }
        if seg.is_compressed() {
            return Err(Error::OpaqueSegment {
                index: i,
                reason: "compressed",
            });
        }
        if delta.saturating_add(ph.p_filesz) > seg.file_size {
            return Err(Error::OutOfBounds {
                what: "program header contents",
                region: "its SELF segment",
                offset: delta,
                size: ph.p_filesz,
                limit: seg.file_size,
            });
        }
        let at = seg
            .file_offset
            .checked_add(delta)
            .ok_or(Error::OutOfBounds {
                what: "SELF segment contents",
                region: "the file",
                offset: seg.file_offset,
                size: delta,
                limit: self.data.len() as u64,
            })?;
        self.file_slice(at, ph.p_filesz, "SELF segment")
    }

    /// The contents of the first segment of the given type.
    pub fn segment_data_of(&self, ty: ProgramType, name: &'static str) -> Result<&[u8]> {
        let index = self.segment_index(ty).ok_or(Error::MissingSegment(name))?;
        self.segment_data(index)
    }

    /// Parses `PT_DYNAMIC`, reading the tables it points at from wherever
    /// this image keeps them.
    ///
    /// PS4 images have a `PT_SCE_DYNLIBDATA` segment and their `DT_SCE_*`
    /// tags hold offsets into it. PS5 images have no such segment: they use
    /// the standard `DT_*` tags holding virtual addresses, resolved here
    /// through the loadable segments. Both are handled.
    ///
    /// Errors with [`Error::MissingSegment`] on an image that has no dynamic
    /// segment (a static `ET_SCE_EXEC`, say), and with
    /// [`Error::OpaqueSegment`] when the segments are still compressed or
    /// encrypted inside a signed SELF.
    pub fn dynamic(&self) -> Result<Dynamic> {
        let dynamic = self.segment_data_of(ProgramType::Dynamic, "PT_DYNAMIC")?;
        match self.segment_index(ProgramType::SceDynlibData) {
            Some(index) => {
                Dynamic::parse_from(dynamic, &dynamic::DynlibData(self.segment_data(index)?))
            }
            None => Dynamic::parse_from(dynamic, self),
        }
    }

    /// Resolves a virtual address to the file bytes backing it, through the
    /// loadable segments. Used for the PS5 dynamic layout, whose tags hold
    /// addresses rather than `PT_SCE_DYNLIBDATA` offsets.
    pub fn data_at_vaddr(&self, vaddr: u64, size: u64) -> Result<&[u8]> {
        for (index, ph) in self.program_headers.iter().enumerate() {
            let ty = ProgramType::from(ph.p_type);
            if ty != ProgramType::Load && ty != ProgramType::SceRelro {
                continue;
            }
            let Some(delta) = vaddr.checked_sub(ph.p_vaddr) else {
                continue;
            };
            if delta >= ph.p_filesz {
                continue;
            }
            let bytes = self.segment_data(index)?;
            let end = delta.checked_add(size);
            return match end {
                Some(end) if end <= bytes.len() as u64 => Ok(&bytes[delta as usize..end as usize]),
                _ => Err(Error::OutOfBounds {
                    what: "table",
                    region: "its loadable segment",
                    offset: delta,
                    size,
                    limit: bytes.len() as u64,
                }),
            };
        }
        Err(Error::UnmappedAddress(vaddr))
    }

    /// The `(module, library, nid)` triples this image imports.
    pub fn imports(&self) -> Result<Vec<DynSymbol>> {
        Ok(self.dynamic()?.imports())
    }

    /// The `(module, library, nid)` triples this image exports.
    pub fn exports(&self) -> Result<Vec<DynSymbol>> {
        Ok(self.dynamic()?.exports())
    }

    fn file_slice(&self, offset: u64, size: u64, what: &'static str) -> Result<&[u8]> {
        let limit = self.data.len() as u64;
        match offset.checked_add(size) {
            Some(end) if end <= limit => Ok(&self.data[offset as usize..end as usize]),
            _ => Err(Error::OutOfBounds {
                what,
                region: "the file",
                offset,
                size,
                limit,
            }),
        }
    }
}

/// PS5 images address their dynamic tables by virtual address.
impl dynamic::TableSource for Image {
    fn slice(&self, what: &'static str, at: u64, size: u64) -> Result<&[u8]> {
        self.data_at_vaddr(at, size).map_err(|err| match err {
            Error::OutOfBounds {
                region,
                offset,
                limit,
                ..
            } => Error::OutOfBounds {
                what,
                region,
                offset,
                size,
                limit,
            },
            other => other,
        })
    }
}
