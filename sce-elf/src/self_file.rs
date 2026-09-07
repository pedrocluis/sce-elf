//! The SELF container: Sony's signed wrapper around a PS4/PS5 ELF.
//!
//! Layout verified against shadPS4's `src/core/loader/elf.h`
//! (https://github.com/shadps4-emu/shadPS4).

use binrw::BinRead;

/// The SELF container magic shadPS4 knows, and what PS4 files and PS5
/// `eboot.bin` carry.
pub const SELF_MAGIC: u32 = 0x1D3D_154F;

/// A second container magic carried by some PS5 `.sprx` files. The header
/// layout and everything after it are identical — verified against retail
/// PS5 libraries, whose ELF header sits at the usual place right after the
/// segment table.
pub const SELF_MAGIC_PS5: u32 = 0xEEF5_1454;

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
#[br(assert(
    magic == SELF_MAGIC || magic == SELF_MAGIC_PS5,
    "not a SELF container: magic {magic:#010x}"
))]
pub struct SelfHeader {
    pub magic: u32,
    pub version: u8,
    pub mode: u8,
    /// 1 = little endian.
    pub endian: u8,
    pub attributes: u8,
    pub category: u8,
    pub program_type: u8,
    pub padding1: u16,
    /// Size of the whole header block — this header, the segment table, the
    /// wrapped ELF header and its tables, and the signing area — i.e. where
    /// the segment payloads start. *Not* the offset of the ELF header, which
    /// sits immediately after the segment table.
    pub header_size: u16,
    pub meta_size: u16,
    pub file_size: u32,
    pub padding2: u32,
    pub segment_count: u16,
    pub unknown1a: u16,
    pub padding3: u32,
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct SelfSegmentHeader {
    pub flags: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

impl SelfSegmentHeader {
    pub fn is_blocked(&self) -> bool {
        self.flags & 0x800 != 0
    }

    pub fn is_ordered(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & 2 != 0
    }

    pub fn is_signed(&self) -> bool {
        self.flags & 4 != 0
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & 8 != 0
    }

    pub fn id(&self) -> u32 {
        ((self.flags >> 20) & 0xFFF) as u32
    }
}
