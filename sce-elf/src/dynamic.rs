//! The `PT_DYNAMIC` segment: tags, symbols, and relocations, including
//! Sony's `DT_SCE_*` extensions that replace the standard symbol/string/hash
//! table tags.
//!
//! Constants verified against shadPS4's `src/core/loader/elf.h`
//! (https://github.com/shadps4-emu/shadPS4).

use binrw::BinRead;

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct DynEntry {
    pub d_tag: i64,
    pub d_val: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynTag {
    Null,
    Needed,
    Rela,
    Init,
    Fini,
    Debug,
    TextRel,
    InitArray,
    FiniArray,
    InitArraySz,
    FiniArraySz,
    Flags,
    PreinitArray,
    PreinitArraySz,
    SceFingerprint,
    SceOriginalFilename,
    SceModuleInfo,
    SceNeededModule,
    SceModuleAttr,
    SceExportLib,
    SceImportLib,
    SceImportLibAttr,
    /// Points at `DT_SCE_SYMTAB`'s hash table (not the standard `DT_HASH`).
    SceHash,
    ScePltGot,
    SceJmpRel,
    ScePltRel,
    ScePltRelSz,
    SceRela,
    SceRelaSz,
    SceRelaEnt,
    SceSymEnt,
    SceHashSz,
    SceStrTab,
    SceStrSz,
    SceSymTab,
    SceSymTabSz,
    Other(i64),
}

impl From<i64> for DynTag {
    fn from(v: i64) -> Self {
        match v {
            0x0 => Self::Null,
            0x1 => Self::Needed,
            0x7 => Self::Rela,
            0xc => Self::Init,
            0xd => Self::Fini,
            0x15 => Self::Debug,
            0x16 => Self::TextRel,
            0x19 => Self::InitArray,
            0x1a => Self::FiniArray,
            0x1b => Self::InitArraySz,
            0x1c => Self::FiniArraySz,
            0x1e => Self::Flags,
            0x20 => Self::PreinitArray,
            0x21 => Self::PreinitArraySz,
            0x6100_0007 => Self::SceFingerprint,
            0x6100_0009 => Self::SceOriginalFilename,
            0x6100_000d => Self::SceModuleInfo,
            0x6100_000f => Self::SceNeededModule,
            0x6100_0011 => Self::SceModuleAttr,
            0x6100_0013 => Self::SceExportLib,
            0x6100_0015 => Self::SceImportLib,
            0x6100_0019 => Self::SceImportLibAttr,
            0x6100_0025 => Self::SceHash,
            0x6100_0027 => Self::ScePltGot,
            0x6100_0029 => Self::SceJmpRel,
            0x6100_002b => Self::ScePltRel,
            0x6100_002d => Self::ScePltRelSz,
            0x6100_002f => Self::SceRela,
            0x6100_0031 => Self::SceRelaSz,
            0x6100_0033 => Self::SceRelaEnt,
            0x6100_003b => Self::SceSymEnt,
            0x6100_003d => Self::SceHashSz,
            0x6100_0035 => Self::SceStrTab,
            0x6100_0037 => Self::SceStrSz,
            0x6100_0039 => Self::SceSymTab,
            0x6100_003f => Self::SceSymTabSz,
            other => Self::Other(other),
        }
    }
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Symbol {
    pub fn bind(&self) -> u8 {
        self.st_info >> 4
    }

    pub fn kind(&self) -> u8 {
        self.st_info & 0xf
    }
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct Relocation {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl Relocation {
    pub fn symbol(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    pub fn kind(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}
