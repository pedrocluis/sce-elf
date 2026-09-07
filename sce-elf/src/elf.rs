//! The ELF64 header and program headers, including Sony's `PT_SCE_*` and
//! `ET_SCE_*` extensions.
//!
//! Constants verified against shadPS4's `src/core/loader/elf.h`
//! (https://github.com/shadps4-emu/shadPS4).

use binrw::BinRead;

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little, magic = b"\x7FELF")]
pub struct ElfHeader {
    pub class: u8,
    pub data: u8,
    pub ident_version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
    #[br(pad_before = 7)]
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    None,
    Rel,
    Exec,
    Dyn,
    Core,
    /// Sony: a self-contained executable (eboot.bin).
    SceExec,
    /// Sony: an import stub library.
    SceStubLib,
    /// Sony: PIE executable.
    SceDynExec,
    /// Sony: a shared library (.sprx / .prx).
    SceDynamic,
    Other(u16),
}

impl From<u16> for ElfType {
    fn from(v: u16) -> Self {
        match v {
            0x0 => Self::None,
            0x1 => Self::Rel,
            0x2 => Self::Exec,
            0x3 => Self::Dyn,
            0x4 => Self::Core,
            0xfe00 => Self::SceExec,
            0xfe0c => Self::SceStubLib,
            0xfe10 => Self::SceDynExec,
            0xfe18 => Self::SceDynamic,
            other => Self::Other(other),
        }
    }
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    /// Sony: relocations for `SceDynlibData`.
    SceRela,
    /// Sony: the region holding the dynamic symbol/string/relocation tables.
    SceDynlibData,
    SceProcParam,
    SceModuleParam,
    SceRelro,
    GnuEhFrame,
    GnuStack,
    GnuRelro,
    SceComment,
    SceLibVersion,
    Other(u32),
}

impl From<u32> for ProgramType {
    fn from(v: u32) -> Self {
        match v {
            0x0 => Self::Null,
            0x1 => Self::Load,
            0x2 => Self::Dynamic,
            0x3 => Self::Interp,
            0x4 => Self::Note,
            0x5 => Self::Shlib,
            0x6 => Self::Phdr,
            0x7 => Self::Tls,
            0x6000_0000 => Self::SceRela,
            0x6100_0000 => Self::SceDynlibData,
            0x6100_0001 => Self::SceProcParam,
            0x6100_0002 => Self::SceModuleParam,
            0x6100_0010 => Self::SceRelro,
            0x6474_e550 => Self::GnuEhFrame,
            0x6474_e551 => Self::GnuStack,
            0x6474_e552 => Self::GnuRelro,
            0x6fff_ff00 => Self::SceComment,
            0x6fff_ff01 => Self::SceLibVersion,
            other => Self::Other(other),
        }
    }
}
