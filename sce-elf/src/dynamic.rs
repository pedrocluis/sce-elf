//! The `PT_DYNAMIC` segment: tags, symbols, and relocations, including
//! Sony's `DT_SCE_*` extensions that replace the standard symbol/string/hash
//! table tags.
//!
//! The `DT_SCE_*` tags that hold an address hold an *offset into
//! `PT_SCE_DYNLIBDATA`*, not a virtual address — the string, symbol and
//! relocation tables all live in that segment rather than in the loaded
//! image. [`Dynamic::parse`] takes both segments for exactly that reason.
//!
//! Constants and the decode verified against shadPS4's
//! `src/core/loader/elf.h` and `src/core/module.cpp`
//! (https://github.com/shadps4-emu/shadPS4).

use std::io::{Cursor, Seek, SeekFrom};

use binrw::BinRead;

use crate::error::{Error, Result};
use crate::nid::NID_ALPHABET;

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

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
/// Sony: `module_start` / `module_stop`.
pub const STT_SCE: u8 = 11;

/// The size of one `Elf64_Sym`, and the expected `DT_SCE_SYMENT`.
pub const SYMBOL_SIZE: u64 = 24;

/// The size of one `Elf64_Rela`, and the expected `DT_SCE_RELAENT`.
pub const RELOCATION_SIZE: u64 = 24;

pub const R_X86_64_NONE: u32 = 0;
/// Direct 64-bit: `symbol + addend`.
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// Creates a PLT entry.
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// Adjust by program base: `base + addend`, no symbol involved.
pub const R_X86_64_RELATIVE: u32 = 8;
/// TLS module id. Everything below is TLS and needs a `PT_TLS` image.
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;

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

/// Encodes a module or library id the way symbol names reference it.
///
/// Sony assigns each module and library a small integer id, but a symbol name
/// spells that id out in a compact base64 over [`NID_ALPHABET`] — one
/// character below `0x40`, two below `0x1000`, three otherwise. Transcribed
/// from `EncodeId` in shadPS4's `src/core/module.cpp`.
pub fn encode_id(id: u16) -> String {
    let codes = NID_ALPHABET.as_bytes();
    let v = id as usize;
    let mut out = String::with_capacity(3);
    if v >= 0x1000 {
        out.push(codes[(v >> 12) & 0x3f] as char);
    }
    if v >= 0x40 {
        out.push(codes[(v >> 6) & 0x3f] as char);
    }
    out.push(codes[v & 0x3f] as char);
    out
}

/// A module named by `DT_SCE_MODULE_INFO` or `DT_SCE_NEEDED_MODULE`.
///
/// The tag's `d_val` packs the fields as `name_offset: u32`,
/// `version_minor: u8`, `version_major: u8`, `id: u16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    pub id: u16,
    pub version_major: u8,
    pub version_minor: u8,
    /// `id` in the form symbol names use — see [`encode_id`].
    pub enc_id: String,
}

impl ModuleInfo {
    fn decode(value: u64, str_table: &[u8]) -> Result<Self> {
        let id = (value >> 48) as u16;
        Ok(Self {
            name: string_at(str_table, value as u32 as u64)?,
            id,
            version_major: (value >> 40) as u8,
            version_minor: (value >> 32) as u8,
            enc_id: encode_id(id),
        })
    }
}

/// A library named by `DT_SCE_EXPORT_LIB` or `DT_SCE_IMPORT_LIB`.
///
/// The tag's `d_val` packs the fields as `name_offset: u32`, `version: u16`,
/// `id: u16`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryInfo {
    pub name: String,
    pub id: u16,
    pub version: u16,
    /// `id` in the form symbol names use — see [`encode_id`].
    pub enc_id: String,
}

impl LibraryInfo {
    fn decode(value: u64, str_table: &[u8]) -> Result<Self> {
        let id = (value >> 48) as u16;
        Ok(Self {
            name: string_at(str_table, value as u32 as u64)?,
            id,
            version: (value >> 32) as u16,
            enc_id: encode_id(id),
        })
    }
}

/// One dynamic symbol with its `NID#library#module` name decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynSymbol {
    pub module: String,
    pub library: String,
    pub nid: String,
    /// `STT_FUNC`, `STT_OBJECT`, ...
    pub kind: u8,
}

/// The contents of `PT_DYNAMIC`, with every `DT_SCE_*` table it points at
/// resolved against `PT_SCE_DYNLIBDATA`.
#[derive(Debug, Clone, Default)]
pub struct Dynamic {
    /// Every entry up to (not including) the terminating `DT_NULL`.
    pub entries: Vec<DynEntry>,
    /// `DT_SCE_STRTAB` / `DT_SCE_STRSZ`. Names elsewhere are NUL-terminated
    /// strings at byte offsets into this — see [`Dynamic::string`].
    pub str_table: Vec<u8>,
    /// `DT_SCE_SYMTAB`, sliced by `DT_SCE_SYMENT`.
    pub symbols: Vec<Symbol>,
    /// `DT_NEEDED` — plain shared-object names.
    pub needed: Vec<String>,
    /// `DT_SCE_ORIGINAL_FILENAME`.
    pub original_filename: Option<String>,
    /// `DT_SCE_MODULE_INFO` — this module itself. Normally exactly one entry.
    /// (shadPS4 calls these the export modules.)
    pub export_modules: Vec<ModuleInfo>,
    /// `DT_SCE_NEEDED_MODULE` — the modules this one imports from.
    pub import_modules: Vec<ModuleInfo>,
    /// `DT_SCE_EXPORT_LIB` — the libraries this module publishes.
    pub export_libs: Vec<LibraryInfo>,
    /// `DT_SCE_IMPORT_LIB` — the libraries this module pulls symbols from.
    pub import_libs: Vec<LibraryInfo>,
    /// `DT_SCE_RELA`, sliced by `DT_SCE_RELAENT`.
    pub relocations: Vec<Relocation>,
    /// `DT_SCE_JMPREL`, sized by `DT_SCE_PLTRELSZ` — the PLT/GOT slots.
    pub plt_relocations: Vec<Relocation>,
}

impl Dynamic {
    /// Parses the `PT_DYNAMIC` entry array, resolving its `DT_SCE_*` offsets
    /// against the `PT_SCE_DYNLIBDATA` blob.
    pub fn parse(dynamic: &[u8], dynlibdata: &[u8]) -> Result<Self> {
        let entries = read_entries(dynamic)?;

        // Two passes: the module/library/filename tags name themselves by
        // offset into the string table, and nothing guarantees DT_SCE_STRTAB
        // comes first.
        let mut str_off = None;
        let mut str_sz = None;
        let mut sym_off = None;
        let mut sym_sz = None;
        let mut sym_ent = None;
        let mut rela_off = None;
        let mut rela_sz = None;
        let mut rela_ent = None;
        let mut jmprel_off = None;
        let mut jmprel_sz = None;
        for entry in &entries {
            match DynTag::from(entry.d_tag) {
                DynTag::SceStrTab => str_off = Some(entry.d_val),
                DynTag::SceStrSz => str_sz = Some(entry.d_val),
                DynTag::SceSymTab => sym_off = Some(entry.d_val),
                DynTag::SceSymTabSz => sym_sz = Some(entry.d_val),
                DynTag::SceSymEnt => sym_ent = Some(entry.d_val),
                DynTag::SceRela => rela_off = Some(entry.d_val),
                DynTag::SceRelaSz => rela_sz = Some(entry.d_val),
                DynTag::SceRelaEnt => rela_ent = Some(entry.d_val),
                DynTag::SceJmpRel => jmprel_off = Some(entry.d_val),
                DynTag::ScePltRelSz => jmprel_sz = Some(entry.d_val),
                _ => {}
            }
        }

        let str_table = match (str_off, str_sz) {
            (Some(offset), Some(size)) => {
                sub_slice(dynlibdata, "DT_SCE_STRTAB", offset, size)?.to_vec()
            }
            _ => Vec::new(),
        };

        let symbols = match (sym_off, sym_sz) {
            (Some(offset), Some(size)) => {
                let stride = sym_ent.unwrap_or(SYMBOL_SIZE);
                if stride < SYMBOL_SIZE {
                    return Err(Error::BadEntrySize {
                        what: "DT_SCE_SYMENT",
                        size: stride,
                        minimum: SYMBOL_SIZE,
                    });
                }
                let bytes = sub_slice(dynlibdata, "DT_SCE_SYMTAB", offset, size)?;
                let mut cursor = Cursor::new(bytes);
                (0..size / stride)
                    .map(|i| {
                        cursor.seek(SeekFrom::Start(i * stride))?;
                        Ok(Symbol::read(&mut cursor)?)
                    })
                    .collect::<Result<Vec<_>>>()?
            }
            _ => Vec::new(),
        };

        // Both tables use DT_SCE_RELAENT as their stride; DT_SCE_PLTREL only
        // says the PLT table is DT_RELA-shaped, which is the sole form
        // shadPS4 has ever seen in the wild.
        let stride = rela_ent.unwrap_or(RELOCATION_SIZE);
        let relocations = match (rela_off, rela_sz) {
            (Some(offset), Some(size)) => {
                read_relocations(dynlibdata, "DT_SCE_RELA", offset, size, stride)?
            }
            _ => Vec::new(),
        };
        let plt_relocations = match (jmprel_off, jmprel_sz) {
            (Some(offset), Some(size)) => {
                read_relocations(dynlibdata, "DT_SCE_JMPREL", offset, size, stride)?
            }
            _ => Vec::new(),
        };

        let mut this = Self {
            str_table,
            symbols,
            relocations,
            plt_relocations,
            ..Default::default()
        };

        for entry in &entries {
            match DynTag::from(entry.d_tag) {
                DynTag::Needed => this.needed.push(this.string(entry.d_val)?),
                DynTag::SceOriginalFilename => {
                    this.original_filename = Some(this.string(entry.d_val)?);
                }
                DynTag::SceModuleInfo => {
                    this.export_modules
                        .push(ModuleInfo::decode(entry.d_val, &this.str_table)?);
                }
                DynTag::SceNeededModule => {
                    this.import_modules
                        .push(ModuleInfo::decode(entry.d_val, &this.str_table)?);
                }
                DynTag::SceExportLib => {
                    this.export_libs
                        .push(LibraryInfo::decode(entry.d_val, &this.str_table)?);
                }
                DynTag::SceImportLib => {
                    this.import_libs
                        .push(LibraryInfo::decode(entry.d_val, &this.str_table)?);
                }
                _ => {}
            }
        }

        this.entries = entries;
        Ok(this)
    }

    /// The NUL-terminated string at `offset` in the string table.
    pub fn string(&self, offset: u64) -> Result<String> {
        string_at(&self.str_table, offset)
    }

    /// The value of a tag, if it appears at all. For the tags that may repeat
    /// (`DT_NEEDED`, `DT_SCE_IMPORT_LIB`, ...) this returns the first.
    pub fn tag(&self, tag: DynTag) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| DynTag::from(e.d_tag) == tag)
            .map(|e| e.d_val)
    }

    /// Symbols this module imports: linkable symbols with no address of their
    /// own.
    pub fn imports(&self) -> Vec<DynSymbol> {
        self.linkable_symbols(false)
    }

    /// Symbols this module exports: linkable symbols that carry an address.
    pub fn exports(&self) -> Vec<DynSymbol> {
        self.linkable_symbols(true)
    }

    /// Decodes one symbol's `NID#library#module` name, resolving the encoded
    /// library and module ids to their names. Returns `None` for names that
    /// aren't in that form — ordinary local names, debug entries.
    pub fn decode_symbol(&self, sym: &Symbol) -> Option<DynSymbol> {
        let name = self.string(sym.st_name as u64).ok()?;
        let (nid, lib_id, mod_id) = split_encoded_name(&name)?;
        Some(DynSymbol {
            module: self.module_name(mod_id),
            library: self.library_name(lib_id),
            nid: nid.to_owned(),
            kind: sym.kind(),
        })
    }

    /// Per shadPS4's `Module::LoadSymbols`: only `STB_GLOBAL`/`STB_WEAK`
    /// functions and objects take part in linking, and a symbol is an export
    /// exactly when `st_value` is non-zero. Symbols whose name isn't in the
    /// `NID#library#module` form are skipped the same way the reference
    /// implementation skips them.
    fn linkable_symbols(&self, exports: bool) -> Vec<DynSymbol> {
        self.symbols
            .iter()
            .filter_map(|sym| {
                let bind = sym.bind();
                if bind != STB_GLOBAL && bind != STB_WEAK {
                    return None;
                }
                let kind = sym.kind();
                if kind != STT_FUNC && kind != STT_OBJECT {
                    return None;
                }
                if exports != (sym.st_value != 0) {
                    return None;
                }
                self.decode_symbol(sym)
            })
            .collect()
    }

    /// Resolves an encoded module id to its name, searching imports before
    /// exports as shadPS4's `FindModule` does. Falls back to the encoded id
    /// itself when no `DT_SCE_*_MODULE*` entry claims it.
    pub fn module_name(&self, enc_id: &str) -> String {
        self.import_modules
            .iter()
            .chain(&self.export_modules)
            .find(|m| m.enc_id == enc_id)
            .map(|m| m.name.clone())
            .unwrap_or_else(|| enc_id.to_owned())
    }

    /// Resolves an encoded library id to its name, searching imports before
    /// exports as shadPS4's `FindLibrary` does. Falls back to the encoded id
    /// itself when no `DT_SCE_*_LIB` entry claims it.
    pub fn library_name(&self, enc_id: &str) -> String {
        self.import_libs
            .iter()
            .chain(&self.export_libs)
            .find(|l| l.enc_id == enc_id)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| enc_id.to_owned())
    }
}

/// Splits a `NID#library#module` symbol name. Anything that isn't exactly
/// three `#`-separated fields is not a NID-encoded symbol.
fn split_encoded_name(name: &str) -> Option<(&str, &str, &str)> {
    let mut parts = name.split('#');
    let nid = parts.next()?;
    let library = parts.next()?;
    let module = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((nid, library, module))
}

fn read_entries(dynamic: &[u8]) -> Result<Vec<DynEntry>> {
    const ENTRY_SIZE: usize = 16;
    let mut cursor = Cursor::new(dynamic);
    let mut entries = Vec::with_capacity(dynamic.len() / ENTRY_SIZE);
    while (cursor.position() as usize) + ENTRY_SIZE <= dynamic.len() {
        let entry = DynEntry::read(&mut cursor)?;
        if DynTag::from(entry.d_tag) == DynTag::Null {
            break;
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn read_relocations(
    dynlibdata: &[u8],
    what: &'static str,
    offset: u64,
    size: u64,
    stride: u64,
) -> Result<Vec<Relocation>> {
    if stride < RELOCATION_SIZE {
        return Err(Error::BadEntrySize {
            what: "DT_SCE_RELAENT",
            size: stride,
            minimum: RELOCATION_SIZE,
        });
    }
    let bytes = sub_slice(dynlibdata, what, offset, size)?;
    let mut cursor = Cursor::new(bytes);
    (0..size / stride)
        .map(|i| {
            cursor.seek(SeekFrom::Start(i * stride))?;
            Ok(Relocation::read(&mut cursor)?)
        })
        .collect()
}

fn sub_slice<'a>(
    dynlibdata: &'a [u8],
    what: &'static str,
    offset: u64,
    size: u64,
) -> Result<&'a [u8]> {
    let end = offset.checked_add(size);
    let limit = dynlibdata.len() as u64;
    match end {
        Some(end) if end <= limit => Ok(&dynlibdata[offset as usize..end as usize]),
        _ => Err(Error::OutOfBounds {
            what,
            region: "PT_SCE_DYNLIBDATA",
            offset,
            size,
            limit,
        }),
    }
}

fn string_at(str_table: &[u8], offset: u64) -> Result<String> {
    let start = usize::try_from(offset)
        .ok()
        .filter(|&s| s <= str_table.len());
    let string = start.and_then(|start| {
        let rest = &str_table[start..];
        let end = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..end]).ok()
    });
    string.map(str::to_owned).ok_or(Error::BadString(offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ids_like_shadps4() {
        // One character below 0x40, two below 0x1000, three above.
        assert_eq!(encode_id(0), "A");
        assert_eq!(encode_id(1), "B");
        assert_eq!(encode_id(0x3f), "-");
        assert_eq!(encode_id(0x40), "BA");
        assert_eq!(encode_id(0xfff), "--");
        assert_eq!(encode_id(0x1000), "BAA");
        assert_eq!(encode_id(u16::MAX), "P--");
    }

    #[test]
    fn splits_only_three_field_names() {
        assert_eq!(
            split_encoded_name("4J2sUJmuHZQ#f#f"),
            Some(("4J2sUJmuHZQ", "f", "f"))
        );
        assert_eq!(split_encoded_name("module_start"), None);
        assert_eq!(split_encoded_name("a#b"), None);
        assert_eq!(split_encoded_name("a#b#c#d"), None);
    }

    #[test]
    fn string_table_lookups_are_bounds_checked() {
        let table = b"\0libkernel\0";
        assert_eq!(string_at(table, 1).unwrap(), "libkernel");
        assert_eq!(string_at(table, 0).unwrap(), "");
        // Past the end, and a run with no terminator.
        assert!(string_at(table, 99).is_err());
        assert!(string_at(b"nul-free", 0).is_err());
    }
}
