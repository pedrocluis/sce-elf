//! End-to-end check of the dynamic segment reader against a synthetic image,
//! built both as a raw ELF and as a SELF whose program header offsets have to
//! be remapped through the SELF segment table.

use sce_elf::dynamic::{
    R_X86_64_DTPMOD64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE, STB_GLOBAL,
    STT_FUNC,
};
use sce_elf::{DynSymbol, Error, Image, ImplementedNids, ProgramType};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;

const DT_NULL: i64 = 0;
const DT_SCE_MODULE_INFO: i64 = 0x6100_000d;
const DT_SCE_NEEDED_MODULE: i64 = 0x6100_000f;
const DT_SCE_EXPORT_LIB: i64 = 0x6100_0013;
const DT_SCE_IMPORT_LIB: i64 = 0x6100_0015;
const DT_SCE_JMPREL: i64 = 0x6100_0029;
const DT_SCE_PLTRELSZ: i64 = 0x6100_002d;
const DT_SCE_RELA: i64 = 0x6100_002f;
const DT_SCE_RELASZ: i64 = 0x6100_0031;
const DT_SCE_RELAENT: i64 = 0x6100_0033;
const DT_SCE_STRTAB: i64 = 0x6100_0035;
const DT_SCE_STRSZ: i64 = 0x6100_0037;
const DT_SCE_SYMTAB: i64 = 0x6100_0039;
const DT_SCE_SYMENT: i64 = 0x6100_003b;
const DT_SCE_SYMTABSZ: i64 = 0x6100_003f;

const IMPORT_NID: &str = "AbCdEfGhIjK";
/// Addend on the `R_X86_64_RELATIVE` entry in the fixture.
const RELATIVE_ADDEND: i64 = 0x1234;
/// `p_vaddr`/size of the fixture's `PT_LOAD`, which the relocations target.
const LOAD_SIZE: u64 = 0x40;
const EXPORT_NID: &str = "ZyXwVuTsRqP";

#[derive(Default)]
struct StrTab(Vec<u8>);

impl StrTab {
    fn new() -> Self {
        Self(vec![0])
    }

    fn add(&mut self, s: &str) -> u32 {
        let offset = self.0.len() as u32;
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        offset
    }
}

fn dyn_entry(out: &mut Vec<u8>, tag: i64, value: u64) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
}

fn symbol(out: &mut Vec<u8>, st_name: u32, st_info: u8, st_value: u64) {
    out.extend_from_slice(&st_name.to_le_bytes());
    out.push(st_info);
    out.push(0); // st_other
    out.extend_from_slice(&0u16.to_le_bytes()); // st_shndx
    out.extend_from_slice(&st_value.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // st_size
}

fn relocation(out: &mut Vec<u8>, r_offset: u64, kind: u32, symbol: u32, addend: i64) {
    out.extend_from_slice(&r_offset.to_le_bytes());
    out.extend_from_slice(&(((symbol as u64) << 32) | kind as u64).to_le_bytes());
    out.extend_from_slice(&addend.to_le_bytes());
}

/// `name_offset: u32`, `version_minor: u8`, `version_major: u8`, `id: u16`.
fn module_value(name_offset: u32, major: u8, minor: u8, id: u16) -> u64 {
    name_offset as u64 | (minor as u64) << 32 | (major as u64) << 40 | (id as u64) << 48
}

/// `name_offset: u32`, `version: u16`, `id: u16`.
fn library_value(name_offset: u32, version: u16, id: u16) -> u64 {
    name_offset as u64 | (version as u64) << 32 | (id as u64) << 48
}

/// The two segments the reader needs: `PT_DYNAMIC` and `PT_SCE_DYNLIBDATA`.
///
/// The image exports `EXPORT_NID` from `myModule`'s `myLib` (id 1, so the
/// encoded id is `B`) and imports `IMPORT_NID` from `libkernel` (id 0, `A`).
fn segments() -> (Vec<u8>, Vec<u8>) {
    segments_with(0, false)
}

/// `table_base` is added to every table address written into the dynamic
/// array — 0 for the PS4 layout, where they are offsets into
/// `PT_SCE_DYNLIBDATA`, or the tables' virtual address for the PS5 layout.
/// `ps5` selects the standard ELF tag spellings and PS5's module/library
/// tag constants.
fn segments_with(table_base: u64, ps5: bool) -> (Vec<u8>, Vec<u8>) {
    let mut strtab = StrTab::new();
    let this_module = strtab.add("myModule");
    let this_lib = strtab.add("myLib");
    let libkernel = strtab.add("libkernel");
    let import_name = strtab.add(&format!("{IMPORT_NID}#A#A"));
    let export_name = strtab.add(&format!("{EXPORT_NID}#B#B"));
    // A plain, non-NID-encoded name: must be skipped, not mis-split.
    let plain_name = strtab.add("module_start");

    let global_func = (STB_GLOBAL << 4) | STT_FUNC;
    let mut symtab = Vec::new();
    symbol(&mut symtab, import_name, global_func, 0); // no address => import
    symbol(&mut symtab, export_name, global_func, 0x1000);
    symbol(&mut symtab, plain_name, global_func, 0x2000);
    // A local symbol, which takes no part in linking either way.
    symbol(&mut symtab, import_name, STT_FUNC, 0);

    // Symbol 0 is the import, symbol 1 the export defined in this image.
    let mut rela = Vec::new();
    relocation(&mut rela, 0x00, R_X86_64_RELATIVE, 0, RELATIVE_ADDEND);
    relocation(&mut rela, 0x10, R_X86_64_GLOB_DAT, 1, 0);
    relocation(&mut rela, 0x18, R_X86_64_DTPMOD64, 0, 0);
    let mut jmprel = Vec::new();
    relocation(&mut jmprel, 0x08, R_X86_64_JUMP_SLOT, 0, 0);

    let mut dynlibdata = strtab.0;
    dynlibdata.resize(dynlibdata.len().next_multiple_of(8), 0);
    let symtab_offset = dynlibdata.len() as u64;
    let symtab_size = symtab.len() as u64;
    dynlibdata.extend_from_slice(&symtab);
    let rela_offset = dynlibdata.len() as u64;
    let rela_size = rela.len() as u64;
    dynlibdata.extend_from_slice(&rela);
    let jmprel_offset = dynlibdata.len() as u64;
    let jmprel_size = jmprel.len() as u64;
    dynlibdata.extend_from_slice(&jmprel);

    // PS5 spells the table tags the standard ELF way and gives the module
    // and library entries their own constants; the packing is identical.
    let (t_symtab, t_syment, t_rela, t_relasz, t_relaent, t_jmprel, t_pltrelsz) = if ps5 {
        (0x6, 0xb, 0x7, 0x8, 0x9, 0x17, 0x2)
    } else {
        (
            DT_SCE_SYMTAB,
            DT_SCE_SYMENT,
            DT_SCE_RELA,
            DT_SCE_RELASZ,
            DT_SCE_RELAENT,
            DT_SCE_JMPREL,
            DT_SCE_PLTRELSZ,
        )
    };
    let (t_strtab, t_strsz) = if ps5 {
        (0x5, 0xa)
    } else {
        (DT_SCE_STRTAB, DT_SCE_STRSZ)
    };
    let (t_module_info, t_needed_module, t_export_lib, t_import_lib) = if ps5 {
        (0x6100_0043, 0x6100_0045, 0x6100_0047, 0x6100_0049)
    } else {
        (
            DT_SCE_MODULE_INFO,
            DT_SCE_NEEDED_MODULE,
            DT_SCE_EXPORT_LIB,
            DT_SCE_IMPORT_LIB,
        )
    };

    let mut dynamic = Vec::new();
    dyn_entry(&mut dynamic, t_symtab, table_base + symtab_offset);
    // PS5 keeps DT_SCE_SYMTABSZ: standard ELF has no symbol-table-size tag.
    dyn_entry(&mut dynamic, DT_SCE_SYMTABSZ, symtab_size);
    dyn_entry(&mut dynamic, t_syment, 24);
    dyn_entry(&mut dynamic, t_rela, table_base + rela_offset);
    dyn_entry(&mut dynamic, t_relasz, rela_size);
    dyn_entry(&mut dynamic, t_relaent, 24);
    dyn_entry(&mut dynamic, t_jmprel, table_base + jmprel_offset);
    dyn_entry(&mut dynamic, t_pltrelsz, jmprel_size);
    dyn_entry(
        &mut dynamic,
        t_module_info,
        module_value(this_module, 1, 2, 1),
    );
    dyn_entry(
        &mut dynamic,
        t_needed_module,
        module_value(libkernel, 0, 0, 0),
    );
    dyn_entry(&mut dynamic, t_export_lib, library_value(this_lib, 1, 1));
    dyn_entry(&mut dynamic, t_import_lib, library_value(libkernel, 1, 0));
    // Deliberately last, to prove the reader doesn't depend on seeing the
    // string table before the tags that index into it.
    dyn_entry(&mut dynamic, t_strtab, table_base);
    dyn_entry(&mut dynamic, t_strsz, symtab_offset);
    dyn_entry(&mut dynamic, DT_NULL, 0);
    // Trailing junk after DT_NULL, which a real image has as padding.
    dyn_entry(&mut dynamic, DT_SCE_STRSZ, 0xdead_beef);

    (dynamic, dynlibdata)
}

fn elf_header(phoff: u64, phnum: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\x7FELF");
    h.extend_from_slice(&[2, 1, 1, 0, 0]); // ELF64, little endian, v1, SysV
    h.extend_from_slice(&[0u8; 7]); // e_ident padding
    h.extend_from_slice(&0xfe10u16.to_le_bytes()); // ET_SCE_DYNEXEC
    h.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    h.extend_from_slice(&1u32.to_le_bytes()); // e_version
    h.extend_from_slice(&0x1000u64.to_le_bytes()); // e_entry
    h.extend_from_slice(&phoff.to_le_bytes());
    h.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    h.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    h.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    h.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    h.extend_from_slice(&phnum.to_le_bytes());
    h.extend_from_slice(&[0u8; 6]); // e_shentsize, e_shnum, e_shstrndx
    h
}

fn program_header(p_type: u32, p_offset: u64, p_filesz: u64) -> Vec<u8> {
    program_header_at(p_type, p_offset, p_filesz, 0)
}

fn program_header_at(p_type: u32, p_offset: u64, p_filesz: u64, p_vaddr: u64) -> Vec<u8> {
    let mut ph = Vec::new();
    ph.extend_from_slice(&p_type.to_le_bytes());
    ph.extend_from_slice(&4u32.to_le_bytes()); // p_flags = PF_R
    ph.extend_from_slice(&p_offset.to_le_bytes());
    ph.extend_from_slice(&p_vaddr.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
    ph.extend_from_slice(&p_filesz.to_le_bytes());
    ph.extend_from_slice(&p_filesz.to_le_bytes()); // p_memsz
    ph.extend_from_slice(&8u64.to_le_bytes()); // p_align
    ph
}

fn raw_elf() -> Vec<u8> {
    let (dynamic, dynlibdata) = segments();
    let load_at = 256u64;
    let dynamic_at = 512u64;
    let dynlibdata_at = 1024u64;

    let mut file = elf_header(64, 3);
    file.extend(program_header_at(PT_LOAD, load_at, LOAD_SIZE, 0));
    file.extend(program_header(PT_DYNAMIC, dynamic_at, dynamic.len() as u64));
    file.extend(program_header(
        PT_SCE_DYNLIBDATA,
        dynlibdata_at,
        dynlibdata.len() as u64,
    ));
    file.resize((load_at + LOAD_SIZE) as usize, 0);
    file.resize(dynamic_at as usize, 0);
    file.extend_from_slice(&dynamic);
    file.resize(dynlibdata_at as usize, 0);
    file.extend_from_slice(&dynlibdata);
    file
}

/// The same image wrapped in a SELF, shaped like a real one: a single
/// blocked segment carries a `PT_LOAD` payload, and `PT_DYNAMIC` and
/// `PT_SCE_DYNLIBDATA` merely live *inside* that load segment rather than
/// having SELF segments of their own. The program headers advertise virtual
/// offsets nothing but the SELF segment table can resolve, and `header_size`
/// is deliberately not the ELF header's offset — both mistakes a reader can
/// silently make.
fn self_file(encrypt: bool) -> Vec<u8> {
    let (dynamic, dynlibdata) = segments();
    const HEADER_SIZE: u64 = 32 + 32; // SELF header + one segment header
    /// What `header_size` really measures: the whole header block, well past
    /// the ELF header. Using it as the ELF offset must fail.
    const HEADER_BLOCK_SIZE: u16 = 0x400;

    // The bytes the one blocked SELF segment actually carries.
    let mut payload = dynamic.clone();
    payload.resize(payload.len().next_multiple_of(16), 0);
    let dynlibdata_in_payload = payload.len() as u64;
    payload.extend_from_slice(&dynlibdata);

    // The virtual offsets the program headers advertise.
    let load_voff = 0x10_0000u64;
    let payload_at = 512u64;

    let mut file = Vec::new();
    file.extend_from_slice(&0x1D3D_154Fu32.to_le_bytes());
    file.extend_from_slice(&[0, 1, 1, 0x12, 1, 1]); // version, mode, endian, ...
    file.extend_from_slice(&0u16.to_le_bytes()); // padding1
    file.extend_from_slice(&HEADER_BLOCK_SIZE.to_le_bytes());
    file.extend_from_slice(&0u16.to_le_bytes()); // meta_size
    file.extend_from_slice(&0u32.to_le_bytes()); // file_size
    file.extend_from_slice(&0u32.to_le_bytes()); // padding2
    file.extend_from_slice(&1u16.to_le_bytes()); // segment_count
    file.extend_from_slice(&0u16.to_le_bytes()); // unknown1a
    file.extend_from_slice(&0u32.to_le_bytes()); // padding3

    // Blocked, carrying program header 0 (the PT_LOAD), id in bits 20..32.
    let flags = 0x800u64 | if encrypt { 2 } else { 0 };
    file.extend_from_slice(&flags.to_le_bytes());
    file.extend_from_slice(&payload_at.to_le_bytes());
    file.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    file.extend_from_slice(&(payload.len() as u64).to_le_bytes());

    assert_eq!(file.len() as u64, HEADER_SIZE);
    file.extend(elf_header(64, 3));
    file.extend(program_header(PT_LOAD, load_voff, payload.len() as u64));
    file.extend(program_header(PT_DYNAMIC, load_voff, dynamic.len() as u64));
    file.extend(program_header(
        PT_SCE_DYNLIBDATA,
        load_voff + dynlibdata_in_payload,
        dynlibdata.len() as u64,
    ));
    file.resize(payload_at as usize, 0);
    file.extend_from_slice(&payload);
    file
}

fn expected_import() -> DynSymbol {
    DynSymbol {
        module: "libkernel".into(),
        library: "libkernel".into(),
        nid: IMPORT_NID.into(),
        kind: STT_FUNC,
    }
}

fn expected_export() -> DynSymbol {
    DynSymbol {
        module: "myModule".into(),
        library: "myLib".into(),
        nid: EXPORT_NID.into(),
        kind: STT_FUNC,
    }
}

#[test]
fn reads_the_dynamic_segment_of_a_raw_elf() {
    let image = Image::parse(raw_elf()).unwrap();
    assert!(!image.is_self());

    let dynamic = image.dynamic().unwrap();
    assert_eq!(dynamic.entries.len(), 14);
    assert_eq!(dynamic.symbols.len(), 4);

    let this = &dynamic.export_modules[0];
    assert_eq!(this.name, "myModule");
    assert_eq!((this.id, this.version_major, this.version_minor), (1, 1, 2));
    assert_eq!(this.enc_id, "B");

    let needed = &dynamic.import_modules[0];
    assert_eq!(needed.name, "libkernel");
    assert_eq!(needed.enc_id, "A");

    assert_eq!(dynamic.import_libs[0].name, "libkernel");
    assert_eq!(dynamic.export_libs[0].name, "myLib");
    assert_eq!(dynamic.string(1).unwrap(), "myModule");

    assert_eq!(image.imports().unwrap(), vec![expected_import()]);
    assert_eq!(image.exports().unwrap(), vec![expected_export()]);
}

#[test]
fn resolves_program_header_offsets_through_the_self_segment_table() {
    let image = Image::parse(self_file(false)).unwrap();
    assert!(image.is_self());

    // The ELF header follows the segment table, and `header_size` is
    // something else entirely.
    assert_eq!(image.elf_offset, 32 + 32);
    assert_ne!(
        image.self_header.unwrap().header_size as u64,
        image.elf_offset,
        "header_size must not be usable as the ELF offset by accident"
    );

    // The program headers point far past the end of the file on their own,
    // and PT_SCE_DYNLIBDATA has no SELF segment of its own — it is nested
    // inside the PT_LOAD that does.
    let dynlibdata = image
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_SCE_DYNLIBDATA)
        .unwrap();
    assert!(dynlibdata.p_offset > image.data().len() as u64);
    assert_eq!(image.self_segments.len(), 1);

    assert_eq!(image.imports().unwrap(), vec![expected_import()]);
    assert_eq!(image.exports().unwrap(), vec![expected_export()]);
}

#[test]
fn reports_segments_it_cannot_decode_yet() {
    let image = Image::parse(self_file(true)).unwrap();
    let err = image.dynamic().unwrap_err();
    assert!(
        matches!(
            err,
            Error::OpaqueSegment {
                index: 0,
                reason: "encrypted"
            }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn errors_rather_than_panicking_on_a_truncated_image() {
    let mut file = raw_elf();
    file.truncate(700); // keeps PT_DYNAMIC, cuts PT_SCE_DYNLIBDATA off
    let image = Image::parse(file).unwrap();
    assert!(matches!(
        image.dynamic().unwrap_err(),
        Error::OutOfBounds { .. }
    ));
}

#[test]
fn errors_on_an_image_without_a_dynamic_segment() {
    let mut file = elf_header(64, 1);
    file.extend(program_header(1, 128, 0)); // PT_LOAD only
    file.resize(256, 0);
    let image = Image::parse(file).unwrap();
    assert!(image.segment_index(ProgramType::Dynamic).is_none());
    assert!(matches!(
        image.dynamic().unwrap_err(),
        Error::MissingSegment("PT_DYNAMIC")
    ));
}

const LOAD_BASE: u64 = 0x40_0000;

#[test]
fn applies_relocations_against_a_load_base() {
    let image = Image::parse(raw_elf()).unwrap();
    let dynamic = image.dynamic().unwrap();
    assert_eq!(dynamic.relocations.len(), 3);
    assert_eq!(dynamic.plt_relocations.len(), 1);

    let mut loaded = image.load(LOAD_BASE).unwrap();
    assert_eq!(loaded.data.len(), LOAD_SIZE as usize);

    // Nothing supplies external addresses, so the one genuine import is left
    // for a linker to fill in.
    let report = loaded.relocate(&dynamic, |_| None).unwrap();
    assert_eq!(report.applied, 2);
    assert_eq!(report.skipped_total(), 1);
    assert_eq!(report.skipped.get(&R_X86_64_DTPMOD64), Some(&1));

    assert_eq!(report.unresolved.len(), 1);
    let unresolved = &report.unresolved[0];
    assert_eq!(unresolved.symbol.as_ref().unwrap().nid, IMPORT_NID);
    assert_eq!(unresolved.name, format!("{IMPORT_NID}#A#A"));

    // R_X86_64_RELATIVE: base + addend, no symbol involved.
    assert_eq!(
        loaded.read_u64(0x00).unwrap(),
        LOAD_BASE + RELATIVE_ADDEND as u64
    );
    // R_X86_64_GLOB_DAT against a symbol this image defines: base + st_value.
    assert_eq!(loaded.read_u64(0x10).unwrap(), LOAD_BASE + 0x1000);
    // The unresolved JUMP_SLOT slot is left exactly as it was.
    assert_eq!(loaded.read_u64(0x08).unwrap(), 0);
}

#[test]
fn imports_go_through_the_supplied_resolver() {
    let image = Image::parse(raw_elf()).unwrap();
    let dynamic = image.dynamic().unwrap();
    let mut loaded = image.load(LOAD_BASE).unwrap();

    let mut asked = Vec::new();
    let report = loaded
        .relocate(&dynamic, |sym| {
            asked.push(sym.clone());
            Some(0xdead_0000)
        })
        .unwrap();

    // Only the import is asked about; the locally defined symbol is not.
    assert_eq!(asked, vec![expected_import()]);
    assert_eq!(report.applied, 3);
    assert!(report.unresolved.is_empty());
    assert_eq!(loaded.read_u64(0x08).unwrap(), 0xdead_0000);
}

#[test]
fn relocation_targets_are_bounds_checked() {
    let image = Image::parse(raw_elf()).unwrap();
    let dynamic = image.dynamic().unwrap();
    // An image laid out with no room for the relocation targets must error
    // rather than write out of bounds.
    let mut empty = image.load(LOAD_BASE).unwrap();
    empty.data.truncate(4);
    assert!(matches!(
        empty.relocate(&dynamic, |_| None).unwrap_err(),
        Error::OutOfBounds { .. }
    ));
}

#[test]
fn compat_report_counts_unimplemented_imports() {
    let image = Image::parse(raw_elf()).unwrap();

    let nothing = ImplementedNids::new();
    let report = image.compat_report(&nothing).unwrap();
    assert_eq!(report.total(), 1);
    assert_eq!(report.missing_count(), 1);
    assert_eq!(report.missing, vec![expected_import()]);
    assert_eq!(report.coverage(), 0.0);

    let everything: ImplementedNids = [IMPORT_NID].into_iter().collect();
    let report = image.compat_report(&everything).unwrap();
    assert_eq!(report.total(), 1);
    assert_eq!(report.missing_count(), 0);
    assert_eq!(report.implemented(), 1);
    assert_eq!(report.coverage(), 1.0);
}

#[test]
fn imports_a_bundled_module_supplies_are_not_gaps() {
    use sce_elf::NidSet;
    let image = Image::parse(raw_elf()).unwrap();
    let nothing = NidSet::new();

    // The emulator implements none of it, but the game ships a module that
    // exports the one import: that is not a gap the emulator has to close.
    let bundled: NidSet = [IMPORT_NID].into_iter().collect();
    let report = image.compat_report_with(&nothing, &bundled).unwrap();
    assert_eq!(report.total(), 1);
    assert_eq!(report.missing_count(), 0);
    assert_eq!(report.bundled_count(), 1);
    assert_eq!(report.implemented(), 0);
    assert_eq!(report.bundled, vec![expected_import()]);
    assert_eq!(report.coverage(), 1.0);

    // With nothing bundled it is a gap again, and coverage collapses.
    let report = image.compat_report_with(&nothing, &nothing).unwrap();
    assert_eq!(report.missing_count(), 1);
    assert_eq!(report.bundled_count(), 0);
    assert_eq!(report.coverage(), 0.0);

    // An import the emulator implements is never double-counted as bundled,
    // even when a bundled module also exports it.
    let implemented: NidSet = [IMPORT_NID].into_iter().collect();
    let report = image.compat_report_with(&implemented, &bundled).unwrap();
    assert_eq!(report.implemented(), 1);
    assert_eq!(report.bundled_count(), 0);
    assert_eq!(report.missing_count(), 0);
}

/// A PS5-shaped image: no `PT_SCE_DYNLIBDATA` at all, standard `DT_*` tags
/// holding virtual addresses, and the tables sitting inside a `PT_LOAD`.
fn ps5_elf() -> Vec<u8> {
    const TABLES_VADDR: u64 = 0x20_0000;
    let (dynamic, tables) = segments_with(TABLES_VADDR, true);
    let load_at = 256u64;
    let dynamic_at = 2048u64;

    let mut file = elf_header(64, 2);
    file.extend(program_header_at(
        PT_LOAD,
        load_at,
        tables.len() as u64,
        TABLES_VADDR,
    ));
    file.extend(program_header(PT_DYNAMIC, dynamic_at, dynamic.len() as u64));
    file.resize(load_at as usize, 0);
    file.extend_from_slice(&tables);
    file.resize(dynamic_at as usize, 0);
    file.extend_from_slice(&dynamic);
    file
}

#[test]
fn reads_the_ps5_dynamic_layout() {
    let image = Image::parse(ps5_elf()).unwrap();
    assert!(
        image.segment_index(ProgramType::SceDynlibData).is_none(),
        "the PS5 layout has no PT_SCE_DYNLIBDATA"
    );

    let dynamic = image.dynamic().unwrap();
    assert_eq!(dynamic.symbols.len(), 4);
    assert_eq!(dynamic.relocations.len(), 3);
    assert_eq!(dynamic.plt_relocations.len(), 1);
    assert_eq!(dynamic.export_modules[0].name, "myModule");
    assert_eq!(dynamic.import_modules[0].name, "libkernel");
    assert_eq!(dynamic.import_libs[0].name, "libkernel");

    // Imports decode exactly as they do on PS4 — same NID#library#module
    // names, same tables, only the addressing differs.
    assert_eq!(image.imports().unwrap(), vec![expected_import()]);

    // Exports resolve fully too, now that PS5's export-library tag is known.
    assert_eq!(image.exports().unwrap(), vec![expected_export()]);
    assert_eq!(dynamic.export_libs[0].name, "myLib");
}

#[test]
fn ps5_tag_spellings_canonicalise_onto_the_ps4_ones() {
    use sce_elf::DynTag;
    // The standard ELF spellings PS5 uses for the tables.
    assert_eq!(DynTag::from(0x5).canonical(), DynTag::SceStrTab);
    assert_eq!(DynTag::from(0x6).canonical(), DynTag::SceSymTab);
    assert_eq!(DynTag::from(0x7).canonical(), DynTag::SceRela);
    assert_eq!(DynTag::from(0x17).canonical(), DynTag::SceJmpRel);
    // PS5's own module and library constants.
    assert_eq!(
        DynTag::from(0x6100_0041).canonical(),
        DynTag::SceOriginalFilename
    );
    assert_eq!(DynTag::from(0x6100_0043).canonical(), DynTag::SceModuleInfo);
    assert_eq!(
        DynTag::from(0x6100_0045).canonical(),
        DynTag::SceNeededModule
    );
    assert_eq!(DynTag::from(0x6100_0047).canonical(), DynTag::SceExportLib);
    assert_eq!(DynTag::from(0x6100_0049).canonical(), DynTag::SceImportLib);
    // The PS4 spellings are already canonical.
    assert_eq!(DynTag::from(0x6100_0035).canonical(), DynTag::SceStrTab);
    assert_eq!(DynTag::from(0x6100_0015).canonical(), DynTag::SceImportLib);
}
