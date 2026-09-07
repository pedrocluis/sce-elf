//! End-to-end check of the dynamic segment reader against a synthetic image,
//! built both as a raw ELF and as a SELF whose program header offsets have to
//! be remapped through the SELF segment table.

use sce_elf::dynamic::{STB_GLOBAL, STT_FUNC};
use sce_elf::{DynSymbol, Error, Image, ProgramType};

const PT_DYNAMIC: u32 = 2;
const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;

const DT_NULL: i64 = 0;
const DT_SCE_MODULE_INFO: i64 = 0x6100_000d;
const DT_SCE_NEEDED_MODULE: i64 = 0x6100_000f;
const DT_SCE_EXPORT_LIB: i64 = 0x6100_0013;
const DT_SCE_IMPORT_LIB: i64 = 0x6100_0015;
const DT_SCE_STRTAB: i64 = 0x6100_0035;
const DT_SCE_STRSZ: i64 = 0x6100_0037;
const DT_SCE_SYMTAB: i64 = 0x6100_0039;
const DT_SCE_SYMENT: i64 = 0x6100_003b;
const DT_SCE_SYMTABSZ: i64 = 0x6100_003f;

const IMPORT_NID: &str = "AbCdEfGhIjK";
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

    let mut dynlibdata = strtab.0;
    dynlibdata.resize(dynlibdata.len().next_multiple_of(8), 0);
    let symtab_offset = dynlibdata.len() as u64;
    let symtab_size = symtab.len() as u64;
    dynlibdata.extend_from_slice(&symtab);

    let mut dynamic = Vec::new();
    dyn_entry(&mut dynamic, DT_SCE_SYMTAB, symtab_offset);
    dyn_entry(&mut dynamic, DT_SCE_SYMTABSZ, symtab_size);
    dyn_entry(&mut dynamic, DT_SCE_SYMENT, 24);
    dyn_entry(
        &mut dynamic,
        DT_SCE_MODULE_INFO,
        module_value(this_module, 1, 2, 1),
    );
    dyn_entry(
        &mut dynamic,
        DT_SCE_NEEDED_MODULE,
        module_value(libkernel, 0, 0, 0),
    );
    dyn_entry(
        &mut dynamic,
        DT_SCE_EXPORT_LIB,
        library_value(this_lib, 1, 1),
    );
    dyn_entry(
        &mut dynamic,
        DT_SCE_IMPORT_LIB,
        library_value(libkernel, 1, 0),
    );
    // Deliberately last, to prove the reader doesn't depend on seeing the
    // string table before the tags that index into it.
    dyn_entry(&mut dynamic, DT_SCE_STRTAB, 0);
    dyn_entry(&mut dynamic, DT_SCE_STRSZ, symtab_offset);
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
    let mut ph = Vec::new();
    ph.extend_from_slice(&p_type.to_le_bytes());
    ph.extend_from_slice(&4u32.to_le_bytes()); // p_flags = PF_R
    ph.extend_from_slice(&p_offset.to_le_bytes());
    ph.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
    ph.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
    ph.extend_from_slice(&p_filesz.to_le_bytes());
    ph.extend_from_slice(&p_filesz.to_le_bytes()); // p_memsz
    ph.extend_from_slice(&8u64.to_le_bytes()); // p_align
    ph
}

fn raw_elf() -> Vec<u8> {
    let (dynamic, dynlibdata) = segments();
    let dynamic_at = 256u64;
    let dynlibdata_at = 1024u64;

    let mut file = elf_header(64, 2);
    file.extend(program_header(PT_DYNAMIC, dynamic_at, dynamic.len() as u64));
    file.extend(program_header(
        PT_SCE_DYNLIBDATA,
        dynlibdata_at,
        dynlibdata.len() as u64,
    ));
    file.resize(dynamic_at as usize, 0);
    file.extend_from_slice(&dynamic);
    file.resize(dynlibdata_at as usize, 0);
    file.extend_from_slice(&dynlibdata);
    file
}

/// The same image wrapped in a SELF, with the program headers pointing at
/// offsets that only the SELF segment table can resolve.
fn self_file(encrypt_dynlibdata: bool) -> Vec<u8> {
    let (dynamic, dynlibdata) = segments();
    const HEADER_SIZE: u64 = 32 + 32 * 2; // SELF header + two segment headers
    let dynamic_at = 512u64;
    let dynlibdata_at = 1024u64;

    let mut file = Vec::new();
    file.extend_from_slice(&0x1D3D_154Fu32.to_le_bytes());
    file.extend_from_slice(&[0, 1, 1, 0x12, 1, 1]); // version, mode, endian, ...
    file.extend_from_slice(&0u16.to_le_bytes()); // padding1
    file.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    file.extend_from_slice(&0u16.to_le_bytes()); // meta_size
    file.extend_from_slice(&0u32.to_le_bytes()); // file_size
    file.extend_from_slice(&0u32.to_le_bytes()); // padding2
    file.extend_from_slice(&2u16.to_le_bytes()); // segment_count
    file.extend_from_slice(&0u16.to_le_bytes()); // unknown1a
    file.extend_from_slice(&0u32.to_le_bytes()); // padding3

    // "Blocked", with the program header index in bits 20..32.
    let mut segment_header = |id: u64, extra_flags: u64, offset: u64, size: u64| {
        file.extend_from_slice(&(0x800 | (id << 20) | extra_flags).to_le_bytes());
        file.extend_from_slice(&offset.to_le_bytes());
        file.extend_from_slice(&size.to_le_bytes());
        file.extend_from_slice(&size.to_le_bytes());
    };
    segment_header(0, 0, dynamic_at, dynamic.len() as u64);
    segment_header(
        1,
        if encrypt_dynlibdata { 2 } else { 0 },
        dynlibdata_at,
        dynlibdata.len() as u64,
    );

    assert_eq!(file.len() as u64, HEADER_SIZE);
    file.extend(elf_header(64, 2));
    // Offsets a naive reader would follow straight off the end of the file.
    file.extend(program_header(PT_DYNAMIC, 0x10_0000, dynamic.len() as u64));
    file.extend(program_header(
        PT_SCE_DYNLIBDATA,
        0x20_0000,
        dynlibdata.len() as u64,
    ));
    file.resize(dynamic_at as usize, 0);
    file.extend_from_slice(&dynamic);
    file.resize(dynlibdata_at as usize, 0);
    file.extend_from_slice(&dynlibdata);
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
    assert_eq!(dynamic.entries.len(), 9);
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

    // The program headers point far past the end of the file on their own.
    let dynlibdata = image
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_SCE_DYNLIBDATA)
        .unwrap();
    assert!(dynlibdata.p_offset > image.data().len() as u64);

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
                index: 1,
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
