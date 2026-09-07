use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sce_elf::dynamic::STT_FUNC;
use sce_elf::{DynSymbol, Dynamic, Image, ProgramType, nid};

/// Inspect PS4/PS5 SELF/ELF binaries.
#[derive(Parser)]
#[command(name = "nidscan", version)]
struct Args {
    /// Path to an eboot.bin, .self, .sprx, or raw .elf file.
    file: Option<PathBuf>,

    /// Hash a symbol name into its NID instead of scanning a file.
    #[arg(long)]
    name: Option<String>,

    /// List every imported symbol, not just the count.
    #[arg(long)]
    imports: bool,

    /// List every exported symbol, not just the count.
    #[arg(long)]
    exports: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(name) = args.name {
        println!("{name} => {}", nid::hash(&name));
        return Ok(());
    }

    let path = args
        .file
        .context("expected a file path, or --name <symbol> to hash a NID")?;
    let data = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let image = Image::parse(data).with_context(|| format!("parsing {}", path.display()))?;

    println!("file:      {}", path.display());
    println!(
        "container: {}",
        if image.is_self() { "SELF" } else { "raw ELF" }
    );
    println!("elf type:  {:?}", image.elf_type());
    println!("entry:     0x{:x}", image.elf_header.e_entry);
    println!("phnum:     {}", image.elf_header.e_phnum);
    println!();
    println!("program headers:");
    for (i, ph) in image.program_headers.iter().enumerate() {
        let ty: ProgramType = ph.p_type.into();
        println!(
            "  [{i:2}] {:<16} off=0x{:<10x} vaddr=0x{:<10x} filesz=0x{:<8x} memsz=0x{:<8x}",
            format!("{ty:?}"),
            ph.p_offset,
            ph.p_vaddr,
            ph.p_filesz,
            ph.p_memsz
        );
    }
    println!();

    match image.dynamic() {
        Ok(dynamic) => print_dynamic(&dynamic, args.imports, args.exports),
        // Not every image has a dynamic segment, and a signed SELF's segments
        // can't be read yet — neither is a reason to fail the whole scan.
        Err(err) => println!("dynamic segment: unavailable ({err})"),
    }

    Ok(())
}

fn print_dynamic(dynamic: &Dynamic, list_imports: bool, list_exports: bool) {
    println!("dynamic segment:");
    for module in &dynamic.export_modules {
        println!(
            "  module:   {} (id {}, v{}.{}, {})",
            module.name, module.id, module.version_major, module.version_minor, module.enc_id
        );
    }
    if let Some(filename) = &dynamic.original_filename {
        println!("  filename: {filename}");
    }
    println!(
        "  {} dyn entries, {} symbols, {}-byte string table",
        dynamic.entries.len(),
        dynamic.symbols.len(),
        dynamic.str_table.len()
    );

    for module in &dynamic.import_modules {
        println!(
            "  needs module:  {:<28} id {:<5} v{}.{} ({})",
            module.name, module.id, module.version_major, module.version_minor, module.enc_id
        );
    }
    for name in &dynamic.needed {
        println!("  needs:         {name}");
    }
    for lib in &dynamic.export_libs {
        println!(
            "  exports lib:   {:<28} id {:<5} v{} ({})",
            lib.name, lib.id, lib.version, lib.enc_id
        );
    }
    for lib in &dynamic.import_libs {
        println!(
            "  imports lib:   {:<28} id {:<5} v{} ({})",
            lib.name, lib.id, lib.version, lib.enc_id
        );
    }

    let imports = dynamic.imports();
    let exports = dynamic.exports();
    println!();
    println!("{} imports, {} exports", imports.len(), exports.len());
    if list_imports {
        print_symbols("imports", &imports);
    }
    if list_exports {
        print_symbols("exports", &exports);
    }
}

fn print_symbols(heading: &str, symbols: &[DynSymbol]) {
    println!();
    println!("{heading}:");
    for sym in symbols {
        println!(
            "  {} {:<11}  {}::{}",
            if sym.kind == STT_FUNC { "fn " } else { "obj" },
            sym.nid,
            sym.module,
            sym.library
        );
    }
}
