use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sce_elf::{nid, Image, ProgramType};

/// Inspect PS4/PS5 SELF/ELF binaries.
#[derive(Parser)]
#[command(name = "nidscan", version)]
struct Args {
    /// Path to an eboot.bin, .self, .sprx, or raw .elf file.
    file: Option<PathBuf>,

    /// Hash a symbol name into its NID instead of scanning a file.
    #[arg(long)]
    name: Option<String>,
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

    Ok(())
}
