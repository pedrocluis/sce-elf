use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use sce_elf::compat::ImplementedNids;
use sce_elf::dynamic::STT_FUNC;
use sce_elf::nid::NameTable;
use sce_elf::{DynSymbol, Dynamic, Image, NidSet, ProgramType, nid};

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

    /// Extra symbol-name wordlist to resolve NIDs with. Repeatable.
    #[arg(long, value_name = "FILE")]
    names: Vec<PathBuf>,

    /// A list of NIDs an emulator implements (JSON or plain text). Prints a
    /// compatibility report against this binary's imports.
    #[arg(long, value_name = "FILE")]
    implemented: Option<PathBuf>,

    /// Modules the game ships itself, whose exports the emulator doesn't
    /// need to implement. A directory is scanned for `.prx`/`.sprx`.
    /// Repeatable. Defaults to a `sce_module/` directory beside the target.
    #[arg(long, value_name = "PATH")]
    modules: Vec<PathBuf>,

    /// Lay the image out and apply relocations, reporting what resolved.
    #[arg(long)]
    relocations: bool,

    /// Address to lay the image out at with --relocations.
    #[arg(long, value_name = "ADDR", default_value = "0x400000", value_parser = parse_addr)]
    load_base: u64,
}

fn parse_addr(s: &str) -> Result<u64, std::num::ParseIntError> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse(),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(name) = args.name {
        println!("{name} => {}", nid::hash(&name));
        return Ok(());
    }

    let mut names = NameTable::new();
    for path in &args.names {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let added = names.add_wordlist(&text);
        println!("loaded {added} names from {}", path.display());
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
    println!(
        "names:     {} built in, {} loaded",
        nid::builtin_len(),
        names.len()
    );
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

    let dynamic = match image.dynamic() {
        Ok(dynamic) => dynamic,
        // Not every image has a dynamic segment, and a signed SELF's segments
        // can't be read yet — neither is a reason to fail the whole scan.
        Err(err) => {
            println!("dynamic segment: unavailable ({err})");
            return Ok(());
        }
    };

    print_dynamic(&dynamic, &names, args.imports, args.exports);

    if let Some(list) = &args.implemented {
        println!();
        let bundled = collect_bundled(&args.modules, &path);
        print_compat_report(&dynamic, &names, list, &bundled)?;
    }

    if args.relocations {
        println!();
        print_relocations(&image, &dynamic, args.load_base)?;
    }

    Ok(())
}

fn describe(sym: &DynSymbol, names: &NameTable) -> String {
    let name = names.resolve(&sym.nid).unwrap_or("<unresolved>");
    format!(
        "{} {:<11}  {:<34} {}::{}",
        if sym.kind == STT_FUNC { "fn " } else { "obj" },
        sym.nid,
        name,
        sym.module,
        sym.library
    )
}

fn print_dynamic(dynamic: &Dynamic, names: &NameTable, list_imports: bool, list_exports: bool) {
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
    println!(
        "  {} relocations, {} PLT relocations",
        dynamic.relocations.len(),
        dynamic.plt_relocations.len()
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
    let resolved = imports
        .iter()
        .filter(|s| names.resolve(&s.nid).is_some())
        .count();
    println!();
    println!(
        "{} imports ({resolved} named), {} exports",
        imports.len(),
        exports.len()
    );
    if list_imports {
        print_symbols("imports", &imports, names);
    }
    if list_exports {
        print_symbols("exports", &exports, names);
    }
}

fn print_symbols(heading: &str, symbols: &[DynSymbol], names: &NameTable) {
    println!();
    println!("{heading}:");
    for sym in symbols {
        println!("  {}", describe(sym, names));
    }
}

/// Reads a NID list. JSON of any shape works — every NID-shaped string in it
/// is collected — and anything else is treated as a flat text list.
fn read_implemented(path: &Path) -> Result<ImplementedNids> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
        let mut set = ImplementedNids::new();
        let mut stack = vec![json];
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::String(s) if nid::is_nid(&s) => set.insert(s),
                serde_json::Value::Array(items) => stack.extend(items),
                serde_json::Value::Object(map) => stack.extend(map.into_values()),
                _ => {}
            }
        }
        if !set.is_empty() {
            return Ok(set);
        }
    }

    Ok(ImplementedNids::from_text(&text))
}

/// Exports of the modules the game ships with itself.
///
/// A PS5 title routinely bundles its own `libc.prx` and friends under
/// `sce_module/`; the emulator loads those as guest code rather than
/// implementing them, so counting their functions as gaps is wrong. With no
/// `--modules`, a `sce_module/` directory beside the target is used.
fn collect_bundled(explicit: &[PathBuf], target: &Path) -> NidSet {
    let mut roots: Vec<PathBuf> = explicit.to_vec();
    if roots.is_empty() {
        let beside = target
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("sce_module");
        if beside.is_dir() {
            roots.push(beside);
        }
    }

    let mut files = Vec::new();
    for root in &roots {
        if root.is_dir() {
            let Ok(entries) = std::fs::read_dir(root) else {
                eprintln!("warning: cannot read {}", root.display());
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext.eq_ignore_ascii_case("prx") || ext.eq_ignore_ascii_case("sprx") {
                    files.push(path);
                }
            }
        } else {
            files.push(root.clone());
        }
    }
    files.sort();

    let mut set = NidSet::new();
    let mut loaded = 0usize;
    for file in &files {
        match std::fs::read(file)
            .map_err(anyhow::Error::from)
            .and_then(|d| Image::parse(d).map_err(anyhow::Error::from))
            .and_then(|i| i.exports().map_err(anyhow::Error::from))
        {
            Ok(exports) => {
                for sym in exports {
                    set.insert(sym.nid);
                }
                loaded += 1;
            }
            // A module we can't read just doesn't contribute; it must not
            // sink the whole report.
            Err(err) => eprintln!("warning: skipping {}: {err}", file.display()),
        }
    }

    if loaded > 0 {
        println!(
            "bundled modules: {loaded} from {}, {} exported NIDs",
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            set.len()
        );
    }
    set
}

fn print_compat_report(
    dynamic: &Dynamic,
    names: &NameTable,
    list: &Path,
    bundled: &NidSet,
) -> Result<()> {
    let implemented = read_implemented(list)?;
    let report = dynamic.compat_report_with(&implemented, bundled);

    println!(
        "compatibility vs. {} ({} NIDs implemented):",
        list.display(),
        implemented.len()
    );
    println!("  {} imports", report.total());
    println!("    {} implemented by the emulator", report.implemented());
    if report.bundled_count() > 0 {
        println!(
            "    {} supplied by the game's own modules",
            report.bundled_count()
        );
    }
    println!(
        "    {} missing ({:.1}% covered)",
        report.missing_count(),
        report.coverage() * 100.0
    );

    if !report.missing.is_empty() {
        println!();
        println!("missing:");
        for sym in &report.missing {
            println!("  {}", describe(sym, names));
        }
    }
    Ok(())
}

fn print_relocations(image: &Image, dynamic: &Dynamic, base: u64) -> Result<()> {
    let mut loaded = image
        .load(base)
        .context("laying out the loadable segments")?;
    // Nothing supplies addresses for other modules' exports here, so every
    // genuine import lands in the unresolved list — which is the point: it
    // shows exactly what an external linker would have to provide.
    let report = loaded
        .relocate(dynamic, |_| None)
        .context("applying relocations")?;

    println!(
        "relocations (loaded at 0x{base:x}, {} bytes):",
        loaded.data.len()
    );
    println!(
        "  {} applied, {} unresolved imports, {} skipped",
        report.applied,
        report.unresolved.len(),
        report.skipped_total()
    );
    for (kind, count) in &report.skipped {
        println!("  skipped R_X86_64 type {kind}: {count}");
    }
    Ok(())
}
