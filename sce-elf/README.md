# sce-elf

Parser for Sony's SELF/ELF binary format (PS4 and PS5), with NID hashing and
reverse lookup.

Part of the [sce-elf workspace](https://github.com/pedrocluis/sce-elf); the
`nidscan` CLI is built on it.

```rust
use sce_elf::{Image, nid};

let image = Image::parse(std::fs::read("eboot.bin")?)?;
println!("{:?}", image.elf_type());

for sym in image.imports()? {
    let name = nid::resolve(&sym.nid).unwrap_or("<unresolved>");
    println!("{}::{}  {}  {name}", sym.module, sym.library, sym.nid);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What it handles

- The SELF container (both magics), including mapping a program header's
  contents through the segment table.
- ELF64 headers and `PT_SCE_*` program headers.
- The dynamic segment in both layouts: PS4's `DT_SCE_*` tags holding offsets
  into `PT_SCE_DYNLIBDATA`, and PS5's standard `DT_*` tags holding virtual
  addresses. `DynTag::canonical` collapses the two spellings.
- Symbols decoded from their `NID#library#module` form, with module and
  library names resolved.
- Relocations, and laying an image out at a load base.
- NID hashing, and reverse lookup via a compile-time table.

Malformed input errors rather than panics; there is a robustness suite for it.

## NID lookup

NIDs are one-way. `build.rs` hashes the wordlists in `names/` into a table
sorted by NID, so `nid::resolve` is a binary search over static data. A wrong
guess in a wordlist never matches, so the table can miss but cannot lie.

Add your own at build time with `SCE_NID_NAMES`, or at runtime with
`nid::NameTable`. See [`names/README.md`](names/README.md) — including why no
third-party NID database is vendored here.

## Not supported

Encrypted or compressed SELF segments. Those return
`Error::OpaqueSegment` rather than garbage.

## License

MIT or Apache-2.0, at your option.
