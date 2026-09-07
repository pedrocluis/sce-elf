# sce-elf

Parser for Sony's SELF/ELF binary format (PS4 and PS5), and `nidscan`, a CLI
that tells you what a game binary needs from the operating system — and which
of those an emulator has actually implemented.

```
$ nidscan eboot.bin --names ps5_names.txt --implemented sharpemu.txt

bundled modules: 2 from Game-Files/sce_module, 45743 exported NIDs

dynamic segment:
  module:   Armadillo_Prospero_Master (id 0, v1.1, A)
  272 dyn entries, 1748 symbols, 30351-byte string table
  570232 relocations, 1722 PLT relocations

1747 imports (1738 named), 0 exports

compatibility vs. sharpemu.txt (1164 NIDs implemented):
  1747 imports
    529 implemented by the emulator
    959 supplied by the game's own modules
    259 missing (85.2% covered)

missing:
  fn  1rZSWUv1IRc  sceAgcDcbCopyData          libSceAgc::libSceAgc
  fn  AhGvpITrf4M  sceAgcDriverAgrSubmitDcb   libSceAgcDriver::libSceAgcDriver
```

## Why

A console game doesn't contain all its code. It records a list of functions it
needs from the system libraries — its **imports** — and the OS wires them up at
launch. An emulator has to provide every one of those. So "will this game run?"
is largely "does the emulator implement what this binary asks for?"

Sony makes that hard to read. Instead of storing the name `malloc`, they store
an 11-character hash of it called a **NID** (`gQX+4GDQjpM`). It's one-way, so
the only way back is to hash a wordlist of candidate names and match. This
crate ships one, and takes another at runtime.

## Crates

| Crate | What it is |
| --- | --- |
| [`sce-elf`](sce-elf) | The library: SELF container, ELF64 headers, dynamic segment, symbols, relocations, NID hashing and lookup |
| [`nidscan`](nidscan) | The CLI |

## Install

```sh
cargo install --path nidscan
```

## Use

```sh
nidscan eboot.bin                     # headers, modules, libraries, counts
nidscan eboot.bin --imports           # every import, with names resolved
nidscan libc.prx  --exports           # what a library provides
nidscan --name sceKernelGetProcessTime    # hash a name to its NID
nidscan eboot.bin --relocations       # load the image and apply relocations
```

For a compatibility report you need a list of NIDs an emulator implements.
`scripts/emulator-implemented-nids.sh` scrapes one from a checkout of shadPS4,
Kyty or SharpEmu:

```sh
git clone --depth 1 https://github.com/sharpemu/sharpemu
scripts/emulator-implemented-nids.sh sharpemu > implemented.txt
nidscan eboot.bin --implemented implemented.txt
```

Use a PS5-capable emulator's list for a PS5 title. shadPS4 is PS4-only and will
score near zero against a PS5 binary for reasons that say nothing about the game.

Name coverage from the bundled wordlists is deliberately modest. For real work
pass a large corpus with `--names`; see [`sce-elf/names/README.md`](sce-elf/names/README.md).

## What works

- PS4 and PS5 layouts. PS5 has no `PT_SCE_DYNLIBDATA` and addresses its tables
  by virtual address through standard `DT_*` tags, with its own constants for
  the module and library entries.
- Both SELF container magics (`0x1D3D154F` and `0xEEF51454`).
- `eboot.bin`, `.prx`/`.sprx` libraries, and raw `.elf`.
- Imports and exports as `(module, library, nid)`, with names resolved.
- Relocations: `R_X86_64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, `_64`.

Every format decision is verified against shadPS4's source, against
`InoriRus/Kyty`, or directly against retail binaries — never assumed. Where
something could not be verified it is deliberately not implemented.

## What doesn't

- **Encrypted and compressed SELF segments.** Everything here works on
  decrypted files. A signed binary straight off a disc stops with a clear
  error rather than producing garbage.
- PKG/PFS extraction — out of scope; blocked on keys that aren't public.
- The "back half" of an emulator: no CPU, no GPU, no syscalls. This is static
  analysis. It reads the recipe and tells you which ingredients are missing.

## License

MIT or Apache-2.0, at your option. The bundled wordlists contain no
third-party NID database; see [`sce-elf/names/README.md`](sce-elf/names/README.md)
for how they were produced and why.
