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

`scripts/emulator-implemented-nids.sh` scrapes an implemented-NID list from a
checkout of shadPS4, Kyty or SharpEmu. Use a PS5-capable emulator's list for a
PS5 title — shadPS4 is PS4-only and scores near zero against a PS5 binary for
reasons that say nothing about the game.

The bundled wordlists are deliberately modest; see the data directory below.

## Prebuilt binaries

Each release ships `nidscan` for Linux, macOS and Windows (x86-64 and arm64) —
see [Releases](https://github.com/pedrocluis/sce-elf/releases). No Rust needed.

## Set-up: the data directory

`nidscan` reads wordlists and emulator NID lists from a data directory, so the
common case needs no flags:

```
~/.local/share/nidscan/
├── names/
│   └── ps5_names.txt          # symbol names, for resolving NIDs
└── implemented/
    ├── sharpemu.txt
    ├── shadps4.txt
    └── default.txt -> sharpemu.txt
```

(`$NIDSCAN_DATA` or `$XDG_DATA_HOME/nidscan` override the location;
`%APPDATA%\nidscan` on Windows. If the directory doesn't exist nothing is
loaded, so this is entirely opt-in.)

Every wordlist in `names/` is loaded and merged — more names is strictly
better. Only *one* list in `implemented/` is used, because merging two
emulators' coverage would be meaningless: with several, `default.txt` decides,
otherwise `nidscan` says so and skips the report rather than guessing. Point
`default.txt` at a PS5 emulator for PS5 titles.

Populate it once:

```sh
mkdir -p ~/.local/share/nidscan/{names,implemented}

# Symbol names. SharpEmu ships ~154k of them; not bundled here because that
# repo is GPL-2.0 and the list comes from an unlicensed upstream.
curl -L -o ~/.local/share/nidscan/names/ps5_names.txt \
  https://raw.githubusercontent.com/sharpemu/sharpemu/main/scripts/ps5_names.txt

# What an emulator implements.
git clone --depth 1 https://github.com/sharpemu/sharpemu
scripts/emulator-implemented-nids.sh sharpemu \
  > ~/.local/share/nidscan/implemented/sharpemu.txt
ln -s sharpemu.txt ~/.local/share/nidscan/implemented/default.txt
```

Then a bare invocation gives the full picture:

```
$ nidscan eboot.bin
using ~/.local/share/nidscan/names/ps5_names.txt (154458 names)
bundled modules: 2 from Game-Files/sce_module, 45743 exported NIDs
1747 imports (1738 named), 0 exports
  1747 imports
    529 implemented by the emulator
    959 supplied by the game's own modules
    259 missing (85.2% covered)
```

Explicit `--names` / `--implemented` override the directory; `--no-default-data`
ignores it entirely.

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
