# Symbol-name wordlists

`build.rs` hashes every name in `*.txt` here into a NID and emits a sorted
static table (see `src/nid.rs`). NIDs are one-way, so this is the only way to
"reverse" one: hash candidate names and match on the result. A name that isn't
a real Sony export simply never matches — the table can produce a missing
answer, never a wrong one.

## Why there is no vendored NID database here

The obvious sources can't ship inside an `MIT OR Apache-2.0` crate:

| Source | License | Usable? |
| --- | --- | --- |
| `zecoxao/sce_symbols` | none declared | no — all rights reserved by default |
| `SocraticBliss/ps4libdoc`, `idc/ps4libdoc` | none declared | no |
| shadPS4 (`src/core/aerolib`) | GPL-2.0 | no — incompatible |
| OpenOrbis toolchain | GPL-3.0 | no — incompatible |

So none of them are vendored. What ships instead is a list of *names*, with
every NID recomputed here from scratch.

## How each list was produced

**`libc.txt`** — standard C and POSIX identifiers (plus the `posix_`-prefixed
forms PS4 libraries also export), written out from the standards rather than
copied from anywhere.

**`sce.txt`** — Sony PS4/PS5 API names. Candidate identifiers were harvested
from public emulator source as *guesses only*, then each was hashed and kept
only if it matched a NID publicly known to exist. The hash is what decides:
a kept name is provably Sony's real symbol name, and the mapping is
recomputed by `build.rs` rather than copied. No third-party NID table is
reproduced.

If you would rather not ship this list, delete `sce.txt` — the crate builds
fine with any subset of these files, including none.

## Adding your own

Point `SCE_NID_NAMES` at extra newline-delimited wordlists (`:`-separated) to
fold them in at build time:

```sh
SCE_NID_NAMES=/path/to/ps4_names.txt cargo build
```

Or load them at runtime with `nid::NameTable::add_wordlist`, which is what
`nidscan --names <file>` does. Runtime entries shadow the built-in table, so
a corpus you trust always wins.

Format: one name per line; blank lines and `#` comments ignored.
