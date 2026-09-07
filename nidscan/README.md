# nidscan

CLI to inspect PS4/PS5 SELF/ELF binaries: what a game imports, what a library
exports, and how much of it an emulator has implemented.

Built on [`sce-elf`](../sce-elf).

```sh
cargo install nidscan
```

## Usage

```
nidscan [OPTIONS] [FILE]

  FILE                  eboot.bin, .self, .sprx, .prx, or raw .elf

  --name <NAME>         Hash a symbol name into its NID instead of scanning
  --imports             List every imported symbol
  --exports             List every exported symbol
  --names <FILE>        Extra symbol-name wordlist. Repeatable
  --implemented <FILE>  NIDs an emulator implements (JSON or text)
  --modules <PATH>      Modules the game ships itself. Defaults to a
                        sce_module/ directory beside the target
  --relocations         Lay the image out and apply relocations
  --load-base <ADDR>    Address for --relocations [default: 0x400000]
```

## The compatibility report

```sh
git clone --depth 1 https://github.com/sharpemu/sharpemu
../scripts/emulator-implemented-nids.sh sharpemu > implemented.txt
nidscan eboot.bin --implemented implemented.txt
```

```
1747 imports
  529 implemented by the emulator
  959 supplied by the game's own modules
  259 missing (85.2% covered)
```

PS5 titles ship their own copies of libraries like `libc` under `sce_module/`.
The emulator loads those as guest code rather than implementing them, so they
are counted separately — without that, this title reads as 30% covered instead
of 85%.

This measures what a binary *asks for*, not what it *calls*, and an
implemented NID may still be a stub. It maps the risk; it doesn't predict that
a game boots.

## License

MIT or Apache-2.0, at your option.
