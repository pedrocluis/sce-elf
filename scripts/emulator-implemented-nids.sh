#!/usr/bin/env bash
#
# Emit the NIDs an emulator implements, for `nidscan --implemented`.
#
#   git clone --depth 1 https://github.com/shadps4-emu/shadPS4
#   scripts/emulator-implemented-nids.sh shadPS4 > implemented.txt
#   nidscan eboot.bin --implemented implemented.txt
#
# Each emulator spells its registrations differently, so the checkout is
# sniffed rather than passed a flag:
#
#   shadPS4 (GPL-2.0, PS4)   LIB_FUNCTION("<nid>", "<lib>", <ver>, "<mod>", fn)
#   Kyty    (MIT, PS4+PS5)   LIB_FUNC("<nid>", fn)
#   SharpEmu (GPL-2.0, PS5)  Nid = "<nid>",
#
# For a PS5 title, use a PS5-capable emulator: shadPS4 is PS4-only, so its
# list will look almost entirely unimplemented against a PS5 binary and tell
# you nothing useful.
#
# Output is one NID per line (shadPS4 adds "<library> <module>"); nidscan
# reads the first whitespace-separated field and ignores the rest.
set -euo pipefail

root="${1:-.}"
[ -d "$root" ] || { echo "no such directory: $root" >&2; exit 1; }

if [ -d "$root/src/core/libraries" ]; then
    grep -rhoE 'LIB_FUNCTION\("[^"]{11}", *"[^"]+", *[0-9]+, *"[^"]+"' "$root/src/core/libraries" \
        | sed -E 's/LIB_FUNCTION\("([^"]+)", *"([^"]+)", *[0-9]+, *"([^"]+)"/\1 \2 \3/'
elif [ -d "$root/source/emulator/src" ]; then
    grep -rhoE 'LIB_FUNC\("[^"]{11}"' "$root/source/emulator/src" \
        | sed -E 's/LIB_FUNC\("([^"]+)"/\1/'
elif [ -d "$root/src" ] && ls "$root"/*.sln >/dev/null 2>&1 || [ -d "$root/src/SharpEmu.Libs" ]; then
    grep -rhoE 'Nid = "[A-Za-z0-9+-]{11}"' --include='*.cs' "$root/src" \
        | sed -E 's/Nid = "([^"]+)"/\1/'
else
    echo "unrecognised emulator checkout: $root" >&2
    echo "expected shadPS4 (src/core/libraries), Kyty (source/emulator/src)," >&2
    echo "or SharpEmu (src/SharpEmu.Libs)" >&2
    exit 1
fi | sort -u
