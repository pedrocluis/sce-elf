#!/usr/bin/env bash
#
# Emit the NIDs shadPS4 implements, for `nidscan --implemented`.
#
#   git clone --depth 1 https://github.com/shadps4-emu/shadPS4
#   scripts/shadps4-implemented-nids.sh shadPS4 > implemented.txt
#   nidscan eboot.bin --implemented implemented.txt
#
# shadPS4 spells each NID out literally in its registrations:
#
#   LIB_FUNCTION("<nid>", "<library>", <version>, "<module>", <impl>)
#
# so the list is a grep. Output is "<nid> <library> <module>" per line;
# nidscan reads the first field and ignores the rest.
set -euo pipefail

root="${1:-.}"
src="$root/src/core/libraries"
if [ ! -d "$src" ]; then
    echo "not a shadPS4 checkout: $src does not exist" >&2
    exit 1
fi

grep -rhoE 'LIB_FUNCTION\("[^"]{11}", *"[^"]+", *[0-9]+, *"[^"]+"' "$src" \
    | sed -E 's/LIB_FUNCTION\("([^"]+)", *"([^"]+)", *[0-9]+, *"([^"]+)"/\1 \2 \3/' \
    | sort -u
