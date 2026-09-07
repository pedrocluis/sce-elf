#!/usr/bin/env bash
#
# Emit the NIDs an emulator implements, for `nidscan --implemented`.
#
# Pass an emulator name and it clones (and reuses) a shallow checkout:
#
#   scripts/emulator-implemented-nids.sh sharpemu > implemented.txt
#
# Or pass a path to a checkout you already have:
#
#   scripts/emulator-implemented-nids.sh ~/src/shadPS4 > implemented.txt
#
# With no argument it writes every emulator's list straight into nidscan's
# data directory and points default.txt at the PS5 one:
#
#   scripts/emulator-implemented-nids.sh --install
#
# Each emulator spells its registrations differently, so a checkout is sniffed
# rather than told which it is:
#
#   shadPS4  (GPL-2.0, PS4)      LIB_FUNCTION("<nid>", "<lib>", <ver>, "<mod>", fn)
#   Kyty     (MIT, PS4+PS5)      LIB_FUNC("<nid>", fn)      source/emulator/src
#   KytyPS5  (GPL-2.0, PS5)      LIB_FUNC("<nid>", fn)      src/libs
#   SharpEmu (GPL-2.0, PS5)      Nid = "<nid>",
#
# Kyty and KytyPS5 are separate projects, not forks of each other: same macro,
# different layout and different scope.
#
# For a PS5 title use a PS5-capable emulator. shadPS4 is PS4-only, so its list
# looks almost entirely unimplemented against a PS5 binary and tells you
# nothing about the game.
#
# Output is one NID per line (shadPS4 adds "<library> <module>"); nidscan
# reads the first whitespace-separated field and ignores the rest.
set -euo pipefail

CACHE="${NIDSCAN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/nidscan}"
DATA="${NIDSCAN_DATA:-${XDG_DATA_HOME:-$HOME/.local/share}/nidscan}"

repo_url() {
    case "$1" in
        shadps4|shadPS4)   echo "https://github.com/shadps4-emu/shadPS4" ;;
        kyty|Kyty)         echo "https://github.com/InoriRus/Kyty" ;;
        kytyps5|KytyPS5)   echo "https://github.com/KytyPS5/KytyPS5" ;;
        sharpemu|SharpEmu) echo "https://github.com/sharpemu/sharpemu" ;;
        *)                 return 1 ;;
    esac
}

# A shallow, blobless clone; refreshed if it already exists.
fetch() {
    local name="$1" url dir
    url="$(repo_url "$name")"
    dir="$CACHE/$name"
    mkdir -p "$CACHE"
    if [ -d "$dir/.git" ]; then
        echo "updating $dir" >&2
        git -C "$dir" fetch --depth 1 --quiet origin
        git -C "$dir" reset --hard --quiet FETCH_HEAD
    else
        echo "cloning $url into $dir" >&2
        git clone --depth 1 --filter=blob:none --quiet "$url" "$dir"
    fi
    echo "$dir"
}

scrape() {
    local root="$1"
    if [ -d "$root/src/core/libraries" ]; then
        grep -rhoE 'LIB_FUNCTION\("[^"]{11}", *"[^"]+", *[0-9]+, *"[^"]+"' "$root/src/core/libraries" \
            | sed -E 's/LIB_FUNCTION\("([^"]+)", *"([^"]+)", *[0-9]+, *"([^"]+)"/\1 \2 \3/'
    elif [ -d "$root/source/emulator/src" ]; then
        grep -rhoE 'LIB_(FUNC|OBJECT)\("[^"]{11}"' "$root/source/emulator/src" \
            | sed -E 's/LIB_(FUNC|OBJECT)\("([^"]+)"/\2/'
    elif [ -d "$root/src/libs" ]; then
        grep -rhoE 'LIB_(FUNC|OBJECT)\("[^"]{11}"' "$root/src" \
            | sed -E 's/LIB_(FUNC|OBJECT)\("([^"]+)"/\2/'
    elif [ -d "$root/src/SharpEmu.Libs" ] || [ -d "$root/src/SharpEmu.Core" ]; then
        grep -rhoE 'Nid = "[A-Za-z0-9+-]{11}"' --include='*.cs' "$root/src" \
            | sed -E 's/Nid = "([^"]+)"/\1/'
    else
        echo "unrecognised emulator checkout: $root" >&2
        echo "expected shadPS4 (src/core/libraries), Kyty (source/emulator/src)," >&2
        echo "KytyPS5 (src/libs), or SharpEmu (src/SharpEmu.Libs)" >&2
        return 1
    fi | sort -u
}

case "${1:-}" in
    --install)
        mkdir -p "$DATA/implemented"
        for name in shadps4 kyty kytyps5 sharpemu; do
            out="$DATA/implemented/$name.txt"
            scrape "$(fetch "$name")" > "$out"
            echo "wrote $out ($(wc -l < "$out") NIDs)" >&2
        done
        # KytyPS5 is PS5-focused and currently has the widest coverage, so
        # it is the sensible default. Repoint the symlink to change it.
        ln -sf kytyps5.txt "$DATA/implemented/default.txt"
        echo "default.txt -> kytyps5.txt" >&2
        ;;
    "" | -h | --help)
        sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        if [ -d "$1" ]; then
            scrape "$1"
        elif repo_url "$1" >/dev/null; then
            scrape "$(fetch "$1")"
        else
            echo "not a directory or known emulator: $1" >&2
            echo "known: shadps4, kyty, kytyps5, sharpemu" >&2
            exit 1
        fi
        ;;
esac
