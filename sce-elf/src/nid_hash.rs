// Shared NID hashing core: `base64(sha1(name + salt)[:8])` under Sony's
// alphabet.
//
// `include!`d by both `src/nid.rs` and `build.rs`, so the build-time table
// generator and the runtime hasher can never drift apart. Keep this file free
// of inner doc comments (`//!`) and `crate::` paths for that reason.
//
// Algorithm and salt verified against shadPS4's `scripts/ps4_names2stubs.py`,
// and cross-checked against a live symbol from the emulator's source:
// `sceKernelGetProcessTime` -> `4J2sUJmuHZQ`
// (https://github.com/shadps4-emu/shadPS4).

use base64::Engine;
use base64::alphabet::Alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use sha1::{Digest, Sha1};
use std::sync::LazyLock;

const NID_SALT: [u8; 16] = [
    0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1, 0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30,
];

/// Sony's base64 alphabet: standard, but with `+/` replaced by `+-`. Shared
/// with [`crate::dynamic::encode_id`], which encodes module and library ids
/// under the same alphabet.
#[allow(dead_code)]
pub const NID_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

/// The number of characters in a NID.
#[allow(dead_code)]
pub const NID_LEN: usize = 11;

// Built once. Constructing it parses and validates the alphabet, which is
// far more expensive than the hash itself when running through a wordlist of
// a hundred thousand names.
static ENGINE: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    let alphabet = Alphabet::new(NID_ALPHABET).expect("NID alphabet is a valid 64-symbol set");
    GeneralPurpose::new(
        &alphabet,
        GeneralPurposeConfig::new().with_encode_padding(false),
    )
});

/// Hashes a symbol name (e.g. `"sceKernelGetProcessTime"`) into its
/// 11-character NID (e.g. `"4J2sUJmuHZQ"`).
pub fn hash(name: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.update(NID_SALT);
    let digest = hasher.finalize();

    // Sony's reference implementation reads the first 8 digest bytes as a
    // little-endian u64, then re-encodes that value big-endian before
    // base64 — an artifact of the original tool being ported from a
    // big-endian-oriented codebase. Reproduced here byte-for-byte.
    let id = u64::from_le_bytes(digest[..8].try_into().unwrap());
    ENGINE.encode(id.to_be_bytes())
}
