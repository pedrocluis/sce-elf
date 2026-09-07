//! Sony NID hashing: `base64(sha1(name + salt)[:8])` under a custom
//! alphabet.
//!
//! Algorithm and salt verified against shadPS4's
//! `scripts/ps4_names2stubs.py`, and cross-checked against a live symbol
//! from the emulator's source (see the test below):
//! `sceKernelGetProcessTime` -> `4J2sUJmuHZQ`
//! (https://github.com/shadps4-emu/shadPS4).

use base64::Engine;
use base64::alphabet::Alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use sha1::{Digest, Sha1};

const NID_SALT: [u8; 16] = [
    0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1, 0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30,
];

/// Sony's base64 alphabet: standard, but with `+/` replaced by `+-`. Shared
/// with [`crate::dynamic::encode_id`], which encodes module/library ids under
/// the same alphabet.
pub(crate) const NID_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

fn engine() -> GeneralPurpose {
    let alphabet = Alphabet::new(NID_ALPHABET).expect("NID alphabet is a valid 64-symbol set");
    GeneralPurpose::new(
        &alphabet,
        GeneralPurposeConfig::new().with_encode_padding(false),
    )
}

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
    engine().encode(id.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_shadps4_symbol() {
        assert_eq!(hash("sceKernelGetProcessTime"), "4J2sUJmuHZQ");
    }
}
