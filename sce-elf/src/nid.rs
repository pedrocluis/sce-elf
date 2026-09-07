//! Sony NID hashing (name -> NID) and reverse lookup (NID -> name).
//!
//! NIDs are one-way — a name hashes to a NID, never the reverse — so
//! "resolving" a NID means hashing a wordlist of candidate names and matching
//! on the result. [`build.rs`] does that at compile time and emits a table
//! sorted by NID, so [`resolve`] is a binary search over static data with no
//! start-up cost. A wrong guess in a wordlist simply never matches; it cannot
//! produce a wrong name.
//!
//! The bundled wordlists under `names/` are standard C and POSIX identifiers
//! plus Sony API names verified to hash to NIDs that are publicly known to
//! exist. They are deliberately not a vendored third-party NID database: the
//! usual sources (`zecoxao/sce_symbols`, `SocraticBliss/ps4libdoc`) carry no
//! license at all, and shadPS4's own table is GPL-2.0, none of which can ship
//! inside an `MIT OR Apache-2.0` crate. Point `SCE_NID_NAMES` at extra
//! wordlists at build time, or use [`NameTable`] to load them at runtime, to
//! fold in a corpus you have obtained yourself.
//!
//! [`build.rs`]: https://docs.rs/sce-elf

use std::collections::HashMap;

include!("nid_hash.rs");
include!(concat!(env!("OUT_DIR"), "/nid_table.rs"));

/// Looks a NID up in the built-in table.
pub fn resolve(nid: &str) -> Option<&'static str> {
    NID_NAMES
        .binary_search_by(|(known, _)| (*known).cmp(nid))
        .ok()
        .map(|i| NID_NAMES[i].1)
}

/// How many names the built-in table holds.
pub fn builtin_len() -> usize {
    NID_NAMES.len()
}

/// Whether a string is shaped like a NID: [`NID_LEN`] characters, all from
/// [`NID_ALPHABET`]. Useful for picking NIDs out of a JSON blob of unknown
/// shape.
pub fn is_nid(s: &str) -> bool {
    s.len() == NID_LEN && s.chars().all(|c| NID_ALPHABET.contains(c))
}

/// The built-in table plus wordlists loaded at runtime.
///
/// Runtime entries shadow the built-in ones, so a caller can override a name
/// the crate guessed with one from a corpus they trust.
#[derive(Debug, Default, Clone)]
pub struct NameTable {
    extra: HashMap<String, String>,
}

impl NameTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hashes every name in a newline-delimited wordlist and adds it.
    /// Blank lines and `#` comments are ignored. Returns how many names were
    /// added (duplicates and NID collisions with an earlier entry don't
    /// count).
    pub fn add_wordlist(&mut self, text: &str) -> usize {
        let mut added = 0;
        for line in text.lines() {
            let name = line.split('#').next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            if self.extra.insert(hash(name), name.to_owned()).is_none() {
                added += 1;
            }
        }
        added
    }

    /// Resolves a NID, preferring runtime entries over the built-in table.
    pub fn resolve<'a>(&'a self, nid: &str) -> Option<&'a str> {
        match self.extra.get(nid) {
            Some(name) => Some(name.as_str()),
            None => resolve(nid),
        }
    }

    /// How many names were loaded at runtime, on top of the built-in table.
    pub fn len(&self) -> usize {
        self.extra.len()
    }

    pub fn is_empty(&self) -> bool {
        self.extra.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_shadps4_symbol() {
        assert_eq!(hash("sceKernelGetProcessTime"), "4J2sUJmuHZQ");
    }

    #[test]
    fn built_in_table_is_sorted_and_resolves() {
        assert!(
            builtin_len() > 0,
            "the bundled wordlists should not be empty"
        );
        assert!(
            NID_NAMES.windows(2).all(|w| w[0].0 < w[1].0),
            "the generated table must be sorted for binary search"
        );
        // Every entry must round-trip: the table's key is the hash of its
        // value, and looking that key up returns it again.
        for (nid, name) in NID_NAMES.iter() {
            assert_eq!(&hash(name), nid, "table entry for {name} is stale");
            assert_eq!(resolve(nid), Some(*name));
        }
    }

    #[test]
    fn recognises_nid_shaped_strings() {
        assert!(is_nid("4J2sUJmuHZQ"));
        assert!(is_nid("+-+-+-+-+-+"));
        assert!(!is_nid("4J2sUJmuHZ"), "too short");
        assert!(!is_nid("4J2sUJmuHZQQ"), "too long");
        assert!(!is_nid("4J2sUJmuHZ/"), "'/' is not in Sony's alphabet");
        assert!(!is_nid("sceKernelGet"));
    }

    #[test]
    fn unknown_nids_do_not_resolve() {
        assert_eq!(resolve("00000000000"), None);
        assert_eq!(resolve(""), None);
    }

    #[test]
    fn runtime_wordlists_shadow_the_built_in_table() {
        let mut table = NameTable::new();
        assert_eq!(
            table.add_wordlist("sceKernelGetProcessTime\n\n# a comment\n"),
            1
        );
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.resolve("4J2sUJmuHZQ"),
            Some("sceKernelGetProcessTime")
        );
        // Duplicates don't accumulate.
        assert_eq!(table.add_wordlist("sceKernelGetProcessTime"), 0);
        // Falls through to the built-in table for everything else.
        let (nid, name) = NID_NAMES[0];
        assert_eq!(table.resolve(nid), Some(name));
    }
}
