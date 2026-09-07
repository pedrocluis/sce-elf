//! Comparing a binary's imports against the set of NIDs an emulator has
//! actually implemented.
//!
//! The set is whatever you can scrape — shadPS4 spells its NIDs out literally
//! in `LIB_FUNCTION("<nid>", "<library>", <version>, "<module>", impl)`
//! registrations, so `grep` produces one. [`ImplementedNids::from_text`]
//! parses the flat form; anything richer (JSON) can be fed in through
//! [`ImplementedNids::insert`].

use std::collections::HashSet;

use crate::dynamic::DynSymbol;
use crate::error::Result;
use crate::{Dynamic, Image};

/// A set of NIDs.
///
/// Used for two different things: what an emulator implements, and what a
/// game's own bundled modules export. Both answer "is this import already
/// satisfied?", just from different directions.
#[derive(Debug, Clone, Default)]
pub struct NidSet {
    nids: HashSet<String>,
}

/// The NIDs an emulator implements.
pub type ImplementedNids = NidSet;

impl NidSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses a flat list: one entry per line, `#` comments and blank lines
    /// ignored, and only the first whitespace- or comma-separated field of
    /// each line taken — so `NID`, `NID name`, and `NID,library,module` all
    /// work.
    pub fn from_text(text: &str) -> Self {
        let mut set = Self::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            if let Some(nid) = line.split([' ', '\t', ',', ';']).find(|f| !f.is_empty()) {
                set.insert(nid);
            }
        }
        set
    }

    pub fn insert(&mut self, nid: impl Into<String>) {
        self.nids.insert(nid.into());
    }

    pub fn contains(&self, nid: &str) -> bool {
        self.nids.contains(nid)
    }

    pub fn len(&self) -> usize {
        self.nids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nids.is_empty()
    }
}

impl<S: Into<String>> FromIterator<S> for NidSet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self {
            nids: iter.into_iter().map(Into::into).collect(),
        }
    }
}

/// How much of a binary's imports an emulator covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatReport {
    /// Every distinct `(module, library, nid)` the binary imports, sorted.
    pub imports: Vec<DynSymbol>,
    /// Imports nothing satisfies: not implemented by the emulator, and not
    /// exported by any bundled module. The real gap.
    pub missing: Vec<DynSymbol>,
    /// Imports the emulator doesn't implement but a module shipped with the
    /// game does export, so the emulator never has to provide them.
    pub bundled: Vec<DynSymbol>,
}

impl CompatReport {
    pub fn total(&self) -> usize {
        self.imports.len()
    }

    /// Imports something satisfies, whether the emulator or a bundled module.
    pub fn satisfied(&self) -> usize {
        self.imports.len() - self.missing.len()
    }

    /// Imports the emulator itself implements.
    pub fn implemented(&self) -> usize {
        self.imports.len() - self.missing.len() - self.bundled.len()
    }

    /// Imports a bundled module supplies instead of the emulator.
    pub fn bundled_count(&self) -> usize {
        self.bundled.len()
    }

    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }

    /// Satisfied share of the imports, 0.0 to 1.0 — counting bundled modules,
    /// since an import a game supplies itself is not a gap. An import-free
    /// binary counts as fully covered.
    pub fn coverage(&self) -> f64 {
        if self.imports.is_empty() {
            return 1.0;
        }
        self.satisfied() as f64 / self.imports.len() as f64
    }
}

impl Dynamic {
    /// Compares this module's imports against `implemented`.
    ///
    /// Imports are deduplicated by `(module, library, nid)` and sorted, so
    /// the report is stable across runs.
    pub fn compat_report(&self, implemented: &NidSet) -> CompatReport {
        self.compat_report_with(implemented, &NidSet::new())
    }

    /// Compares this module's imports against `implemented`, treating
    /// anything in `bundled` as already supplied.
    ///
    /// PS5 titles routinely ship their own copies of libraries like `libc` in
    /// a `sce_module/` directory; the emulator loads those as guest code
    /// rather than implementing them. Counting them as gaps badly understates
    /// compatibility — on one retail title it turned 85% coverage into 30%.
    pub fn compat_report_with(&self, implemented: &NidSet, bundled: &NidSet) -> CompatReport {
        let mut imports = self.imports();
        imports
            .sort_by(|a, b| (&a.module, &a.library, &a.nid).cmp(&(&b.module, &b.library, &b.nid)));
        imports.dedup_by(|a, b| (&a.module, &a.library, &a.nid) == (&b.module, &b.library, &b.nid));

        let unimplemented = imports.iter().filter(|sym| !implemented.contains(&sym.nid));
        let (bundled, missing): (Vec<_>, Vec<_>) = unimplemented
            .cloned()
            .partition(|sym| bundled.contains(&sym.nid));

        CompatReport {
            imports,
            missing,
            bundled,
        }
    }
}

impl Image {
    /// Compares this image's imports against `implemented`.
    pub fn compat_report(&self, implemented: &NidSet) -> Result<CompatReport> {
        Ok(self.dynamic()?.compat_report(implemented))
    }

    /// Compares this image's imports against `implemented`, discounting
    /// anything `bundled` already supplies.
    pub fn compat_report_with(
        &self,
        implemented: &NidSet,
        bundled: &NidSet,
    ) -> Result<CompatReport> {
        Ok(self.dynamic()?.compat_report_with(implemented, bundled))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_flat_forms() {
        let set = ImplementedNids::from_text(
            "# a comment\n\
             4J2sUJmuHZQ\n\
             \n\
             yS8U2TGCe1A nanosleep\n\
             QcteRwbsnV0,libkernel,libkernel\n\
             \tj4ViWNHEgww\tstrlen   # trailing comment\n",
        );
        assert_eq!(set.len(), 4);
        for nid in ["4J2sUJmuHZQ", "yS8U2TGCe1A", "QcteRwbsnV0", "j4ViWNHEgww"] {
            assert!(set.contains(nid), "{nid} should have parsed");
        }
        assert!(!set.contains("nanosleep"));
        assert!(!set.contains("#"));
    }

    #[test]
    fn coverage_of_an_empty_report_is_total() {
        let report = CompatReport {
            imports: Vec::new(),
            missing: Vec::new(),
            bundled: Vec::new(),
        };
        assert_eq!(report.coverage(), 1.0);
        assert_eq!(report.total(), 0);
    }
}
