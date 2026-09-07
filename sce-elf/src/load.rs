//! Building a loaded image from the `PT_LOAD`/`PT_SCE_RELRO` segments, and
//! applying relocations to it.
//!
//! Semantics verified against shadPS4's `Module::LoadModuleToMemory` and
//! `Linker::Relocate` (https://github.com/shadps4-emu/shadPS4): the image is
//! mapped as one block starting at the load base, a program header's
//! `p_vaddr` is an offset from that base, and a relocation's `r_offset` is a
//! virtual address in the same space.

use std::collections::BTreeMap;

use crate::dynamic::{
    DynSymbol, Dynamic, R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_NONE,
    R_X86_64_RELATIVE, STB_LOCAL, Symbol,
};
use crate::error::{Error, Result};
use crate::{Image, ProgramType};

/// Refuse to allocate an image larger than this. A corrupt `p_vaddr` would
/// otherwise ask for an arbitrary amount of memory.
const MAX_IMAGE_SIZE: u64 = 1 << 32;

/// An image laid out in memory: `data[v]` holds the byte at virtual address
/// `base + v`.
#[derive(Debug, Clone)]
pub struct LoadedImage {
    /// The address the image was loaded at.
    pub base: u64,
    pub data: Vec<u8>,
}

/// A relocation that named an imported symbol nothing supplied an address
/// for. Its slot was left untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSymbol {
    /// The raw string-table name.
    pub name: String,
    /// The decoded form, when the name is `NID#library#module`.
    pub symbol: Option<DynSymbol>,
}

/// What [`LoadedImage::relocate`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationReport {
    /// Slots written.
    pub applied: usize,
    /// Imports left unwritten because no address was supplied.
    pub unresolved: Vec<UnresolvedSymbol>,
    /// Relocation kinds this crate doesn't apply (the TLS ones), by count.
    pub skipped: BTreeMap<u32, usize>,
}

impl RelocationReport {
    pub fn skipped_total(&self) -> usize {
        self.skipped.values().sum()
    }
}

impl Image {
    /// Lays the loadable segments out at `base`.
    ///
    /// Only `PT_LOAD` and `PT_SCE_RELRO` are mapped, which is what shadPS4
    /// maps; the span runs from address 0 to the highest `p_vaddr + p_memsz`,
    /// so `data` can be indexed by virtual address directly.
    pub fn load(&self, base: u64) -> Result<LoadedImage> {
        let loadable = |ty: ProgramType| ty == ProgramType::Load || ty == ProgramType::SceRelro;

        let mut size = 0u64;
        for ph in &self.program_headers {
            if ph.p_memsz == 0 || !loadable(ph.p_type.into()) {
                continue;
            }
            let end = ph
                .p_vaddr
                .checked_add(align_up(ph.p_memsz, ph.p_align))
                .ok_or(Error::OutOfBounds {
                    what: "segment end",
                    region: "the address space",
                    offset: ph.p_vaddr,
                    size: ph.p_memsz,
                    limit: u64::MAX,
                })?;
            size = size.max(end);
        }
        if size > MAX_IMAGE_SIZE {
            return Err(Error::OutOfBounds {
                what: "loaded image",
                region: "a sane address space",
                offset: 0,
                size,
                limit: MAX_IMAGE_SIZE,
            });
        }

        let mut data = vec![0u8; size as usize];
        for (i, ph) in self.program_headers.iter().enumerate() {
            if ph.p_filesz == 0 || !loadable(ph.p_type.into()) {
                continue;
            }
            let start = usize::try_from(ph.p_vaddr).ok();
            let end = ph
                .p_vaddr
                .checked_add(ph.p_filesz)
                .and_then(|e| usize::try_from(e).ok());
            match (start, end) {
                (Some(start), Some(end)) if end <= data.len() => {
                    data[start..end].copy_from_slice(self.segment_data(i)?);
                }
                _ => {
                    return Err(Error::OutOfBounds {
                        what: "loadable segment",
                        region: "the loaded image",
                        offset: ph.p_vaddr,
                        size: ph.p_filesz,
                        limit: data.len() as u64,
                    });
                }
            }
        }

        Ok(LoadedImage { base, data })
    }
}

impl LoadedImage {
    /// Applies `DT_SCE_RELA` and then `DT_SCE_JMPREL`.
    ///
    /// `resolve` supplies the address of an imported symbol; returning `None`
    /// leaves that slot untouched and records it in the report. Symbols this
    /// image defines itself are resolved internally and never reach `resolve`.
    ///
    /// TLS relocations (`R_X86_64_DTPMOD64` and friends) are counted as
    /// skipped rather than applied — they need a `PT_TLS` module index this
    /// crate doesn't model.
    pub fn relocate<F>(&mut self, dynamic: &Dynamic, mut resolve: F) -> Result<RelocationReport>
    where
        F: FnMut(&DynSymbol) -> Option<u64>,
    {
        let mut report = RelocationReport::default();

        for rel in dynamic.relocations.iter().chain(&dynamic.plt_relocations) {
            let kind = rel.kind();
            // GLOB_DAT and JUMP_SLOT are R_X86_64_64 with the addend forced
            // to zero — the fallthrough in shadPS4's Linker::Relocate.
            let addend = match kind {
                R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => 0,
                _ => rel.r_addend,
            };

            let value = match kind {
                R_X86_64_NONE => continue,
                R_X86_64_RELATIVE => Some(self.base.wrapping_add(addend as u64)),
                R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                    let index = rel.symbol() as usize;
                    let sym = dynamic.symbols.get(index).ok_or(Error::OutOfBounds {
                        what: "relocation symbol index",
                        region: "the symbol table",
                        offset: index as u64,
                        size: 1,
                        limit: dynamic.symbols.len() as u64,
                    })?;
                    match self.symbol_address(dynamic, sym, &mut resolve) {
                        Some(address) => Some(address.wrapping_add(addend as u64)),
                        None => {
                            report.unresolved.push(UnresolvedSymbol {
                                name: dynamic.string(sym.st_name as u64).unwrap_or_default(),
                                symbol: dynamic.decode_symbol(sym),
                            });
                            None
                        }
                    }
                }
                other => {
                    *report.skipped.entry(other).or_default() += 1;
                    None
                }
            };

            if let Some(value) = value {
                self.write_u64(rel.r_offset, value)?;
                report.applied += 1;
            }
        }

        Ok(report)
    }

    /// A local symbol, or one this image defines, resolves against the load
    /// base; anything else is an import and goes to the caller's resolver.
    fn symbol_address<F>(&self, dynamic: &Dynamic, sym: &Symbol, resolve: &mut F) -> Option<u64>
    where
        F: FnMut(&DynSymbol) -> Option<u64>,
    {
        if sym.bind() == STB_LOCAL || sym.st_value != 0 {
            return Some(self.base.wrapping_add(sym.st_value));
        }
        resolve(&dynamic.decode_symbol(sym)?)
    }

    /// Reads the little-endian `u64` at a virtual address.
    pub fn read_u64(&self, vaddr: u64) -> Result<u64> {
        let bytes = self.slot(vaddr)?;
        Ok(u64::from_le_bytes(
            self.data[bytes.0..bytes.1].try_into().unwrap(),
        ))
    }

    /// Writes a little-endian `u64` at a virtual address.
    pub fn write_u64(&mut self, vaddr: u64, value: u64) -> Result<()> {
        let (start, end) = self.slot(vaddr)?;
        self.data[start..end].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn slot(&self, vaddr: u64) -> Result<(usize, usize)> {
        let end = vaddr.checked_add(8);
        match (usize::try_from(vaddr), end) {
            (Ok(start), Some(end)) if end <= self.data.len() as u64 => Ok((start, end as usize)),
            _ => Err(Error::OutOfBounds {
                what: "relocation target",
                region: "the loaded image",
                offset: vaddr,
                size: 8,
                limit: self.data.len() as u64,
            }),
        }
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align).saturating_mul(align)
}
