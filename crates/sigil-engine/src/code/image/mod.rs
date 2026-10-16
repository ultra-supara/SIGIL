//! The image of one file for code analysis (PR-5a spec §4.2, §4.4, §4.6): where code and
//! strings are, the PLT stubs and GOT slots, the FDEs, the relocations that write code, and for
//! a relocatable object the relocations on code fields. The builders are [`linked`] (an
//! executable or shared object) and, from Task 7, `relocatable`.

// Used outside tests from Task 11 (`analyze`); until then only tests build an image.
#![allow(dead_code)]

mod linked;

use std::collections::{BTreeMap, BTreeSet};

use object::elf;
use object::read::elf::{FileHeader, SectionHeader, Sym as _, SymbolTable};
use object::read::{ReadCacheOps, SymbolIndex};
use object::Endianness;
use sigil_model::ImportVia;

use super::data::Signatures;
use super::reader::Reader;
use super::{Run, STRING_BYTES};
use crate::binary::elf::Elf;
use crate::binary::read::Bounded;

// Called outside tests from Task 11 (`analyze`); until then only the test helper calls it.
#[allow(unused_imports)]
pub(crate) use linked::linked;

/// The x86-64 page the loader maps.
pub(crate) const PAGE: u64 = 4096;

/// x86-64 relocation types (psABI); `tests::types_match_object` checks them against `object`.
pub(crate) mod rtype {
    pub const R64: u32 = 1;
    pub const PC32: u32 = 2;
    pub const PLT32: u32 = 4;
    pub const GLOB_DAT: u32 = 6;
    pub const JUMP_SLOT: u32 = 7;
    pub const GOTPCREL: u32 = 9;
    pub const R32: u32 = 10;
    pub const R32S: u32 = 11;
    pub const PC64: u32 = 24;
    pub const GOTPCRELX: u32 = 41;
    pub const REX_GOTPCRELX: u32 = 42;
}

/// `[start, end)` of an address space, at file offset `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Region {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
}

impl Region {
    pub fn holds(&self, start: u64, end: u64) -> bool {
        self.start <= start && start <= end && end <= self.end
    }

    /// The file offset of `addr`, an address of the region. A region's offsets do not overflow
    /// ([`regions`]); the arithmetic saturates all the same, so a misuse cannot panic.
    pub fn offset_of(&self, addr: u64) -> u64 {
        self.offset.saturating_add(addr.saturating_sub(self.start))
    }
}

/// A symbol a slot or stub names: undefined (`defined: None`) or defined at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sym {
    pub name: Vec<u8>,
    pub defined: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Shared,
    Executable,
    Relocatable,
}

/// A relocation on a code field of a relocatable object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldReloc {
    pub r_type: u32,
    pub sym: u32,
    pub addend: i64,
}

/// A relocatable object's symbol as relocations use it: an undefined one by name, a defined one
/// by its file offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelSym {
    pub name: Option<Vec<u8>>,
    pub at: Option<u64>,
}

/// How an instruction uses a field (spec §4.2's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    Branch,
    Memory,
    Lea,
    Immediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Callee {
    Import(Vec<u8>),
    Internal(u64),
}

/// What a relocated field means (spec §4.2's table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Meaning {
    /// A call or jump to the callee.
    Branch(Callee),
    /// A defined address.
    Address(u64),
    /// An undefined symbol's address.
    SymbolAddr(Vec<u8>),
    /// The memory operand is the callee's GOT entry.
    GotEntry(Callee),
    /// Not modeled. `symbol` is the relocation's undefined symbol, if any.
    Unknown {
        symbol: Option<Vec<u8>>,
        why: String,
    },
}

/// The image of one file.
#[derive(Debug)]
pub(crate) struct Image {
    pub kind: Kind,
    /// Executable bytes: file-backed `PF_X` ranges minus overlapped pages, or a relocatable
    /// object's `SHF_EXECINSTR` sections. Sorted and disjoint.
    pub code: Vec<Region>,
    /// Where a constant string may be.
    pub strings: Vec<Region>,
    /// `SHF_EXECINSTR` sections `[start, end)`.
    pub sections: Vec<(u64, u64)>,
    /// `.plt`, `.plt.sec`, `.plt.got`: not searched.
    pub plt: Vec<(u64, u64)>,
    /// PLT stub → (its GOT slot, its section's `via`).
    pub stubs: BTreeMap<u64, (u64, ImportVia)>,
    /// GOT slot (`JUMP_SLOT`/`GLOB_DAT`) → its symbol.
    pub slots: BTreeMap<u64, Sym>,
    /// Bytes inside code that a dynamic relocation writes.
    pub textrel: Vec<(u64, u64)>,
    /// A relocatable object's relocations on code, by field address.
    pub relocs: BTreeMap<u64, FieldReloc>,
    pub rel_syms: BTreeMap<u32, RelSym>,
    /// The capability imports this file has (undefined symbols).
    pub targets: BTreeSet<Vec<u8>>,
    /// FDE ranges, sorted by start.
    pub fdes: Vec<(u64, u64)>,
    /// `fde_ends[i]`: the largest end among `fdes[..=i]`, for containment queries.
    pub fde_ends: Vec<u64>,
}

impl Image {
    pub fn empty(kind: Kind) -> Image {
        Image {
            kind,
            code: vec![],
            strings: vec![],
            sections: vec![],
            plt: vec![],
            stubs: BTreeMap::new(),
            slots: BTreeMap::new(),
            textrel: vec![],
            relocs: BTreeMap::new(),
            rel_syms: BTreeMap::new(),
            targets: BTreeSet::new(),
            fdes: vec![],
            fde_ends: vec![],
        }
    }

    /// Sets the FDEs (sorted) and their running maximum end.
    pub fn set_fdes(&mut self, fdes: Vec<(u64, u64)>) {
        let mut max = 0;
        self.fde_ends = fdes
            .iter()
            .map(|f| {
                max = max.max(f.1);
                max
            })
            .collect();
        self.fdes = fdes;
    }

    /// The code region holding `[start, end)` whole.
    pub fn code_at(&self, start: u64, end: u64) -> Option<&Region> {
        self.code.iter().find(|r| r.holds(start, end))
    }

    /// The FDEs containing `addr`.
    pub fn fdes_at(&self, addr: u64) -> Vec<(u64, u64)> {
        let mut out = vec![];
        let mut i = self.fdes.partition_point(|f| f.0 <= addr);
        while i > 0 {
            i -= 1;
            if self.fde_ends.get(i).is_none_or(|e| *e <= addr) {
                break;
            }
            if let Some(f) = self.fdes.get(i) {
                if addr < f.1 {
                    out.push(*f);
                }
            }
        }
        out
    }

    /// Whether `[start, end)` meets bytes a dynamic relocation writes.
    pub fn textrel_overlaps(&self, start: u64, end: u64) -> bool {
        self.textrel.iter().any(|(s, e)| start < *e && *s < end)
    }

    /// The symbol a stub or a slot address names, with its `via`.
    pub fn symbol_at(&self, addr: u64) -> Option<(Sym, ImportVia)> {
        if let Some((slot, via)) = self.stubs.get(&addr) {
            return self.slots.get(slot).map(|s| (s.clone(), *via));
        }
        self.slots.get(&addr).map(|s| (s.clone(), ImportVia::Got))
    }

    /// Whether `sym` is a capability import of this file.
    pub fn is_target(&self, sym: &Sym) -> bool {
        sym.defined.is_none() && self.targets.contains(&sym.name)
    }

    /// The NUL-terminated string at `addr`, of at most `STRING_BYTES` bytes, in a string region.
    pub fn string(&self, addr: u64, reader: &mut Reader<'_>, run: &mut Run) -> Option<Vec<u8>> {
        let r = self
            .strings
            .iter()
            .find(|r| r.start <= addr && addr < r.end)?;
        let len = (r.end - addr).min(STRING_BYTES);
        match reader.read(r.offset_of(addr), len) {
            Ok(bytes) => {
                let end = bytes.iter().position(|b| *b == 0)?;
                bytes.get(..end).map(<[u8]>::to_vec)
            }
            Err(why) => {
                run.refusal(why, "string", reader);
                None
            }
        }
    }
}

/// A symbol of `symbols` by index: its name and, if defined, its value.
pub(crate) fn read_sym<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    endian: Endianness,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    index: u32,
) -> Option<Sym> {
    let sym = symbols.symbol(SymbolIndex(index as usize)).ok()?;
    let name = sym.name(endian, symbols.strings()).ok()?.to_vec();
    let defined = (sym.st_shndx(endian) != elf::SHN_UNDEF).then(|| sym.st_value(endian).into());
    Some(Sym { name, defined })
}

/// The undefined `GLOBAL`/`WEAK` symbols of `symbols` that the capability table names.
///
/// A name that cannot be read could be a capability's: a gap, never a silent skip (as for the
/// data symbols, PR-4b). object's read, cached by the imports step, comes first; when it fails
/// (it stops looking for the NUL after 4096 bytes), the name is read on, only as far as the
/// longest capability name: a longer one is not one.
pub(crate) fn target_names<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    sig: &Signatures,
    run: &mut Run,
) -> BTreeSet<Vec<u8>> {
    let endian = e.endian;
    let mut out = BTreeSet::new();
    // The symbols' string table (its file range), found at the first name object cannot read.
    let mut strings: Option<Option<(u64, u64)>> = None;
    for sym in symbols.symbols().iter().skip(1) {
        let bind = sym.st_bind();
        if sym.st_shndx(endian) != elf::SHN_UNDEF
            || !(bind == elf::STB_GLOBAL || bind == elf::STB_WEAK)
        {
            continue;
        }
        let name = match sym.name(endian, symbols.strings()) {
            Ok(name) => name,
            Err(_) => {
                let range = *strings.get_or_insert_with(|| {
                    e.header
                        .sections(endian, e.data)
                        .ok()
                        .and_then(|t| t.section(symbols.string_section()).ok())
                        .and_then(|s| s.file_range(endian))
                });
                let read = match range {
                    Some(range) => e.name(range, sym.st_name(endian), sig.longest()),
                    None => Err("no string table in the file".to_string()),
                };
                match read {
                    Ok(Some(name)) => name,
                    // Longer than every capability name.
                    Ok(None) => continue,
                    Err(why) => {
                        run.gap(format!("code: an import's name cannot be read: {why}"));
                        continue;
                    }
                }
            }
        };
        if name.len() <= sig.longest() && sig.capability(name).is_some() {
            out.insert(name.to_vec());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_match_object() {
        assert_eq!(rtype::PC32, elf::R_X86_64_PC32.0);
        assert_eq!(rtype::PLT32, elf::R_X86_64_PLT32.0);
        assert_eq!(rtype::GLOB_DAT, elf::R_X86_64_GLOB_DAT.0);
        assert_eq!(rtype::JUMP_SLOT, elf::R_X86_64_JUMP_SLOT.0);
        assert_eq!(rtype::GOTPCREL, elf::R_X86_64_GOTPCREL.0);
        assert_eq!(rtype::GOTPCRELX, elf::R_X86_64_GOTPCRELX.0);
        assert_eq!(rtype::REX_GOTPCRELX, elf::R_X86_64_REX_GOTPCRELX.0);
        assert_eq!(
            (rtype::R64, rtype::R32, rtype::R32S, rtype::PC64),
            (
                elf::R_X86_64_64.0,
                elf::R_X86_64_32.0,
                elf::R_X86_64_32S.0,
                elf::R_X86_64_PC64.0
            )
        );
    }
}
