//! The image of one file for code analysis (PR-5a spec §4.2, §4.4, §4.6): where code and
//! strings are, the PLT stubs and GOT slots, the FDEs, the relocations that write code, and for
//! a relocatable object the relocations on code fields. The builders are [`linked`] (an
//! executable or shared object) and [`relocatable`].

mod linked;
mod relocatable;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::rc::Rc;

use object::elf;
use object::read::elf::{FileHeader, SectionHeader, SectionTable, Sym as _, SymbolTable};
use object::read::{ReadCacheOps, SymbolIndex};
use object::Endianness;
use sigil_model::ImportVia;

use super::data::Signatures;
use super::reader::Reader;
use super::{Run, STRING_BYTES};
use crate::binary::elf::{Elf, MAX_IMPORT_NAME};
use crate::binary::read::Bounded;

pub(crate) use linked::linked;
pub(crate) use linked::{overlapped_pages, regions};
pub(crate) use relocatable::relocatable;
pub(crate) use relocatable::symbol_offset;

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

    /// Whether §4.2's table gives type `t` a meaning on some code field. `PC64` has one only in
    /// `.eh_frame`.
    pub fn on_code(t: u32) -> bool {
        matches!(
            t,
            PC32 | PLT32 | GOTPCREL | GOTPCRELX | REX_GOTPCRELX | R32 | R32S | R64
        )
    }
}

/// A symbol name. An image reads and holds each distinct string once ([`Names`]), however many
/// slots, stubs, or relocations name it (review C1). A clone is a count.
pub(crate) type Name = Rc<[u8]>;

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
    /// (`linked::regions`); the arithmetic saturates all the same, so a misuse cannot panic.
    pub fn offset_of(&self, addr: u64) -> u64 {
        self.offset.saturating_add(addr.saturating_sub(self.start))
    }
}

/// A symbol a slot or stub names: undefined (`defined: None`) or defined at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sym {
    pub name: Name,
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

/// The relocations on one code field of a relocatable object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reloc {
    One(FieldReloc),
    /// Two different relocations write the field (a crafted object): its meaning is unknown
    /// ([`RelocWhy::Conflict`]). Of a third or later one, only one that names a target is kept,
    /// in place of the second, and only when neither kept one does: a target among them stays
    /// visible.
    Two(FieldReloc, FieldReloc),
}

impl Reloc {
    /// The relocations kept: one or two.
    pub fn each(&self) -> impl Iterator<Item = &FieldReloc> {
        let (a, b) = match self {
            Reloc::One(a) => (a, None),
            Reloc::Two(a, b) => (a, Some(b)),
        };
        std::iter::once(a).chain(b)
    }
}

/// A relocatable object's symbol as relocations use it: an undefined one by name, a defined one
/// by its file offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelSym {
    /// An undefined symbol's name; `None` for a defined one, or a name that cannot be read.
    pub name: Option<Name>,
    /// `S`: a defined symbol's section's `sh_offset` plus its `st_value`. `None` when undefined,
    /// or in no section with file bytes (`SHN_ABS`, `SHN_COMMON`, `SHT_NOBITS`).
    pub at: Option<u64>,
}

/// How an instruction uses a field (spec §4.2's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// The displacement of a `call`, `jmp`, or `jcc rel32`.
    Branch,
    /// The displacement of a `[rip+disp32]` memory operand, not a `lea`'s.
    Memory,
    /// The displacement of a `lea`'s `[rip+disp32]`.
    Lea,
    /// An immediate.
    Immediate,
    /// A displacement not relative to RIP (`[disp32]`, `[base+index*scale+disp32]`, a `lea`'s
    /// included): like an immediate, the field is a value, not `next_ip`-relative (the table's
    /// "absolute displacement").
    Absolute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Callee {
    Import(Name),
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
    SymbolAddr(Name),
    /// The memory operand is the callee's GOT entry.
    GotEntry(Callee),
    /// Not modeled. `symbol` is the relocation's undefined symbol, if any.
    Unknown { symbol: Option<Name>, why: RelocWhy },
}

/// Why a relocated field is not modeled ([`Meaning::Unknown`]). Nothing is formatted until a gap
/// says it ([`RelocWhy::shown`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocWhy {
    /// A branch to the undefined symbol plus this offset (`A + (next_ip − P)`, not 0).
    BranchBeside(i128),
    /// A GOT relocation this far off its entry, or on a field other than a memory operand.
    Got(i128),
    /// `PC32` data of an undefined symbol, other than an exact `lea`.
    PcData,
    /// An absolute relocation of an undefined symbol with an addend.
    AbsoluteBeside,
    /// `PLT32` on a field other than a branch displacement.
    PltOffBranch,
    /// A type not modeled on this field.
    Type(u32),
    /// Two different relocations write the field ([`Reloc::Two`]).
    Conflict,
    /// No symbol, or a defined one in no section with file bytes.
    NoAddress,
    /// The address passes 2^64 or 0.
    OutOfRange,
}

impl RelocWhy {
    /// The gap text (spec §4.2's where it has one), naming `symbol`, the relocation's, where the
    /// text needs it: `branch to connect+4`.
    pub fn shown<'a>(&'a self, symbol: Option<&'a Name>) -> impl fmt::Display + 'a {
        Shown { why: self, symbol }
    }
}

impl fmt::Display for RelocWhy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.shown(None).fmt(f)
    }
}

/// [`RelocWhy::shown`].
struct Shown<'a> {
    why: &'a RelocWhy,
    symbol: Option<&'a Name>,
}

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.why {
            RelocWhy::BranchBeside(off) => match self.symbol {
                Some(name) => write!(f, "branch to {}{off:+}", String::from_utf8_lossy(name)),
                None => write!(f, "branch to the symbol{off:+}"),
            },
            RelocWhy::Got(off) => write!(f, "GOT reference {off:+}"),
            RelocWhy::PcData => f.write_str("PC32 data of an undefined symbol"),
            RelocWhy::AbsoluteBeside => f.write_str("an absolute address beside the symbol"),
            RelocWhy::PltOffBranch => f.write_str("PLT32 off a branch"),
            RelocWhy::Type(t) => write!(f, "relocation type {t}"),
            RelocWhy::Conflict => f.write_str("two relocations on the field"),
            RelocWhy::NoAddress => f.write_str("a symbol without an address"),
            RelocWhy::OutOfRange => f.write_str("an address out of range"),
        }
    }
}

/// Which FDE holds an address ([`Image::fde_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FdeAt {
    /// No FDE.
    None,
    /// This FDE alone.
    One((u64, u64)),
    /// Two FDEs or more (spec §4.5: a gap).
    Overlap,
}

/// The image of one file.
#[derive(Debug)]
pub(crate) struct Image {
    pub kind: Kind,
    /// Executable bytes: file-backed `PF_X` ranges minus overlapped pages, or a relocatable
    /// object's `SHF_EXECINSTR` sections (overlapping ones merged). Sorted and disjoint:
    /// [`Image::code_at`] searches it.
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
    /// Bytes inside code that a dynamic relocation writes: sorted and merged
    /// ([`Image::set_textrel`]).
    pub textrel: Vec<(u64, u64)>,
    /// A relocatable object's relocations on code, by field address ([`Image::field`]).
    pub relocs: BTreeMap<u64, Reloc>,
    /// The symbols `relocs` and `.rela.eh_frame` name, by `.symtab` index.
    pub rel_syms: BTreeMap<u32, RelSym>,
    /// The capability imports this file has (undefined symbols).
    pub targets: BTreeSet<Name>,
    /// FDE ranges, sorted by start ([`Image::set_fdes`]).
    pub fdes: Vec<(u64, u64)>,
    /// `fde_max[i]`: the index of an FDE with the largest end among `fdes[..=i]`.
    pub fde_max: Vec<usize>,
    /// Where two FDEs or more cover: sorted, merged ranges.
    pub fde_shared: Vec<(u64, u64)>,
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
            fde_max: vec![],
            fde_shared: vec![],
        }
    }

    /// Sets the FDEs, sorted, with which one reaches furthest so far and where two or more
    /// cover. An FDE meets an earlier one exactly where it starts before the furthest end so far:
    /// `[start, min(end, that end))`, covered by both. Those ranges, merged, are every address two
    /// FDEs hold.
    pub fn set_fdes(&mut self, mut fdes: Vec<(u64, u64)>) {
        fdes.sort_unstable();
        let mut max: Option<(u64, usize)> = None;
        let mut fde_max = Vec::with_capacity(fdes.len());
        let mut shared: Vec<(u64, u64)> = vec![];
        for (i, &(start, end)) in fdes.iter().enumerate() {
            if let Some((reach, _)) = max {
                let cut = (start, end.min(reach));
                if cut.0 < cut.1 {
                    match shared.last_mut() {
                        Some(last) if cut.0 <= last.1 => last.1 = last.1.max(cut.1),
                        _ => shared.push(cut),
                    }
                }
            }
            if max.is_none_or(|(reach, _)| end > reach) {
                max = Some((end, i));
            }
            fde_max.push(max.map_or(i, |(_, at)| at));
        }
        self.fdes = fdes;
        self.fde_max = fde_max;
        self.fde_shared = shared;
    }

    /// The FDE holding `addr`, by binary search. In a range two FDEs cover: `Overlap`. Elsewhere
    /// at most one FDE holds `addr`, and if one does, the one reaching furthest among those
    /// starting at or before `addr` does.
    pub fn fde_at(&self, addr: u64) -> FdeAt {
        let s = self.fde_shared.partition_point(|r| r.1 <= addr);
        if self.fde_shared.get(s).is_some_and(|r| r.0 <= addr) {
            return FdeAt::Overlap;
        }
        let i = self.fdes.partition_point(|f| f.0 <= addr);
        match i
            .checked_sub(1)
            .and_then(|last| self.fde_max.get(last))
            .and_then(|at| self.fdes.get(*at))
        {
            Some(f) if addr < f.1 => FdeAt::One(*f),
            _ => FdeAt::None,
        }
    }

    /// The code region holding `[start, end)` whole, by binary search. In sorted, disjoint
    /// regions only the first one not ending before `start`, or the next if it starts at `start`,
    /// can.
    pub fn code_at(&self, start: u64, end: u64) -> Option<&Region> {
        let i = self.code.partition_point(|r| r.end < start);
        self.code
            .get(i..)?
            .iter()
            .take(2)
            .find(|r| r.holds(start, end))
    }

    /// Sets the bytes dynamic relocations write in code: sorted, and merged where they meet.
    pub fn set_textrel(&mut self, mut ranges: Vec<(u64, u64)>) {
        ranges.retain(|r| r.0 < r.1);
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.textrel = merged;
    }

    /// Whether `[start, end)` meets bytes a dynamic relocation writes, by binary search.
    pub fn textrel_overlaps(&self, start: u64, end: u64) -> bool {
        let i = self.textrel.partition_point(|t| t.1 <= start);
        self.textrel.get(i).is_some_and(|t| t.0 < end)
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

/// The name of `sym`, read as the imports step reads it (spec §3.7): object's read first (cached
/// by the imports step), then, past the 4096 bytes object reads, on through [`Elf::name`], up to
/// `max` bytes. `Ok(None)`: longer than `max`. The bytes are the parse cache's: nothing is copied.
pub(crate) fn name_of<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    sym: &H::Sym,
    max: usize,
) -> Result<Option<&'d [u8]>, String> {
    let endian = e.endian;
    if let Ok(name) = sym.name(endian, symbols.strings()) {
        return Ok((name.len() <= max).then_some(name));
    }
    match table
        .section(symbols.string_section())
        .ok()
        .and_then(|s| s.file_range(endian))
    {
        Some(strings) => e.name(strings, sym.st_name(endian), max),
        None => Err("no string table in the file".to_string()),
    }
}

/// The symbol names of one image, each read and held once, by (string table, `st_name`) (review
/// C1). The first read of a name goes through the parse cache, which charges it to
/// `binary_parse_bytes` (once, in the imports step, for most), and a read the cache serves again
/// is not copied again: the names held are bounded by that budget, not by how many symbols,
/// slots, or relocations name them.
#[derive(Debug, Default)]
pub(crate) struct Names {
    /// `Ok(None)`: longer than [`MAX_IMPORT_NAME`].
    read: BTreeMap<(usize, u32), Result<Option<Name>, String>>,
    /// The names [`target_names`] found are no capability's, or cannot be read (its gap says so):
    /// it does not read them again for another symbol. A repeat of a name past the 4096 bytes
    /// object reads would otherwise charge the parse budget a failed search each time.
    not_targets: BTreeSet<(usize, u32)>,
}

impl Names {
    /// The name of `sym` of `symbols` ([`name_of`]), up to [`MAX_IMPORT_NAME`] bytes, as the
    /// imports step keeps it. `Err`: why it cannot be read, a longer name included.
    pub fn of<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
        &mut self,
        e: &Elf<'d, R, H>,
        table: &SectionTable<'d, H, &'d Bounded<R>>,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
        sym: &H::Sym,
    ) -> Result<Name, String> {
        let key = (symbols.string_section().0, sym.st_name(e.endian));
        let found = match self.read.get(&key) {
            Some(found) => found.clone(),
            None => {
                let found = name_of(e, table, symbols, sym, MAX_IMPORT_NAME)
                    .map(|name| name.map(Name::from));
                self.read.insert(key, found.clone());
                found
            }
        };
        found.and_then(|name| name.ok_or_else(|| format!("a name over {MAX_IMPORT_NAME} bytes")))
    }

    /// Symbol `index` of `symbols`: its name ([`Self::of`]) and, if defined, its value.
    pub fn sym<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
        &mut self,
        e: &Elf<'d, R, H>,
        table: &SectionTable<'d, H, &'d Bounded<R>>,
        symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
        index: u32,
    ) -> Result<Sym, String> {
        let sym = symbols
            .symbol(SymbolIndex(index as usize))
            .map_err(|e| e.to_string())?;
        let name = self.of(e, table, symbols, sym)?;
        let defined =
            (sym.st_shndx(e.endian) != elf::SHN_UNDEF).then(|| sym.st_value(e.endian).into());
        Ok(Sym { name, defined })
    }
}

/// The undefined `GLOBAL`/`WEAK` symbols of `symbols` that the capability table names, held in
/// `names`. A name is read only as far as the longest capability name ([`name_of`]): a longer
/// one is not one, and nothing is held for it. A name that cannot be read could be a
/// capability's: a gap, never a silent skip (as for the data symbols, PR-4b).
pub(crate) fn target_names<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    symbols: &SymbolTable<'d, H, &'d Bounded<R>>,
    sig: &Signatures,
    names: &mut Names,
    run: &mut Run,
) -> BTreeSet<Name> {
    let endian = e.endian;
    let mut out = BTreeSet::new();
    for sym in symbols.symbols().iter().skip(1) {
        let bind = sym.st_bind();
        if sym.st_shndx(endian) != elf::SHN_UNDEF
            || !(bind == elf::STB_GLOBAL || bind == elf::STB_WEAK)
        {
            continue;
        }
        let key = (symbols.string_section().0, sym.st_name(endian));
        if names.not_targets.contains(&key) {
            continue;
        }
        let read = match names.read.get(&key) {
            Some(found) => found.clone(),
            None => match name_of(e, table, symbols, sym, sig.longest()) {
                // A complete name: held only if it is a capability's.
                Ok(Some(name)) if sig.capability(name).is_some() => {
                    let name = Name::from(name);
                    names.read.insert(key, Ok(Some(name.clone())));
                    Ok(Some(name))
                }
                Ok(_) => Ok(None),
                // Not kept: one gap says it, and no string is held per name.
                Err(why) => Err(why),
            },
        };
        match read {
            Ok(Some(name)) if sig.capability(&name).is_some() => {
                out.insert(name);
            }
            Ok(_) => {
                names.not_targets.insert(key);
            }
            Err(why) => {
                run.gap(format!("code: an import's name cannot be read: {why}"));
                names.not_targets.insert(key);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fde_at_tells_none_one_and_overlap() {
        let mut img = Image::empty(Kind::Shared);
        // A long FDE holding a short one; one beside them; one far off; two that touch.
        img.set_fdes(vec![
            (0x100, 0x200),
            (0x300, 0x1000),
            (0x400, 0x500),
            (0x2000, 0x2100),
            (0x2100, 0x2200),
        ]);
        let long = FdeAt::One((0x300, 0x1000));
        assert_eq!(img.fde_at(0x50), FdeAt::None, "before every FDE");
        assert_eq!(img.fde_at(0x150), FdeAt::One((0x100, 0x200)));
        assert_eq!(img.fde_at(0x250), FdeAt::None, "between FDEs");
        // Spec §4.5: only an address in the overlap is a gap.
        assert_eq!(img.fde_at(0x350), long, "only in the long one");
        assert_eq!(img.fde_at(0x400), FdeAt::Overlap, "the overlap's start");
        assert_eq!(img.fde_at(0x450), FdeAt::Overlap, "in both");
        assert_eq!(img.fde_at(0x4ff), FdeAt::Overlap, "the overlap's last byte");
        assert_eq!(img.fde_at(0x500), long, "past the short one");
        assert_eq!(img.fde_at(0xfff), long);
        assert_eq!(img.fde_at(0x1000), FdeAt::None, "the long one's end");
        assert_eq!(img.fde_at(0x20ff), FdeAt::One((0x2000, 0x2100)));
        assert_eq!(
            img.fde_at(0x2100),
            FdeAt::One((0x2100, 0x2200)),
            "touching is no overlap"
        );
        assert_eq!(img.fde_at(u64::MAX), FdeAt::None);

        // A chain: [0, 0x10) and [5, 0x20) share [5, 0x10); [0x10, 0x18) shares [0x10, 0x18)
        // with the second: one overlap [5, 0x18). [0x15, 0x30) adds [0x18, 0x20).
        img.set_fdes(vec![(0, 0x10), (5, 0x20), (0x10, 0x18), (0x15, 0x30)]);
        assert_eq!(img.fde_at(4), FdeAt::One((0, 0x10)));
        for addr in [5, 0xf, 0x10, 0x17, 0x18, 0x1f] {
            assert_eq!(img.fde_at(addr), FdeAt::Overlap, "{addr:#x}");
        }
        assert_eq!(img.fde_at(0x20), FdeAt::One((0x15, 0x30)));
        assert_eq!(img.fde_at(0x2f), FdeAt::One((0x15, 0x30)));
        assert_eq!(img.fde_at(0x30), FdeAt::None);
    }

    #[test]
    fn code_at_finds_the_region_holding_a_range() {
        let mut img = Image::empty(Kind::Shared);
        let region = |start, end| Region {
            start,
            end,
            offset: start,
        };
        img.code = vec![
            region(0x1000, 0x2000),
            region(0x2000, 0x3000),
            region(0x5000, 0x6000),
        ];
        assert_eq!(img.code_at(0x1ff0, 0x2000), Some(&region(0x1000, 0x2000)));
        assert_eq!(img.code_at(0x2000, 0x2010), Some(&region(0x2000, 0x3000)));
        assert_eq!(img.code_at(0x2000, 0x2000), Some(&region(0x1000, 0x2000)));
        assert_eq!(img.code_at(0x1ff0, 0x2010), None, "across two regions");
        assert_eq!(img.code_at(0x4000, 0x4001), None);
        assert_eq!(img.code_at(0x5000, 0x6000), Some(&region(0x5000, 0x6000)));
        assert_eq!(img.code_at(0x6000, 0x6001), None);
    }

    #[test]
    fn text_relocations_are_sorted_merged_and_searched() {
        let mut img = Image::empty(Kind::Shared);
        img.set_textrel(vec![
            (0x30, 0x38),
            (0x10, 0x18),
            (0x18, 0x20),
            (0x5, 0x5),
            (0x100, u64::MAX),
        ]);
        assert_eq!(img.textrel, [(0x10, 0x20), (0x30, 0x38), (0x100, u64::MAX)]);
        assert!(!img.textrel_overlaps(0x20, 0x30));
        assert!(img.textrel_overlaps(0x1f, 0x21));
        assert!(!img.textrel_overlaps(0x38, 0x100));
        assert!(img.textrel_overlaps(0x200, 0x201));
        assert!(!img.textrel_overlaps(0, 0x10));
    }

    /// Task 6 review: 2,000 undefined symbols naming one 5,000-byte name, past the 4096 bytes
    /// object reads: each object read of it fails and is charged a full search (4,224 bytes).
    /// `target_names` reads it once, not once per symbol (8 MB).
    #[test]
    fn a_long_name_many_symbols_share_is_read_once() {
        use crate::binary::read::{Budgeted, ENTRY_OVERHEAD, STRING_LIMIT};
        use crate::binary::{elf as binelf, BinaryBudgets};
        use crate::code::{data, synth, CodeBudgets};
        use object::elf::FileHeader64;

        let mut syms = vec![0u8; 24];
        for _ in 0..2000 {
            syms.extend_from_slice(&synth::sym64(1, 0x12, 0, 0, 0));
        }
        let strs = [&[0u8][..], &[b'n'; 5000], &[0]].concat();
        let strs_at = 0x1000 + syms.len() as u64;
        let mut img = synth::ElfImage::new(3);
        img.put(0x1000, &syms).put(strs_at, &strs);
        img.sec_linked(
            ".dynsym",
            synth::SHT_DYNSYM,
            0x1000,
            0x1000,
            syms.len() as u64,
            2,
            24,
        )
        .sec(".dynstr", synth::SHT_STRTAB, strs_at, 0, strs.len() as u64);
        let file = synth::file(&img.build());
        let size = file.metadata().unwrap().len();
        let data = Bounded::new(Budgeted::new(&file, size), size, 64 << 20);
        let p =
            binelf::parts::<_, FileHeader64<Endianness>>(&data, BinaryBudgets::default()).unwrap();
        let table = p.sections.table.as_ref().unwrap();
        let symbols = p.sections.symbols.as_ref().unwrap();
        let mut names = Names::default();
        let mut run = Run::new(CodeBudgets::default());
        let before = data.used();
        let sig = data::signatures().unwrap();
        let targets = target_names(&p.elf, table, symbols, sig, &mut names, &mut run);
        let used = data.used() - before;
        assert!(targets.is_empty());
        assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        assert!(!data.refused());
        assert!(used <= 2 * (STRING_LIMIT + ENTRY_OVERHEAD), "{used} bytes");
    }

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
