//! The image of one file for code analysis (PR-5a spec §4.2, §4.4, §4.6): where code and
//! strings are, the PLT stubs and GOT slots, the FDEs, the relocations that write code, and for
//! a relocatable object the relocations on code fields.

// Used outside tests from Task 11 (`analyze`); until then only tests build an image.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader, Sym as _, SymbolTable};
use object::read::{ReadCacheOps, SymbolIndex};
use object::Endianness;
use sigil_model::ImportVia;

use super::data::Signatures;
use super::reader::Reader;
use super::{fde, Run, STRING_BYTES};
use crate::binary::elf::{Dynamic, Elf, Rela, Sections};
use crate::binary::read::Bounded;
use crate::binary::vaddr::{Load, Loads, Place};

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

/// The page ranges that two `PT_LOAD`s share, merged. A sweep over the sorted ranges, so a file
/// with many segments costs `n log n`.
pub(crate) fn overlapped_pages(loads: &Loads) -> Vec<(u64, u64)> {
    let mut pages: Vec<(u64, u64)> = loads
        .0
        .iter()
        .filter_map(|l| {
            let start = l.vaddr & !(PAGE - 1);
            let end = l.vaddr.checked_add(l.memsz)?.checked_add(PAGE - 1)? & !(PAGE - 1);
            (start < end).then_some((start, end))
        })
        .collect();
    pages.sort_unstable();
    let mut out: Vec<(u64, u64)> = vec![];
    let mut reach = 0;
    for (start, end) in pages {
        if start < reach {
            let cut = (start, end.min(reach));
            match out.last_mut() {
                Some(last) if last.1 >= cut.0 => last.1 = last.1.max(cut.1),
                _ => out.push(cut),
            }
        }
        reach = reach.max(end);
    }
    out
}

/// The file-backed ranges of the `PT_LOAD`s `want` selects, minus `cuts`, sorted. A segment
/// whose file range passes 2^64 is in no file: it gives none.
pub(crate) fn regions(loads: &Loads, want: fn(&Load) -> bool, cuts: &[(u64, u64)]) -> Vec<Region> {
    let mut out = vec![];
    for l in loads.0.iter().filter(|l| want(l)) {
        let (Some(end), Some(_)) = (
            l.vaddr.checked_add(l.filesz),
            l.offset.checked_add(l.filesz),
        ) else {
            continue;
        };
        let mut parts = vec![(l.vaddr, end)];
        for (cs, ce) in cuts {
            parts = parts
                .into_iter()
                .flat_map(|(s, e)| {
                    if *ce <= s || e <= *cs {
                        vec![(s, e)]
                    } else {
                        [(s, (*cs).max(s)), ((*ce).min(e), e)]
                            .into_iter()
                            .filter(|(a, b)| a < b)
                            .collect()
                    }
                })
                .collect();
        }
        for (s, e) in parts {
            out.push(Region {
                start: s,
                end: e,
                offset: l.offset + (s - l.vaddr),
            });
        }
    }
    out.sort_unstable();
    out
}

/// The stubs of one PLT section: each `jmp [rip+slot]` to a known slot, and an `endbr64` right
/// before it. `Err(addr)`: an invalid instruction at `addr`, and no stub of the section is kept.
pub(crate) fn plt_stubs(
    bytes: &[u8],
    start: u64,
    slots: &BTreeMap<u64, Sym>,
) -> Result<Vec<(u64, u64)>, u64> {
    let mut dec = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    let mut prev: Option<Instruction> = None;
    let mut out = vec![];
    while dec.can_decode() {
        dec.decode_out(&mut ins);
        if ins.is_invalid() {
            return Err(ins.ip());
        }
        if ins.flow_control() == FlowControl::IndirectBranch && ins.is_ip_rel_memory_operand() {
            let slot = ins.ip_rel_memory_address();
            if slots.contains_key(&slot) {
                out.push((ins.ip(), slot));
                if let Some(p) =
                    prev.filter(|p| p.mnemonic() == Mnemonic::Endbr64 && p.next_ip() == ins.ip())
                {
                    out.push((p.ip(), slot));
                }
            }
        }
        prev = Some(ins);
    }
    out.sort_unstable();
    Ok(out)
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

/// The image of an executable or shared object, or `None` when it has no section headers.
pub(crate) fn linked<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'d, R, H>,
    sections: &Sections<'d, R, H>,
    dynamic: &Dynamic,
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Option<Image> {
    let endian = e.endian;
    let Some(table) = sections.table.as_ref() else {
        run.gap("code: no section headers".to_string());
        return None;
    };
    let kind = if e.header.e_type(endian) == elf::ET_EXEC {
        Kind::Executable
    } else {
        Kind::Shared
    };
    let mut img = Image::empty(kind);
    let overlaps = overlapped_pages(&e.loads);
    for (start, _) in &overlaps {
        run.gap(format!("code: PT_LOAD segments overlap at {start:#x}"));
    }
    img.code = regions(&e.loads, |l| l.executable, &overlaps);
    img.strings = regions(&e.loads, |l| !l.writable && !l.executable, &overlaps);
    for s in table.iter() {
        if s.sh_flags(endian).0 & elf::SHF_EXECINSTR.0 != 0 && s.sh_type(endian) != elf::SHT_NOBITS
        {
            let start: u64 = s.sh_addr(endian).into();
            let size: u64 = s.sh_size(endian).into();
            if let Some(end) = start.checked_add(size) {
                img.sections.push((start, end));
            }
        }
    }
    // The loader binds imports through PT_DYNAMIC (DT_SYMTAB, DT_STRTAB, the relocations), never
    // through section headers. Without the very table it reads, the imports cannot be listed, and
    // "no target" would be a false Complete (plan review P1-1): a gap instead, and no search.
    let has_dynamic = e.phdrs.iter().any(|p| p.p_type(endian) == elf::PT_DYNAMIC);
    let symbols = sections
        .symbols
        .as_ref()
        .filter(|_| sections.dynamic_symbols_agree);
    if has_dynamic && (!dynamic.read || symbols.is_none()) {
        run.gap(
            "code: the dynamic symbols the loader binds through cannot be read; imports not listed"
                .to_string(),
        );
        return Some(img);
    }
    if let Some(symbols) = symbols {
        img.targets = target_names(e, symbols, sig, run);
    }
    // GOT slots, and the dynamic relocations that write code (text relocations).
    let mut slot_syms: BTreeMap<u64, Option<u32>> = BTreeMap::new();
    let mut textrel_syms: Vec<(u64, u64, u32)> = vec![];
    let code = img.code.clone();
    let limit = run.budgets.references;
    let mut over = false;
    let walk = e.for_each_rela(dynamic, symbols, |r: Rela| {
        if r.r_type == rtype::JUMP_SLOT || r.r_type == rtype::GLOB_DAT {
            slot_syms
                .entry(r.at)
                .and_modify(|s| {
                    if *s != Some(r.sym) {
                        *s = None;
                    }
                })
                .or_insert(Some(r.sym));
        }
        let (at, end) = textrel_range(&r);
        if at < end && code.iter().any(|c| at < c.end && c.start < end) {
            if textrel_syms.len() >= limit {
                over = true;
            } else {
                textrel_syms.push((at, end, r.sym));
            }
        }
    });
    if let Err(why) = walk {
        run.gap(format!("code: relocations: {why}"));
    }
    if over {
        run.limit("references", limit as u64);
    }
    for (at, end, sym) in &textrel_syms {
        img.textrel.push((*at, *end));
        if let Some(s) = symbols.and_then(|t| read_sym(endian, t, *sym)) {
            if img.is_target(&s) {
                run.gap(format!(
                    "code: {}: text relocation at {at:#x}",
                    String::from_utf8_lossy(&s.name)
                ));
            }
        }
    }
    if let Some(symbols) = symbols {
        for (at, sym) in slot_syms {
            let Some(index) = sym else {
                run.gap(format!("code: GOT slot {at:#x} has two symbols"));
                continue;
            };
            match read_sym(endian, symbols, index) {
                Some(s) => {
                    img.slots.insert(at, s);
                }
                None => run.gap(format!("code: GOT slot {at:#x}: symbol {index} unreadable")),
            }
        }
    }
    for (name, via) in [
        (".plt", ImportVia::Plt),
        (".plt.got", ImportVia::Plt),
        (".plt.sec", ImportVia::PltSec),
    ] {
        let Some(s) = e.section_named(table, name.as_bytes()) else {
            continue;
        };
        let start: u64 = s.sh_addr(endian).into();
        let size: u64 = s.sh_size(endian).into();
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        img.plt.push((start, end));
        let Some(region) = img.code_at(start, end).copied() else {
            run.gap(format!("code: {name}: not in executable bytes"));
            continue;
        };
        let bytes = match reader.read(region.offset_of(start), size) {
            Ok(b) => b,
            Err(why) => {
                run.refusal(why, name, reader);
                continue;
            }
        };
        match plt_stubs(&bytes, start, &img.slots) {
            Ok(found) => {
                for (stub, slot) in found {
                    img.stubs.insert(stub, (slot, via));
                }
            }
            Err(at) => run.gap(format!("code: {name}: decode failure at {at:#x}")),
        }
    }
    if let Some(s) = e.section_named(table, b".eh_frame") {
        let start: u64 = s.sh_addr(endian).into();
        let size: u64 = s.sh_size(endian).into();
        match e.loads.place(start, size) {
            Place::File(off) => match reader.read(off, size) {
                Ok(bytes) => img.set_fdes(fde::parse(&bytes, start, run)),
                Err(why) => run.refusal(why, ".eh_frame", reader),
            },
            _ => run.gap("code: .eh_frame: not in the file".to_string()),
        }
    }
    Some(img)
}

/// The bytes a dynamic relocation writes (plan review P2): `[at, at + extent)` from
/// [`Elf::write_extent`], or to the end of the address space when unbounded, so every
/// instruction after it in that code fails.
pub(crate) fn textrel_range(r: &Rela) -> (u64, u64) {
    (r.at, r.extent.map_or(u64::MAX, |n| r.at.saturating_add(n)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::testing::with_image;
    use crate::code::CodeBudgets;

    fn name_of(img: &Image, addr: u64) -> String {
        img.symbol_at(addr)
            .map(|(s, _)| String::from_utf8(s.name).unwrap())
            .unwrap_or_default()
    }

    #[test]
    fn plt_stubs_and_slots_of_a_plt_file() {
        with_image("net-plt-gcc.so", CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.kind, Kind::Shared);
            assert!(img.targets.contains(b"connect".as_slice()));
            let stubs: Vec<_> = img
                .stubs
                .iter()
                .filter(|(a, _)| name_of(img, **a) == "connect")
                .collect();
            assert_eq!(stubs.len(), 1, "one .plt stub for connect: {stubs:x?}");
            assert_eq!(stubs[0].1 .1, ImportVia::Plt);
            assert!(!img.fdes.is_empty());
            assert!(img.textrel.is_empty());
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
    }

    #[test]
    fn pltsec_stubs_start_at_endbr64_and_at_the_jmp() {
        with_image("net-pltsec-gcc.so", CodeBudgets::default(), |img, _, _| {
            let sec: Vec<u64> = img
                .stubs
                .iter()
                .filter(|(a, (_, via))| *via == ImportVia::PltSec && name_of(img, **a) == "connect")
                .map(|(a, _)| *a)
                .collect();
            assert_eq!(sec.len(), 2, "endbr64 and jmp: {sec:x?}");
            assert_eq!(sec[1] - sec[0], 4, "endbr64 is 4 bytes");
        });
    }

    #[test]
    fn noplt_files_have_slots_and_no_connect_stub() {
        with_image("net-noplt-gcc.so", CodeBudgets::default(), |img, _, _| {
            assert!(img
                .slots
                .values()
                .any(|s| s.name == b"connect" && s.defined.is_none()));
            assert!(!img.stubs.keys().any(|a| name_of(img, *a) == "connect"));
        });
    }

    #[test]
    fn a_text_relocation_against_a_target_is_a_gap() {
        with_image("textrel.so", CodeBudgets::default(), |img, run, _| {
            assert!(!img.textrel.is_empty());
            assert!(run
                .clone_gaps()
                .iter()
                .any(|g| g.starts_with("code: connect: text relocation at ")));
        });
    }

    #[test]
    fn overlapping_load_pages_are_merged_and_cut() {
        let loads = Loads(vec![
            Load {
                vaddr: 0x1000,
                offset: 0x1000,
                filesz: 0x1800,
                memsz: 0x1800,
                writable: false,
                executable: true,
            },
            Load {
                vaddr: 0x2400,
                offset: 0x2400,
                filesz: 0x100,
                memsz: 0x100,
                writable: true,
                executable: false,
            },
            Load {
                vaddr: 0x9000,
                offset: 0x9000,
                filesz: 0x10,
                memsz: 0x10,
                writable: false,
                executable: false,
            },
        ]);
        assert_eq!(overlapped_pages(&loads), [(0x2000, 0x3000)]);
        let code = regions(&loads, |l| l.executable, &overlapped_pages(&loads));
        assert_eq!(
            code,
            [Region {
                start: 0x1000,
                end: 0x2000,
                offset: 0x1000
            }]
        );
    }

    #[test]
    fn plt_decode_failure_drops_that_sections_stubs() {
        let slots = BTreeMap::from([(
            0x3000,
            Sym {
                name: b"connect".to_vec(),
                defined: None,
            },
        )]);
        // jmp [rip+0x1ffa] at 0x1000 (next ip 0x1006 → slot 0x3000), then an invalid byte pair.
        let bytes = [0xff, 0x25, 0xfa, 0x1f, 0x00, 0x00, 0xff, 0xff];
        assert_eq!(
            plt_stubs(&bytes[..6], 0x1000, &slots),
            Ok(vec![(0x1000, 0x3000)])
        );
        assert_eq!(plt_stubs(&bytes, 0x1000, &slots), Err(0x1006));
    }

    #[test]
    fn a_text_relocation_covers_its_whole_extent() {
        let r = |extent| Rela {
            at: 0x1000,
            r_type: 0,
            sym: 0,
            addend: 0,
            extent,
        };
        assert_eq!(
            textrel_range(&r(Some(16))),
            (0x1000, 0x1010),
            "a TLSDESC writes 16 bytes, not 8"
        );
        assert_eq!(
            textrel_range(&r(Some(0))),
            (0x1000, 0x1000),
            "NONE writes nothing"
        );
        assert_eq!(textrel_range(&r(None)), (0x1000, u64::MAX), "unbounded");
    }

    #[test]
    fn an_import_name_that_cannot_be_read_is_a_gap() {
        use object::read::elf::FileHeader as _;
        use std::io::Write;

        // `net-plt-gcc.so` with connect's `st_name` past `.dynstr`: the loader reads on into
        // whatever follows, which could spell `connect`. Its `.dynsym` entry is found by name.
        let path = format!(
            "{}/tests/fixtures/code/net-plt-gcc.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut bytes = std::fs::read(path).unwrap();
        let data = bytes.as_slice();
        let header = elf::FileHeader64::<Endianness>::parse(data).unwrap();
        let endian = header.endian().unwrap();
        let table = header.sections(endian, data).unwrap();
        let dynsym = table.symbols(endian, data, elf::SHT_DYNSYM).unwrap();
        let index = dynsym
            .symbols()
            .iter()
            .position(|s| {
                s.name(endian, dynsym.strings())
                    .is_ok_and(|n| n == b"connect")
            })
            .unwrap();
        let at = table.section(dynsym.section()).unwrap().sh_offset(endian) as usize + index * 24;
        bytes[at..at + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let mut patched = tempfile::NamedTempFile::new().unwrap();
        patched.write_all(&bytes).unwrap();

        crate::code::testing::with_image_at(
            patched.path(),
            CodeBudgets::default(),
            |img, run, _| {
                assert!(!img.targets.contains(b"connect".as_slice()));
                let gaps = run.clone_gaps();
                assert!(
                    gaps.contains(
                        &"code: an import's name cannot be read: a name past its string table"
                            .to_string()
                    ),
                    "{gaps:?}"
                );
            },
        );
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
