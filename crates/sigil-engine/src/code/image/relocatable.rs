//! The image of a relocatable object (PR-5a spec §4.2): an address is a file offset. Code is the
//! `SHF_EXECINSTR` `SHT_PROGBITS` sections, and each relocation on a code field is kept by its
//! field, to be read by its type and the field's use ([`Image::field`]). `.eh_frame` is relocated
//! in a private copy before its FDEs are read.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use object::elf;
use object::read::elf::{
    FileHeader, Rela as _, SectionHeader, SectionTable, Sym as _, SymbolTable,
};
use object::read::{ReadCacheOps, SectionIndex, SymbolIndex};
use object::Endianness;

use super::{
    rtype, target_names, Callee, FieldReloc, Image, Kind, Meaning, Name, Names, Region, RelSym,
    Reloc, RelocWhy, Use,
};
use crate::binary::elf::{Elf, Sections};
use crate::binary::read::Bounded;
use crate::code::data::Signatures;
use crate::code::reader::Reader;
use crate::code::{fde, Run};

impl Image {
    /// What the relocation on the field at `field` means, for the instruction ending at `next_ip`
    /// that uses the field as `use_` (spec §4.2's table). `None`: no relocation there.
    /// - `P` is `field`; `S` is a defined symbol's file offset ([`RelSym::at`]); an undefined
    ///   symbol has no `S` and is named only symbolically.
    /// - Exact: `A + (next_ip − P) = 0`, the field names the symbol (or its GOT entry) itself.
    /// - No PLT or GOT address exists before linking, and none is made up: a GOT relocation is
    ///   the symbolic [`Meaning::GotEntry`].
    /// - Two relocations on the field: unknown, naming a target among their symbols if one is.
    pub fn field(&self, field: u64, next_ip: u64, use_: Use) -> Option<Meaning> {
        use rtype::{GOTPCREL, GOTPCRELX, PC32, PLT32, R32, R32S, R64, REX_GOTPCRELX};
        let name_of = |r: &FieldReloc| self.rel_syms.get(&r.sym).and_then(|s| s.name.clone());
        let r = match self.relocs.get(&field)? {
            Reloc::One(r) => r,
            Reloc::Two(a, b) => {
                let names = [name_of(a), name_of(b)];
                let target = names.iter().flatten().find(|n| self.targets.contains(*n));
                return Some(Meaning::Unknown {
                    symbol: target.or(names.iter().flatten().next()).cloned(),
                    why: RelocWhy::Conflict,
                });
            }
        };
        let name = name_of(r);
        let at = self.rel_syms.get(&r.sym).and_then(|s| s.at);
        // `A + (next_ip − P)`: how far the operand is from the symbol itself.
        let adjust = i128::from(r.addend) + i128::from(next_ip) - i128::from(field);
        let exact = adjust == 0;
        let pcrel = |s: u64| u64::try_from(i128::from(s) + adjust).ok();
        let unknown = |why: RelocWhy| Meaning::Unknown {
            symbol: name.clone(),
            why,
        };
        let out_of_range = || unknown(RelocWhy::OutOfRange);
        let no_address = || unknown(RelocWhy::NoAddress);
        Some(match (r.r_type, use_) {
            (PC32 | PLT32, Use::Branch) => match (&name, at) {
                (Some(n), _) if exact => Meaning::Branch(Callee::Import(n.clone())),
                (Some(_), _) => unknown(RelocWhy::BranchBeside(adjust)),
                (None, Some(s)) => {
                    pcrel(s).map_or_else(out_of_range, |t| Meaning::Branch(Callee::Internal(t)))
                }
                (None, None) => no_address(),
            },
            (PLT32, _) => unknown(RelocWhy::PltOffBranch),
            (PC32, Use::Memory | Use::Lea) => match (&name, at) {
                (None, Some(s)) => pcrel(s).map_or_else(out_of_range, Meaning::Address),
                (Some(n), _) if exact && use_ == Use::Lea => Meaning::SymbolAddr(n.clone()),
                (Some(_), _) => unknown(RelocWhy::PcData),
                (None, None) => no_address(),
            },
            (GOTPCREL | GOTPCRELX | REX_GOTPCRELX, Use::Memory) if exact => match (&name, at) {
                (Some(n), _) => Meaning::GotEntry(Callee::Import(n.clone())),
                (None, Some(s)) => Meaning::GotEntry(Callee::Internal(s)),
                (None, None) => no_address(),
            },
            (GOTPCREL | GOTPCRELX | REX_GOTPCRELX, _) => unknown(RelocWhy::Got(adjust)),
            (R32 | R32S | R64, Use::Immediate | Use::Absolute) => match (&name, at) {
                (None, Some(s)) => s
                    .checked_add_signed(r.addend)
                    .map_or_else(out_of_range, Meaning::Address),
                (Some(n), _) if r.addend == 0 => Meaning::SymbolAddr(n.clone()),
                (Some(_), _) => unknown(RelocWhy::AbsoluteBeside),
                (None, None) => no_address(),
            },
            (t, _) => unknown(RelocWhy::Type(t)),
        })
    }
}

/// The image of a relocatable object (spec §4.2), or `None` without section headers or `.symtab`:
/// its regions ([`regions`]), targets, relocations on code ([`relocations`]) and their symbols
/// ([`symbols`]), and the FDEs of `.eh_frame`, relocated ([`eh_frame`]).
pub(crate) fn relocatable<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'d, R, H>,
    sections: &Sections<'d, R, H>,
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Option<Image> {
    let Some(table) = sections.table.as_ref() else {
        run.gap("code: no section headers".to_string());
        return None;
    };
    let Some(symtab) = sections.symbols.as_ref() else {
        run.gap("code: no .symtab".to_string());
        return None;
    };
    let mut img = Image::empty(Kind::Relocatable);
    regions(&mut img, table, e.endian, run);
    let mut names = Names::default();
    img.targets = target_names(e, table, symtab, sig, &mut names, run);
    let targets = target_indices(e.endian, symtab, &names, &img.targets);
    // clang types it `SHT_X86_64_UNWIND`, gcc `SHT_PROGBITS`: found by name.
    let eh = e
        .section_index_named(table, b".eh_frame")
        .map(|(index, s)| EhFrame {
            index,
            ty: s.sh_type(e.endian),
            offset: s.sh_offset(e.endian).into(),
            size: s.sh_size(e.endian).into(),
        });
    let (relocs, eh_relocs) = relocations(e, table, symtab, eh.map(|s| s.index), &targets, run);
    img.relocs = relocs;
    let wanted = img
        .relocs
        .values()
        .flat_map(Reloc::each)
        .chain(eh_relocs.iter().map(|(_, r)| r))
        .map(|r| r.sym)
        .collect();
    img.rel_syms = symbols(e, table, symtab, wanted, &mut names, run);
    if let Some(eh) = eh {
        eh_frame(&mut img, eh, &eh_relocs, reader, run);
    }
    Some(img)
}

/// `.eh_frame`'s section.
#[derive(Debug, Clone, Copy)]
struct EhFrame {
    index: usize,
    ty: elf::SectionType,
    offset: u64,
    size: u64,
}

/// The regions of a relocatable object, at their file offsets:
/// - code: the `SHF_EXECINSTR` `SHT_PROGBITS` sections, sorted; those that overlap (a crafted
///   object) are merged, each overlap a gap;
/// - strings: the `SHF_ALLOC` `SHT_PROGBITS` sections without `SHF_WRITE` and `SHF_EXECINSTR`
///   that no relocation section names: a relocated section's bytes are final only once linked.
fn regions<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    img: &mut Image,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    endian: Endianness,
    run: &mut Run,
) {
    let relocated: BTreeSet<usize> = table
        .iter()
        .filter(|s| is_relocations(s.sh_type(endian)))
        .map(|s| s.sh_info(endian) as usize)
        .collect();
    let mut code = vec![];
    for (i, s) in table.iter().enumerate() {
        if s.sh_type(endian) != elf::SHT_PROGBITS {
            continue;
        }
        let start: u64 = s.sh_offset(endian).into();
        let size: u64 = s.sh_size(endian).into();
        let Some(end) = start.checked_add(size).filter(|end| start < *end) else {
            continue;
        };
        let region = Region {
            start,
            end,
            offset: start,
        };
        let flags = s.sh_flags(endian).0;
        if flags & elf::SHF_EXECINSTR.0 != 0 {
            code.push(region);
            img.sections.push((start, end));
        } else if flags & elf::SHF_ALLOC.0 != 0
            && flags & elf::SHF_WRITE.0 == 0
            && !relocated.contains(&i)
        {
            img.strings.push(region);
        }
    }
    img.code = disjoint(code, run);
    img.sections.sort_unstable();
    img.strings.sort_unstable();
}

/// Whether a section of type `ty` holds relocations.
fn is_relocations(ty: elf::SectionType) -> bool {
    ty == elf::SHT_RELA || ty == elf::SHT_REL || ty == elf::SHT_CREL
}

/// The `.symtab` indices of the targets: the undefined `GLOBAL`/`WEAK` symbols whose names
/// [`target_names`] read into `names`, and found in `targets`. Nothing is read again.
fn target_indices<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    endian: Endianness,
    symtab: &SymbolTable<'d, H, &'d Bounded<R>>,
    names: &Names,
    targets: &BTreeSet<Name>,
) -> BTreeSet<u32> {
    let strings = symtab.string_section().0;
    symtab
        .symbols()
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, s)| {
            s.st_shndx(endian) == elf::SHN_UNDEF
                && (s.st_bind() == elf::STB_GLOBAL || s.st_bind() == elf::STB_WEAK)
        })
        .filter_map(
            |(i, s)| match names.read.get(&(strings, s.st_name(endian))) {
                Some(Ok(Some(name))) if targets.contains(name) => u32::try_from(i).ok(),
                _ => None,
            },
        )
        .collect()
}

/// The relocations on code, by field, and those on `.eh_frame` (section `eh`), by offset in it:
/// from the `SHT_RELA` sections against `.symtab`, each table read once, at most
/// `run.budgets.relocations` in all (review C1). A REL or CREL section there is a gap.
fn relocations<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    symtab: &SymbolTable<'d, H, &'d Bounded<R>>,
    eh: Option<usize>,
    targets: &BTreeSet<u32>,
    run: &mut Run,
) -> (BTreeMap<u64, Reloc>, Vec<(u64, FieldReloc)>) {
    let endian = e.endian;
    let limit = run.budgets.relocations;
    let mut count: usize = 0;
    // The file ranges read: the parse cache serves a repeat free, so a table many sections name
    // would otherwise be collected once per section.
    let mut read: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut relocs = BTreeMap::new();
    let mut eh_relocs = vec![];
    for (i, s) in table.iter().enumerate() {
        let ty = s.sh_type(endian);
        if !is_relocations(ty) {
            continue;
        }
        let info = s.sh_info(endian) as usize;
        let on_eh = eh == Some(info);
        let on_code = code_section(table, info, endian);
        if !on_eh && on_code.is_none() {
            continue;
        }
        if ty == elf::SHT_REL {
            run.gap(format!("code: section {i}: REL relocations"));
            continue;
        }
        if ty == elf::SHT_CREL {
            run.gap(format!("code: section {i}: CREL relocations"));
            continue;
        }
        if s.sh_link(endian) as usize != symtab.section().0 {
            run.gap(format!(
                "code: section {i}: relocations not against .symtab"
            ));
            continue;
        }
        let range: (u64, u64) = (s.sh_offset(endian).into(), s.sh_size(endian).into());
        if range.1 == 0 {
            continue;
        }
        if !read.insert(range) {
            run.gap(format!("code: section {i}: relocation table read twice"));
            continue;
        }
        let entries = match s.rela(endian, e.data) {
            Ok(Some((entries, _))) => entries,
            Ok(None) => continue,
            Err(why) => {
                run.gap(format!("code: section {i}: {why}"));
                continue;
            }
        };
        for r in entries {
            if count >= limit {
                run.limit("relocation", limit as u64);
                return (relocs, eh_relocs);
            }
            count += 1;
            let off: u64 = r.r_offset(endian).into();
            let item = FieldReloc {
                r_type: r.r_type(endian, false).0,
                sym: r.r_sym(endian, false),
                addend: r.r_addend(endian).into(),
            };
            if on_eh {
                eh_relocs.push((off, item));
            }
            let Some((base, size)) = on_code else {
                continue;
            };
            let Some(p) = base.checked_add(off).filter(|_| off < size) else {
                run.gap(format!(
                    "code: section {i}: a relocation at {off:#x} outside its section"
                ));
                continue;
            };
            add(&mut relocs, p, item, targets, run);
        }
    }
    (relocs, eh_relocs)
}

/// Adds `item` on the field at `p`. A different relocation already there makes [`Reloc::Two`]
/// and the gap `code: two relocations at <p>`; of the later ones, only one naming a target is
/// kept, in place of the second, when neither kept one names a target.
fn add(
    relocs: &mut BTreeMap<u64, Reloc>,
    p: u64,
    item: FieldReloc,
    targets: &BTreeSet<u32>,
    run: &mut Run,
) {
    let mut kept = match relocs.entry(p) {
        Entry::Vacant(v) => {
            v.insert(Reloc::One(item));
            return;
        }
        Entry::Occupied(o) => o,
    };
    let next = match *kept.get() {
        r if r.each().any(|k| *k == item) => return,
        Reloc::One(a) => Some(Reloc::Two(a, item)),
        Reloc::Two(a, b)
            if targets.contains(&item.sym)
                && !targets.contains(&a.sym)
                && !targets.contains(&b.sym) =>
        {
            Some(Reloc::Two(a, item))
        }
        Reloc::Two(..) => None,
    };
    run.gap(format!("code: two relocations at {p:#x}"));
    if let Some(next) = next {
        kept.insert(next);
    }
}

/// `(sh_offset, sh_size)` of section `index` when it is code (as [`regions`] takes it).
fn code_section<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    index: usize,
    endian: Endianness,
) -> Option<(u64, u64)> {
    let s = table.section(SectionIndex(index)).ok()?;
    let code =
        s.sh_type(endian) == elf::SHT_PROGBITS && s.sh_flags(endian).0 & elf::SHF_EXECINSTR.0 != 0;
    code.then(|| (s.sh_offset(endian).into(), s.sh_size(endian).into()))
}

/// The `.symtab` symbols `wanted` (relocations' `r_sym`), each read once, its name held once
/// ([`Names`]): an undefined one by name, a defined one by `S`. `STN_UNDEF` (0) is no symbol.
fn symbols<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &Elf<'d, R, H>,
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    symtab: &SymbolTable<'d, H, &'d Bounded<R>>,
    wanted: BTreeSet<u32>,
    names: &mut Names,
    run: &mut Run,
) -> BTreeMap<u32, RelSym> {
    let endian = e.endian;
    let mut out = BTreeMap::new();
    for index in wanted {
        // `STN_UNDEF`: no symbol, so nothing is named and no `S` is known.
        if index == 0 {
            continue;
        }
        let si = SymbolIndex(index as usize);
        let Ok(sym) = symtab.symbol(si) else {
            run.gap(format!("code: relocation symbol {index} out of range"));
            continue;
        };
        let entry = if sym.st_shndx(endian) == elf::SHN_UNDEF {
            // A name that cannot be read is a gap of `target_names` when it could be a
            // capability's: here it names nothing.
            RelSym {
                name: names.of(e, table, symtab, sym).ok(),
                at: None,
            }
        } else {
            let value: u64 = sym.st_value(endian).into();
            let at = match symtab.symbol_section(endian, sym, si) {
                Ok(Some(section)) => {
                    file_offset(table, section, endian).and_then(|base| base.checked_add(value))
                }
                // `SHN_ABS`, `SHN_COMMON`: no file offset.
                Ok(None) => None,
                Err(why) => {
                    run.gap(format!("code: relocation symbol {index}: {why}"));
                    None
                }
            };
            RelSym { name: None, at }
        };
        out.insert(index, entry);
    }
    out
}

/// The file offset of section `index`, where its symbols are: none for a section without file
/// bytes (`SHT_NOBITS`), whose offset can be another section's.
fn file_offset<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    table: &SectionTable<'d, H, &'d Bounded<R>>,
    index: SectionIndex,
    endian: Endianness,
) -> Option<u64> {
    let s = table.section(index).ok()?;
    (s.sh_type(endian) != elf::SHT_NOBITS).then(|| s.sh_offset(endian).into())
}

/// `regions` (each at its own offset) sorted, those that overlap merged, each overlap a gap: a
/// crafted object's sections can share bytes, and [`Image::code_at`] needs disjoint regions.
/// Regions that only touch stay apart.
fn disjoint(mut regions: Vec<Region>, run: &mut Run) -> Vec<Region> {
    regions.sort_unstable();
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        match out.last_mut() {
            Some(last) if r.start < last.end => {
                run.gap(format!("code: code sections overlap at {:#x}", r.start));
                last.end = last.end.max(r.end);
            }
            _ => out.push(r),
        }
    }
    out
}

/// The FDEs of `.eh_frame`, read at its file offset into a private copy, relocated
/// ([`relocate_eh_frame`]), and parsed with that offset as its address.
fn eh_frame(
    img: &mut Image,
    eh: EhFrame,
    relocs: &[(u64, FieldReloc)],
    reader: &mut Reader<'_>,
    run: &mut Run,
) {
    if eh.ty == elf::SHT_NOBITS {
        run.gap("code: .eh_frame: no bytes in the file".to_string());
        return;
    }
    match reader.read(eh.offset, eh.size) {
        Ok(mut bytes) => {
            relocate_eh_frame(&mut bytes, eh.offset, relocs, img, run);
            img.set_fdes(fde::parse(&bytes, eh.offset, run));
        }
        Err(why) => run.refusal(why, ".eh_frame", reader),
    }
}

/// Applies `.rela.eh_frame` to `bytes`, the contents of `.eh_frame` at file offset `base`:
/// - `PC32` and `PC64` write `S + A − P` (FDE starts are `PC32`);
/// - `R_X86_64_32`, `32S` and `64` write `S + A` (a non-PIC object's exception-table pointers);
/// - a relocation against a symbol without `S` (undefined: a personality routine) is skipped: it
///   names no FDE start. Any other type, or a value that does not fit its field, is a gap.
fn relocate_eh_frame(
    bytes: &mut [u8],
    base: u64,
    relocs: &[(u64, FieldReloc)],
    img: &Image,
    run: &mut Run,
) {
    for (r_off, r) in relocs {
        let Some(s) = img.rel_syms.get(&r.sym).and_then(|s| s.at) else {
            continue;
        };
        let p = i128::from(base) + i128::from(*r_off);
        let value = i128::from(s) + i128::from(r.addend) - p;
        let absolute = i128::from(s) + i128::from(r.addend);
        let at = *r_off;
        let written = match r.r_type {
            rtype::PC32 => i32::try_from(value).is_ok_and(|v| put(bytes, at, &v.to_le_bytes())),
            rtype::PC64 => i64::try_from(value).is_ok_and(|v| put(bytes, at, &v.to_le_bytes())),
            rtype::R32 => u32::try_from(absolute).is_ok_and(|v| put(bytes, at, &v.to_le_bytes())),
            rtype::R32S => i32::try_from(absolute).is_ok_and(|v| put(bytes, at, &v.to_le_bytes())),
            rtype::R64 => u64::try_from(absolute).is_ok_and(|v| put(bytes, at, &v.to_le_bytes())),
            t => {
                run.gap(format!("code: .eh_frame: relocation type {t}"));
                continue;
            }
        };
        if !written {
            run.gap(format!(
                "code: .eh_frame: relocation at {r_off:#x} out of range"
            ));
        }
    }
}

/// Writes `value` at `at` of `bytes`: `false`, and nothing written, when it does not fit.
fn put(bytes: &mut [u8], at: u64, value: &[u8]) -> bool {
    let field = usize::try_from(at)
        .ok()
        .and_then(|a| bytes.get_mut(a..a.checked_add(value.len())?));
    match field {
        Some(field) => {
            field.copy_from_slice(value);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::synth;
    use crate::code::testing::{with_image, with_image_at};
    use crate::code::CodeBudgets;
    use std::io::Write;

    fn named(n: &str) -> Name {
        Name::from(n.as_bytes())
    }

    fn reloc(r_type: u32, sym: u32, addend: i64) -> FieldReloc {
        FieldReloc {
            r_type,
            sym,
            addend,
        }
    }

    /// An image with the relocations `(P, type, symbol, A)` and the symbols `(index, name, S)`;
    /// `connect` is its target.
    fn img_with(
        relocs: &[(u64, u32, u32, i64)],
        syms: &[(u32, Option<&str>, Option<u64>)],
    ) -> Image {
        let mut img = Image::empty(Kind::Relocatable);
        for (p, t, s, a) in relocs {
            img.relocs.insert(*p, Reloc::One(reloc(*t, *s, *a)));
        }
        for (i, name, at) in syms {
            img.rel_syms.insert(
                *i,
                RelSym {
                    name: name.map(named),
                    at: *at,
                },
            );
        }
        img.targets.insert(named("connect"));
        img
    }

    fn import(n: &str) -> Callee {
        Callee::Import(named(n))
    }

    fn unknown(symbol: Option<&str>, why: RelocWhy) -> Option<Meaning> {
        Some(Meaning::Unknown {
            symbol: symbol.map(named),
            why,
        })
    }

    #[test]
    fn branch_relocations_name_the_callee() {
        // call rel32 at 0x40 (field 0x41, next_ip 0x45), addend -4: exact.
        let img = img_with(
            &[
                (0x41, rtype::PLT32, 1, -4),
                (0x51, rtype::PC32, 2, -4),
                (0x61, rtype::PLT32, 1, 0),
            ],
            &[(1, Some("connect"), None), (2, None, Some(0x200))],
        );
        assert_eq!(
            img.field(0x41, 0x45, Use::Branch),
            Some(Meaning::Branch(import("connect")))
        );
        assert_eq!(
            img.field(0x51, 0x55, Use::Branch),
            Some(Meaning::Branch(Callee::Internal(0x200)))
        );
        assert_eq!(
            img.field(0x61, 0x65, Use::Branch),
            unknown(Some("connect"), RelocWhy::BranchBeside(4)),
            "not exact"
        );
        assert_eq!(
            img.field(0x99, 0x9d, Use::Branch),
            None,
            "no relocation there"
        );
    }

    #[test]
    fn got_relocations_are_symbolic_entries() {
        // call *[rip+X] (field at 0x12, next_ip 0x16) and mov r15,[rip+X] with REX_GOTPCRELX.
        let img = img_with(
            &[
                (0x12, rtype::GOTPCRELX, 1, -4),
                (0x23, rtype::REX_GOTPCRELX, 1, -4),
                (0x33, rtype::GOTPCRELX, 1, 0),
                (0x43, rtype::GOTPCREL, 2, -4),
                (0x53, rtype::GOTPCREL, 1, -4),
            ],
            &[(1, Some("connect"), None), (2, None, Some(0x300))],
        );
        let entry = Some(Meaning::GotEntry(import("connect")));
        assert_eq!(img.field(0x12, 0x16, Use::Memory), entry);
        assert_eq!(img.field(0x23, 0x27, Use::Memory), entry);
        assert_eq!(
            img.field(0x33, 0x37, Use::Memory),
            unknown(Some("connect"), RelocWhy::Got(4)),
            "+4 off the entry"
        );
        assert_eq!(
            img.field(0x43, 0x47, Use::Memory),
            Some(Meaning::GotEntry(Callee::Internal(0x300)))
        );
        assert_eq!(
            img.field(0x53, 0x57, Use::Lea),
            unknown(Some("connect"), RelocWhy::Got(0)),
            "a lea of a GOT entry"
        );
        assert_eq!(
            img.field(0x12, 0x16, Use::Branch),
            unknown(Some("connect"), RelocWhy::Got(0)),
            "a GOT relocation on a branch"
        );
        // `cmp [rip+X], imm8`: next_ip is 1 past the field's end, and the addend is -5.
        let img = img_with(
            &[(0x62, rtype::GOTPCREL, 1, -5)],
            &[(1, Some("connect"), None)],
        );
        assert_eq!(img.field(0x62, 0x67, Use::Memory), entry);
    }

    #[test]
    fn data_and_absolute_relocations() {
        let img = img_with(
            &[
                (0x10, rtype::PC32, 3, -4),
                (0x20, rtype::PC32, 1, -4),
                (0x30, rtype::R32, 3, 8),
                (0x40, rtype::R64, 1, 0),
                (0x50, rtype::PLT32, 1, -4),
                (0x60, rtype::R64, 1, 8),
            ],
            &[(1, Some("connect"), None), (3, None, Some(0x500))],
        );
        assert_eq!(
            img.field(0x10, 0x14, Use::Lea),
            Some(Meaning::Address(0x500))
        );
        assert_eq!(
            img.field(0x10, 0x14, Use::Memory),
            Some(Meaning::Address(0x500))
        );
        assert_eq!(
            img.field(0x20, 0x24, Use::Lea),
            Some(Meaning::SymbolAddr(named("connect")))
        );
        assert_eq!(
            img.field(0x20, 0x24, Use::Memory),
            unknown(Some("connect"), RelocWhy::PcData),
            "undefined data"
        );
        assert_eq!(
            img.field(0x30, 0x34, Use::Immediate),
            Some(Meaning::Address(0x508))
        );
        assert_eq!(
            img.field(0x30, 0x34, Use::Absolute),
            Some(Meaning::Address(0x508))
        );
        assert_eq!(
            img.field(0x40, 0x48, Use::Immediate),
            Some(Meaning::SymbolAddr(named("connect")))
        );
        assert_eq!(
            img.field(0x60, 0x68, Use::Immediate),
            unknown(Some("connect"), RelocWhy::AbsoluteBeside),
            "an undefined symbol + 8"
        );
        for use_ in [Use::Lea, Use::Memory, Use::Immediate, Use::Absolute] {
            assert_eq!(
                img.field(0x50, 0x54, use_),
                unknown(Some("connect"), RelocWhy::PltOffBranch),
                "{use_:?}"
            );
        }
        // The table's fields: an absolute type on a RIP-relative operand, and PC32 on a value.
        for (at, use_, t) in [
            (0x30, Use::Memory, rtype::R32),
            (0x30, Use::Lea, rtype::R32),
            (0x10, Use::Absolute, rtype::PC32),
            (0x10, Use::Immediate, rtype::PC32),
        ] {
            assert_eq!(
                img.field(at, at + 4, use_),
                unknown(None, RelocWhy::Type(t)),
                "{at:#x} {use_:?}"
            );
        }
    }

    /// I2: a defined symbol's `S + A + (next_ip − P)` when `A + (next_ip − P)` is not 0.
    #[test]
    fn defined_symbols_resolve_beside_their_offset() {
        // `.rodata.str1.1` at 0x100 and `.text.unlikely` at 0x400: section symbols.
        let img = img_with(
            &[
                // lea .LC1(%rip), .LC1 = .rodata.str1.1 + 0x10: A = 0x10 - 4.
                (0x23, rtype::PC32, 5, 0x10 - 4),
                // jmp .text.unlikely + 0x20 (a cold part): A = 0x20 - 4.
                (0x31, rtype::PC32, 6, 0x20 - 4),
                (0x36, rtype::PLT32, 6, 0x20 - 4),
                // movl $1, .LC0+8(%rip): an imm32 after the field, next_ip = P + 8, A = 0.
                (0x42, rtype::PC32, 5, 0),
                // cmpb $1, .LC0(%rip): an imm8 after the field, A = -5.
                (0x52, rtype::PC32, 5, -5),
            ],
            &[(5, None, Some(0x100)), (6, None, Some(0x400))],
        );
        assert_eq!(
            img.field(0x23, 0x27, Use::Lea),
            Some(Meaning::Address(0x110))
        );
        assert_eq!(
            img.field(0x31, 0x35, Use::Branch),
            Some(Meaning::Branch(Callee::Internal(0x420)))
        );
        assert_eq!(
            img.field(0x36, 0x3a, Use::Branch),
            Some(Meaning::Branch(Callee::Internal(0x420)))
        );
        assert_eq!(
            img.field(0x42, 0x4a, Use::Memory),
            Some(Meaning::Address(0x108))
        );
        assert_eq!(
            img.field(0x52, 0x57, Use::Memory),
            Some(Meaning::Address(0x100))
        );
        // Below 0 is no address.
        let img = img_with(&[(0x10, rtype::PC32, 5, -0x200)], &[(5, None, Some(0x100))]);
        assert_eq!(
            img.field(0x10, 0x14, Use::Lea),
            unknown(None, RelocWhy::OutOfRange)
        );
    }

    #[test]
    fn a_field_two_relocations_write_is_unknown_naming_a_target() {
        let mut img = img_with(
            &[],
            &[(1, Some("connect"), None), (2, Some("socket"), None)],
        );
        img.relocs.insert(
            0x10,
            Reloc::Two(reloc(rtype::PLT32, 2, -4), reloc(rtype::PLT32, 1, -4)),
        );
        img.relocs.insert(
            0x20,
            Reloc::Two(reloc(rtype::PLT32, 2, -4), reloc(rtype::PC32, 3, -4)),
        );
        assert_eq!(
            img.field(0x10, 0x14, Use::Branch),
            unknown(Some("connect"), RelocWhy::Conflict),
            "the target, though second"
        );
        assert_eq!(
            img.field(0x20, 0x24, Use::Branch),
            unknown(Some("socket"), RelocWhy::Conflict),
            "no target: the first name"
        );
    }

    /// M2: no type is reserved for a conflict.
    #[test]
    fn any_type_is_a_type() {
        let img = img_with(&[(0x10, u32::MAX, 1, -4)], &[(1, Some("connect"), None)]);
        let m = img.field(0x10, 0x14, Use::Branch);
        assert_eq!(m, unknown(Some("connect"), RelocWhy::Type(u32::MAX)));
        assert_eq!(
            RelocWhy::Type(u32::MAX).to_string(),
            "relocation type 4294967295"
        );
    }

    #[test]
    fn later_relocations_on_a_field_keep_a_target() {
        let targets = BTreeSet::from([1]);
        let mut run = Run::new(CodeBudgets::default());
        let mut relocs = BTreeMap::new();
        let (a, b, c, d) = (
            reloc(rtype::PC32, 2, -4),
            reloc(rtype::PC32, 3, -4),
            reloc(rtype::PLT32, 1, -4),
            reloc(rtype::PLT32, 4, -4),
        );
        add(&mut relocs, 0x10, a, &targets, &mut run);
        add(&mut relocs, 0x10, a, &targets, &mut run);
        assert_eq!(relocs[&0x10], Reloc::One(a), "a repeat is one relocation");
        assert!(run.clone_gaps().is_empty());
        add(&mut relocs, 0x10, b, &targets, &mut run);
        assert_eq!(relocs[&0x10], Reloc::Two(a, b));
        add(&mut relocs, 0x10, c, &targets, &mut run);
        assert_eq!(
            relocs[&0x10],
            Reloc::Two(a, c),
            "the target replaces the second"
        );
        add(&mut relocs, 0x10, d, &targets, &mut run);
        assert_eq!(relocs[&0x10], Reloc::Two(a, c), "the target stays");
        assert_eq!(run.clone_gaps(), ["code: two relocations at 0x10"]);
        assert_eq!(
            relocs[&0x10].each().map(|r| r.sym).collect::<Vec<_>>(),
            [2, 1]
        );
    }

    /// M3: the spec's texts, formatted only when shown.
    #[test]
    fn the_reasons_read_as_the_spec_says() {
        let connect = named("connect");
        let cases = [
            (RelocWhy::BranchBeside(4), "branch to connect+4"),
            (RelocWhy::BranchBeside(-2), "branch to connect-2"),
            (RelocWhy::Got(4), "GOT reference +4"),
            (RelocWhy::Got(0), "GOT reference +0"),
            (RelocWhy::PcData, "PC32 data of an undefined symbol"),
            (
                RelocWhy::AbsoluteBeside,
                "an absolute address beside the symbol",
            ),
            (RelocWhy::PltOffBranch, "PLT32 off a branch"),
            (RelocWhy::Type(41), "relocation type 41"),
            (RelocWhy::Conflict, "two relocations on the field"),
            (RelocWhy::NoAddress, "a symbol without an address"),
            (RelocWhy::OutOfRange, "an address out of range"),
        ];
        for (why, text) in cases {
            assert_eq!(why.shown(Some(&connect)).to_string(), text);
        }
        assert_eq!(
            RelocWhy::BranchBeside(4).to_string(),
            "branch to the symbol+4"
        );
    }

    #[test]
    fn the_image_of_an_unlinked_got_object() {
        with_image(
            "calls-noplt-gcc-O0.o",
            CodeBudgets::default(),
            |img, run, _| {
                assert_eq!(img.kind, Kind::Relocatable);
                assert!(img.targets.contains(b"connect".as_slice()));
                assert!(img
                    .relocs
                    .values()
                    .flat_map(Reloc::each)
                    .any(|r| r.r_type == rtype::GOTPCRELX));
                assert!(
                    img.fdes.len() >= 4,
                    "kernel, loop, calls_helper, helper: {:x?}",
                    img.fdes
                );
                // Every FDE lies in a code section: `.rela.eh_frame` was applied.
                assert!(
                    img.fdes.iter().all(|f| img.code_at(f.0, f.1).is_some()),
                    "{:x?} in {:x?}",
                    img.fdes,
                    img.code
                );
                assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
            },
        );
    }

    /// `.text` is at file offset 0x40 in every relocatable fixture.
    const TEXT: u64 = 0x40;

    #[test]
    fn the_relocatable_fixtures_resolve_by_type_and_field() {
        // gcc reaches `helper` (`.text` + 0) through its GOT entry, clang directly: S is `.text`'s
        // file offset plus `st_value`.
        with_image(
            "calls-noplt-gcc-O0.o",
            CodeBudgets::default(),
            |img, _, _| {
                let (connect, helper) = (TEXT + 0x2e, TEXT + 0x8a);
                assert_eq!(
                    img.field(connect, connect + 4, Use::Memory),
                    Some(Meaning::GotEntry(import("connect")))
                );
                assert_eq!(
                    img.field(helper, helper + 4, Use::Memory),
                    Some(Meaning::GotEntry(Callee::Internal(TEXT)))
                );
            },
        );
        with_image(
            "calls-noplt-clang-O0.o",
            CodeBudgets::default(),
            |img, run, _| {
                let helper = TEXT + 0x8f;
                assert_eq!(
                    img.field(helper, helper + 4, Use::Branch),
                    Some(Meaning::Branch(Callee::Internal(TEXT)))
                );
                assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
            },
        );
        // gotrel.o's `g`: the call is +4 off connect's entry; the `lea` of the entry, and the
        // `lea` of `connect@PLT`, are no call; the `cmp` reads the entry.
        with_image("gotrel.o", CodeBudgets::default(), |img, run, _| {
            let at = |p: u64, use_| img.field(p, p + 4, use_);
            let connect = |why| unknown(Some("connect"), why);
            assert_eq!(at(TEXT + 2, Use::Memory), connect(RelocWhy::Got(4)));
            assert_eq!(at(TEXT + 9, Use::Lea), connect(RelocWhy::Got(0)));
            assert_eq!(
                at(TEXT + 0x10, Use::Memory),
                Some(Meaning::GotEntry(import("connect")))
            );
            assert_eq!(at(TEXT + 0x17, Use::Lea), connect(RelocWhy::PltOffBranch));
            assert_eq!(
                at(TEXT + 0x1e, Use::Memory),
                unknown(Some("extern_data"), RelocWhy::PcData)
            );
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
    }

    #[test]
    fn every_relocatable_fixture_has_its_fdes_in_code() {
        for (f, target) in [
            ("suspicious_kernel-clang-O0.o", true),
            ("suspicious_kernel-gcc-O2.o", true),
            ("clean_kernel-clang-O0.o", false),
            ("clean_kernel-gcc-O2.o", false),
            ("calls-noplt-clang-O0.o", true),
            ("calls-noplt-clang-O2.o", true),
            ("calls-noplt-gcc-O2.o", true),
            ("gotrel.o", true),
        ] {
            with_image(f, CodeBudgets::default(), |img, run, _| {
                // clang's `.eh_frame` is `SHT_X86_64_UNWIND`: found by name all the same.
                assert!(!img.fdes.is_empty(), "{f}");
                assert!(
                    img.fdes.iter().all(|f| img.code_at(f.0, f.1).is_some()),
                    "{f}: {:x?} in {:x?}",
                    img.fdes,
                    img.code
                );
                assert_eq!(img.targets.contains(b"connect".as_slice()), target, "{f}");
                // `.eh_frame` is relocated: no string is read from it.
                assert!(img.strings.is_empty(), "{f}: {:x?}", img.strings);
                assert!(run.clone_gaps().is_empty(), "{f}: {:?}", run.clone_gaps());
            });
        }
    }

    /// The section headers of a file: `(name, sh_type, header offset, sh_offset, sh_size,
    /// sh_link)`.
    type Headers = [(String, u32, usize, u64, u64, u32)];

    /// [`with_image_at`] for the relocatable object `bytes`.
    fn with_bytes<T>(
        bytes: &[u8],
        budgets: CodeBudgets,
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let mut file = tempfile::Builder::new().suffix(".o").tempfile().unwrap();
        file.write_all(bytes).unwrap();
        with_image_at(file.path(), budgets, f)
    }

    /// [`with_image`] for `calls-noplt-gcc-O0.o` with `patch` applied to its bytes. Its sections:
    /// `.text` 1 (0xa2 bytes at 0x40), `.rela.text` 2 (4 entries), `.data` 3, `.bss` 4,
    /// `.eh_frame` 7 (0x98 bytes), `.rela.eh_frame` 8 (4 entries), `.symtab` 9.
    fn with_patched<T>(
        patch: impl FnOnce(&mut Vec<u8>, &Headers),
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let mut bytes = synth::fixture("code/calls-noplt-gcc-O0.o");
        let headers = synth::sections64(&bytes);
        patch(&mut bytes, &headers);
        with_bytes(&bytes, CodeBudgets::default(), f)
    }

    /// The header of section `name`, and its `sh_offset`.
    fn header(headers: &Headers, name: &str) -> (usize, usize) {
        let h = headers.iter().find(|h| h.0 == name).unwrap();
        (h.2, h.3 as usize)
    }

    fn set_u32(bytes: &mut [u8], at: usize, v: u32) {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_u64(bytes: &mut [u8], at: usize, v: u64) {
        bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Entry `k` of the relocation table of section `name`: `(r_offset, r_info's type, r_info's
    /// symbol)` at these file offsets.
    fn entry(headers: &Headers, name: &str, k: usize) -> (usize, usize, usize) {
        let at = header(headers, name).1 + k * 24;
        (at, at + 8, at + 12)
    }

    #[test]
    fn relocations_as_rel_or_crel_or_not_against_symtab_are_gaps() {
        with_patched(
            |b, h| set_u32(b, header(h, ".rela.text").0 + 4, 9), // SHT_REL
            |img, run, _| {
                assert!(img.relocs.is_empty());
                assert_eq!(run.clone_gaps(), ["code: section 2: REL relocations"]);
            },
        );
        with_patched(
            |b, h| set_u32(b, header(h, ".rela.text").0 + 40, 0), // sh_link
            |img, run, _| {
                assert!(img.relocs.is_empty());
                assert_eq!(
                    run.clone_gaps(),
                    ["code: section 2: relocations not against .symtab"]
                );
            },
        );
        // I1: CREL on code, and on `.eh_frame`, which then is no string region either.
        with_patched(
            |b, h| set_u32(b, header(h, ".rela.text").0 + 4, elf::SHT_CREL.0),
            |img, run, _| {
                assert!(img.relocs.is_empty());
                assert_eq!(run.clone_gaps(), ["code: section 2: CREL relocations"]);
            },
        );
        with_patched(
            |b, h| set_u32(b, header(h, ".rela.eh_frame").0 + 4, elf::SHT_CREL.0),
            |img, run, _| {
                assert!(img.strings.is_empty(), "{:x?}", img.strings);
                assert_eq!(run.clone_gaps(), ["code: section 8: CREL relocations"]);
            },
        );
    }

    /// C1: a table two sections name is read once.
    #[test]
    fn a_relocation_table_is_read_once() {
        with_patched(
            |b, h| {
                let (rela_eh, rela_text) = (header(h, ".rela.eh_frame").0, header(h, ".rela.text"));
                set_u64(b, rela_eh + 24, rela_text.1 as u64);
                set_u64(b, rela_eh + 32, 4 * 24);
            },
            |img, run, _| {
                assert_eq!(img.relocs.len(), 4);
                assert_eq!(
                    run.clone_gaps(),
                    ["code: section 8: relocation table read twice"]
                );
            },
        );
    }

    /// A relocatable object: `.text` (section 1: 16 `nop`s at 0x1000), `.eh_frame` (2: 64 zero
    /// bytes at 0x1100), `.symtab` (3: the null symbol and `.text`'s section symbol) and
    /// `.strtab` (4), then `count` `.rela.eh_frame` sections (from 5) that all name one table of
    /// `entries` `PC32` relocations against `.text`, at 0x2000.
    fn object(count: usize, entries: usize) -> Vec<u8> {
        use synth::*;
        let symtab = [[0u8; 24], sym64(0, 3, 1, 0, 0)].concat();
        let info = (1u64 << 32) | u64::from(rtype::PC32);
        let rela: Vec<u8> = (0..entries)
            .flat_map(|_| [8u64.to_le_bytes(), info.to_le_bytes(), [0; 8]].concat())
            .collect();
        let mut img = ElfImage::new(1);
        img.put(0x1000, &[0x90; 16])
            .put(0x1100, &[0; 64])
            .put(0x1200, &symtab)
            .put(0x1300, &[0])
            .put(0x2000, &rela);
        img.sec(".text", SHT_PROGBITS, 0x1000, 0, 16)
            .sec(".eh_frame", SHT_PROGBITS, 0x1100, 0, 64)
            .sec_linked(".symtab", SHT_SYMTAB, 0x1200, 0, 48, 4, 24)
            .sec(".strtab", SHT_STRTAB, 0x1300, 0, 1);
        for _ in 0..count {
            img.sec_linked(".rela.eh_frame", 4, 0x2000, 0, rela.len() as u64, 3, 24);
        }
        let mut bytes = img.build();
        let headers = sections64(&bytes);
        set_u64(&mut bytes, header(&headers, ".text").0 + 8, 0x6); // SHF_ALLOC | SHF_EXECINSTR
        set_u64(&mut bytes, header(&headers, ".eh_frame").0 + 8, 0x2); // SHF_ALLOC
        set_u32(&mut bytes, header(&headers, ".symtab").0 + 44, 2); // the first global
        for h in headers.iter().filter(|h| h.0 == ".rela.eh_frame") {
            set_u32(&mut bytes, h.2 + 44, 2); // sh_info: `.eh_frame`
        }
        bytes
    }

    /// C1: 2,000 sections naming one table of 8,000 entries. Read once per section, that is 16
    /// million relocations (about 400 MB); read once, 8,000.
    #[test]
    fn many_relocation_sections_on_one_table_read_it_once_limit() {
        with_bytes(&object(2000, 8000), CodeBudgets::default(), |_, run, _| {
            let gaps = run.clone_gaps();
            assert!(!run.stopped(), "{gaps:?}");
            assert!(
                gaps.contains(&"code: section 6: relocation table read twice".to_string()),
                "{gaps:?}"
            );
            assert!(
                !gaps.iter().any(|g| g.contains("relocation limit")),
                "{gaps:?}"
            );
        });
    }

    /// C1: the relocations read, on code and on `.eh_frame`, are limited. calls-noplt-gcc-O0.o
    /// has 4 of each, `.rela.text` first.
    #[test]
    fn relocations_stop_at_the_relocation_limit() {
        let at = |relocations| CodeBudgets {
            relocations,
            ..CodeBudgets::default()
        };
        with_image("calls-noplt-gcc-O0.o", at(8), |img, run, _| {
            assert_eq!(img.relocs.len(), 4);
            assert!(!run.stopped());
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
        with_image("calls-noplt-gcc-O0.o", at(7), |img, run, _| {
            assert_eq!(img.relocs.len(), 4);
            assert!(run.stopped());
            assert!(run
                .clone_gaps()
                .contains(&"code: relocation limit 7 reached".to_string()));
        });
        with_image("calls-noplt-gcc-O0.o", at(2), |img, run, _| {
            assert_eq!(img.relocs.len(), 2);
            assert!(run.stopped());
            assert_eq!(run.clone_gaps(), ["code: relocation limit 2 reached"]);
        });
    }

    #[test]
    fn two_relocations_on_one_field_are_a_gap_and_unknown() {
        // The third `.rela.text` entry (helper's, at 0x8a) moved onto the first (connect's).
        with_patched(
            |b, h| set_u64(b, entry(h, ".rela.text", 2).0, 0x2e),
            |img, run, _| {
                let p = TEXT + 0x2e;
                assert_eq!(
                    run.clone_gaps(),
                    [format!("code: two relocations at {p:#x}")]
                );
                assert!(matches!(img.relocs[&p], Reloc::Two(..)));
                assert_eq!(
                    img.field(p, p + 4, Use::Memory),
                    unknown(Some("connect"), RelocWhy::Conflict)
                );
            },
        );
    }

    #[test]
    fn a_relocation_past_its_section_is_a_gap() {
        // `.text` is 0xa2 bytes: a field at 0xa1 is in it, one at 0xa2 is not.
        with_patched(
            |b, h| set_u64(b, entry(h, ".rela.text", 0).0, 0xa1),
            |img, run, _| {
                assert!(img.relocs.contains_key(&(TEXT + 0xa1)));
                assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
            },
        );
        with_patched(
            |b, h| set_u64(b, entry(h, ".rela.text", 0).0, 0xa2),
            |img, run, _| {
                assert_eq!(img.relocs.len(), 3);
                assert_eq!(
                    run.clone_gaps(),
                    ["code: section 2: a relocation at 0xa2 outside its section"]
                );
            },
        );
    }

    #[test]
    fn symbol_zero_names_nothing_and_a_symbol_past_the_table_is_a_gap() {
        let p = TEXT + 0x2e;
        with_patched(
            |b, h| set_u32(b, entry(h, ".rela.text", 0).2, 0),
            |img, run, _| {
                assert!(!img.rel_syms.contains_key(&0));
                assert_eq!(
                    img.field(p, p + 4, Use::Memory),
                    unknown(None, RelocWhy::NoAddress)
                );
                assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
            },
        );
        with_patched(
            |b, h| set_u32(b, entry(h, ".rela.text", 0).2, 99),
            |img, run, _| {
                assert!(!img.rel_syms.contains_key(&99));
                assert_eq!(
                    run.clone_gaps(),
                    ["code: relocation symbol 99 out of range"]
                );
            },
        );
    }

    #[test]
    fn overlapping_code_sections_are_merged_and_a_gap() {
        // `.data` (empty, at 0xe2) made executable over `.text` [0x40, 0xe2) from 0x80.
        with_patched(
            |b, h| {
                let data = header(h, ".data").0;
                set_u64(b, data + 8, 0x6); // SHF_ALLOC | SHF_EXECINSTR
                set_u64(b, data + 24, 0x80);
                set_u64(b, data + 32, 0x100);
            },
            |img, run, _| {
                assert_eq!(
                    img.code,
                    [Region {
                        start: TEXT,
                        end: 0x180,
                        offset: TEXT
                    }]
                );
                assert_eq!(run.clone_gaps(), ["code: code sections overlap at 0x80"]);
            },
        );
    }

    #[test]
    fn a_symbol_without_file_bytes_has_no_address() {
        // `helper` (symbol 3) moved into `.bss` (section 4), whose offset is `.comment`'s.
        with_patched(
            |b, h| {
                let at = header(h, ".symtab").1 + 3 * 24 + 6;
                b[at..at + 2].copy_from_slice(&4u16.to_le_bytes());
            },
            |img, _, _| {
                assert_eq!(
                    img.rel_syms[&3],
                    RelSym {
                        name: None,
                        at: None
                    }
                );
                let helper = TEXT + 0x8a;
                assert_eq!(
                    img.field(helper, helper + 4, Use::Memory),
                    unknown(None, RelocWhy::NoAddress)
                );
            },
        );
    }

    #[test]
    fn eh_frame_relocations_of_other_types_are_gaps() {
        // The first `.rela.eh_frame` entry made `R_X86_64_GOTPCREL` (9): its FDE is not
        // relocated.
        with_patched(
            |b, h| set_u32(b, entry(h, ".rela.eh_frame", 0).1, 9),
            |_, run, _| {
                assert_eq!(run.clone_gaps(), ["code: .eh_frame: relocation type 9"]);
            },
        );
        // An offset past `.eh_frame`'s end (0x98 bytes: a 4-byte field at 0x94 is the last).
        with_patched(
            |b, h| set_u64(b, entry(h, ".rela.eh_frame", 0).0, 0x96),
            |_, run, _| {
                assert_eq!(
                    run.clone_gaps(),
                    ["code: .eh_frame: relocation at 0x96 out of range"]
                );
            },
        );
    }

    #[test]
    fn an_eh_frame_without_file_bytes_is_a_gap() {
        with_patched(
            |b, h| set_u32(b, header(h, ".eh_frame").0 + 4, 8), // SHT_NOBITS
            |img, run, reader| {
                assert!(img.fdes.is_empty());
                assert_eq!(reader.used(), 0, "nothing read");
                assert_eq!(run.clone_gaps(), ["code: .eh_frame: no bytes in the file"]);
            },
        );
    }

    /// `PC64` writes `S + A − P`; the absolute types `S + A` (a non-PIC object's exception-table
    /// pointer: `R_X86_64_32` against `.gcc_except_table`), each range-checked.
    #[test]
    fn eh_frame_relocations_write_their_values() {
        let mut img = Image::empty(Kind::Relocatable);
        // Symbol 1: `.text` at 0x40; 2: `.gcc_except_table` at 0x300; 3: undefined.
        for (i, at) in [(1, Some(0x40)), (2, Some(0x300)), (3, None)] {
            img.rel_syms.insert(i, RelSym { name: None, at });
        }
        let base = 0x100;
        let relocs = [
            (0, reloc(rtype::PC64, 1, 4)),      // 0x44 - 0x100
            (8, reloc(rtype::R32, 2, 0x10)),    // the exception table + 0x10
            (12, reloc(rtype::R32S, 1, -0x50)), // -0x10
            (16, reloc(rtype::R64, 1, 0)),
            (24, reloc(rtype::R32, 3, 0)),     // undefined: skipped
            (28, reloc(rtype::R32, 1, -0x41)), // -1: not a u32
            (30, reloc(rtype::R32, 1, 0)),     // past the end
        ];
        let mut bytes = [0u8; 32];
        let mut run = Run::new(CodeBudgets::default());
        relocate_eh_frame(&mut bytes, base, &relocs, &img, &mut run);
        assert_eq!(bytes[0..8], (-0xbci64).to_le_bytes());
        assert_eq!(bytes[8..12], 0x310u32.to_le_bytes());
        assert_eq!(bytes[12..16], (-0x10i32).to_le_bytes());
        assert_eq!(bytes[16..24], 0x40u64.to_le_bytes());
        assert_eq!(bytes[24..32], [0; 8]);
        assert_eq!(
            run.clone_gaps(),
            [
                "code: .eh_frame: relocation at 0x1c out of range",
                "code: .eh_frame: relocation at 0x1e out of range",
            ]
        );
    }
}
