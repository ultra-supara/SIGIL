//! The image of a relocatable object (PR-5a spec §4.2): an address is a file offset. Code is the
//! `SHF_EXECINSTR` `SHT_PROGBITS` sections, and each relocation on a code field is kept by its
//! field, to be read by its type and the field's use ([`Image::field`]). `.eh_frame` is relocated
//! in a private copy before its FDEs are read.

use std::collections::btree_map::Entry;
use std::collections::BTreeSet;

use object::elf;
use object::read::elf::{FileHeader, Rela as _, SectionHeader, SectionTable, Sym as _};
use object::read::{ReadCacheOps, SectionIndex, SymbolIndex};
use object::Endianness;

use super::{
    rtype, target_names, Callee, FieldReloc, Image, Kind, Meaning, Name, Names, Region, RelSym, Use,
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
    pub fn field(&self, field: u64, next_ip: u64, use_: Use) -> Option<Meaning> {
        use rtype::{CONFLICT, GOTPCREL, GOTPCRELX, PC32, PLT32, R32, R32S, R64, REX_GOTPCRELX};
        let r = self.relocs.get(&field)?;
        let sym = self.rel_syms.get(&r.sym);
        let name = sym.and_then(|s| s.name.clone());
        let at = sym.and_then(|s| s.at);
        // `A + (next_ip − P)`: how far the operand is from the symbol itself.
        let adjust = i128::from(r.addend) + i128::from(next_ip) - i128::from(field);
        let exact = adjust == 0;
        let pcrel = |s: u64| u64::try_from(i128::from(s) + adjust).ok();
        let unknown = |why: String| Meaning::Unknown {
            symbol: name.clone(),
            why,
        };
        let out_of_range = || unknown("an address out of range".to_string());
        let no_address = || unknown("a symbol without an address".to_string());
        Some(match (r.r_type, use_) {
            (CONFLICT, _) => unknown("two relocations on the field".to_string()),
            (PC32 | PLT32, Use::Branch) => match (&name, at) {
                (Some(n), _) if exact => Meaning::Branch(Callee::Import(n.clone())),
                (Some(n), _) => unknown(format!("branch to {}{adjust:+}", shown(n))),
                (None, Some(s)) => {
                    pcrel(s).map_or_else(out_of_range, |t| Meaning::Branch(Callee::Internal(t)))
                }
                (None, None) => no_address(),
            },
            (PC32, Use::Memory | Use::Lea) => match (&name, at) {
                (None, Some(s)) => pcrel(s).map_or_else(out_of_range, Meaning::Address),
                (Some(n), _) if exact && use_ == Use::Lea => Meaning::SymbolAddr(n.clone()),
                (Some(_), _) => unknown("PC32 data of an undefined symbol".to_string()),
                (None, None) => no_address(),
            },
            (GOTPCREL | GOTPCRELX | REX_GOTPCRELX, Use::Memory) if exact => match (&name, at) {
                (Some(n), _) => Meaning::GotEntry(Callee::Import(n.clone())),
                (None, Some(s)) => Meaning::GotEntry(Callee::Internal(s)),
                (None, None) => no_address(),
            },
            (GOTPCREL | GOTPCRELX | REX_GOTPCRELX, _) => {
                unknown(format!("GOT reference {adjust:+}"))
            }
            (R32 | R32S | R64, Use::Immediate | Use::Absolute) => match (&name, at) {
                (None, Some(s)) => s
                    .checked_add_signed(r.addend)
                    .map_or_else(out_of_range, Meaning::Address),
                (Some(n), _) if r.addend == 0 => Meaning::SymbolAddr(n.clone()),
                (Some(_), _) => unknown("an absolute address beside the symbol".to_string()),
                (None, None) => no_address(),
            },
            (t, _) => unknown(format!("relocation type {t}")),
        })
    }
}

/// A symbol name as a gap shows it.
fn shown(name: &Name) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// The image of a relocatable object (spec §4.2), or `None` without section headers or `.symtab`.
/// - Code: the `SHF_EXECINSTR` `SHT_PROGBITS` sections at their file offsets, sorted; sections
///   that overlap (a crafted object) are merged, each overlap a gap.
/// - Strings: the `SHF_ALLOC` `SHT_PROGBITS` sections without `SHF_WRITE` and `SHF_EXECINSTR`
///   that no relocation section names: a relocated section's bytes are not final until linked.
/// - Relocations: the `SHT_RELA` sections on code, against `.symtab`; their symbols, an undefined
///   one by name, a defined one by its file offset (`S`); and `.rela.eh_frame`, applied to a copy
///   of `.eh_frame` (`PC32`, `PC64`) before its FDEs are read at its file offset.
pub(crate) fn relocatable<'d, R: ReadCacheOps, H: FileHeader<Endian = Endianness>>(
    e: &mut Elf<'d, R, H>,
    sections: &Sections<'d, R, H>,
    sig: &Signatures,
    reader: &mut Reader<'_>,
    run: &mut Run,
) -> Option<Image> {
    let endian = e.endian;
    let Some(table) = sections.table.as_ref() else {
        run.gap("code: no section headers".to_string());
        return None;
    };
    let Some(symtab) = sections.symbols.as_ref() else {
        run.gap("code: no .symtab".to_string());
        return None;
    };
    let mut img = Image::empty(Kind::Relocatable);
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
    let mut names = Names::default();
    img.targets = target_names(e, table, symtab, sig, &mut names, run);
    // clang types it `SHT_X86_64_UNWIND`, gcc `SHT_PROGBITS`: found by name.
    let eh: Option<(usize, elf::SectionType, u64, u64)> =
        e.section_index_named(table, b".eh_frame").map(|(i, s)| {
            let (off, size) = (s.sh_offset(endian).into(), s.sh_size(endian).into());
            (i, s.sh_type(endian), off, size)
        });
    let mut eh_relocs: Vec<(u64, FieldReloc)> = vec![];
    let symtab_index = symtab.section().0;
    for (i, s) in table.iter().enumerate() {
        let ty = s.sh_type(endian);
        if !is_relocations(ty) {
            continue;
        }
        let info = s.sh_info(endian) as usize;
        let on_eh = eh.is_some_and(|(k, ..)| k == info);
        let on_code = code_section(table, info, endian);
        if !on_eh && on_code.is_none() {
            continue;
        }
        if ty == elf::SHT_REL {
            run.gap(format!("code: section {i}: REL relocations"));
            continue;
        }
        if s.sh_link(endian) as usize != symtab_index {
            run.gap(format!(
                "code: section {i}: relocations not against .symtab"
            ));
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
            match img.relocs.entry(p) {
                Entry::Vacant(v) => {
                    v.insert(item);
                }
                Entry::Occupied(mut o) if *o.get() != item => {
                    run.gap(format!("code: two relocations at {p:#x}"));
                    o.get_mut().r_type = rtype::CONFLICT;
                }
                Entry::Occupied(_) => {}
            }
        }
    }
    // The symbols the relocations name: each read once, its name held once ([`Names`]).
    let wanted: BTreeSet<u32> = img
        .relocs
        .values()
        .map(|r| r.sym)
        .chain(eh_relocs.iter().map(|(_, r)| r.sym))
        .collect();
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
        img.rel_syms.insert(index, entry);
    }
    match eh {
        Some((_, ty, _, _)) if ty == elf::SHT_NOBITS => {
            run.gap("code: .eh_frame: no bytes in the file".to_string())
        }
        Some((_, _, off, size)) => match reader.read(off, size) {
            Ok(mut bytes) => {
                relocate_eh_frame(&mut bytes, off, &eh_relocs, &img, run);
                img.set_fdes(fde::parse(&bytes, off, run));
            }
            Err(why) => run.refusal(why, ".eh_frame", reader),
        },
        None => {}
    }
    Some(img)
}

/// Whether a section of type `ty` holds relocations.
fn is_relocations(ty: elf::SectionType) -> bool {
    ty == elf::SHT_RELA || ty == elf::SHT_REL
}

/// `(sh_offset, sh_size)` of section `index` when it is code (as [`relocatable`] takes it).
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

/// Applies `.rela.eh_frame` to `bytes`, the contents of `.eh_frame` at file offset `base`:
/// `PC32` and `PC64` write `S + A − P`. A relocation against a symbol without `S` (undefined: a
/// personality routine) names no FDE start and is skipped; any other type is a gap.
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
        let written = match r.r_type {
            rtype::PC32 => i32::try_from(value).is_ok_and(|v| put(bytes, *r_off, &v.to_le_bytes())),
            rtype::PC64 => i64::try_from(value).is_ok_and(|v| put(bytes, *r_off, &v.to_le_bytes())),
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

    /// An image with the relocations `(P, type, symbol, A)` and the symbols `(index, name, S)`.
    fn img_with(
        relocs: &[(u64, u32, u32, i64)],
        syms: &[(u32, Option<&str>, Option<u64>)],
    ) -> Image {
        let mut img = Image::empty(Kind::Relocatable);
        for (p, t, s, a) in relocs {
            img.relocs.insert(
                *p,
                FieldReloc {
                    r_type: *t,
                    sym: *s,
                    addend: *a,
                },
            );
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
            Some(Meaning::Unknown {
                symbol: Some(named("connect")),
                why: "branch to connect+4".to_string()
            }),
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
        assert!(
            matches!(img.field(0x33, 0x37, Use::Memory), Some(Meaning::Unknown { why, .. }) if why == "GOT reference +4"),
            "+4 off the entry"
        );
        assert_eq!(
            img.field(0x43, 0x47, Use::Memory),
            Some(Meaning::GotEntry(Callee::Internal(0x300)))
        );
        assert!(
            matches!(
                img.field(0x53, 0x57, Use::Lea),
                Some(Meaning::Unknown { .. })
            ),
            "a lea of a GOT entry"
        );
        assert!(
            matches!(
                img.field(0x12, 0x16, Use::Branch),
                Some(Meaning::Unknown { .. })
            ),
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
        assert!(
            matches!(
                img.field(0x20, 0x24, Use::Memory),
                Some(Meaning::Unknown { .. })
            ),
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
        assert!(
            matches!(
                img.field(0x50, 0x54, Use::Lea),
                Some(Meaning::Unknown { .. })
            ),
            "PLT32 off a branch"
        );
        // The table's fields: an absolute type on a RIP-relative operand, and PC32 on a value.
        for (at, use_) in [
            (0x30, Use::Memory),
            (0x30, Use::Lea),
            (0x10, Use::Absolute),
            (0x10, Use::Immediate),
        ] {
            assert!(
                matches!(img.field(at, at + 4, use_), Some(Meaning::Unknown { .. })),
                "{at:#x} {use_:?}"
            );
        }
    }

    #[test]
    fn a_field_two_relocations_write_is_unknown() {
        let img = img_with(
            &[(0x10, rtype::CONFLICT, 1, -4)],
            &[(1, Some("connect"), None)],
        );
        assert_eq!(
            img.field(0x10, 0x14, Use::Branch),
            Some(Meaning::Unknown {
                symbol: Some(named("connect")),
                why: "two relocations on the field".to_string()
            })
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
                assert!(img.relocs.values().any(|r| r.r_type == rtype::GOTPCRELX));
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
            let why = |at: u64, use_| match img.field(at, at + 4, use_) {
                Some(Meaning::Unknown { why, .. }) => why,
                m => panic!("{at:#x}: {m:?}"),
            };
            assert_eq!(why(TEXT + 2, Use::Memory), "GOT reference +4");
            assert_eq!(why(TEXT + 9, Use::Lea), "GOT reference +0");
            assert_eq!(
                img.field(TEXT + 0x10, TEXT + 0x14, Use::Memory),
                Some(Meaning::GotEntry(import("connect")))
            );
            assert_eq!(why(TEXT + 0x17, Use::Lea), "relocation type 4");
            assert_eq!(
                img.field(TEXT + 0x1e, TEXT + 0x22, Use::Memory),
                Some(Meaning::Unknown {
                    symbol: Some(named("extern_data")),
                    why: "PC32 data of an undefined symbol".to_string()
                })
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

    /// The section headers of a fixture: `(name, sh_type, header offset, sh_offset, sh_size,
    /// sh_link)`.
    type Headers = [(String, u32, usize, u64, u64, u32)];

    /// [`with_image`] for `fixture` with `patch` applied to its bytes.
    fn with_patched<T>(
        fixture: &str,
        patch: impl FnOnce(&mut Vec<u8>, &Headers),
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let mut bytes = synth::fixture(&format!("code/{fixture}"));
        let headers = synth::sections64(&bytes);
        patch(&mut bytes, &headers);
        let mut file = tempfile::Builder::new().suffix(".o").tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        with_image_at(file.path(), CodeBudgets::default(), f)
    }

    /// The header offset of section `name`.
    fn header(headers: &Headers, name: &str) -> usize {
        headers.iter().find(|h| h.0 == name).unwrap().2
    }

    fn set_u32(bytes: &mut [u8], at: usize, v: u32) {
        bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_u64(bytes: &mut [u8], at: usize, v: u64) {
        bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn relocations_as_rel_or_not_against_symtab_are_gaps() {
        // `.rela.text` is section 2 of calls-noplt-gcc-O0.o.
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| set_u32(b, header(h, ".rela.text") + 4, 9), // SHT_REL
            |img, run, _| {
                assert!(img.relocs.is_empty());
                assert_eq!(run.clone_gaps(), ["code: section 2: REL relocations"]);
            },
        );
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| set_u32(b, header(h, ".rela.text") + 40, 0), // sh_link
            |img, run, _| {
                assert!(img.relocs.is_empty());
                assert_eq!(
                    run.clone_gaps(),
                    ["code: section 2: relocations not against .symtab"]
                );
            },
        );
    }

    #[test]
    fn two_relocations_on_one_field_are_a_gap_and_unknown() {
        // The third `.rela.text` entry (helper's, at 0x8a) moved onto the first (connect's).
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| {
                let rela = h.iter().find(|h| h.0 == ".rela.text").unwrap().3 as usize;
                set_u64(b, rela + 2 * 24, 0x2e);
            },
            |img, run, _| {
                let p = TEXT + 0x2e;
                assert_eq!(
                    run.clone_gaps(),
                    [format!("code: two relocations at {p:#x}")]
                );
                assert!(matches!(
                    img.field(p, p + 4, Use::Memory),
                    Some(Meaning::Unknown { why, .. }) if why == "two relocations on the field"
                ));
            },
        );
    }

    #[test]
    fn overlapping_code_sections_are_merged_and_a_gap() {
        // `.data` (empty, at 0xe2) made executable over `.text` [0x40, 0xe2) from 0x80.
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| {
                let data = header(h, ".data");
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
            "calls-noplt-gcc-O0.o",
            |b, h| {
                let symtab = h.iter().find(|h| h.0 == ".symtab").unwrap().3 as usize;
                b[symtab + 3 * 24 + 6..symtab + 3 * 24 + 8].copy_from_slice(&4u16.to_le_bytes());
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
                assert!(matches!(
                    img.field(helper, helper + 4, Use::Memory),
                    Some(Meaning::Unknown { .. })
                ));
            },
        );
    }

    #[test]
    fn eh_frame_relocations_of_other_types_are_gaps() {
        // The first `.rela.eh_frame` entry made `R_X86_64_32` (10): its FDE is not relocated.
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| {
                let rela = h.iter().find(|h| h.0 == ".rela.eh_frame").unwrap().3 as usize;
                set_u32(b, rela + 8, 10);
            },
            |_, run, _| {
                assert_eq!(run.clone_gaps(), ["code: .eh_frame: relocation type 10"]);
            },
        );
        // An offset past `.eh_frame`'s end.
        with_patched(
            "calls-noplt-gcc-O0.o",
            |b, h| {
                let rela = h.iter().find(|h| h.0 == ".rela.eh_frame").unwrap().3 as usize;
                set_u64(b, rela, 0x96);
            },
            |_, run, _| {
                assert_eq!(
                    run.clone_gaps(),
                    ["code: .eh_frame: relocation at 0x96 out of range"]
                );
            },
        );
    }
}
