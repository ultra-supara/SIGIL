//! The image of an executable or shared object (PR-5a spec §4.2, §4.4): code and string
//! regions, overlapped pages, PLT stubs, GOT slots, text relocations, and FDEs.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::read::ReadCacheOps;
use object::Endianness;
use sigil_model::ImportVia;

use super::{read_sym, rtype, target_names, Image, Kind, Region, Sym, PAGE};
use crate::binary::elf::{Dynamic, Elf, Rela, Sections};
use crate::binary::vaddr::{Load, Loads, Place};
use crate::code::data::Signatures;
use crate::code::reader::Reader;
use crate::code::{fde, Run};

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
        use object::read::elf::{FileHeader as _, Sym as _};
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
}
