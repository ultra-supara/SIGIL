//! The image of an executable or shared object (PR-5a spec §4.2, §4.4): code and string
//! regions, overlapped pages, PLT stubs, GOT slots, text relocations, and FDEs.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use object::elf;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::read::ReadCacheOps;
use object::Endianness;
use sigil_model::ImportVia;

use super::{rtype, target_names, Image, Kind, Names, Region, Sym, PAGE};
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

/// The file-backed ranges of the `PT_LOAD`s `want` selects, minus `cuts` (sorted and disjoint,
/// as [`overlapped_pages`] gives them), sorted. Each segment finds its first cut by binary search
/// and walks only the cuts it meets (review I2). A segment whose file range passes 2^64 is in no
/// file: it gives none.
pub(crate) fn regions(loads: &Loads, want: fn(&Load) -> bool, cuts: &[(u64, u64)]) -> Vec<Region> {
    let mut out = vec![];
    for l in loads.0.iter().filter(|l| want(l)) {
        let (Some(end), Some(_)) = (
            l.vaddr.checked_add(l.filesz),
            l.offset.checked_add(l.filesz),
        ) else {
            continue;
        };
        let mut piece = |s: u64, e: u64| {
            if s < e {
                out.push(Region {
                    start: s,
                    end: e,
                    offset: l.offset + (s - l.vaddr),
                });
            }
        };
        let mut from = l.vaddr;
        let first = cuts.partition_point(|c| c.1 <= from);
        for (cs, ce) in cuts.get(first..).unwrap_or_default() {
            if *cs >= end {
                break;
            }
            piece(from, (*cs).max(from));
            from = from.max(*ce);
            if from >= end {
                break;
            }
        }
        piece(from, end);
    }
    out.sort_unstable();
    out
}

/// Why a PLT section gives no stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PltError {
    /// An invalid instruction at this address.
    Invalid(u64),
    /// A second `jmp` on this GOT slot (review I1).
    TwoStubs(u64),
}

/// The stubs of one PLT section: each near `jmp [rip+slot]` to a known slot, and an `endbr64`
/// right before it. A slot has at most one `jmp` in all the PLT sections (`claimed`: the slots
/// earlier sections have), so the stubs are at most twice the slots. `Err`: no stub of the
/// section is kept.
pub(crate) fn plt_stubs(
    bytes: &[u8],
    start: u64,
    slots: &BTreeMap<u64, Sym>,
    claimed: &BTreeSet<u64>,
) -> Result<Vec<(u64, u64)>, PltError> {
    let mut dec = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    let mut prev: Option<Instruction> = None;
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    while dec.can_decode() {
        dec.decode_out(&mut ins);
        if ins.is_invalid() {
            return Err(PltError::Invalid(ins.ip()));
        }
        // `jmp r/m64` only: not `jmp far` (review M3). A `bnd` or `notrack` prefix is the same
        // instruction.
        if ins.code() == Code::Jmp_rm64 && ins.is_ip_rel_memory_operand() {
            let slot = ins.ip_rel_memory_address();
            if slots.contains_key(&slot) {
                if claimed.contains(&slot) || !seen.insert(slot) {
                    return Err(PltError::TwoStubs(slot));
                }
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

/// Whether `[start, end)` meets `regions` (sorted and disjoint), by binary search (review I3).
fn meets(regions: &[Region], start: u64, end: u64) -> bool {
    let i = regions.partition_point(|r| r.end <= start);
    start < end && regions.get(i).is_some_and(|r| r.start < end)
}

/// The image of an executable or shared object, or `None` when it has no section headers. A file
/// with no target gets an empty image, and nothing past its symbols is read.
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
    let mut names = Names::default();
    if let Some(symbols) = symbols {
        img.targets = target_names(e, table, symbols, sig, &mut names, run);
    }
    // No target: nothing to search (spec §4.4), so nothing else is read. A text relocation
    // against a target, or DT_REL's, would need one.
    if img.targets.is_empty() {
        return Some(img);
    }
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
    // musl applies DT_REL on x86-64 (glibc does not); SIGIL does not read it.
    if dynamic.rel.is_some() {
        run.gap("code: DT_REL relocations are not modeled".to_string());
    }
    // GOT slots, at most `slots` (P1-2), and the dynamic relocations that write code (text
    // relocations): RELA entries with their symbol, and the words DT_RELR relocates. Together at
    // most `references` (R-f).
    let mut slot_syms: BTreeMap<u64, Option<u32>> = BTreeMap::new();
    let slot_limit = run.budgets.slots;
    let mut slots_over = false;
    let mut textrel: Vec<(u64, u64, Option<u32>)> = vec![];
    let limit = run.budgets.references;
    let mut over = false;
    let code = &img.code;
    let walk = e.for_each_rela(dynamic, symbols, |r: Rela| {
        if r.r_type == rtype::JUMP_SLOT || r.r_type == rtype::GLOB_DAT {
            // A slot listed again is checked, never added: only new slots count.
            let full = slot_syms.len() >= slot_limit;
            match slot_syms.entry(r.at) {
                Entry::Occupied(mut s) => {
                    if *s.get() != Some(r.sym) {
                        s.insert(None);
                    }
                }
                Entry::Vacant(_) if full => slots_over = true,
                Entry::Vacant(s) => {
                    s.insert(Some(r.sym));
                }
            }
        }
        let (at, end) = textrel_range(&r);
        if meets(code, at, end) {
            if textrel.len() >= limit {
                over = true;
            } else {
                textrel.push((at, end, Some(r.sym)));
            }
        }
    });
    if let Err(why) = walk {
        run.gap(format!("code: relocations: {why}"));
    }
    let word = if e.header.is_type_64() { 8 } else { 4 };
    let walk = e.for_each_relr(dynamic, |entry| {
        let (lo, hi) = entry.span(word);
        if !meets(code, lo, hi) {
            return ControlFlow::Continue(());
        }
        for (at, end) in entry.words(word) {
            if meets(code, at, end) {
                if textrel.len() >= limit {
                    over = true;
                    return ControlFlow::Break(());
                }
                textrel.push((at, end, None));
            }
        }
        ControlFlow::Continue(())
    });
    if let Err(why) = walk {
        run.gap(format!("code: DT_RELR: {why}"));
    }
    if slots_over {
        run.limit("GOT-slot", slot_limit as u64);
    }
    if over {
        run.limit("references", limit as u64);
    }
    if let Some(symbols) = symbols {
        for (at, _, sym) in &textrel {
            let Some(index) = sym else {
                continue;
            };
            if let Ok(s) = names.sym(e, table, symbols, *index) {
                if img.is_target(&s) {
                    run.gap(format!(
                        "code: {}: text relocation at {at:#x}",
                        String::from_utf8_lossy(&s.name)
                    ));
                }
            }
        }
        for (at, sym) in slot_syms {
            let Some(index) = sym else {
                run.gap(format!("code: GOT slot {at:#x} has two symbols"));
                continue;
            };
            match names.sym(e, table, symbols, index) {
                Ok(s) => {
                    img.slots.insert(at, s);
                }
                Err(_) => run.gap(format!("code: GOT slot {at:#x}: symbol {index} unreadable")),
            }
        }
    }
    img.set_textrel(textrel.into_iter().map(|(at, end, _)| (at, end)).collect());
    // The slots the PLT sections so far have a stub for.
    let mut claimed = BTreeSet::new();
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
        match plt_stubs(&bytes, start, &img.slots, &claimed) {
            Ok(found) => {
                for (stub, slot) in found {
                    claimed.insert(slot);
                    img.stubs.insert(stub, (slot, via));
                }
            }
            Err(PltError::Invalid(at)) => {
                run.gap(format!("code: {name}: decode failure at {at:#x}"))
            }
            Err(PltError::TwoStubs(slot)) => {
                run.gap(format!("code: {name}: two stubs for GOT slot {slot:#x}"))
            }
        }
    }
    // `.eh_frame` is read where code would be (review M1): file-backed, and in no page two
    // PT_LOADs share.
    if let Some(s) = e.section_named(table, b".eh_frame") {
        let start: u64 = s.sh_addr(endian).into();
        let size: u64 = s.sh_size(endian).into();
        let shared = start
            .checked_add(size)
            .is_none_or(|end| meets_cut(&overlaps, start, end));
        match e.loads.place(start, size) {
            _ if shared => {
                run.gap("code: .eh_frame: in a page two PT_LOAD segments share".to_string())
            }
            Place::File(off) => match reader.read(off, size) {
                Ok(bytes) => img.set_fdes(fde::parse(&bytes, start, run)),
                Err(why) => run.refusal(why, ".eh_frame", reader),
            },
            _ => run.gap("code: .eh_frame: not in the file".to_string()),
        }
    }
    Some(img)
}

/// Whether `[start, end)` meets one of `cuts` (sorted and disjoint).
fn meets_cut(cuts: &[(u64, u64)], start: u64, end: u64) -> bool {
    let i = cuts.partition_point(|c| c.1 <= start);
    cuts.get(i).is_some_and(|c| c.0 < end)
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
    use crate::code::image::Name;
    use crate::code::synth;
    use crate::code::testing::{with_image, with_image_at};
    use crate::code::CodeBudgets;
    use std::io::Write;
    use std::path::Path;
    use std::rc::Rc;

    fn name_of(img: &Image, addr: u64) -> String {
        img.symbol_at(addr)
            .map(|(s, _)| String::from_utf8(s.name.to_vec()).unwrap())
            .unwrap_or_default()
    }

    /// Where [`dso`] puts the code, and the GOT slots.
    const TEXT: u64 = 0x1000;
    const SLOTS: u64 = 0x4000_0000;

    /// A shared object for the tests, file-backed at vaddr == offset:
    /// - `text` at [`TEXT`], in an R+X `PT_LOAD` (at most 0x1000 bytes);
    /// - from 0x2000, in an R `PT_LOAD`: `.dynsym` (symbol `i + 1` is `names[i]`, undefined),
    ///   `.dynstr`, a `DT_HASH` over them, the `DT_RELA` entries `relas` (`(offset, type,
    ///   symbol)`), the `DT_RELR` entries `relr`, and `PT_DYNAMIC` (with `dynamic` added);
    /// - [`SLOTS`]: a zero-filled RW `PT_LOAD` for the GOT slots;
    /// - the `PROGBITS` sections `secs` (`(name, address, size)`), and the R `PT_LOAD`s `loads`
    ///   (`(vaddr, size)`).
    #[derive(Default)]
    struct Dso<'a> {
        names: &'a [&'a [u8]],
        relas: &'a [(u64, u32, u32)],
        relr: &'a [u64],
        text: &'a [u8],
        dynamic: &'a [(i64, u64)],
        secs: &'a [(&'a str, u64, u64)],
        loads: &'a [(u64, u64)],
    }

    fn dso(d: &Dso) -> Vec<u8> {
        use synth::*;
        let align = |n: usize, a: usize| n.div_ceil(a) * a;
        let mut syms = vec![0u8; 24];
        let mut strs = vec![0u8];
        for n in d.names {
            syms.extend_from_slice(&sym64(strs.len() as u32, 0x12, 0, 0, 0));
            strs.extend_from_slice(n);
            strs.push(0);
        }
        // DT_HASH: one bucket, chained 1 → 2 → … → the last symbol.
        let count = d.names.len() as u32 + 1;
        let mut words = vec![1, count, u32::from(count > 1), 0];
        words.extend((1..count).map(|i| if i + 1 < count { i + 1 } else { 0 }));
        let hash: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let rela: Vec<u8> = d
            .relas
            .iter()
            .flat_map(|(at, t, sym)| {
                let info = (u64::from(*sym) << 32) | u64::from(*t);
                [at.to_le_bytes(), info.to_le_bytes(), 0u64.to_le_bytes()].concat()
            })
            .collect();
        let relr: Vec<u8> = d.relr.iter().flat_map(|w| w.to_le_bytes()).collect();
        let syms_at = 0x2000;
        let strs_at = align(syms_at + syms.len(), 16);
        let hash_at = align(strs_at + strs.len(), 8);
        let rela_at = align(hash_at + hash.len(), 8);
        let relr_at = align(rela_at + rela.len(), 8);
        let dyn_at = align(relr_at + relr.len(), 16);
        let mut tags = vec![
            (DT_SYMTAB, syms_at as u64),
            (DT_STRTAB, strs_at as u64),
            (DT_STRSZ, strs.len() as u64),
            (DT_HASH, hash_at as u64),
        ];
        if !rela.is_empty() {
            tags.extend([
                (DT_RELA, rela_at as u64),
                (DT_RELASZ, rela.len() as u64),
                (DT_RELAENT, 24),
            ]);
        }
        if !relr.is_empty() {
            tags.extend([
                (DT_RELR, relr_at as u64),
                (DT_RELRSZ, relr.len() as u64),
                (DT_RELRENT, 8),
            ]);
        }
        tags.extend_from_slice(d.dynamic);
        let table = dynamic(&tags);
        let mut img = ElfImage::new(3);
        img.put(TEXT, d.text)
            .put(syms_at as u64, &syms)
            .put(strs_at as u64, &strs)
            .put(hash_at as u64, &hash)
            .put(rela_at as u64, &rela)
            .put(relr_at as u64, &relr)
            .put(dyn_at as u64, &table);
        let (text, end) = (d.text.len() as u64, (dyn_at + table.len()) as u64);
        img.seg(PT_LOAD, PF_R | PF_X, TEXT, TEXT, text, text)
            .seg(PT_LOAD, PF_R, 0x2000, 0x2000, end - 0x2000, end - 0x2000)
            .seg(PT_LOAD, PF_R | PF_W, 0, SLOTS, 0, 0x1000_0000)
            .seg(
                PT_DYNAMIC,
                PF_R | PF_W,
                dyn_at as u64,
                dyn_at as u64,
                table.len() as u64,
                table.len() as u64,
            );
        for (vaddr, size) in d.loads {
            img.seg(PT_LOAD, PF_R, *vaddr, *vaddr, *size, *size);
        }
        img.sec_linked(
            ".dynsym",
            SHT_DYNSYM,
            syms_at as u64,
            syms_at as u64,
            syms.len() as u64,
            2,
            24,
        )
        .sec(
            ".dynstr",
            SHT_STRTAB,
            strs_at as u64,
            strs_at as u64,
            strs.len() as u64,
        );
        for (name, addr, size) in d.secs {
            img.sec(name, SHT_PROGBITS, *addr, *addr, *size);
        }
        img.build()
    }

    /// [`with_image_at`] for the file `bytes`.
    fn with_dso<T>(
        bytes: &[u8],
        budgets: CodeBudgets,
        f: impl FnOnce(&Image, &mut Run, &mut Reader<'_>) -> T,
    ) -> T {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        with_image_at(file.path(), budgets, f)
    }

    /// `jmp [rip+disp]` at `at` to `slot`, with the prefix `prefix` (e.g. `bnd`).
    fn jmp(prefix: &[u8], at: u64, slot: u64) -> Vec<u8> {
        let next = at + prefix.len() as u64 + 6;
        let disp = (slot as i64 - next as i64) as i32;
        [prefix, &[0xff, 0x25], &disp.to_le_bytes()].concat()
    }

    const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

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
                .any(|s| &*s.name == b"connect" && s.defined.is_none()));
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
                name: Name::from(&b"connect"[..]),
                defined: None,
            },
        )]);
        let none = BTreeSet::new();
        // jmp [rip+0x1ffa] at 0x1000 (next ip 0x1006 → slot 0x3000), then an invalid byte pair.
        let bytes = [0xff, 0x25, 0xfa, 0x1f, 0x00, 0x00, 0xff, 0xff];
        assert_eq!(
            plt_stubs(&bytes[..6], 0x1000, &slots, &none),
            Ok(vec![(0x1000, 0x3000)])
        );
        assert_eq!(
            plt_stubs(&bytes, 0x1000, &slots, &none),
            Err(PltError::Invalid(0x1006))
        );
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

    #[test]
    fn adjacent_overlaps_are_merged_into_one_cut() {
        let load = |vaddr, memsz| Load {
            vaddr,
            offset: vaddr,
            filesz: memsz,
            memsz,
            writable: false,
            executable: true,
        };
        // Pages [0x1000, 0x3000), [0x2000, 0x4000), [0x3000, 0x4000): the cuts [0x2000, 0x3000)
        // and [0x3000, 0x4000) touch, and are one.
        let loads = Loads(vec![
            load(0x1000, 0x1800),
            load(0x2400, 0x1400),
            load(0x3400, 0x100),
        ]);
        assert_eq!(overlapped_pages(&loads), [(0x2000, 0x4000)]);
    }

    #[test]
    fn regions_skip_every_cut_a_segment_meets() {
        let loads = Loads(vec![
            Load {
                vaddr: 0x1000,
                offset: 0x11000,
                filesz: 0x8000,
                memsz: 0x8000,
                writable: false,
                executable: true,
            },
            Load {
                vaddr: 0x2800,
                offset: 0x2800,
                filesz: 0x1800,
                memsz: 0x1800,
                writable: false,
                executable: false,
            },
        ]);
        let cuts = [
            (0x0, 0x800),
            (0x2000, 0x3000),
            (0x5000, 0x6000),
            (0x9000, 0xa000),
        ];
        let region = |start, end, offset| Region { start, end, offset };
        assert_eq!(
            regions(&loads, |l| l.executable, &cuts),
            [
                region(0x1000, 0x2000, 0x11000),
                region(0x3000, 0x5000, 0x13000),
                region(0x6000, 0x9000, 0x16000),
            ]
        );
        // A segment that starts inside a cut.
        assert_eq!(
            regions(&loads, |l| !l.executable, &cuts),
            [region(0x3000, 0x4000, 0x3000)]
        );
    }

    #[test]
    fn plt_stubs_take_bnd_jmp_and_only_an_adjacent_endbr64() {
        let slots = BTreeMap::from([(
            0x3000,
            Sym {
                name: Name::from(&b"connect"[..]),
                defined: None,
            },
        )]);
        let none = BTreeSet::new();
        // endbr64; bnd jmp [rip→0x3000]: both are stubs.
        let bytes = [&ENDBR64[..], &jmp(&[0xf2], 0x1004, 0x3000)].concat();
        assert_eq!(
            plt_stubs(&bytes, 0x1000, &slots, &none),
            Ok(vec![(0x1000, 0x3000), (0x1004, 0x3000)])
        );
        // endbr64; nop; jmp: the endbr64 is not right before the jmp.
        let bytes = [&ENDBR64[..], &[0x90], &jmp(&[], 0x1005, 0x3000)].concat();
        assert_eq!(
            plt_stubs(&bytes, 0x1000, &slots, &none),
            Ok(vec![(0x1005, 0x3000)])
        );
        // jmp far [rip→0x3000] (FF /5) is not a stub (review M3).
        let disp = (0x3000i64 - 0x1006) as i32;
        let far = [&[0xff, 0x2d][..], &disp.to_le_bytes()].concat();
        assert_eq!(plt_stubs(&far, 0x1000, &slots, &none), Ok(vec![]));
        // Two jmps on one slot: no stub of the section is kept (review I1).
        let two = [jmp(&[], 0x1000, 0x3000), jmp(&[], 0x1006, 0x3000)].concat();
        assert_eq!(
            plt_stubs(&two, 0x1000, &slots, &none),
            Err(PltError::TwoStubs(0x3000))
        );
        // A slot an earlier PLT section claimed: the same (review: stubs ≤ 2 × slots).
        let claimed = BTreeSet::from([0x3000]);
        assert_eq!(
            plt_stubs(&jmp(&[], 0x1000, 0x3000), 0x1000, &slots, &claimed),
            Err(PltError::TwoStubs(0x3000))
        );
    }

    #[test]
    fn a_plt_with_two_stubs_for_one_slot_is_a_gap_and_keeps_none() {
        let one = jmp(&[], TEXT, SLOTS);
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relas: &[(SLOTS, rtype::JUMP_SLOT, 1)],
            text: &one,
            secs: &[(".plt", TEXT, one.len() as u64)],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(name_of(img, TEXT), "connect", "the builder's stub");
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
        let two = [jmp(&[], TEXT, SLOTS), jmp(&[], TEXT + 6, SLOTS)].concat();
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relas: &[(SLOTS, rtype::JUMP_SLOT, 1)],
            text: &two,
            secs: &[(".plt", TEXT, two.len() as u64)],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert!(img.stubs.is_empty());
            assert_eq!(
                run.clone_gaps(),
                ["code: .plt: two stubs for GOT slot 0x40000000"]
            );
        });
    }

    #[test]
    fn one_stub_per_slot_across_the_plt_sections() {
        // `.plt` and `.plt.sec` both jump through one slot: the later section's stubs are dropped.
        let text = [jmp(&[], TEXT, SLOTS), jmp(&[], TEXT + 6, SLOTS)].concat();
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relas: &[(SLOTS, rtype::JUMP_SLOT, 1)],
            text: &text,
            secs: &[(".plt", TEXT, 6), (".plt.sec", TEXT + 6, 6)],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.stubs, BTreeMap::from([(TEXT, (SLOTS, ImportVia::Plt))]));
            assert_eq!(
                run.clone_gaps(),
                ["code: .plt.sec: two stubs for GOT slot 0x40000000"]
            );
        });
    }

    #[test]
    fn a_plt_outside_executable_bytes_is_a_gap() {
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relas: &[(SLOTS, rtype::JUMP_SLOT, 1)],
            secs: &[(".plt", 0x2000, 0x10)],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.plt, [(0x2000, 0x2010)]);
            assert!(img.stubs.is_empty());
            assert_eq!(run.clone_gaps(), ["code: .plt: not in executable bytes"]);
        });
    }

    #[test]
    fn two_symbols_on_one_slot_are_a_gap_and_no_slot() {
        let bytes = dso(&Dso {
            names: &[b"connect", b"socket"],
            relas: &[
                (SLOTS, rtype::GLOB_DAT, 1),
                (SLOTS, rtype::JUMP_SLOT, 2),
                (SLOTS + 8, rtype::JUMP_SLOT, 1),
            ],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert!(!img.slots.contains_key(&SLOTS));
            assert_eq!(&*img.slots[&(SLOTS + 8)].name, b"connect");
            assert_eq!(
                run.clone_gaps(),
                ["code: GOT slot 0x40000000 has two symbols"]
            );
        });
    }

    /// Review C1 and M2: 400,000 JUMP_SLOTs naming one 5,000-byte name. Copied per slot, that is
    /// 2 GB, past the 1 GiB cap the limit tests run under; held once, a few MB. 5,000 bytes is
    /// also past the 4,096 that object reads: the name is read on, not a gap.
    #[test]
    fn many_slots_naming_one_long_name_hold_it_once_limit() {
        let name = vec![b'n'; 5000];
        let n = 400_000;
        let relas: Vec<(u64, u32, u32)> = (0..n)
            .map(|i| (SLOTS + 8 * i, rtype::JUMP_SLOT, 1))
            .collect();
        let bytes = dso(&Dso {
            names: &[&name, b"connect"],
            relas: &relas,
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.slots.len(), n as usize);
            let first = &img.slots[&SLOTS].name;
            assert_eq!(**first, *name);
            assert!(img.slots.values().all(|s| Rc::ptr_eq(&s.name, first)));
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
    }

    /// P1-2: the GOT slots collected are limited too. The slots past the limit are absent, and
    /// the run is stopped.
    #[test]
    fn got_slots_stop_at_the_slot_limit() {
        let bytes = dso(&Dso {
            names: &[b"connect", b"socket", b"getenv"],
            relas: &[
                (SLOTS, rtype::JUMP_SLOT, 1),
                (SLOTS + 8, rtype::GLOB_DAT, 2),
                (SLOTS, rtype::JUMP_SLOT, 1),
                (SLOTS + 16, rtype::JUMP_SLOT, 3),
                (SLOTS + 24, rtype::GLOB_DAT, 1),
            ],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.slots.len(), 4);
            assert!(!run.stopped());
        });
        let two = CodeBudgets {
            slots: 2,
            ..CodeBudgets::default()
        };
        with_dso(&bytes, two, |img, run, _| {
            // A slot listed again is no new slot: the first two slots are kept.
            assert_eq!(
                img.slots.keys().copied().collect::<Vec<_>>(),
                [SLOTS, SLOTS + 8]
            );
            assert!(run.stopped());
            assert_eq!(run.clone_gaps(), ["code: GOT-slot limit 2 reached"]);
        });
    }

    /// R-f: text relocations count against `references`.
    #[test]
    fn text_relocations_count_against_the_references_limit() {
        let budgets = CodeBudgets {
            references: 0,
            ..CodeBudgets::default()
        };
        with_image("textrel.so", budgets, |img, run, _| {
            assert!(img.textrel.is_empty());
            assert!(run.stopped());
            assert!(run
                .clone_gaps()
                .contains(&"code: references limit 0 reached".to_string()));
        });
    }

    #[test]
    fn dt_rel_is_a_gap() {
        let bytes = dso(&Dso {
            names: &[b"connect"],
            dynamic: &[
                (synth::DT_REL, 0x2000),
                (synth::DT_RELSZ, 16),
                (synth::DT_RELENT, 16),
            ],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |_, run, _| {
            assert_eq!(
                run.clone_gaps(),
                ["code: DT_REL relocations are not modeled"]
            );
        });
    }

    #[test]
    fn relr_words_in_code_are_text_relocations() {
        let text = [0x90; 0x40];
        // The word at TEXT + 8; a bitmap from TEXT + 0x10 with its second word (TEXT + 0x18);
        // a word in the data, not code.
        let relr = [TEXT + 8, 0b101, 0x2000];
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relr: &relr,
            text: &text,
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert_eq!(img.textrel, [(0x1008, 0x1010), (0x1018, 0x1020)]);
            assert!(run.clone_gaps().is_empty(), "{:?}", run.clone_gaps());
        });
        let one = CodeBudgets {
            references: 1,
            ..CodeBudgets::default()
        };
        with_dso(&bytes, one, |img, run, _| {
            assert_eq!(img.textrel, [(0x1008, 0x1010)]);
            assert!(run.stopped());
            assert!(run
                .clone_gaps()
                .contains(&"code: references limit 1 reached".to_string()));
        });
        // A bitmap before any address: glibc writes from address 0, musl from nowhere known.
        let bytes = dso(&Dso {
            names: &[b"connect"],
            relr: &[0b11],
            text: &text,
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, _| {
            assert!(img.textrel.is_empty());
            assert_eq!(
                run.clone_gaps(),
                ["code: DT_RELR: a bitmap before any address"]
            );
        });
    }

    #[test]
    fn a_packed_relative_file_has_no_text_relocation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata-relr.so");
        with_image_at(&path, CodeBudgets::default(), |img, run, _| {
            assert!(img.textrel.is_empty());
            assert!(
                !run.clone_gaps().iter().any(|g| g.contains("RELR")),
                "{:?}",
                run.clone_gaps()
            );
        });
    }

    /// Review M1: `.eh_frame` is read only where code would be: file-backed, in no shared page.
    #[test]
    fn an_eh_frame_in_a_shared_page_is_not_read() {
        let bytes = dso(&Dso {
            names: &[b"connect"],
            secs: &[(".eh_frame", 0x2000, 0x10)],
            loads: &[(0x2800, 0x100)],
            ..Dso::default()
        });
        with_dso(&bytes, CodeBudgets::default(), |img, run, reader| {
            assert!(img.fdes.is_empty());
            assert_eq!(reader.used(), 0, "nothing read");
            assert_eq!(
                run.clone_gaps(),
                [
                    "code: .eh_frame: in a page two PT_LOAD segments share",
                    "code: PT_LOAD segments overlap at 0x2000",
                ]
            );
        });
    }
}
