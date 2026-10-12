//! ELF facts (spec §4.3): every fact read in full, confirmed absent, or a gap. Committed fixtures
//! and raw images only.

mod common;

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::{ContainerFacts, ElfFacts, UntrustedText};

fn facts_of(bytes: &[u8], budgets: BinaryBudgets) -> (ElfFacts, Parsed) {
    let parsed = parse(&file(bytes), bytes.len() as u64, budgets);
    let ContainerFacts::Elf(f) = parsed.container.clone() else {
        panic!()
    };
    (f, parsed)
}

fn t(s: &str) -> UntrustedText {
    UntrustedText::new(s)
}

fn texts(v: &[UntrustedText]) -> Vec<String> {
    v.iter()
        .map(|x| x.as_str().unwrap_or_default().to_string())
        .collect()
}

/// The NEEDED order and build-id that build.sh produced (Task 5, Step 2).
const LIBDATA_NEEDED: &[&str] = &["libm.so.6", "libc.so.6"];
const LIBDATA_BUILD_ID: &str = "7f9ab1dd1c36c8cd2427ccd47b7523eb96168157";

#[test]
fn a_shared_object_s_facts() {
    let (f, p) = facts_of(&fixture("elf/libdata.so"), BinaryBudgets::default());
    assert_eq!(f.soname, Some(t("libdata.so.1")));
    assert_eq!(texts(&f.needed), LIBDATA_NEEDED);
    assert_eq!(texts(&f.runpath), ["$ORIGIN"]);
    assert!(f.rpath.is_empty());
    assert_eq!(f.interp, None);
    assert_eq!(f.build_id.as_deref(), Some(LIBDATA_BUILD_ID));
    assert!(f
        .comment
        .iter()
        .any(|c| c.as_str().is_some_and(|c| c.starts_with("GCC:"))));
    assert_eq!(f.stripped, Some(false));
    assert!(
        f.exports >= 6,
        "the two functions and the four data symbols"
    );
    let imports: Vec<(String, Option<String>)> = f
        .imports
        .iter()
        .map(|i| {
            (
                i.name.as_str().unwrap().to_string(),
                i.version
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            )
        })
        .collect();
    assert!(imports
        .iter()
        .any(|(n, v)| n == "connect" && v.as_deref().is_some_and(|v| v.starts_with("GLIBC_"))));
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

#[test]
fn an_executable_has_its_interpreter_and_rpath() {
    let (f, p) = facts_of(&fixture("elf/exe-nopie"), BinaryBudgets::default());
    assert!(f
        .interp
        .as_ref()
        .and_then(|i| i.as_str())
        .is_some_and(|i| i.contains("ld-linux")));
    assert_eq!(texts(&f.rpath), ["/opt/sigil-test/lib"]);
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

#[test]
fn a_static_executable_has_no_dynamic_facts_and_no_gap() {
    let (f, p) = facts_of(&fixture("elf/static"), BinaryBudgets::default());
    assert_eq!((f.interp, f.soname), (None, None));
    assert!(f.needed.is_empty() && f.imports.is_empty() && f.exports == 0);
    assert!(p.gaps.is_empty(), "absent is not a gap: {:?}", p.gaps);
}

#[test]
fn without_section_headers_needed_and_soname_still_come_from_pt_dynamic() {
    // The review's P1-1: remove the section header table of a real shared object.
    let mut bytes = fixture("elf/libdata.so");
    bytes[40..48].fill(0); // e_shoff
    bytes[60..64].fill(0); // e_shnum, e_shstrndx
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(f.soname, Some(t("libdata.so.1")));
    assert_eq!(texts(&f.needed), LIBDATA_NEEDED);
    assert_eq!(
        f.build_id.as_deref(),
        Some(LIBDATA_BUILD_ID),
        "from PT_NOTE"
    );
    assert_eq!(f.stripped, None);
    assert!(
        p.gaps
            .contains(&"sections: no section header table".to_string()),
        "{:?}",
        p.gaps
    );
    assert!(
        p.gaps.iter().any(|g| g.starts_with("symbols: ")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn a_section_header_table_out_of_the_file_is_a_malformed_gap() {
    let mut bytes = fixture("elf/libdata.so");
    bytes[40..48].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(f.stripped, None);
    assert!(
        p.gaps.iter().any(|g| g.starts_with("sections: malformed")),
        "{:?}",
        p.gaps
    );
    assert_eq!(texts(&f.needed), LIBDATA_NEEDED, "PT_DYNAMIC is unaffected");
}

/// A raw image: one PT_LOAD over the whole file, PT_DYNAMIC at 0x2000 with `entries`, strings at
/// 0x3000 (`strtab`), mapped at vaddr == offset.
fn image(entries: &[(i64, u64)], strtab: &[u8]) -> ElfImage {
    let dynamic = dynamic(entries);
    let mut img = ElfImage::new(3);
    img.put(0x2000, &dynamic).put(0x3000, strtab);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end).seg(
        PT_DYNAMIC,
        PF_R | PF_W,
        0x2000,
        0x2000,
        dynamic.len() as u64,
        dynamic.len() as u64,
    );
    img
}

#[test]
fn only_pt_note_gives_the_build_id() {
    let mut img = ElfImage::new(3);
    let n = note(b"GNU", 3, &[0xab; 20]);
    img.put(0x2000, &n);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R, 0, 0, end, end).seg(
        PT_NOTE,
        PF_R,
        0x2000,
        0x2000,
        n.len() as u64,
        n.len() as u64,
    );
    let (f, _) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(f.build_id.as_deref(), Some("ab".repeat(20).as_str()));
}

#[test]
fn dynamic_strings_must_be_file_backed_and_inside_strsz() {
    // DT_STRTAB outside every PT_LOAD.
    let img = image(
        &[(DT_STRTAB, 0x9_0000), (DT_STRSZ, 8), (DT_NEEDED, 1)],
        b"\0libx.so\0",
    );
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(f.needed.is_empty());
    assert!(
        p.gaps.iter().any(|g| g.starts_with("dynamic: ")),
        "{:?}",
        p.gaps
    );
    // A NEEDED offset past DT_STRSZ.
    let img = image(
        &[(DT_STRTAB, 0x3000), (DT_STRSZ, 4), (DT_NEEDED, 9)],
        b"\0libx.so\0",
    );
    let (_, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(
        p.gaps.iter().any(|g| g.starts_with("dynamic: ")),
        "{:?}",
        p.gaps
    );
    // A string tag without DT_STRTAB.
    let img = image(&[(DT_NEEDED, 1)], b"\0libx.so\0");
    let (_, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(
        p.gaps.iter().any(|g| g.starts_with("dynamic: ")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn output_limits_keep_what_they_can_and_say_so() {
    // 100,000 DT_NEEDED entries pointing at one short string (the review's case).
    let mut entries = vec![(DT_STRTAB, 0x3000), (DT_STRSZ, 9)];
    entries.extend(std::iter::repeat_n((DT_NEEDED, 1), 100_000));
    let img = image(&entries, b"\0libx.so\0");
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(f.needed.len() <= 1024);
    assert!(p.gaps.iter().any(|g| g.contains("over")), "{:?}", p.gaps);
    // A 4 KiB build-id descriptor.
    let mut img = ElfImage::new(3);
    let n = note(b"GNU", 3, &[0x11; 4096]);
    img.put(0x2000, &n);
    let end = img.body.len() as u64;
    img.seg(PT_LOAD, PF_R, 0, 0, end, end).seg(
        PT_NOTE,
        PF_R,
        0x2000,
        0x2000,
        n.len() as u64,
        n.len() as u64,
    );
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(f.build_id, None);
    assert!(
        p.gaps.iter().any(|g| g.starts_with("build-id: over")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn the_parse_budget_bounds_a_lying_section_size() {
    // A section declared 48 MiB long inside a 64 MiB file, with a 1 MiB budget.
    let mut img = ElfImage::new(3);
    img.put((64 << 20) - 1, &[0]);
    img.sec(".comment", SHT_PROGBITS, 0x1000, 0, 48 << 20);
    let (_, p) = facts_of(
        &img.build(),
        BinaryBudgets {
            parse_bytes: 1 << 20,
            ..BinaryBudgets::default()
        },
    );
    assert!(
        p.gaps.iter().any(|g| g.starts_with("binary_parse_bytes")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn malformed_and_truncated_files_are_gaps_never_panics() {
    let good = fixture("elf/libdata.so");
    for cut in [64usize, 200, 1000, good.len() / 2] {
        let (_, p) = facts_of(&good[..cut], BinaryBudgets::default());
        assert!(!p.gaps.is_empty(), "cut at {cut}");
    }
    // A PT_LOAD whose address arithmetic overflows.
    let mut img = image(
        &[(DT_STRTAB, 0x3000), (DT_STRSZ, 9), (DT_NEEDED, 1)],
        b"\0libx.so\0",
    );
    img.seg(PT_LOAD, PF_R, 0, u64::MAX - 4, 0x100, 0x100);
    let _ = facts_of(&img.build(), BinaryBudgets::default());
}

#[test]
fn the_header_check_and_the_parser_agree_on_every_fixture() {
    for name in [
        "libdata.so",
        "libdata-relr.so",
        "libsym64.so",
        "exe-nopie",
        "static",
        "libdata-aarch64.so",
        "net.o",
    ] {
        let bytes = fixture(&format!("elf/{name}"));
        assert!(
            sigil_engine::binary::header::read(&bytes[..64]).is_some(),
            "{name}"
        );
        let p = parse(&file(&bytes), bytes.len() as u64, BinaryBudgets::default());
        assert!(
            !p.gaps.iter().any(|g| g.starts_with("malformed: header")),
            "{name}: {:?}",
            p.gaps
        );
    }
}

#[test]
fn a_dynamic_table_without_dt_null_or_whole_entries_is_a_gap() {
    // The review's case: PT_DYNAMIC cut after the first NEEDED, so the second and DT_NULL are
    // not read. NEEDED must not look complete.
    let mut img = image(
        &[
            (DT_STRTAB, 0x3000),
            (DT_STRSZ, 17),
            (DT_NEEDED, 1),
            (DT_NEEDED, 9),
        ],
        b"\0libA.so\0libB.so\0",
    );
    let pt = img
        .segs
        .iter_mut()
        .find(|s| s.p_type == PT_DYNAMIC)
        .unwrap();
    pt.filesz = 3 * 16;
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(texts(&f.needed), ["libA.so"]);
    assert!(
        p.gaps.contains(&"dynamic: missing DT_NULL".to_string()),
        "{:?}",
        p.gaps
    );
    // A size that is not a whole number of entries.
    let pt = img
        .segs
        .iter_mut()
        .find(|s| s.p_type == PT_DYNAMIC)
        .unwrap();
    pt.filesz = 5 * 16 + 8;
    let (_, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(
        p.gaps
            .iter()
            .any(|g| g.starts_with("dynamic: malformed: p_filesz")),
        "{:?}",
        p.gaps
    );
    // The full table: no gap.
    let pt = img
        .segs
        .iter_mut()
        .find(|s| s.p_type == PT_DYNAMIC)
        .unwrap();
    pt.filesz = 5 * 16;
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(texts(&f.needed), ["libA.so", "libB.so"]);
    assert!(
        !p.gaps.iter().any(|g| g.starts_with("dynamic")),
        "{:?}",
        p.gaps
    );
}

/// `libdata.so`'s `.gnu.version`: `(file offset, size)`.
fn versym(bytes: &[u8]) -> (usize, usize, usize) {
    let (_, _, header, offset, size, _) = sections64(bytes)
        .into_iter()
        .find(|s| s.1 == SHT_GNU_VERSYM)
        .unwrap();
    (header, offset as usize, size as usize)
}

#[test]
fn a_symbol_version_that_does_not_resolve_is_a_gap() {
    // Every versym entry set to an index past the version table: not "unversioned".
    let mut bytes = fixture("elf/libdata.so");
    let (_, offset, size) = versym(&bytes);
    for e in (offset..offset + size).step_by(2).skip(1) {
        bytes[e..e + 2].copy_from_slice(&0x7ff0u16.to_le_bytes());
    }
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        p.gaps.iter().any(|g| g.starts_with("versions: ")),
        "{:?}",
        p.gaps
    );
    assert_eq!(
        p.gaps
            .iter()
            .filter(|g| g.starts_with("versions: "))
            .count(),
        1,
        "one gap, not one per symbol: {:?}",
        p.gaps
    );
}

#[test]
fn a_version_table_shorter_than_the_symbols_is_a_gap() {
    let mut bytes = fixture("elf/libdata.so");
    let (header, _, _) = versym(&bytes);
    bytes[header + 32..header + 40].copy_from_slice(&2u64.to_le_bytes()); // sh_size: one entry
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        p.gaps
            .contains(&"versions: .gnu.version is shorter than .dynsym".to_string()),
        "{:?}",
        p.gaps
    );
}

/// PR-4b-2a spec §4.4: a relocatable object has no `.dynsym`. Its imports are the undefined
/// symbols of its link-time symbol table, left for the linker, and its exports its defined
/// global ones. No versions, no data values.
#[test]
fn a_relocatable_object_s_symbols_come_from_symtab() {
    let (f, p) = facts_of(&fixture("elf/net.o"), BinaryBudgets::default());
    let names: Vec<String> = f
        .imports
        .iter()
        .map(|i| i.name.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names, ["connect", "socket"]);
    assert!(f.imports.iter().all(|i| i.version.is_none() && !i.weak));
    assert_eq!(f.exports, 1, "sigil_connect_loopback");
    assert_eq!(f.stripped, Some(false));
    assert!(f.data.is_empty() && f.needed.is_empty() && f.interp.is_none());
    assert!(!f.comment.is_empty());
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

#[test]
fn a_relocatable_object_without_symtab_is_a_gap() {
    let mut img = ElfImage::new(1); // ET_REL
    img.put(0x1000, &[0xc3]);
    img.sec(".text", SHT_PROGBITS, 0x1000, 0, 1);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(f.imports.is_empty());
    assert_eq!(p.gaps, ["symbols: no SHT_SYMTAB in a relocatable object"]);
}

/// Review of Part B: a relocatable object's symbol table, built by hand. Locals and hidden
/// globals are not exports; a weak undefined symbol is a weak import; a known data symbol is
/// listed as `Unknown` with its gap (its data is not linked yet), never left out as absent.
#[test]
fn a_relocatable_object_s_symtab_follows_the_dynsym_rules_and_keeps_known_symbols() {
    let mut img = ElfImage::new(1); // ET_REL
    let names = b"\0local_fn\0hidden_fn\0weak_ref\0LLAMA_COMMIT\0exported\0";
    let at = |s: &[u8]| names.windows(s.len()).position(|w| w == s).unwrap() as u32;
    let mut syms = vec![0u8; 24];
    syms.extend_from_slice(&sym64(at(b"local_fn"), 0x02, 1, 0, 1)); // LOCAL FUNC
    let mut hidden = sym64(at(b"hidden_fn"), 0x12, 1, 0, 1); // GLOBAL FUNC
    hidden[5] = 2; // STV_HIDDEN
    syms.extend_from_slice(&hidden);
    syms.extend_from_slice(&sym64(at(b"weak_ref"), 0x20, 0, 0, 0)); // WEAK NOTYPE, undefined
    syms.extend_from_slice(&sym64(at(b"LLAMA_COMMIT"), 0x11, 1, 0, 8)); // GLOBAL OBJECT
    syms.extend_from_slice(&sym64(at(b"exported"), 0x12, 1, 0, 1)); // GLOBAL FUNC
    let (sym_off, str_off) = (0x1000u64, 0x2000u64);
    img.put(sym_off, &syms).put(str_off, names);
    // Section 1 is .symtab, linked to section 2, .strtab.
    img.sec_linked(".symtab", SHT_SYMTAB, sym_off, 0, syms.len() as u64, 2, 24)
        .sec(".strtab", SHT_STRTAB, str_off, 0, names.len() as u64);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(
        f.exports, 2,
        "exported and LLAMA_COMMIT; not the local or the hidden one"
    );
    assert_eq!(f.imports.len(), 1);
    assert_eq!(f.imports[0].name.as_str(), Some("weak_ref"));
    assert!(f.imports[0].weak);
    assert_eq!(f.data.len(), 1, "{:?}", f.data);
    assert_eq!(f.data[0].symbol, "LLAMA_COMMIT");
    assert!(
        matches!(&f.data[0].value, sigil_model::DataValue::Unknown { why } if why.contains("relocatable")),
        "{:?}",
        f.data[0].value
    );
    assert_eq!(
        p.gaps,
        ["LLAMA_COMMIT: not linked yet (a relocatable object)"]
    );
}

/// Review of #89 (P2): a defined data symbol whose name cannot be read (its `st_name` past the
/// string table) is a gap, never skipped silently: it could be a known data symbol.
#[test]
fn a_data_symbol_whose_name_cannot_be_read_is_a_gap() {
    let mut img = ElfImage::new(1); // ET_REL
    let names = b"\0exported\0";
    let mut syms = vec![0u8; 24];
    syms.extend_from_slice(&sym64(1, 0x12, 1, 0, 1)); // GLOBAL FUNC "exported"
    syms.extend_from_slice(&sym64(0xffff, 0x11, 1, 0, 8)); // GLOBAL OBJECT, name out of range
    let (sym_off, str_off) = (0x1000u64, 0x2000u64);
    img.put(sym_off, &syms).put(str_off, names);
    img.sec_linked(".symtab", SHT_SYMTAB, sym_off, 0, syms.len() as u64, 2, 24)
        .sec(".strtab", SHT_STRTAB, str_off, 0, names.len() as u64);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(f.data.is_empty());
    assert!(
        p.gaps
            .iter()
            .any(|g| g.starts_with("malformed: symbols: a data symbol's name")),
        "{:?}",
        p.gaps
    );
}

/// Review of #89 (the same class as P2): a section whose name cannot be read could be `.comment`
/// or `.go.buildinfo`. It is a gap, never "absent".
#[test]
fn a_section_whose_name_cannot_be_read_is_a_gap() {
    let mut img = ElfImage::new(3);
    img.put(0x1000, b"GCC: test\0")
        .sec(".comment", SHT_PROGBITS, 0x1000, 0, 10);
    let readable = img.build();
    let (f, p) = facts_of(&readable, BinaryBudgets::default());
    assert_eq!(texts(&f.comment), ["GCC: test"]);
    assert!(
        p.gaps.iter().all(|g| !g.contains("section names")),
        "{:?}",
        p.gaps
    );
    // `.comment` is section 1: its `sh_name` set past `.shstrtab`.
    let mut bytes = readable;
    let shoff = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    bytes[shoff + 64..shoff + 68].copy_from_slice(&0xffff_u32.to_le_bytes());
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(f.comment.is_empty());
    assert_eq!(f.stripped, Some(true));
    assert!(
        p.gaps
            .iter()
            .any(|g| g.starts_with("malformed: section names: ")),
        "{:?}",
        p.gaps
    );
}

/// Review of the #89 fixes: a valid name of 4096 bytes or more (a C++ section or symbol) is no
/// gap. object's string lookup stops at 4096 bytes; SIGIL reads only what a wanted name needs.
#[test]
fn a_long_valid_name_is_no_gap_and_an_unterminated_one_is() {
    let long = "x".repeat(5000);
    let mut img = ElfImage::new(3);
    img.put(0x1000, b"GCC: test\0")
        .sec(&format!(".text.{long}"), SHT_PROGBITS, 0x1000, 0, 0)
        .sec(".comment", SHT_PROGBITS, 0x1000, 0, 10);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(texts(&f.comment), ["GCC: test"]);
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);

    let symtab = |names: &[u8]| {
        let mut img = ElfImage::new(1); // ET_REL
        let mut syms = vec![0u8; 24];
        syms.extend_from_slice(&sym64(1, 0x12, 1, 0, 1)); // GLOBAL FUNC "exported"
        syms.extend_from_slice(&sym64(10, 0x11, 1, 0, 8)); // GLOBAL OBJECT, the name at 10
        let (sym_off, str_off) = (0x1000u64, 0x2000u64);
        img.put(sym_off, &syms).put(str_off, names);
        img.sec_linked(".symtab", SHT_SYMTAB, sym_off, 0, syms.len() as u64, 2, 24)
            .sec(".strtab", SHT_STRTAB, str_off, 0, names.len() as u64);
        facts_of(&img.build(), BinaryBudgets::default()).1.gaps
    };
    let mut names = b"\0exported\0".to_vec();
    names.extend_from_slice(long.as_bytes());
    names.push(0);
    assert!(symtab(&names).is_empty(), "{:?}", symtab(&names));
    // "LLAMA" at the end of the table with no NUL: it could be a known name, cut.
    let gaps = symtab(b"\0exported\0LLAMA");
    assert!(
        gaps.iter()
            .any(|g| g
                .starts_with("malformed: symbols: a data symbol's name: a name not terminated")),
        "{gaps:?}"
    );
}
