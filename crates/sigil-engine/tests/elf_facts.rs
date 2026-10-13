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

/// The gaps about `PT_DYNAMIC` (an image without sections also has a `sections: ` gap).
fn dynamic_gaps(p: &Parsed) -> Vec<String> {
    p.gaps
        .iter()
        .filter(|g| g.starts_with("dynamic"))
        .cloned()
        .collect()
}

/// Spec §3.5: glibc and musl keep the last `PT_DYNAMIC` and read it at its `p_vaddr`.
#[test]
fn the_last_pt_dynamic_is_read_where_its_address_is() {
    let strings = b"\0libA.so\0libB.so\0";
    let entries = [(DT_STRTAB, 0x3000), (DT_STRSZ, 17), (DT_NEEDED, 1)];
    // Two tables: libA.so's at 0x2000 (first), libB.so's at 0x2800 (last).
    let mut img = image(&entries, strings);
    let second = dynamic(&[(DT_STRTAB, 0x3000), (DT_STRSZ, 17), (DT_NEEDED, 9)]);
    let len = second.len() as u64;
    img.put(0x2800, &second)
        .seg(PT_DYNAMIC, PF_R | PF_W, 0x2800, 0x2800, len, len);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(texts(&f.needed), ["libB.so"]);
    assert_eq!(dynamic_gaps(&p), ["dynamic: more than one PT_DYNAMIC"]);

    // p_offset elsewhere: still read at p_vaddr, with no gap.
    let mut img = image(&entries, strings);
    img.segs
        .iter_mut()
        .find(|s| s.p_type == PT_DYNAMIC)
        .unwrap()
        .offset = 0x100;
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(texts(&f.needed), ["libA.so"]);
    assert!(dynamic_gaps(&p).is_empty(), "{:?}", p.gaps);

    // p_vaddr in no PT_LOAD: not where the loader could read it.
    let mut img = image(&entries, strings);
    img.segs
        .iter_mut()
        .find(|s| s.p_type == PT_DYNAMIC)
        .unwrap()
        .vaddr = 0x9_0000;
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert!(f.needed.is_empty());
    assert_eq!(dynamic_gaps(&p), ["dynamic: not file-backed at p_vaddr"]);

    // A real shared object with its PT_DYNAMIC p_offset zeroed: the same facts, no gap.
    let mut bytes = fixture("elf/libdata.so");
    let h = phdr64(&bytes, PT_DYNAMIC);
    bytes[h + 8..h + 16].fill(0);
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(texts(&f.needed), LIBDATA_NEEDED);
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
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

/// An ET_DYN image: `.dynsym` (null, then the defined GLOBAL FUNCs "one" and "two") at 0x1000
/// (`DT_SYMTAB`), its strings at 0x1100, a `DT_GNU_HASH` reaching both at 0x1200, `PT_DYNAMIC` at
/// 0x2000 with `entries` added (a later tag overrides it, as in the loader), and each
/// `(offset, bytes)` of `extra`. One PT_LOAD maps the file at vaddr == offset.
fn dynsym_image(entries: &[(i64, u64)], extra: &[(u64, &[u8])]) -> Vec<u8> {
    dynsym_elf(entries, extra).build()
}

/// `dynsym_image` before it is built, for more segments or sections (`.dynsym` is section 1 and
/// `.dynstr` section 2).
fn dynsym_elf(entries: &[(i64, u64)], extra: &[(u64, &[u8])]) -> ElfImage {
    let names = b"\0one\0two\0";
    let mut syms = vec![0u8; 24];
    syms.extend_from_slice(&sym64(1, 0x12, 5, 0x3000, 1));
    syms.extend_from_slice(&sym64(5, 0x12, 5, 0x3001, 1));
    let mut all = vec![
        (DT_SYMTAB, 0x1000),
        (DT_STRTAB, 0x1100),
        (DT_STRSZ, names.len() as u64),
        (DT_GNU_HASH, 0x1200),
    ];
    all.extend_from_slice(entries);
    let table = dynamic(&all);
    let mut img = ElfImage::new(3);
    img.put(0x1000, &syms)
        .put(0x1100, names)
        .put(0x1200, &gnu_hash(1, &[1], &[0x10, 0x21]))
        .put(0x2000, &table);
    for (at, bytes) in extra {
        img.put(*at, bytes);
    }
    img.put(0x3fff, &[0]);
    let end = img.body.len() as u64;
    let len = table.len() as u64;
    img.seg(PT_LOAD, PF_R | PF_W, 0, 0, end, end).seg(
        PT_DYNAMIC,
        PF_R | PF_W,
        0x2000,
        0x2000,
        len,
        len,
    );
    // Section 1 is .dynsym, linked to section 2, .dynstr.
    img.sec_linked(
        ".dynsym",
        SHT_DYNSYM,
        0x1000,
        0x1000,
        syms.len() as u64,
        2,
        24,
    )
    .sec(".dynstr", SHT_STRTAB, 0x1100, 0x1100, names.len() as u64);
    img
}

/// Spec §3.1: ld.so checks versions through `DT_VERSYM`. A `.gnu.version` section that is
/// missing, or not where `DT_VERSYM` is, leaves a gap, never "unversioned" in silence.
#[test]
fn dt_versym_without_its_section_is_a_gap() {
    let mut bytes = fixture("elf/libdata.so");
    let (header, _, _) = versym(&bytes);
    bytes[header + 4..header + 8].copy_from_slice(&SHT_PROGBITS.to_le_bytes());
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        f.imports.iter().all(|i| i.version.is_none()),
        "{:?}",
        f.imports
    );
    assert_eq!(
        p.gaps,
        ["versions: DT_VERSYM without a .gnu.version section"]
    );

    let mut bytes = fixture("elf/libdata.so");
    let (header, _, _) = versym(&bytes);
    let addr = u64::from_le_bytes(bytes[header + 16..header + 24].try_into().unwrap());
    bytes[header + 16..header + 24].copy_from_slice(&(addr + 2).to_le_bytes());
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(p.gaps, ["versions: .gnu.version is not at DT_VERSYM"]);
}

/// Review of #91 (P1-1): the loader reads `DT_SYMTAB` and `DT_STRTAB` through the PT_LOADs,
/// object reads `.dynsym` and its strings at their `sh_offset`. With the address right and the
/// offset on a valid copy elsewhere, SIGIL would read other symbols or names than the loader.
#[test]
fn dynsym_and_its_strings_must_be_the_bytes_mapped_at_their_tags() {
    // The copies: "one" and "two" undefined, and the names "eno" and "owt".
    let mut imports = vec![0u8; 24];
    imports.extend_from_slice(&sym64(1, 0x12, 0, 0, 0));
    imports.extend_from_slice(&sym64(5, 0x12, 0, 0, 0));
    let bytes = dynsym_image(
        &[],
        &[(0x3800, imports.as_slice()), (0x3900, b"\0eno\0owt\0")],
    );
    let header = |name: &str| {
        sections64(&bytes)
            .into_iter()
            .find(|s| s.0 == name)
            .unwrap()
            .2
    };
    // Section `name` with `sh_addr` `addr` and `sh_offset` `offset`.
    let gaps = |name: &str, addr: u64, offset: u64, symtab: u64| {
        let mut b = bytes.clone();
        let h = header(name);
        b[h + 16..h + 24].copy_from_slice(&addr.to_le_bytes());
        b[h + 24..h + 32].copy_from_slice(&offset.to_le_bytes());
        set_dynamic(&mut b, DT_SYMTAB, symtab);
        facts_of(&b, BinaryBudgets::default()).1.gaps
    };
    assert!(gaps(".dynsym", 0x1000, 0x1000, 0x1000).is_empty());
    assert_eq!(
        gaps(".dynsym", 0x1000, 0x3800, 0x1000),
        ["symbols: .dynsym is not the bytes mapped at DT_SYMTAB"]
    );
    assert_eq!(
        gaps(".dynsym", 0x9_0000, 0x1000, 0x9_0000),
        ["symbols: .dynsym is not the bytes mapped at DT_SYMTAB"],
        "an address no PT_LOAD maps"
    );
    assert_eq!(
        gaps(".dynstr", 0x1100, 0x3900, 0x1000),
        ["symbols: .dynsym's string table is not the bytes mapped at DT_STRTAB"]
    );
    assert_eq!(
        gaps(".dynstr", 0x3900, 0x3900, 0x1000),
        ["symbols: .dynsym's string table is not at DT_STRTAB"]
    );
}

/// Review of #91 (P1-1): ld.so reads the versions at `DT_VERSYM`, `DT_VERNEED`, and
/// `DT_VERDEF`; object reads the first section of each type at its `sh_offset`.
#[test]
fn version_sections_must_be_the_bytes_mapped_at_their_tags() {
    for (tag, tag_name, sh_type, name, link) in [
        (DT_VERSYM, "DT_VERSYM", SHT_GNU_VERSYM, ".gnu.version", 1),
        (
            DT_VERNEED,
            "DT_VERNEED",
            SHT_GNU_VERNEED,
            ".gnu.version_r",
            2,
        ),
        (DT_VERDEF, "DT_VERDEF", SHT_GNU_VERDEF, ".gnu.version_d", 2),
    ] {
        // The section at `(sh_offset, sh_addr)`, or none; `DT_*` is 0x3a00.
        let gaps = |at: Option<(u64, u64)>| {
            let mut img = dynsym_elf(&[(tag, 0x3a00)], &[]);
            if let Some((offset, addr)) = at {
                img.sec_linked(name, sh_type, offset, addr, 6, link, 0);
            }
            facts_of(&img.build(), BinaryBudgets::default()).1.gaps
        };
        assert!(gaps(Some((0x3a00, 0x3a00))).is_empty(), "{name}");
        assert_eq!(
            gaps(Some((0x3b00, 0x3a00))),
            [format!(
                "versions: {name} is not the bytes mapped at {tag_name}"
            )]
        );
        assert_eq!(
            gaps(Some((0x3a00, 0x3b00))),
            [format!("versions: {name} is not at {tag_name}")]
        );
        assert_eq!(
            gaps(None),
            [format!("versions: {tag_name} without a {name} section")]
        );
    }
}

/// Review of #91 (P1-1): on a real version table. object names the versions from the strings of
/// the symbol table `.gnu.version` links; ld.so from `DT_STRTAB`.
#[test]
fn versions_come_from_the_tables_and_strings_the_loader_reads() {
    // An identical .gnu.version_r past the PT_LOADs: object parses it, the loader never reads it.
    let mut bytes = fixture("elf/libdata.so");
    let (_, _, h, offset, size, _) = sections64(&bytes)
        .into_iter()
        .find(|s| s.1 == SHT_GNU_VERNEED)
        .unwrap();
    let copy = bytes.len() as u64;
    let section = bytes[offset as usize..(offset + size) as usize].to_vec();
    bytes.extend_from_slice(&section);
    bytes[h + 24..h + 32].copy_from_slice(&copy.to_le_bytes());
    let (f, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        f.imports.iter().any(|i| i.version.is_some()),
        "the copy parses: {:?}",
        f.imports
    );
    assert_eq!(
        p.gaps,
        ["versions: .gnu.version_r is not the bytes mapped at DT_VERNEED"]
    );
    // .gnu.version linked to .symtab: the names would come from .strtab.
    let mut bytes = fixture("elf/libdata.so");
    let (header, _, _) = versym(&bytes);
    let symtab = sections64(&bytes)
        .iter()
        .position(|s| s.1 == SHT_SYMTAB)
        .unwrap() as u32;
    bytes[header + 40..header + 44].copy_from_slice(&symtab.to_le_bytes());
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        p.gaps
            .contains(&"versions: .gnu.version does not link .dynsym".to_string()),
        "{:?}",
        p.gaps
    );
    // No DT_STRTAB: the loader has no names for the symbols.
    let mut bytes = fixture("elf/libdata.so");
    retag(&mut bytes, DT_STRTAB, DT_DEBUG);
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        p.gaps
            .contains(&"symbols: DT_SYMTAB without DT_STRTAB".to_string()),
        "{:?}",
        p.gaps
    );
}

/// Second review of #91 (P1): ld.so reads the dynamic symbols through `DT_SYMTAB`, their versions
/// through `DT_VERSYM`, `DT_VERNEED`, and `DT_VERDEF`, and looks them up through a hash table.
/// When `PT_DYNAMIC` is read, a section the loader has no tag for, or symbols with no hash table,
/// are not what the loader reads.
#[test]
fn a_section_without_its_tag_is_a_gap_when_pt_dynamic_is_read() {
    for (tag, gap) in [
        (DT_SYMTAB, "symbols: .dynsym without DT_SYMTAB"),
        (DT_VERSYM, "versions: .gnu.version without DT_VERSYM"),
        (DT_VERNEED, "versions: .gnu.version_r without DT_VERNEED"),
        (
            DT_GNU_HASH,
            "symbols: DT_SYMTAB without DT_HASH or DT_GNU_HASH",
        ),
    ] {
        let mut bytes = fixture("elf/libdata.so");
        retag(&mut bytes, tag, DT_DEBUG);
        let (_, p) = facts_of(&bytes, BinaryBudgets::default());
        assert_eq!(p.gaps, [gap], "{gap}");
    }
    let mut img = dynsym_elf(&[], &[]);
    img.sec_linked(".gnu.version_d", SHT_GNU_VERDEF, 0x3a00, 0x3a00, 6, 2, 0);
    let (_, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(p.gaps, ["versions: .gnu.version_d without DT_VERDEF"]);
    // With no PT_DYNAMIC, no loader links the file: nothing to agree with, so no gap.
    let mut img = dynsym_elf(&[], &[]);
    img.segs.retain(|s| s.p_type != PT_DYNAMIC);
    img.sec_linked(".gnu.version", SHT_GNU_VERSYM, 0x3a00, 0x3a00, 6, 1, 0);
    let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(f.exports, 2, "the symbols are still read");
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

/// Checked for the third review of #91: no loader reads `DT_SYMENT` (glibc reads it on hppa only,
/// musl never), so the symbols are read 24 bytes apart whatever it says, as SIGIL reads them.
/// Spec rev. 3 said glibc refused another size; it does not. No gap.
#[test]
fn a_dt_syment_other_than_the_symbol_size_is_no_gap() {
    let mut bytes = fixture("elf/libdata.so");
    set_dynamic(&mut bytes, DT_SYMENT, 16);
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

/// Third review of #91: glibc's `elf_get_dynamic_info` and `_ELF_DYNAMIC_DO_RELOC` read a table's
/// size and entry size with no NULL check, and assert that `DT_PLTREL` names the kind the machine
/// uses (only `DT_RELA` on x86-64 and AArch64). glibc skips a `DT_JMPREL` without `DT_PLTREL`;
/// musl applies `DT_JMPREL` and `DT_PLTRELSZ` whatever is missing. A tag missing its partner, and
/// another kind, are malformed.
#[test]
fn the_dynamic_tags_the_loader_reads_together() {
    let gaps = |machine: u16, entries: &[(i64, u64)]| {
        let mut img = dynsym_elf(entries, &[(0x2800, &[0u8; 48][..])]);
        img.machine = machine;
        facts_of(&img.build(), BinaryBudgets::default()).1.gaps
    };
    let (x86_64, s390) = (62, 22);
    let (rel, rela) = (DT_REL as u64, DT_RELA as u64);
    for (machine, entries) in [
        (
            x86_64,
            vec![(DT_RELA, 0x2800), (DT_RELASZ, 24), (DT_RELAENT, 24)],
        ),
        (
            x86_64,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 24), (DT_PLTREL, rela)],
        ),
        (
            x86_64,
            vec![(DT_RELR, 0x2800), (DT_RELRSZ, 8), (DT_RELRENT, 8)],
        ),
        (
            s390,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 16), (DT_PLTREL, rel)],
        ),
    ] {
        assert!(gaps(machine, &entries).is_empty(), "{entries:?}");
    }
    for (machine, entries, gap) in [
        (
            x86_64,
            vec![(DT_RELA, 0x2800), (DT_RELASZ, 24)],
            "DT_RELA without DT_RELAENT",
        ),
        (
            x86_64,
            vec![(DT_RELA, 0x2800), (DT_RELAENT, 24)],
            "DT_RELA without DT_RELASZ",
        ),
        (
            x86_64,
            vec![(DT_REL, 0x2800), (DT_RELSZ, 16)],
            "DT_REL without DT_RELENT",
        ),
        (
            x86_64,
            vec![(DT_REL, 0x2800), (DT_RELENT, 16)],
            "DT_REL without DT_RELSZ",
        ),
        (
            x86_64,
            vec![(DT_RELR, 0x2800), (DT_RELRSZ, 8)],
            "DT_RELR without DT_RELRENT",
        ),
        (
            x86_64,
            vec![(DT_RELR, 0x2800), (DT_RELRENT, 8)],
            "DT_RELR without DT_RELRSZ",
        ),
        (
            x86_64,
            vec![(DT_RELR, 0x2800), (DT_RELRSZ, 8), (DT_RELRENT, 4)],
            "DT_RELRENT is not 8",
        ),
        (
            x86_64,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 24)],
            "DT_JMPREL without DT_PLTREL",
        ),
        (
            x86_64,
            vec![(DT_JMPREL, 0x2800), (DT_PLTREL, rela)],
            "DT_JMPREL without DT_PLTRELSZ",
        ),
        (
            x86_64,
            vec![(DT_PLTREL, rela), (DT_PLTRELSZ, 24)],
            "DT_PLTREL without DT_JMPREL",
        ),
        (
            x86_64,
            vec![(DT_PLTRELSZ, 24)],
            "DT_PLTRELSZ without DT_JMPREL",
        ),
        (
            x86_64,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 16), (DT_PLTREL, rel)],
            "DT_PLTREL is not DT_RELA",
        ),
        (
            x86_64,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 0), (DT_PLTREL, 0xdead)],
            "DT_PLTREL is not DT_RELA",
        ),
        (
            s390,
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 0), (DT_PLTREL, 0xdead)],
            "DT_PLTREL is neither DT_REL nor DT_RELA",
        ),
    ] {
        let g = gaps(machine, &entries);
        let want = format!("dynamic: malformed: {gap}");
        assert!(g.contains(&want), "{entries:?}: {g:?}");
    }
}

/// Spec §3.2: REL tables are read for their symbol indices, so their sizes are checked as
/// RELA's are.
#[test]
fn rel_table_sizes_are_checked_as_rela_s_are() {
    assert!(
        facts_of(&dynsym_image(&[], &[]), BinaryBudgets::default())
            .1
            .gaps
            .is_empty(),
        "the image itself has no gap"
    );
    for (entries, gap) in [
        (
            vec![(DT_REL, 0x2800), (DT_RELSZ, 16), (DT_RELENT, 8)],
            "dynamic: malformed: DT_RELENT is not 16",
        ),
        (
            vec![(DT_REL, 0x2800), (DT_RELSZ, 20)],
            "dynamic: malformed: DT_RELSZ is not a whole number of entries",
        ),
        (
            vec![(DT_JMPREL, 0x2800), (DT_PLTRELSZ, 20), (DT_PLTREL, 17)],
            "dynamic: malformed: DT_PLTRELSZ is not a whole number of entries",
        ),
    ] {
        let bytes = dynsym_image(&entries, &[(0x2800, &[0u8; 32][..])]);
        let (_, p) = facts_of(&bytes, BinaryBudgets::default());
        assert!(p.gaps.contains(&gap.to_string()), "{gap}: {:?}", p.gaps);
    }
}

/// The `.dynsym` section header's file offset.
fn dynsym_header(bytes: &[u8]) -> usize {
    sections64(bytes)
        .into_iter()
        .find(|s| s.1 == SHT_DYNSYM)
        .unwrap()
        .2
}

/// Spec §3.2: `.dynsym` must be the table the loader reads, and as long as what it reaches.
#[test]
fn dynsym_must_be_where_and_as_long_as_the_loader_reads_it() {
    // libdata.so: 13 symbols, all reached by DT_GNU_HASH. One entry short:
    let mut bytes = fixture("elf/libdata.so");
    let h = dynsym_header(&bytes);
    bytes[h + 32..h + 40].copy_from_slice(&(12u64 * 24).to_le_bytes());
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert!(
        p.gaps
            .contains(&"symbols: .dynsym has 12 entries, DT_GNU_HASH 13".to_string()),
        "{:?}",
        p.gaps
    );
    // Not at DT_SYMTAB.
    let mut bytes = fixture("elf/libdata.so");
    let h = dynsym_header(&bytes);
    bytes[h + 16..h + 24].copy_from_slice(&0x280u64.to_le_bytes());
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(p.gaps, ["symbols: .dynsym is not at DT_SYMTAB"]);
    // A JUMP_SLOT naming symbol 99: an import the section does not hold.
    let mut bytes = fixture("elf/libdata.so");
    let plt = sections64(&bytes)
        .into_iter()
        .find(|s| s.0 == ".rela.plt")
        .unwrap()
        .3 as usize;
    bytes[plt + 8..plt + 16].copy_from_slice(&((99u64 << 32) | 7).to_le_bytes());
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(
        p.gaps,
        ["symbols: a relocation names symbol 99 past .dynsym's 13 entries"]
    );
    // DT_GNU_HASH where nothing is mapped.
    let mut bytes = fixture("elf/libdata.so");
    set_dynamic(&mut bytes, DT_GNU_HASH, 0x9_0000);
    let (_, p) = facts_of(&bytes, BinaryBudgets::default());
    assert_eq!(p.gaps, ["symbols: DT_GNU_HASH cannot be read"]);
}

/// A `DT_GNU_HASH` table (ELF64): `buckets.len()` buckets, `symoffset`, one bloom word, then
/// the buckets and the chain values (bit 0 ends a chain).
fn gnu_hash(symoffset: u32, buckets: &[u32], chains: &[u32]) -> Vec<u8> {
    let mut out = vec![];
    for w in [buckets.len() as u32, symoffset, 1, 6] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&u64::MAX.to_le_bytes());
    for w in buckets.iter().chain(chains) {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

#[test]
fn dt_gnu_hash_must_reach_every_symbol_of_dynsym() {
    let gaps = |table: Vec<u8>| {
        let bytes = dynsym_image(&[(DT_GNU_HASH, 0x2800)], &[(0x2800, table.as_slice())]);
        facts_of(&bytes, BinaryBudgets::default()).1.gaps
    };
    // "one" and "two" (symbols 1 and 2) in one chain: 3 symbols.
    assert!(gaps(gnu_hash(1, &[1], &[0x10, 0x21])).is_empty());
    assert_eq!(
        gaps(gnu_hash(1, &[1], &[0x11])),
        ["symbols: .dynsym has 3 entries, DT_GNU_HASH 2"]
    );
    // symoffset 0 is counted like any other (object's count skips it; glibc does not).
    assert!(gaps(gnu_hash(0, &[1], &[0, 0x10, 0x21])).is_empty());
    assert_eq!(
        gaps(gnu_hash(0, &[1], &[0, 0x11])),
        ["symbols: .dynsym has 3 entries, DT_GNU_HASH 2"]
    );
    // Empty (every bucket 0): no count, but the unhashed symbols below symoffset must be in the
    // table (review of rev. 2, P2-3).
    for symoffset in [1, 3] {
        assert!(
            gaps(gnu_hash(symoffset, &[0], &[])).is_empty(),
            "empty, symoffset {symoffset}"
        );
    }
    for symoffset in [4, 500] {
        assert_eq!(
            gaps(gnu_hash(symoffset, &[0, 0], &[])),
            [format!(
                "symbols: .dynsym has 3 entries, DT_GNU_HASH's symoffset {symoffset}"
            )],
        );
    }
    // Every non-empty bucket, not only the highest, must be at least symoffset.
    assert_eq!(
        gaps(gnu_hash(2, &[2, 1], &[0x21])),
        ["symbols: DT_GNU_HASH cannot be read"],
        "a bucket below symoffset beside a valid one"
    );
    assert_eq!(
        gaps(gnu_hash(5, &[2], &[0x11])),
        ["symbols: DT_GNU_HASH cannot be read"],
        "the highest bucket below symoffset"
    );
    assert_eq!(
        gaps(gnu_hash(1, &[1], &[0x10, 0x20])),
        ["symbols: DT_GNU_HASH cannot be read"],
        "a chain that never ends before the end of its PT_LOAD"
    );
}

/// Review of #91 (P2-1): the loader reads the bloom words too. A header at 0x3fe0 whose 0x1802
/// bloom words run from 0x3ff0 past the first PT_LOAD (it ends at 0x4000) to 0x10000, where a
/// second PT_LOAD maps the buckets and chains (file 0x3000): the count alone would agree.
#[test]
fn dt_gnu_hash_is_read_whole_bloom_words_included() {
    let gaps = |bloom_words: u32| {
        let header: Vec<u8> = [1u32, 1, bloom_words, 6]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let rest: Vec<u8> = [1u32, 0x10, 0x21]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let mut img = dynsym_elf(
            &[(DT_GNU_HASH, 0x3fe0)],
            &[(0x3fe0, header.as_slice()), (0x3000, rest.as_slice())],
        );
        img.seg(PT_LOAD, PF_R, 0x3000, 0x1_0000, 0x100, 0x100);
        facts_of(&img.build(), BinaryBudgets::default()).1.gaps
    };
    assert_eq!(gaps(0x1802), ["symbols: DT_GNU_HASH cannot be read"]);
}

/// A `DT_HASH` table: `nbucket`, `nchain`, then that many buckets and chain values (all 0).
fn sysv_hash(nbucket: u32, nchain: u32) -> Vec<u8> {
    let mut out = [nbucket.to_le_bytes(), nchain.to_le_bytes()].concat();
    out.resize(8 + 4 * (nbucket as usize + nchain as usize), 0);
    out
}

/// A `DT_HASH` table with these buckets and chain values (`nchain` is `chains.len()`).
fn sysv_hash_with(buckets: &[u32], chains: &[u32]) -> Vec<u8> {
    [buckets.len() as u32, chains.len() as u32]
        .iter()
        .chain(buckets)
        .chain(chains)
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

/// Second review of #91 (P1): the loader walks each bucket's chain, reading `symtab[i]` and then
/// `chain[i]`, with no bound. Every index it reaches must be one of the `nchain` symbols, and
/// each at most once: past them it reads past `.dynsym`, and one reached twice loops (or joins
/// another chain, which no linker writes).
#[test]
fn dt_hash_chains_must_stay_within_its_symbols() {
    let gaps = |table: Vec<u8>| {
        let bytes = dynsym_image(&[(DT_HASH, 0x2800)], &[(0x2800, table.as_slice())]);
        facts_of(&bytes, BinaryBudgets::default()).1.gaps
    };
    // Symbols 1 and 2 in one chain, and one in each of two buckets.
    assert!(gaps(sysv_hash_with(&[1], &[0, 2, 0])).is_empty());
    assert!(gaps(sysv_hash_with(&[2, 1], &[0, 0, 0])).is_empty());
    let unreadable = ["symbols: DT_HASH cannot be read"];
    assert_eq!(
        gaps(sysv_hash_with(&[99], &[0, 0, 0])),
        unreadable,
        "a bucket past nchain"
    );
    assert_eq!(
        gaps(sysv_hash_with(&[0, 1], &[0, 5, 0])),
        unreadable,
        "a chain past nchain"
    );
    // Joined first: without the check, a loop would never end.
    assert_eq!(
        gaps(sysv_hash_with(&[1, 2], &[0, 2, 0])),
        unreadable,
        "two chains joined"
    );
    assert_eq!(gaps(sysv_hash_with(&[1], &[0, 2, 1])), unreadable, "a loop");
}

#[test]
fn dt_hash_must_count_the_symbols_of_dynsym() {
    let gaps = |entries: &[(i64, u64)], extra: &[(u64, &[u8])]| {
        facts_of(&dynsym_image(entries, extra), BinaryBudgets::default())
            .1
            .gaps
    };
    let three = sysv_hash(1, 3);
    let two = sysv_hash(1, 2);
    assert!(gaps(&[(DT_HASH, 0x2800)], &[(0x2800, three.as_slice())]).is_empty());
    assert_eq!(
        gaps(&[(DT_HASH, 0x2800)], &[(0x2800, two.as_slice())]),
        ["symbols: .dynsym has 3 entries, DT_HASH 2"]
    );
    assert_eq!(
        gaps(&[(DT_HASH, 0x9_0000)], &[]),
        ["symbols: DT_HASH cannot be read"]
    );
    // Review of #91 (P2-1): the buckets and chains are read too. Only the 8-byte header at the
    // end of the PT_LOAD (0x4000), with `nchain` right; and a size that overflows.
    let header = &three[..8];
    assert_eq!(
        gaps(&[(DT_HASH, 0x3ff8)], &[(0x3ff8, header)]),
        ["symbols: DT_HASH cannot be read"]
    );
    let huge = [u32::MAX.to_le_bytes(), 3u32.to_le_bytes()].concat();
    assert_eq!(
        gaps(&[(DT_HASH, 0x2800)], &[(0x2800, huge.as_slice())]),
        ["symbols: DT_HASH cannot be read"]
    );
}

/// Review of rev. 2 (P2-2): every relocation table is read for its symbol indices whether or not
/// a known data symbol is there. `dynsym_image` defines none, so `data::read` reads no table.
#[test]
fn a_relocation_past_dynsym_is_a_gap_with_no_data_symbol() {
    // One relocation at 0x2800 naming symbol `sym` (type 1, R_X86_64_64); a RELA entry has its
    // addend after it.
    let entry = |sym: u64, rela: bool| {
        let mut e = 0x3000u64.to_le_bytes().to_vec();
        e.extend_from_slice(&((sym << 32) | 1).to_le_bytes());
        if rela {
            e.extend_from_slice(&0u64.to_le_bytes());
        }
        e
    };
    // (the table, whether its entries are RELA, its PT_DYNAMIC entries)
    let kinds = [
        (
            "DT_RELA",
            true,
            [(DT_RELA, 0x2800), (DT_RELASZ, 24), (DT_RELAENT, 24)],
        ),
        (
            "DT_REL",
            false,
            [(DT_REL, 0x2800), (DT_RELSZ, 16), (DT_RELENT, 16)],
        ),
        (
            "DT_JMPREL (RELA)",
            true,
            [
                (DT_JMPREL, 0x2800),
                (DT_PLTRELSZ, 24),
                (DT_PLTREL, DT_RELA as u64),
            ],
        ),
        (
            "DT_JMPREL (REL)",
            false,
            [
                (DT_JMPREL, 0x2800),
                (DT_PLTRELSZ, 16),
                (DT_PLTREL, DT_REL as u64),
            ],
        ),
    ];
    for (kind, rela, entries) in kinds {
        for (sym, gap) in [
            (2, None),
            (
                5,
                Some("symbols: a relocation names symbol 5 past .dynsym's 3 entries"),
            ),
        ] {
            let table = entry(sym, rela);
            let mut img = dynsym_elf(&entries, &[(0x2800, table.as_slice())]);
            // x86-64 allows only DT_RELA as DT_PLTREL (third review of #91): REL on S390.
            if !rela {
                img.machine = 22;
            }
            let (f, p) = facts_of(&img.build(), BinaryBudgets::default());
            assert!(f.data.is_empty(), "{kind}: no known data symbol");
            assert_eq!(
                p.gaps,
                gap.into_iter().collect::<Vec<_>>(),
                "{kind}, symbol {sym}"
            );
        }
    }
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
            .any(|g| g.starts_with("malformed: symbols: a defined symbol's name")),
        "{:?}",
        p.gaps
    );
}

/// Spec §3.3: a function whose name cannot be read could be a second definition of a known name.
#[test]
fn a_defined_symbol_whose_name_cannot_be_read_is_a_gap_whatever_its_type() {
    let mut img = ElfImage::new(1); // ET_REL
    let names = b"\0exported\0";
    let mut syms = vec![0u8; 24];
    syms.extend_from_slice(&sym64(1, 0x12, 1, 0, 1)); // GLOBAL FUNC "exported"
    syms.extend_from_slice(&sym64(0xffff, 0x12, 1, 0, 1)); // GLOBAL FUNC, name out of range
    let (sym_off, str_off) = (0x1000u64, 0x2000u64);
    img.put(sym_off, &syms).put(str_off, names);
    img.sec_linked(".symtab", SHT_SYMTAB, sym_off, 0, syms.len() as u64, 2, 24)
        .sec(".strtab", SHT_STRTAB, str_off, 0, names.len() as u64);
    let (_, p) = facts_of(&img.build(), BinaryBudgets::default());
    assert_eq!(
        p.gaps,
        ["malformed: symbols: a defined symbol's name: a name past its string table"]
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
                .starts_with("malformed: symbols: a defined symbol's name: a name not terminated")),
        "{gaps:?}"
    );
    // One byte longer than the longest known name (18 bytes), cut by the end of the table:
    // malformed, never "longer than any known name" (review of rev. 2, P2-1).
    let cut =
        "malformed: symbols: a defined symbol's name: a name not terminated in its string table";
    let gaps = symtab(b"\0exported\0LLAMA_BUILD_NUMBERX");
    assert!(gaps.iter().any(|g| g == cut), "{gaps:?}");
}

/// `.dynsym` with one undefined GLOBAL FUNC per name, and no program headers (as
/// `parse_memory.rs`). `terminated: false` drops the last name's NUL.
fn imports_image(names: &[Vec<u8>], terminated: bool) -> Vec<u8> {
    let mut img = ElfImage::new(3);
    let mut strtab = vec![0u8];
    let mut syms = vec![0u8; 24];
    for name in names {
        syms.extend_from_slice(&sym64(strtab.len() as u32, 0x12, 0, 0, 0));
        strtab.extend_from_slice(name);
        strtab.push(0);
    }
    if !terminated {
        strtab.pop();
    }
    let sym_off = 0x1000u64;
    let str_off = sym_off + syms.len() as u64;
    img.put(sym_off, &syms).put(str_off, &strtab);
    img.sec_linked(".dynsym", SHT_DYNSYM, sym_off, 0, syms.len() as u64, 2, 24)
        .sec(".dynstr", SHT_STRTAB, str_off, 0, strtab.len() as u64);
    img.build()
}

/// Spec §3.7: object stops looking for a name's NUL after 4096 bytes. An import name of that
/// length or more is read in full, up to 65,536 bytes.
#[test]
fn long_import_names_are_read_in_full_up_to_the_limit() {
    let names: Vec<Vec<u8>> = [255usize, 256, 1024, 4095, 4096, 4097, 5000, 16_385, 65_536]
        .iter()
        .enumerate()
        .map(|(i, len)| {
            let mut name = vec![b'a' + i as u8];
            name.resize(*len, b'x');
            name
        })
        .collect();
    let (f, p) = facts_of(&imports_image(&names, true), BinaryBudgets::default());
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
    let got: Vec<Vec<u8>> = f
        .imports
        .iter()
        .map(|i| i.name.as_bytes().to_vec())
        .collect();
    assert!(got == names, "every name, in full");

    // Over the limit: that import is skipped, with its gap.
    let mut over = vec![b'z'; 65_537];
    over[0] = b'o';
    let (f, p) = facts_of(
        &imports_image(&[b"ok".to_vec(), over], true),
        BinaryBudgets::default(),
    );
    let kept: Vec<_> = f.imports.iter().map(|i| i.name.clone()).collect();
    assert_eq!(texts(&kept), ["ok"]);
    assert_eq!(p.gaps, ["imports: a name over 65536 bytes"]);

    // At the limit (review of rev. 2, P2-1): the last name of its table, with or without its
    // NUL. A table that ends before the NUL is malformed, even exactly 65,537 bytes on; a name
    // with more table after its first 65,537 bytes is over the limit.
    let cut = "malformed: symbols: a name not terminated in its string table";
    let long = "imports: a name over 65536 bytes";
    for (len, terminated, gap) in [
        (65_536, true, None),
        (65_537, true, Some(long)),
        (65_538, true, Some(long)),
        (65_536, false, Some(cut)),
        (65_537, false, Some(cut)),
        (65_538, false, Some(long)),
    ] {
        let image = imports_image(&[vec![b'q'; len]], terminated);
        let (f, p) = facts_of(&image, BinaryBudgets::default());
        let case = format!("{len} bytes, terminated: {terminated}");
        assert_eq!(p.gaps, gap.into_iter().collect::<Vec<_>>(), "{case}");
        assert_eq!(f.imports.len(), usize::from(gap.is_none()), "{case}");
    }
}
