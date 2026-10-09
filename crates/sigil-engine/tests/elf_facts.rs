//! ELF facts (spec §4.3): every fact read in full, confirmed absent, or a gap. Committed fixtures
//! and raw images only.

mod common;

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::{ContainerFacts, ElfFacts, UntrustedText};

fn facts_of(bytes: &[u8], budgets: BinaryBudgets) -> (ElfFacts, Parsed) {
    let parsed = parse(&file(bytes), bytes.len() as u64, budgets);
    let ContainerFacts::Elf(f) = parsed.container.clone();
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
