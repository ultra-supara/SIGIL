//! Known data symbols (spec §4.4): the value after loading, or `Unknown`, never a guess.

mod common;

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::{ContainerFacts, DataValue, Loc};

fn values(bytes: &[u8]) -> (Vec<(String, DataValue)>, Parsed) {
    let p = parse(&file(bytes), bytes.len() as u64, BinaryBudgets::default());
    let ContainerFacts::Elf(f) = &p.container else {
        panic!()
    };
    (
        f.data
            .iter()
            .map(|d| (d.symbol.clone(), d.value.clone()))
            .collect(),
        p.clone(),
    )
}

fn text(s: &str) -> DataValue {
    DataValue::Text(sigil_model::UntrustedText::new(s))
}

fn unknown_with(v: &DataValue, why: &str) -> bool {
    matches!(v, DataValue::Unknown { why: w } if w.contains(why))
}

#[test]
fn x86_64_values_come_from_relative_relocations() {
    let (v, p) = values(&fixture("elf/libdata.so"));
    assert_eq!(
        v,
        [
            ("LLAMA_BUILD_NUMBER".into(), DataValue::Int(1)),
            ("LLAMA_BUILD_TARGET".into(), text("x86_64-linux-gnu")),
            ("LLAMA_COMMIT".into(), text("6f3a9f3de")),
            ("LLAMA_COMPILER".into(), text("GNU 11.2.1")),
        ]
    );
    let ContainerFacts::Elf(f) = &p.container else {
        panic!()
    };
    let commit = f.data.iter().find(|d| d.symbol == "LLAMA_COMMIT").unwrap();
    assert!(matches!(
        commit.at.as_slice(),
        [Loc::Symbol(_), Loc::VAddr(_)]
    ));
    assert!(p.gaps.is_empty(), "{:?}", p.gaps);
}

#[test]
fn aarch64_values_come_from_r_aarch64_relative() {
    let (v, _) = values(&fixture("elf/libdata-aarch64.so"));
    assert!(v.contains(&("LLAMA_COMMIT".into(), text("6f3a9f3de"))));
    assert!(v.contains(&("LLAMA_BUILD_NUMBER".into(), DataValue::Int(7))));
}

#[test]
fn a_non_pie_executable_s_stored_pointer_is_its_value() {
    let (v, _) = values(&fixture("elf/exe-nopie"));
    assert_eq!(v, [("LLAMA_COMMIT".into(), text("6f3a9f3de"))]);
}

#[test]
fn a_pointer_relocated_by_another_type_is_unknown_even_with_a_valid_stored_address() {
    // The review's case: R_X86_64_64 at LLAMA_COMMIT, and the file stores the address of a
    // valid string there.
    let mut bytes = fixture("elf/libsym64.so");
    // LLAMA_COMMIT's address and other_commit's address, from libsym64.so.readelf (Task 5).
    // LLAMA_COMMIT is at 0x4008, in the RW PT_LOAD at offset 0x2e58 / vaddr 0x3e58.
    const LLAMA_COMMIT_FILE_OFFSET: usize = 0x3008;
    const OTHER_COMMIT_VADDR: u64 = 0x2000;
    bytes[LLAMA_COMMIT_FILE_OFFSET..LLAMA_COMMIT_FILE_OFFSET + 8]
        .copy_from_slice(&OTHER_COMMIT_VADDR.to_le_bytes());
    let (v, p) = values(&bytes);
    assert!(unknown_with(&v[0].1, "R_X86_64_64"), "{v:?}");
    assert!(
        p.gaps.iter().any(|g| g.starts_with("LLAMA_COMMIT: ")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn rel_or_relr_and_unrelocated_position_independent_pointers_are_unknown() {
    let (v, _) = values(&fixture("elf/libdata-relr.so"));
    assert!(v.iter().all(|(_, x)| unknown_with(x, "REL/RELR")), "{v:?}");
    // libdata.so with its RELA table hidden: an ET_DYN pointer with no relocation.
    let mut bytes = fixture("elf/libdata.so");
    retag(&mut bytes, 7, 21); // DT_RELA → DT_DEBUG
    retag(&mut bytes, 8, 21); // DT_RELASZ → DT_DEBUG
    let (v, _) = values(&bytes);
    let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
    assert!(unknown_with(commit, "position-independent"), "{commit:?}");
}

#[test]
fn another_machine_s_relocations_are_not_read() {
    let mut bytes = fixture("elf/libdata.so");
    bytes[18..20].copy_from_slice(&22u16.to_le_bytes()); // e_machine = S390
    let (v, _) = values(&bytes);
    assert_eq!(v.len(), 4, "{v:?}");
    assert!(
        v.iter()
            .filter(|(s, _)| s != "LLAMA_BUILD_NUMBER")
            .all(|(_, x)| unknown_with(x, "not read")),
        "{v:?}"
    );
}

/// The file offset of the whole RELA entry `(r_offset, R_X86_64_RELATIVE, addend)`. The addend is
/// part of the pattern: `(r_offset, 8)` alone also matches a `.dynsym` entry's value and size.
fn relative_entry(bytes: &[u8], r_offset: u64, addend: u64) -> usize {
    let mut needle = r_offset.to_le_bytes().to_vec();
    needle.extend_from_slice(&8u64.to_le_bytes()); // r_info: symbol 0, type R_X86_64_RELATIVE
    needle.extend_from_slice(&addend.to_le_bytes());
    let found: Vec<usize> = bytes
        .windows(24)
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(found.len(), 1, "one RELATIVE entry");
    found[0]
}

#[test]
fn a_relative_addend_outside_the_file_is_unknown() {
    let mut bytes = fixture("elf/libdata.so");
    // LLAMA_COMMIT is at 0x4030 and its string at 0x201c in libdata.so (libdata.so.readelf).
    let at = relative_entry(&bytes, 0x4030, 0x201c) + 16;
    bytes[at..at + 8].copy_from_slice(&0xdead_0000u64.to_le_bytes());
    let (v, p) = values(&bytes);
    let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
    assert!(unknown_with(commit, "outside every PT_LOAD"), "{commit:?}");
    assert!(
        p.gaps.iter().any(|g| g.starts_with("LLAMA_COMMIT: ")),
        "{:?}",
        p.gaps
    );
}

#[test]
fn a_known_symbol_defined_twice_has_no_single_value() {
    // Rename LLAMA_COMPILER to LLAMA_COMMIT in .dynsym: two definitions of one known name. Each
    // record must stay unique (B5), and the value is Unknown, not either one.
    let mut bytes = fixture("elf/libdata.so");
    let secs = sections64(&bytes);
    let (_, _, _, sym_off, sym_size, link) =
        secs.iter().find(|s| s.1 == SHT_DYNSYM).unwrap().clone();
    let str_off = secs[link as usize].3 as usize;
    let name_of = |b: &[u8], e: usize| {
        let at = str_off + u32::from_le_bytes(b[e..e + 4].try_into().unwrap()) as usize;
        let end = b[at..].iter().position(|c| *c == 0).unwrap();
        b[at..at + end].to_vec()
    };
    let entries: Vec<usize> = (sym_off as usize..(sym_off + sym_size) as usize)
        .step_by(24)
        .collect();
    let commit = *entries
        .iter()
        .find(|e| name_of(&bytes, **e) == b"LLAMA_COMMIT")
        .unwrap();
    let compiler = *entries
        .iter()
        .find(|e| name_of(&bytes, **e) == b"LLAMA_COMPILER")
        .unwrap();
    let st_name = bytes[commit..commit + 4].to_vec();
    bytes[compiler..compiler + 4].copy_from_slice(&st_name);
    let (v, p) = values(&bytes);
    let commits: Vec<_> = v.iter().filter(|(s, _)| s == "LLAMA_COMMIT").collect();
    assert_eq!(commits.len(), 1, "{v:?}");
    assert!(unknown_with(&commits[0].1, "more than once"), "{v:?}");
    assert!(
        p.gaps
            .contains(&"LLAMA_COMMIT: defined more than once".to_string()),
        "{:?}",
        p.gaps
    );
}

/// The `.dynsym` entry (its file offset) of the symbol named `name`, in an ELF64 little-endian
/// file.
fn dynsym_entry(bytes: &[u8], name: &[u8]) -> usize {
    let secs = sections64(bytes);
    let (_, _, _, sym_off, sym_size, link) =
        secs.iter().find(|s| s.1 == SHT_DYNSYM).unwrap().clone();
    let str_off = secs[link as usize].3 as usize;
    (sym_off as usize..(sym_off + sym_size) as usize)
        .step_by(24)
        .find(|e| {
            let at = str_off + u32::from_le_bytes(bytes[*e..*e + 4].try_into().unwrap()) as usize;
            bytes[at..].starts_with(name) && bytes[at + name.len()] == 0
        })
        .unwrap()
}

/// Spec §3.3: a known name is looked for in every defined symbol, whatever its type.
#[test]
fn a_known_name_of_another_type_is_unknown_never_absent() {
    // LLAMA_COMMIT typed STT_FUNC.
    let mut bytes = fixture("elf/libdata.so");
    let e = dynsym_entry(&bytes, b"LLAMA_COMMIT");
    bytes[e + 4] = (bytes[e + 4] & 0xf0) | 2;
    let (v, p) = values(&bytes);
    let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
    assert!(
        unknown_with(commit, "not a data object (STT_FUNC)"),
        "{commit:?}"
    );
    assert!(
        p.gaps
            .contains(&"LLAMA_COMMIT: not a data object (STT_FUNC)".to_string()),
        "{:?}",
        p.gaps
    );

    // A second definition of LLAMA_COMMIT typed STT_NOTYPE (LLAMA_COMPILER renamed).
    let mut bytes = fixture("elf/libdata.so");
    let commit = dynsym_entry(&bytes, b"LLAMA_COMMIT");
    let compiler = dynsym_entry(&bytes, b"LLAMA_COMPILER");
    let st_name = bytes[commit..commit + 4].to_vec();
    bytes[compiler..compiler + 4].copy_from_slice(&st_name);
    bytes[compiler + 4] &= 0xf0;
    let (v, _) = values(&bytes);
    let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
    assert!(unknown_with(commit, "more than once"), "{v:?}");
}

/// Spec §3.4: a relocation is matched by the bytes it writes, not by its address alone. In
/// libdata.so (libdata.so.readelf), LLAMA_BUILD_NUMBER is the 4-byte int at 0x4018, LLAMA_COMMIT's
/// string "6f3a9f3de" is at 0x201c, and a RELATIVE at 0x4010 (`__dso_handle`, addend 0x4010)
/// writes 0x4010..0x4018.
#[test]
fn a_relocation_overlapping_a_value_or_its_string_makes_it_unknown() {
    // Moved to 0x4014: it now writes 0x4014..0x401c, over the int.
    let mut bytes = fixture("elf/libdata.so");
    let entry = relative_entry(&bytes, 0x4010, 0x4010);
    bytes[entry..entry + 8].copy_from_slice(&0x4014u64.to_le_bytes());
    let (v, p) = values(&bytes);
    let number = &v.iter().find(|(s, _)| s == "LLAMA_BUILD_NUMBER").unwrap().1;
    assert!(
        unknown_with(number, "a relocation overlaps it (R_X86_64_RELATIVE)"),
        "{number:?}"
    );
    assert!(
        p.gaps.contains(
            &"LLAMA_BUILD_NUMBER: a relocation overlaps it (R_X86_64_RELATIVE)".to_string()
        ),
        "{:?}",
        p.gaps
    );

    // Moved to 0x2020: it writes into LLAMA_COMMIT's string.
    let mut bytes = fixture("elf/libdata.so");
    let entry = relative_entry(&bytes, 0x4010, 0x4010);
    bytes[entry..entry + 8].copy_from_slice(&0x2020u64.to_le_bytes());
    let (v, p) = values(&bytes);
    let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
    assert!(
        unknown_with(
            commit,
            "a relocation writes into the string (R_X86_64_RELATIVE)"
        ),
        "{commit:?}"
    );
    assert!(
        v.contains(&("LLAMA_COMPILER".into(), text("GNU 11.2.1"))),
        "the other strings are unchanged: {v:?}"
    );
    let ContainerFacts::Elf(f) = &p.container else {
        panic!()
    };
    let d = f.data.iter().find(|d| d.symbol == "LLAMA_COMMIT").unwrap();
    assert_eq!(
        d.at.len(),
        1,
        "an Unknown value has only its symbol: {:?}",
        d.at
    );
    assert!(
        p.gaps.contains(
            &"LLAMA_COMMIT: a relocation writes into the string (R_X86_64_RELATIVE)".to_string()
        ),
        "{:?}",
        p.gaps
    );

    // RELA RELATIVE at every pointer, plus a DT_RELR table: RELR may write the same bytes.
    let mut bytes = fixture("elf/libdata.so");
    retag(&mut bytes, DT_RELACOUNT, DT_RELR);
    let (v, _) = values(&bytes);
    assert_eq!(v.len(), 4, "{v:?}");
    assert!(v.iter().all(|(_, x)| unknown_with(x, "REL/RELR")), "{v:?}");
}

/// The review of the PR-4b-1 plan: the loader walks a relocation table up to its size, so a size
/// that is not a whole number of entries ends in a partial entry SIGIL would not see, and an entry
/// size other than `Elf64_Rela`'s is refused by the loader. Each is a gap, and the values that
/// rest on the tables are `Unknown`.
#[test]
fn relocation_table_sizes_must_be_whole_entries_of_the_rela_size() {
    for (tag, value, gap) in [
        (
            DT_RELASZ,
            241,
            "dynamic: malformed: DT_RELASZ is not a whole number of entries",
        ),
        (
            DT_PLTRELSZ,
            49,
            "dynamic: malformed: DT_PLTRELSZ is not a whole number of entries",
        ),
        (DT_RELAENT, 16, "dynamic: malformed: DT_RELAENT is not 24"),
    ] {
        let mut bytes = fixture("elf/libdata.so");
        set_dynamic(&mut bytes, tag, value);
        let (v, p) = values(&bytes);
        assert!(p.gaps.iter().any(|g| g == gap), "{tag}: {:?}", p.gaps);
        let commit = &v.iter().find(|(s, _)| s == "LLAMA_COMMIT").unwrap().1;
        assert!(
            unknown_with(commit, "relocations not read"),
            "{tag}: {commit:?}"
        );
    }
}

/// The same gap without any known data symbol: the tables are checked where `PT_DYNAMIC` is read,
/// not only when a value needs them.
#[test]
fn a_malformed_relocation_size_is_a_gap_without_known_symbols() {
    let mut bytes = without_known_symbols(&fixture("elf/libdata.so"));
    let (v, p) = values(&bytes);
    assert!(v.is_empty() && p.gaps.is_empty(), "{v:?} {:?}", p.gaps);
    set_dynamic(&mut bytes, DT_RELASZ, 241);
    let (_, p) = values(&bytes);
    assert_eq!(
        p.gaps,
        ["dynamic: malformed: DT_RELASZ is not a whole number of entries"]
    );
}
