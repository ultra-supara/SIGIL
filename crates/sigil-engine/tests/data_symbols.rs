//! Known data symbols (spec §4.4): the value after loading, or `Unknown`, never a guess.

mod common;

use common::elf::*;
use sigil_engine::binary::{parse, BinaryBudgets, Parsed};
use sigil_model::{ContainerFacts, DataValue, Loc};

fn values(bytes: &[u8]) -> (Vec<(String, DataValue)>, Parsed) {
    let p = parse(&file(bytes), bytes.len() as u64, BinaryBudgets::default());
    let ContainerFacts::Elf(f) = &p.container;
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

/// The ELF64 little-endian program headers of `bytes`: `(p_type, p_offset, p_vaddr, p_filesz)`.
fn phdrs(bytes: &[u8]) -> Vec<(u32, u64, u64, u64)> {
    let u16le = |a: usize| u16::from_le_bytes([bytes[a], bytes[a + 1]]) as usize;
    let u64le = |a: usize| u64::from_le_bytes(bytes[a..a + 8].try_into().unwrap());
    let (phoff, phnum) = (u64le(32) as usize, u16le(56));
    (0..phnum)
        .map(|i| {
            let p = phoff + i * 56;
            let t = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            (t, u64le(p + 8), u64le(p + 16), u64le(p + 32))
        })
        .collect()
}

/// Replaces every dynamic tag `from` with `to` (e.g. hides DT_RELA as DT_DEBUG).
fn retag(bytes: &mut [u8], from: i64, to: i64) {
    let (_, off, _, size) = phdrs(bytes)
        .into_iter()
        .find(|p| p.0 == PT_DYNAMIC)
        .unwrap();
    for e in (off as usize..(off + size) as usize).step_by(16) {
        if i64::from_le_bytes(bytes[e..e + 8].try_into().unwrap()) == from {
            bytes[e..e + 8].copy_from_slice(&to.to_le_bytes());
        }
    }
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
    let ContainerFacts::Elf(f) = &p.container;
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
