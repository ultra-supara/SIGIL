use super::*;
use crate::code::CodeBudgets;

#[test]
fn clang_linked_exact_oracle_extents() {
    let file = std::fs::File::open(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/code-aarch64/elf-clang-plt.so"
    ))
    .unwrap();
    let size = file.metadata().unwrap().len();
    let mut reader = Reader::new(&file, size, CodeBudgets::default().bytes);
    let image = build(
        &mut reader,
        SliceWindow { base: 0, len: size },
        &mut Run::new(CodeBudgets::default()),
    )
    .unwrap();
    assert_eq!(image.fdes, [(0x1038c, 0x103b0), (0x103b0, 0x103d4)]);
}

use crate::code::aarch64::{
    decode_cfg,
    search::{resolve_cfg, Candidates},
    Proofs,
};
use object::{Object, ObjectSection};
use std::io::Write;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/code-aarch64/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn inspect(
    bytes: &[u8],
    base: u64,
    len: u64,
    budgets: CodeBudgets,
) -> (Option<A64ElfImage>, Run, u64) {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, budgets.bytes);
    let mut run = Run::new(budgets);
    let image = build(&mut reader, SliceWindow { base, len }, &mut run);
    (image, run, reader.used())
}
fn normal(bytes: &[u8]) -> (A64ElfImage, Run) {
    let (i, r, _) = inspect(bytes, 0, bytes.len() as u64, CodeBudgets::default());
    let g = r.clone_gaps();
    (i.unwrap_or_else(|| panic!("{g:?}")), r)
}
fn section(bytes: &[u8], name: &str) -> (usize, u64, u64) {
    let o = object::File::parse(bytes).unwrap();
    let s = o.section_by_name(name).unwrap();
    (s.index().0, s.file_range().unwrap().0, s.size())
}
fn sh(bytes: &[u8], name: &str) -> usize {
    u64le(bytes, 40) as usize + section(bytes, name).0 * 64
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn run_calls(bytes: &[u8]) -> (Vec<(u64, Branch)>, Vec<String>) {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 28);
    let mut run = Run::new(CodeBudgets::default());
    let Some(image) = build(
        &mut reader,
        SliceWindow {
            base: 0,
            len: bytes.len() as u64,
        },
        &mut run,
    ) else {
        return (vec![], run.into_gaps());
    };
    let mut candidates = Candidates::default();
    candidates.scan(&image, &mut reader, &mut run);
    let mut calls = vec![];
    for (&(entry, end), pcs) in &candidates.functions {
        let bytes = image
            .read_code(entry, end - entry, &mut reader, &mut run)
            .unwrap();
        let proofs = Proofs {
            executable: &|s, e| image.executable(s, e),
            excluded: &|s, e| image.excluded(s, e),
            noreturn: &|_, _| false,
            candidates: pcs,
        };
        if let Ok(cfg) = decode_cfg(&bytes, entry, end, &proofs, &mut run) {
            if let Ok(c) = resolve_cfg(&cfg, &image, &mut run) {
                calls.extend(c);
            }
        }
    }
    (calls, run.into_gaps())
}

#[test]
fn every_clang_gcc_fixture_matches_independent_oracle_ranges_and_calls() {
    let oracle = include_str!("../../../tests/fixtures/code-aarch64/oracle.tsv");
    let mut expected: BTreeMap<&str, Vec<Vec<&str>>> = BTreeMap::new();
    for row in oracle.lines().skip(1) {
        let cols: Vec<_> = row.split('\t').collect();
        expected.entry(cols[0]).or_default().push(cols);
    }
    for (name, rows) in expected {
        let bytes = fixture(name);
        let (image, run) = normal(&bytes);
        let mut ranges = vec![];
        for cols in &rows {
            if cols[3] != "-" {
                let n = |s: &str| u64::from_str_radix(&s[2..], 16).unwrap();
                ranges.push((n(cols[3]), n(cols[4])));
            }
        }
        ranges.sort_unstable();
        let actual: Vec<_> = image
            .fdes
            .iter()
            .copied()
            .filter(|r| !image.plt.contains(r))
            .collect();
        assert_eq!(actual, ranges, "{name}: {:?}", run.clone_gaps());
        let (calls, gaps) = run_calls(&bytes);
        for cols in &rows {
            if cols[5] != "-" {
                let pc = u64::from_str_radix(&cols[5][2..], 16).unwrap();
                assert!(
                    calls.iter().any(|(at, b)| *at == pc
                        && matches!(b,Branch::Import(w) if &*w.name==b"connect")),
                    "{name} {pc:#x}: {calls:?} {gaps:?}"
                );
            }
        }
        if name == "elf-no-fde.so" {
            assert!(calls.is_empty());
            assert!(gaps.iter().any(|g| g.contains("no exact function bounds")));
        }
    }
}

#[test]
fn exact_slice_reads_and_object_address_domain() {
    let bytes = fixture("elf-clang-o2.o");
    let mut joined = vec![0x99; 0x100];
    joined.extend(&bytes);
    joined.extend(&bytes);
    let (image, run, used) = inspect(&joined, 0x100, bytes.len() as u64, CodeBudgets::default());
    let image = image.unwrap();
    assert_eq!(image.fdes, [(0x140, 0x164), (0x164, 0x188)]);
    assert!(run.clone_gaps().is_empty());
    assert!(used > 64);
    for len in [0, 63, bytes.len() as u64 - 1] {
        assert!(inspect(&joined, 0x100, len, CodeBudgets::default())
            .0
            .is_none());
    }
    let (image, _, used) = inspect(&joined, u64::MAX - 8, 32, CodeBudgets::default());
    assert!(image.is_none());
    assert_eq!(used, 0);
    let mut mutated = bytes.clone();
    let at = sh(&mutated, ".text");
    put64(&mut mutated, at + 24, bytes.len() as u64);
    let mut joined = mutated.clone();
    joined.extend(&bytes);
    assert!(
        inspect(&joined, 0, mutated.len() as u64, CodeBudgets::default())
            .0
            .is_none()
    );
}

#[test]
fn rejects_other_abis_before_metadata() {
    let original = fixture("elf-clang-plt.so");
    for (at, value) in [(4, 1), (5, 2), (18, 62), (19, 1)] {
        let mut bytes = original.clone();
        bytes[at] = value;
        let (i, _, used) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
        assert!(i.is_none());
        assert_eq!(used, 64);
    }
}

#[test]
fn each_plt_instruction_slot_and_relocation_mutation_loses_witness() {
    let original = fixture("elf-clang-plt.so");
    let (image, _) = normal(&original);
    assert_eq!(image.stubs.len(), 1);
    let (_, rel, _) = section(&original, ".rela.plt");
    for (at, value, width) in [
        (0x400, 0x90000011, 4),
        (0x400, 0x90000090, 4), // wrong register/page
        (0x404, 0xf9427211, 4),
        (0x404, 0xf9426e10, 4), // slot/destination
        (0x408, 0x91138210, 4),
        (0x408, 0x91536210, 4), // low bits/shift
        (0x40c, 0xd61f0200, 4),
        (0x40c, 0xd61f0221, 4), // BR source/reserved
        (rel as usize, 0x304e0, 8),
        (rel as usize + 8, 0xffff00000402, 8), // slot/symbol
        (rel as usize + 8, 0x100000401, 8),
        (rel as usize + 8, 0x100000403, 8), // valid GLOB_DAT, unsupported RELATIVE
        (rel as usize + 16, 1, 8),
    ] {
        let mut bytes = original.clone();
        if width == 4 {
            put32(&mut bytes, at, value as u32);
        } else {
            put64(&mut bytes, at, value);
        }
        let (image, run, _) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
        if at == rel as usize + 8 && value == 0x100000401 {
            assert_eq!(image.unwrap().stubs.len(), 1);
            continue;
        }
        assert!(
            image.is_none_or(|i| i.stubs.is_empty()),
            "offset {at:#x}: {:?}",
            run.clone_gaps()
        );
    }
}

#[test]
fn object_branch_relocation_mutations_are_unresolved() {
    let original = fixture("elf-clang-o2.o");
    let (_, rel, _) = section(&original, ".rela.text");
    let (image, _) = normal(&original);
    assert!(matches!(
        image.branch(0x54, 0x94000000),
        Some(Branch::Import(_))
    ));
    for (at, value, width) in [
        (rel as usize + 16, 4, 8),
        (rel as usize + 8, 0xffff0000011b, 8),
        (rel as usize + 8, 0x60000011a, 8),
        (0x54, 0x14000000, 4),
        (0x54, 0x94000001, 4),
    ] {
        let mut bytes = original.clone();
        if width == 4 {
            put32(&mut bytes, at, value as u32);
        } else {
            put64(&mut bytes, at, value);
        }
        let (calls, gaps) = run_calls(&bytes);
        assert!(!calls.iter().any(|(pc, _)| *pc == 0x54), "{at:#x}");
        assert!(!gaps.is_empty());
    }
    // Undefined weak calls can be relaxed to no-ops by the linker.
    let (_, sym, _) = section(&original, ".symtab");
    let mut bytes = original.clone();
    bytes[sym as usize + 6 * 24 + 4] = 0x20;
    assert!(run_calls(&bytes).0.is_empty());
    // Duplicate/composed relocation at the same location remains poisoned permanently.
    let mut bytes = original.clone();
    put64(&mut bytes, rel as usize + 24, 0x14);
    let (image, run) = normal(&bytes);
    assert!(image.relocs[&0x54].is_none());
    assert!(!run.clone_gaps().is_empty());
    assert!(run_calls(&bytes).0.is_empty());
    let mut bytes = original.clone();
    let at = sh(&bytes, ".rela.text");
    put32(&mut bytes, at + 4, 9);
    assert!(
        inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
            .0
            .is_none()
    );
}

#[test]
fn linked_got_provenance_rejects_wrong_register_slot_and_clobber() {
    let original = fixture("elf-clang-got.so");
    assert_eq!(run_calls(&original).0.len(), 2);
    for (at, word) in [
        (0x370, 0xd63f0120),
        (0x368, 0xf9422d08),
        (0x36c, 0x2a1f03e8),
        (0x35c, 0x900000a8),
        (0x36c, 0xa8c127e8),
    ] {
        let mut bytes = original.clone();
        put32(&mut bytes, at, word);
        let (calls, gaps) = run_calls(&bytes);
        assert!(
            !calls.iter().any(|(pc, _)| *pc == 0x10370),
            "{at:#x}: {calls:?}"
        );
        assert!(calls.iter().any(|(pc, _)| *pc == 0x1039c));
        assert!(!gaps.is_empty());
    }
}

#[test]
fn malformed_missing_overlapping_fdes_cannot_supply_a_function() {
    let original = fixture("elf-clang-plt.so");
    let (_, off, _) = section(&original, ".eh_frame");
    let mut bytes = original.clone();
    put32(&mut bytes, off as usize, 0xfffffff0);
    let (image, run) = normal(&bytes);
    assert!(image.fdes.is_empty());
    assert!(!run.clone_gaps().is_empty());
    let mut bytes = original.clone();
    let at = sh(&bytes, ".eh_frame");
    put64(&mut bytes, at + 32, 0);
    assert!(normal(&bytes).0.fdes.is_empty());
    assert!(run_calls(&bytes).0.is_empty());
    // First FDE range grows into the adjacent second function.
    let mut bytes = original.clone();
    put32(&mut bytes, off as usize + 0x20, 0x48);
    let (image, run) = normal(&bytes);
    assert!(!run.clone_gaps().is_empty());
    assert!(matches!(image.function(0x103c4), FdeAt::Overlap));
    let object = fixture("elf-clang-o2.o");
    let (_, rel, _) = section(&object, ".rela.eh_frame");
    for (offset, value) in [
        (rel as usize, 0x20),
        (rel as usize + 8, 0x200000101),
        (rel as usize + 24, 0x1c),
        (rel as usize + 16, u64::MAX),
    ] {
        let mut bytes = object.clone();
        put64(&mut bytes, offset, value);
        let (image, _, _) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
        assert!(
            image.is_none_or(|i| !i.fdes.iter().any(|r| r.0 == 0x40)),
            "offset {offset:#x}"
        );
    }
}

#[test]
fn object_adjacent_sections_are_separate_and_aliases_rejected() {
    let original = fixture("elf-clang-o2.o");
    let mut bytes = original.clone();
    let text = sh(&bytes, ".text");
    let eh = sh(&bytes, ".eh_frame");
    // The adjacent .eh_frame becomes a second executable section only for this mapping test.
    put64(&mut bytes, eh + 8, 6);
    let (image, _, _) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
    let image = image.unwrap();
    assert_eq!(image.code.len(), 2);
    assert!(!image.executable(0x40, 0x8c));
    let mut bytes = original.clone();
    let off = u64le(&bytes, text + 24);
    put64(&mut bytes, eh + 24, off);
    assert!(
        inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
            .0
            .is_none()
    );
}

#[test]
fn candidate_reservations_are_deduplicated_and_shared_across_functions_slices() {
    let bytes = fixture("elf-clang-plt.so");
    let (image, _) = normal(&bytes);
    let mut run = Run::new(CodeBudgets {
        references: 3,
        ..CodeBudgets::default()
    });
    let mut a = Candidates::default();
    assert!(a.reserve(0x103a0, &image, &mut run));
    assert!(a.reserve(0x103a0, &image, &mut run));
    assert!(a.reserve(0x103c4, &image, &mut run));
    assert_eq!(a.functions.len(), 2);
    let mut b = Candidates::default();
    assert!(b.reserve(0x103a0, &image, &mut run));
    assert!(!b.reserve(0x103c4, &image, &mut run));
    assert!(run.stopped());
    assert_eq!(a.functions.len(), 2);
    assert_eq!(b.functions.len(), 1);
    let mut run = Run::new(CodeBudgets {
        references: 1,
        ..CodeBudgets::default()
    });
    let mut c = Candidates::default();
    assert!(c.reserve(0x10400, &image, &mut run));
    assert!(c.functions.is_empty());
    assert!(!run.clone_gaps().is_empty());
    assert!(!c.reserve(0x103a0, &image, &mut run));
}

#[test]
fn object_got_pairs_require_symbol_addend_register_and_unclobbered_origin() {
    let mut bytes = fixture("elf-clang-o2.o");
    let (_, rel, _) = section(&bytes, ".rela.text");
    put32(&mut bytes, 0x48, 0x90000008);
    put32(&mut bytes, 0x50, 0xf9400108);
    put32(&mut bytes, 0x54, 0xd63f0100);
    put64(&mut bytes, rel as usize, 8);
    put64(&mut bytes, rel as usize + 8, 0x600000137);
    put64(&mut bytes, rel as usize + 24, 16);
    put64(&mut bytes, rel as usize + 32, 0x600000138);
    let (calls, gaps) = run_calls(&bytes);
    assert!(
        calls.iter().any(|(pc, w)| *pc == 0x54
            && matches!(w,Branch::Import(w) if w.at==0x50 && w.relocation==LD64_GOT_LO12)),
        "{gaps:?}"
    );
    for (at, value, width) in [
        (rel as usize + 32, 0x700000138, 8),
        (rel as usize + 40, 4, 8),
        (0x50, 0xf9400128, 4),
        (0x4c, 0x52800008, 4),
        (0x54, 0xd63f0120, 4),
        (0x48, 0x90000009, 4),
    ] {
        let mut mutation = bytes.clone();
        if width == 4 {
            put32(&mut mutation, at, value as u32);
        } else {
            put64(&mut mutation, at, value);
        }
        let (calls, gaps) = run_calls(&mutation);
        assert!(calls.is_empty(), "{at:#x}: {calls:?}");
        assert!(!gaps.is_empty());
    }
    // A same-symbol nonzero addend is still not the exact import.
    put64(&mut bytes, rel as usize + 16, 4);
    put64(&mut bytes, rel as usize + 40, 4);
    assert!(run_calls(&bytes).0.is_empty());
}

#[test]
fn defined_branch_and_jump26_use_bounded_object_file_offsets() {
    let original = fixture("elf-clang-o2.o");
    let (_, rel, _) = section(&original, ".rela.text");
    let mut bytes = original.clone();
    put64(&mut bytes, rel as usize + 8, 0x20000011b);
    put64(&mut bytes, rel as usize + 16, 0x24);
    let (image, _) = normal(&bytes);
    assert_eq!(image.branch(0x54, 0x94000000), Some(Branch::Internal(0x64)));
    put64(&mut bytes, rel as usize + 16, 0x1000);
    assert!(normal(&bytes).0.branch(0x54, 0x94000000).is_none());
    let mut bytes = original.clone();
    put64(&mut bytes, rel as usize + 8, 0x60000011a);
    put32(&mut bytes, 0x54, 0x14000000);
    assert!(matches!(
        normal(&bytes).0.branch(0x54, 0x14000000),
        Some(Branch::Import(_))
    ));
    put64(&mut bytes, rel as usize + 16, 4);
    assert!(normal(&bytes).0.branch(0x54, 0x14000000).is_none());
}

#[test]
fn repeated_slot_ownership_is_never_deduplicated_as_a_proof() {
    let original = fixture("elf-cases.so");
    let (_, off, size) = section(&original, ".rela.plt");
    assert_eq!(size, 48);
    let mut bytes = original.clone();
    let slot = u64le(&bytes, off as usize);
    put64(&mut bytes, off as usize + 24, slot);
    let (image, run) = normal(&bytes);
    assert!(!image.slots.contains_key(&slot));
    assert!(image.stubs.values().all(|w| w.at != slot));
    assert!(run
        .clone_gaps()
        .iter()
        .any(|g| g.contains("ambiguous GOT slot")));
}

#[test]
fn file_vm_aliases_and_dynamic_symbol_disagreement_are_rejected() {
    let original = fixture("elf-clang-plt.so");
    let ph = u64le(&original, 32) as usize;
    let count = u16le(&original, 56) as usize;
    let loads: Vec<_> = (0..count)
        .map(|i| ph + i * 56)
        .filter(|at| u32le(&original, *at) == 1)
        .collect();
    for delta in [8, 16] {
        let mut bytes = original.clone();
        let value = u64le(&bytes, loads[0] + delta);
        put64(&mut bytes, loads[1] + delta, value);
        assert!(
            inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
                .0
                .is_none()
        );
    }
    let mut bytes = original.clone();
    let s = sh(&bytes, ".dynsym");
    put64(&mut bytes, s + 16, 0x240);
    assert!(
        inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
            .0
            .is_none()
    );
    let (image, mut run) = normal(&original);
    image.values(&mut run).unwrap();
    // LLD aliases the first file page across RX/RW loads; none may prove readonly constants.
    assert!(image
        .mappings
        .iter()
        .all(|m| m.writable || m.executable || m.relocated));
}

#[test]
fn metadata_instruction_and_name_limits_are_shared_across_images() {
    let bytes = fixture("elf-clang-plt.so");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&bytes).unwrap();
    let window = SliceWindow {
        base: 0,
        len: bytes.len() as u64,
    };
    let mut r = Reader::new(f.as_file(), window.len, 1 << 28);
    let mut full = Run::new(CodeBudgets::default());
    assert!(build(&mut r, window, &mut full).is_some());
    for budgets in [
        CodeBudgets {
            fdes: full.fdes as usize + 1,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            slots: full.slots as usize + 1,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            relocations: full.relocations as usize,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            instructions: full.instructions + 1,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            name_bytes: full.name_bytes + 1,
            ..CodeBudgets::default()
        },
    ] {
        let mut reader = Reader::new(f.as_file(), window.len, 1 << 28);
        let mut run = Run::new(budgets);
        let first = build(&mut reader, window, &mut run).unwrap();
        let second = build(&mut reader, window, &mut run);
        assert!(run.stopped());
        assert!(second.is_none());
        assert_eq!(first.fdes.len(), 2);
        assert_eq!(first.stubs.len(), 1);
    }
    let (_, _, used) = inspect(&bytes, 0, window.len, CodeBudgets::default());
    assert!(inspect(
        &bytes,
        0,
        window.len,
        CodeBudgets {
            bytes: used,
            ..CodeBudgets::default()
        }
    )
    .0
    .is_some());
    assert!(inspect(
        &bytes,
        0,
        window.len,
        CodeBudgets {
            bytes: used - 1,
            ..CodeBudgets::default()
        }
    )
    .0
    .is_none());
}

#[test]
fn unapplied_object_relocations_cannot_be_argument_constants() {
    let mut bytes = fixture("elf-clang-o2.o");
    let (_, rel, _) = section(&bytes, ".rela.text");
    put32(&mut bytes, 0x48, 0x90000000);
    put32(&mut bytes, 0x4c, 0x91000000);
    put64(&mut bytes, rel as usize, 8);
    put64(&mut bytes, rel as usize + 8, 0x200000113);
    put64(&mut bytes, rel as usize + 16, 0x24);
    put64(&mut bytes, rel as usize + 24, 12);
    put64(&mut bytes, rel as usize + 32, 0x200000115);
    put64(&mut bytes, rel as usize + 40, 0x24);
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 28);
    let mut run = Run::new(CodeBudgets::default());
    let image = build(
        &mut reader,
        SliceWindow {
            base: 0,
            len: bytes.len() as u64,
        },
        &mut run,
    )
    .unwrap();
    let raw = image.read_code(0x40, 0x24, &mut reader, &mut run).unwrap();
    let p = Proofs {
        executable: &|s, e| image.executable(s, e),
        excluded: &|s, e| image.excluded(s, e),
        noreturn: &|_, _| false,
        candidates: &[],
    };
    let cfg = decode_cfg(&raw, 0x40, 0x64, &p, &mut run).unwrap();
    let result = image.solve_values(&cfg, &mut reader, &mut run).unwrap();
    assert!(
        matches!(result.calls[&0x54].regs[0], value::Value::Unknown(_)),
        "{:?}",
        result.calls[&0x54].regs[0]
    );
}

#[test]
fn elf_mapping_symbols_exclude_data_words_from_function_proof() {
    let mut bytes = fixture("elf-clang-o2.o");
    let at = bytes.windows(3).position(|b| b == b"$x\0").unwrap();
    bytes[at + 1] = b'd';
    let (image, run) = normal(&bytes);
    assert!(image.fdes.is_empty());
    assert!(image.excluded(0x40, 0x88));
    assert!(!run.clone_gaps().is_empty());
    assert!(run_calls(&bytes).0.is_empty());
}

#[test]
fn got_provenance_joins_require_identical_origins() {
    let original = fixture("elf-clang-got.so");
    for clobber in [false, true] {
        let mut bytes = original.clone();
        for (at, word) in [
            (0x354, 0x90000088),
            (0x358, 0xf9422908),
            (0x35c, 0xb4000060),
            (0x360, if clobber { 0x52800008 } else { 0xd503201f }),
            (0x364, 0x14000002),
            (0x368, 0xd503201f),
            (0x36c, 0xd503201f),
        ] {
            put32(&mut bytes, at, word);
        }
        let (calls, gaps) = run_calls(&bytes);
        assert_eq!(
            calls.iter().any(|(pc, _)| *pc == 0x10370),
            !clobber,
            "{gaps:?}"
        );
        assert!(calls.iter().any(|(pc, _)| *pc == 0x1039c));
    }
}

#[test]
fn duplicate_fdes_overlapping_slots_and_unmodeled_fixups_do_not_prove_targets() {
    let original = fixture("elf-clang-plt.so");
    let (_, off, _) = section(&original, ".eh_frame");
    let mut bytes = original.clone();
    let first = u32le(&bytes, off as usize + 0x1c);
    put32(&mut bytes, off as usize + 0x44, first.wrapping_sub(0x28));
    let (image, run) = normal(&bytes);
    assert_eq!(image.fdes.len(), 2);
    assert_eq!(image.fdes[0], image.fdes[1]);
    assert!(matches!(image.function(0x103a0), FdeAt::Overlap));
    assert!(!run.clone_gaps().is_empty());
    let mut bytes = fixture("elf-cases.so");
    let (_, rel, _) = section(&bytes, ".rela.plt");
    let first = u64le(&bytes, rel as usize);
    put64(&mut bytes, rel as usize + 24, first + 4);
    assert!(
        inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
            .0
            .is_none()
    );
    for tag in [17, 36, 0x60000011, 0x70000003, 0x6ffffef8] {
        let mut bytes = original.clone();
        let (_, off, size) = section(&bytes, ".dynamic");
        let at = (off..off + size)
            .step_by(16)
            .find(|at| u64le(&bytes, *at as usize) == 14)
            .unwrap();
        put64(&mut bytes, at as usize, tag);
        assert!(
            inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default())
                .0
                .is_none(),
            "{tag:#x}"
        );
    }
}

#[test]
fn same_fd_code_io_failure_keeps_the_exact_charge() {
    let bytes = fixture("elf-clang-plt.so");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 28);
    let mut run = Run::new(CodeBudgets::default());
    let image = crate::binary::elf::aarch64_image(
        &mut reader,
        SliceWindow {
            base: 0,
            len: bytes.len() as u64,
        },
        &mut run,
    )
    .unwrap();
    let before = reader.used();
    f.as_file().set_len(0x390).unwrap();
    assert!(image
        .read_code(0x1038c, 0x24, &mut reader, &mut run)
        .is_none());
    assert_eq!(reader.used() - before, 0x24);
    assert!(!run.clone_gaps().is_empty());
}

#[test]
fn hostile_metadata_and_truncations_preserve_image_invariants() {
    let mut seed = 0x48e1_fde9_u64;
    let mut cases = 0;
    for name in ["elf-clang-o2.o", "elf-gcc-plt.so", "elf-clang-got.so"] {
        let original = fixture(name);
        for at in 0..original.len() {
            if at < 64 || at % 13 == 0 {
                let (image, _, used) =
                    inspect(&original[..at], 0, at as u64, CodeBudgets::default());
                assert!(image.is_none());
                assert!(used <= CodeBudgets::default().bytes);
                cases += 1;
            }
        }
        for _ in 0..512 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut bytes = original.clone();
            let at = seed as usize % bytes.len();
            bytes[at] ^= (seed >> 32) as u8 | 1;
            let (image, _, used) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
            assert!(used <= CodeBudgets::default().bytes);
            if let Some(image) = image {
                assert!(image.code.windows(2).all(|r| r[0].end <= r[1].start));
                assert!(image.fdes.iter().all(|&(s, e)| s & 3 == 0
                    && e & 3 == 0
                    && image.executable(s, e)
                    && !image.excluded(s, e)));
                assert!(image
                    .stubs
                    .values()
                    .all(|w| image.slots.get(&w.at) == Some(w) && !w.weak));
            }
            cases += 1;
        }
    }
    assert!(cases > 1800);
}

#[test]
fn one_reference_outside_any_fde_leaves_a_gap_and_keeps_the_other_function() {
    // Controlled fixture derivative: zero the first recorded FDE length; preserve the actual
    // function bytes, symbol, PLT and the second independent FDE. Symbols cannot fill the hole.
    let mut bytes = fixture("elf-clang-plt.so");
    let (_, off, _) = section(&bytes, ".eh_frame");
    put32(&mut bytes, off as usize + 0x20, 0);
    let (image, _) = normal(&bytes);
    assert_eq!(image.fdes, [(0x103b0, 0x103d4)]);
    let (calls, gaps) = run_calls(&bytes);
    assert!(!calls.iter().any(|(pc, _)| *pc == 0x103a0));
    assert!(calls.iter().any(|(pc, _)| *pc == 0x103c4));
    assert!(gaps
        .iter()
        .any(|g| g.contains("0x103a0") && g.contains("no exact function bounds")));
}

#[test]
fn runtime_relocated_plt_bytes_never_establish_a_stub_witness() {
    let mut bytes = fixture("elf-cases.so");
    let (image, _) = normal(&bytes);
    let stub = *image.stubs.keys().next().unwrap();
    let (_, rel, _) = section(&bytes, ".rela.plt");
    put64(&mut bytes, rel as usize + 24, stub);
    let info = u64le(&bytes, rel as usize + 32);
    put64(&mut bytes, rel as usize + 32, (info & !0xffff_ffff) | 257);
    let (image, run) = normal(&bytes);
    assert!(image.stubs.is_empty(), "{:?}", image.stubs);
    assert!(!run.clone_gaps().is_empty());
}

#[test]
fn plt_adrp_uses_signed_page_pc_across_a_page_boundary() {
    for (pc, page_word, slot) in [
        (0x20ffc, 0x90ffff90u32, 0x10028),
        (0x10ffc, 0x90000090, 0x20028),
    ] {
        let mut bytes = vec![0; 32];
        for word in [page_word, 0xf9401611, 0x9100a210, 0xd61f0220] {
            bytes.extend(word.to_le_bytes());
        }
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&bytes).unwrap();
        let mut reader = Reader::new(f.as_file(), 48, 48);
        let mut run = Run::new(CodeBudgets::default());
        let witness = ImportWitness {
            name: Rc::from(&b"connect"[..]),
            relocation: JUMP_SLOT,
            at: slot,
            weak: false,
        };
        let mut image = A64ElfImage {
            window: SliceWindow { base: 0, len: 48 },
            object: false,
            code: vec![Region {
                start: pc - 32,
                end: pc + 16,
                offset: 0,
            }],
            mappings: vec![],
            fdes: vec![],
            slots: BTreeMap::from([(slot, witness.clone())]),
            stubs: BTreeMap::new(),
            relocs: BTreeMap::new(),
            excluded: vec![],
            plt: vec![(pc - 32, pc + 16)],
            plt_verified: vec![],
            bounds: Image::empty(Kind::Shared),
        };
        stubs(&mut image, None, &mut reader, &mut run).unwrap();
        assert_eq!(image.stubs.get(&pc), Some(&witness));
        assert_eq!(reader.used(), 48);
    }
}

#[test]
fn a_failed_scan_cannot_become_successful_when_repeated() {
    let bytes = fixture("elf-clang-plt.so");
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 28);
    let mut run = Run::new(CodeBudgets::default());
    let image = build(
        &mut reader,
        SliceWindow {
            base: 0,
            len: bytes.len() as u64,
        },
        &mut run,
    )
    .unwrap();
    f.as_file().set_len(0).unwrap();
    let mut candidates = Candidates::default();
    assert!(!candidates.scan(&image, &mut reader, &mut run));
    let used = reader.used();
    assert!(!candidates.scan(&image, &mut reader, &mut run));
    assert_eq!(reader.used(), used);
}

#[test]
fn aarch64_loader_granules_cannot_hide_readonly_file_aliases() {
    // Distinct 4KiB file pages can alias in a supported 64KiB arm64 loader granule.
    let segments = [
        Segment {
            flags: 4,
            off: 0,
            addr: 0,
            filesz: 0x1000,
            memsz: 0x1000,
        },
        Segment {
            flags: 6,
            off: 0x2000,
            addr: 0x12000,
            filesz: 0x1000,
            memsz: 0x1000,
        },
    ];
    validate_segments(&segments).unwrap();
    let (mut image, _) = normal(&fixture("elf-clang-plt.so"));
    image.mappings.clear();
    image.code.clear();
    image.plt.clear();
    image.window.len = 0x3000;
    mappings(&mut image, &[], &segments).unwrap();
    assert!(
        image.mappings[0].relocated,
        "a 4KiB-only alias check falsely permits readonly constants"
    );
    let mut overlap = segments;
    overlap[1].addr = 0x2000;
    assert!(validate_segments(&overlap).is_err());
}

#[test]
fn an_import_reference_in_unproved_plt0_cannot_disappear() {
    let mut bytes = fixture("elf-clang-plt.so");
    // Independent reviewer reproduction: BL at executable VA0x103e0 targets the real
    // connect stub0x10400. Remove both original calls, leaving exactly this reference.
    assert_eq!(u32le(&bytes, 0x3e0), 0xa9bf7bf0);
    put32(&mut bytes, 0x3e0, 0x94000008);
    put32(&mut bytes, 0x3a0, 0xd503201f);
    put32(&mut bytes, 0x3c4, 0xd503201f);
    let (calls, gaps) = run_calls(&bytes);
    assert!(calls.is_empty(), "no FDE establishes a function at0x103e0");
    assert!(
        gaps.iter()
            .any(|g| g.contains("0x103e0") && g.contains("no exact function bounds")),
        "calls={calls:?} gaps={gaps:?}"
    );
}

#[test]
fn a_plt_name_prefix_does_not_hide_an_ordinary_function_section() {
    let mut bytes = fixture("elf-clang-plt.so");
    let text_header = sh(&bytes, ".text");
    let names_header = u64le(&bytes, 40) as usize + u16le(&bytes, 62) as usize * 64;
    let name = u64le(&bytes, names_header + 24) as usize + u32le(&bytes, text_header) as usize;
    bytes[name..name + 5].copy_from_slice(b".pltX");
    let (calls, gaps) = run_calls(&bytes);
    assert_eq!(
        calls.iter().map(|(pc, _)| *pc).collect::<Vec<_>>(),
        [0x103a0, 0x103c4],
        "{gaps:?}"
    );
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn every_unproved_plt0_word_stays_searchable_and_healthy_calls_survive() {
    for (name, start, offset, stub, calls) in [
        (
            "elf-clang-plt.so",
            0x103e0u64,
            0x3e0usize,
            0x10400u64,
            [0x3a0usize, 0x3c4],
        ),
        ("elf-gcc-plt.so", 0x260, 0x260, 0x280, [0x2b4, 0x2d8]),
    ] {
        let original = fixture(name);
        let (image, run) = normal(&original);
        assert!(
            run.clone_gaps().is_empty(),
            "{name}: {:?}",
            run.clone_gaps()
        );
        for pc in (start..stub + 16).step_by(4) {
            assert!(image.verified_plt_instruction(pc), "{name} {pc:#x}");
        }
        assert!(run_calls(&original).1.is_empty());
        for index in 0..8 {
            let pc = start + index * 4;
            let word = 0x94000000 | ((stub - pc) / 4) as u32;
            let mut mutation = original.clone();
            put32(&mut mutation, offset + index as usize * 4, word);
            let (image, run) = normal(&mutation);
            assert!(run
                .clone_gaps()
                .iter()
                .any(|g| g.contains("unproved PLT resolver header")));
            for pc in (start..stub).step_by(4) {
                assert!(!image.verified_plt_instruction(pc));
            }
            assert!(image.verified_plt_instruction(stub));
            let (retained, gaps) = run_calls(&mutation);
            assert_eq!(retained.len(), 2, "{name} index{index}: {gaps:?}");
            assert!(!gaps.is_empty());
            for at in calls {
                put32(&mut mutation, at, 0xd503201f);
            }
            let (retained, gaps) = run_calls(&mutation);
            assert!(retained.is_empty(), "{name} index{index}: {retained:?}");
            assert!(!gaps.is_empty());
            if name.starts_with("elf-clang") {
                assert!(
                    gaps.iter().any(|g| g.contains(&format!("{pc:#x}"))
                        && g.contains("no exact function bounds")),
                    "{gaps:?}"
                );
            }
        }
    }
}

#[test]
fn plt0_requires_the_unique_unrelocated_dynamic_resolver_slot() {
    let original = fixture("elf-clang-plt.so");
    let (_, dynoff, size) = section(&original, ".dynamic");
    let got_tag = (dynoff..dynoff + size)
        .step_by(16)
        .find(|at| u64le(&original, *at as usize) == 3)
        .unwrap() as usize;
    let got = u64le(&original, got_tag + 8);
    for case in 0..5 {
        let mut bytes = original.clone();
        match case {
            0 => put64(&mut bytes, got_tag, 21),          // absent DT_PLTGOT
            1 => put64(&mut bytes, got_tag + 8, got + 8), // points into symbol-owned word
            2 => {
                let other = (dynoff..dynoff + size)
                    .step_by(16)
                    .find(|at| u64le(&bytes, *at as usize) == 14)
                    .unwrap() as usize;
                put64(&mut bytes, other, 3);
                put64(&mut bytes, other + 8, got);
            }
            3 => {
                // A syntactically valid header loading connect's slot is a reference, not PLT0.
                put32(&mut bytes, 0x3e8, 0xf9426e11);
                put32(&mut bytes, 0x3ec, 0x91136210);
            }
            _ => {
                let (_, rel, _) = section(&bytes, ".rela.plt");
                put64(&mut bytes, rel as usize, got + 16);
            }
        }
        let (image, run, _) = inspect(&bytes, 0, bytes.len() as u64, CodeBudgets::default());
        if let Some(image) = image {
            assert!(!image.verified_plt_instruction(0x103e0), "case{case}");
        }
        assert!(!run.clone_gaps().is_empty(), "case{case}");
        let (_, gaps) = run_calls(&bytes);
        assert!(!gaps.is_empty(), "case{case}");
    }
}

#[test]
fn a_truncated_plt_section_does_not_close_search_with_unproved_jump_slots() {
    let mut bytes = fixture("elf-clang-plt.so");
    let plt = sh(&bytes, ".plt");
    // The physical stub remains, but its section now claims only the32-byte resolver header.
    put64(&mut bytes, plt + 32, 32);
    let (calls, gaps) = run_calls(&bytes);
    assert!(calls.is_empty());
    assert!(!gaps.is_empty(), "unproved JUMP_SLOT must not vanish");
}

#[test]
fn an_import_reference_in_an_unproved_stub_stays_searchable() {
    let original = fixture("elf-cases.so");
    let (image, _) = normal(&original);
    let target = *image.stubs.keys().next().unwrap();
    let (_, off, _) = section(&original, ".plt");
    let start = image.plt[0].0;
    let bad_stub = start + 48;
    let mut bytes = original.clone();
    put32(
        &mut bytes,
        (off + bad_stub - start) as usize,
        0x94000000 | (((target as i64 - bad_stub as i64) / 4) as u32 & 0x03ff_ffff),
    );
    let (calls, gaps) = run_calls(&bytes);
    assert!(!calls.is_empty());
    assert!(
        gaps.iter().any(
            |g| g.contains(&format!("{bad_stub:#x}")) && g.contains("no exact function bounds")
        ),
        "{gaps:?}"
    );
}
