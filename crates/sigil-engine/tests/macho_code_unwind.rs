//! The private production metadata adapters and actual shared Run/Reader, with LLVM 21.1.8
//! fixture boundaries. Decoder dispatch stays gated until Tasks 14–15.
#[allow(dead_code)]
#[path = "../src/code/fde.rs"]
pub(crate) mod fde;
#[allow(dead_code)]
#[path = "../src/code/macho/image.rs"]
mod image;
#[allow(dead_code)]
#[path = "../src/code/reader.rs"]
pub(crate) mod reader;
#[allow(dead_code)]
#[path = "../src/code/run.rs"]
mod run;
#[allow(dead_code)]
#[path = "../src/code/macho/unwind.rs"]
mod unwind;
use reader::{Reader, SliceWindow};
use run::{Run, Work};
use sigil_engine::code::{CodeBudgets, CodeOutcome};
mod code {
    pub(crate) use crate::{fde, reader, CodeBudgets, Run, Work};
}
use sigil_model::{Arch, ArtifactId, BoundsSource, SliceId};
use std::io::Write;
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/code-macho/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn file(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f
}
fn view(reader: &mut Reader<'_>, base: u64, len: u64) -> image::MachCodeView {
    let header = reader::read_slice(reader, SliceWindow { base, len }, 4, 4).unwrap();
    let arch = if get32(&header, 0) == 0x01000007 {
        Arch::X86_64
    } else {
        Arch::Aarch64
    };
    image::build(
        reader,
        SliceId::from_parts(
            &ArtifactId::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            arch,
            base,
        ),
        SliceWindow { base, len },
        arch,
        None,
    )
    .unwrap()
}
fn analyze(bytes: &[u8]) -> (Vec<unwind::MachBounds>, Vec<String>) {
    let f = file(bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let v = view(&mut reader, 0, bytes.len() as u64);
    let mut run = Run::new(CodeBudgets::default());
    let got = unwind::read_bounds(&v, &mut reader, &mut run);
    (got, run.into_gaps())
}
fn ranges(bounds: &[unwind::MachBounds]) -> Vec<(u64, u64)> {
    bounds.iter().map(|b| (b.start, b.end)).collect()
}
#[test]
fn native_object_explicit_lengths_and_linked_dwarf_offsets_are_separate_proofs() {
    let (got, gaps) = analyze(&fixture("compact-object.o"));
    assert_eq!(ranges(&got), [(0x188, 0x1ac), (0x1ac, 0x1d0)]);
    assert!(got
        .iter()
        .all(|b| b.source == BoundsSource::MachOCompactUnwind));
    assert!(gaps.is_empty(), "{gaps:?}");
    let (got, gaps) = analyze(&fixture("arm64-classic"));
    assert_eq!(ranges(&got), [(0x520, 0x544), (0x544, 0x568)]);
    assert!(got.iter().all(|b| b.source == BoundsSource::EhFrameFde));
    assert!(gaps.is_empty(), "{gaps:?}");
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn section_header(b: &[u8], name: &[u8]) -> usize {
    let mut at = 32;
    for _ in 0..get32(b, 16) {
        if get32(b, at) == 0x19 {
            for i in 0..get32(b, at + 64) as usize {
                let s = at + 72 + i * 80;
                if &b[s..s + name.len()] == name {
                    return s;
                }
            }
        }
        at += get32(b, at + 4) as usize;
    }
    panic!("missing section")
}
fn section_at(b: &[u8], name: &[u8]) -> usize {
    get32(b, section_header(b, name) + 48) as usize
}
fn regular(mut b: Vec<u8>) -> Vec<u8> {
    let u = section_at(&b, b"__unwind_info");
    let index = u + get32(&b, u + 20) as usize;
    let page = u + get32(&b, index + 4) as usize;
    let common = u + get32(&b, u + 4) as usize;
    let offsets = get32(&b, page + 4);
    let entries = page + (offsets & 0xffff) as usize;
    let count = offsets >> 16;
    let base = get32(&b, index);
    let pairs: Vec<_> = (0..count as usize)
        .map(|i| {
            let raw = get32(&b, entries + i * 4);
            (
                base + (raw & 0xffffff),
                get32(&b, common + (raw >> 24) as usize * 4),
            )
        })
        .collect();
    put32(&mut b, page, 2);
    put32(&mut b, page + 4, (count << 16) | 8);
    for (i, (start, encoding)) in pairs.into_iter().enumerate() {
        put32(&mut b, page + 8 + i * 8, start);
        put32(&mut b, page + 12 + i * 8, encoding);
    }
    b
}
#[test]
fn folded_native_regular_compressed_local_and_function_starts_never_supply_ends() {
    let original = fixture("unwind-folded");
    let u = section_at(&original, b"__unwind_info");
    let page = u + 0x38;
    let mut local = original.clone();
    put32(&mut local, u + 8, 0); // use a local encoding rather than the common array
    put32(&mut local, page + 8, (1 << 16) | 16);
    put32(&mut local, page + 16, 0x04000000);
    let mut with_starts = original.clone();
    // Repurpose the empty LC_DATA_IN_CODE as an LC_FUNCTION_STARTS stream with two starts.
    let mut at = 32;
    while get32(&with_starts, at) != 0x29 {
        at += get32(&with_starts, at + 4) as usize;
    }
    let starts = with_starts.len();
    with_starts.extend([0xc0, 0x09, 0x24, 0]);
    put32(&mut with_starts, at, 0x26);
    put32(&mut with_starts, at + 8, starts as u32);
    put32(&mut with_starts, at + 12, 4);
    for bytes in [original.clone(), regular(original), local, with_starts] {
        let (got, gaps) = analyze(&bytes);
        assert!(got.is_empty());
        assert!(
            gaps.iter()
                .any(|g| g.contains("lacks exact function bounds")),
            "{gaps:?}"
        );
        assert!(
            !gaps
                .iter()
                .any(|g| g.contains("array") || g.contains("page kind")),
            "{gaps:?}"
        );
    }
    let (got, gaps) = analyze(&regular(fixture("arm64-classic")));
    assert_eq!(ranges(&got), [(0x520, 0x544), (0x544, 0x568)]);
    assert!(gaps.is_empty(), "{gaps:?}");
}
#[test]
fn object_relocation_fields_lengths_encodings_and_overlap_are_validated() {
    let original = fixture("compact-object.o");
    let s = section_header(&original, b"__compact_unwind");
    let data = section_at(&original, b"__compact_unwind");
    let reloc = get32(&original, s + 56) as usize;
    // These corrupt the complete relocation proof, so neither function survives.
    for (at, value) in [
        (reloc, 0x24),
        (reloc, 0x80000020),
        (reloc + 4, 0x06000002),
        (reloc + 4, 0x07000001),
        (reloc + 4, 0x04000001),
        (reloc + 4, 0x0e000001),
        (reloc + 4, 0x16000001),
        (reloc + 4, 0x06000000),
        (reloc + 8, 0x20),
        (s + 60, 1),
    ] {
        let mut b = original.clone();
        put32(&mut b, at, value);
        let (got, gaps) = analyze(&b);
        if at == reloc + 4 && value == 0x06000002 {
            assert_eq!(ranges(&got), [(0x188, 0x1ac)]);
        } else {
            assert!(got.is_empty(), "{at:#x} {value:#x}: {got:?}");
        }
        assert!(!gaps.is_empty());
    }
    for (offset, value) in [
        (8, 0),
        (8, u32::MAX),
        (12, 0),
        (12, 0x01000000),
        (12, 0x84000000),
    ] {
        let mut b = original.clone();
        put32(&mut b, data + offset, value);
        let (got, gaps) = analyze(&b);
        assert_eq!(ranges(&got), [(0x1ac, 0x1d0)]);
        assert!(!gaps.is_empty());
    }
    let mut overlap = original.clone();
    put64(&mut overlap, data + 32, 0x20);
    let (got, gaps) = analyze(&overlap);
    assert!(got.is_empty());
    assert!(gaps.iter().any(|g| g.contains("overlapping")));
    let mut noncode = original.clone();
    put32(&mut noncode, section_header(&original, b"__text") + 64, 0);
    assert!(analyze(&noncode).0.is_empty());
    let mut badptr = original.clone();
    put64(&mut badptr, data, u64::MAX);
    assert_eq!(ranges(&analyze(&badptr).0), [(0x1ac, 0x1d0)]);
}
#[test]
fn linked_page_offsets_indexes_order_sentinel_and_fde_matching_fail_closed() {
    let original = fixture("arm64-classic");
    let u = section_at(&original, b"__unwind_info");
    let index = u + get32(&original, u + 20) as usize;
    let page = u + get32(&original, index + 4) as usize;
    let entries = page + (get32(&original, page + 4) & 0xffff) as usize;
    let common =
        u + get32(&original, u + 4) as usize + (get32(&original, entries) >> 24) as usize * 4;
    let first = get32(&original, entries);
    let next = get32(&original, entries + 4);
    for (at, value) in [
        (u, 2),
        (u + 8, u32::MAX),
        (u + 20, 28),
        (u + 24, u32::MAX),
        (index + 4, u32::MAX),
        (index + 12, get32(&original, index)),
        (index + 16, 1),
        (page, 1),
        (page + 4, 0xffff000c),
        (page + 8, 0x0001ffff),
        (entries, 0xff000000),
        (entries + 4, first),
        (entries + 4, (next & 0xff000000) | 0xffffff),
    ] {
        let mut b = original.clone();
        put32(&mut b, at, value);
        let (got, gaps) = analyze(&b);
        assert!(got.is_empty(), "{at:#x} {value:#x}: {got:?}");
        assert!(!gaps.is_empty());
    }
    // Exact section-relative FDE offsets are required, even though independent valid FDEs exist.
    for encoding in [
        0x03000000, 0x03000015, 0x03000048, 0x83000014, 0, 0x01000000,
    ] {
        let mut b = original.clone();
        put32(&mut b, common, encoding);
        let (got, gaps) = analyze(&b);
        assert!(
            !got.iter().any(|b| b.start == 0x520),
            "{encoding:#x}: {got:?}"
        );
        assert!(!gaps.is_empty());
    }
    // A native arm64 FRAME encoding is not x86's DWARF mode and cannot reinterpret low bits.
    let mut native = original.clone();
    put32(&mut native, common, 0x04000014);
    assert_eq!(
        ranges(&analyze(&native).0),
        [(0x520, 0x544), (0x544, 0x568)]
    );
}
#[test]
fn malformed_indirect_overlapping_and_wrapping_fdes_never_create_bounds() {
    let original = fixture("arm64-classic");
    let eh = section_at(&original, b"__eh_frame");
    // This fixture uses 64-bit PC-relative fields (zR=0x10); LLVM records offsets14 and48.
    for (at, value) in [(eh + 0x18, 0xffffffff), (eh + 0x4c, 0xffffffff)] {
        let mut b = original.clone();
        put32(&mut b, at, value);
        let (got, gaps) = analyze(&b);
        assert!(!gaps.is_empty());
        if at == eh + 0x18 {
            assert!(got.is_empty());
        } else {
            assert_eq!(ranges(&got), [(0x520, 0x544)]);
        }
    }
    let mut indirect = original.clone();
    indirect[eh + 16] = 0x90;
    assert!(analyze(&indirect).0.is_empty());
    let mut overlap = original.clone();
    put64(&mut overlap, eh + 0x24, 0x28);
    let (got, gaps) = analyze(&overlap);
    assert!(got.is_empty());
    assert!(gaps.iter().any(|g| g.contains("overlapping")), "{gaps:?}");
    let mut empty = original.clone();
    put64(&mut empty, eh + 0x24, 0);
    let (got, gaps) = analyze(&empty);
    assert_eq!(ranges(&got), [(0x544, 0x568)]);
    assert!(gaps.iter().any(|g| g.contains("empty FDE")));
    let mut wrap = original.clone();
    put64(&mut wrap, eh + 0x24, u64::MAX);
    assert!(!analyze(&wrap).0.iter().any(|b| b.start == 0x520));
}
#[test]
fn slice_base_shared_work_and_byte_limits_and_neighboring_slice_reads() {
    let original = fixture("compact-object.o");
    let base = 4096;
    let mut bytes = vec![0; base];
    bytes.extend(&original);
    bytes.extend(&original);
    let f = file(&bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let v = view(&mut reader, base as u64, original.len() as u64);
    let sibling = view(
        &mut reader,
        (base + original.len()) as u64,
        original.len() as u64,
    );
    let mut run = Run::new(CodeBudgets {
        fdes: 3,
        ..CodeBudgets::default()
    });
    assert_eq!(
        ranges(&unwind::read_bounds(&v, &mut reader, &mut run)),
        [
            (base as u64 + 0x188, base as u64 + 0x1ac),
            (base as u64 + 0x1ac, base as u64 + 0x1d0)
        ]
    );
    assert!(unwind::read_bounds(&sibling, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    assert!(run.into_gaps().iter().any(|g| g.contains("FDE limit 3")));
    let mut run = Run::new(CodeBudgets {
        relocations: 1,
        ..CodeBudgets::default()
    });
    assert!(unwind::read_bounds(&v, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    let mut bounded = view(&mut reader, base as u64, original.len() as u64);
    let s = bounded
        .sections
        .iter_mut()
        .find(|s| &s.name == b"__compact_unwind")
        .unwrap();
    s.relative = original.len() as u64 - 32..original.len() as u64 + 32;
    let before = reader.used();
    let mut run = Run::new(CodeBudgets::default());
    assert!(unwind::read_bounds(&bounded, &mut reader, &mut run).is_empty());
    assert_eq!(reader.used(), before);
    assert!(run
        .into_gaps()
        .iter()
        .any(|g| g.contains("outside the file")));
    // Metadata reads must charge before IO: compact entries fit, relocation bytes do not.
    let f = file(&original);
    let mut reader = Reader::new(f.as_file(), original.len() as u64, 396 + 64 + 15);
    let v = view(&mut reader, 0, original.len() as u64);
    let mut run = Run::new(CodeBudgets::default());
    assert!(unwind::read_bounds(&v, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    assert_eq!(reader.used(), 460);
    let mut too_big = v;
    too_big.sections[1].relative = 0..(16 << 20) + 32;
    let mut run = Run::new(CodeBudgets {
        fdes: usize::MAX,
        ..CodeBudgets::default()
    });
    let before = reader.used();
    assert!(unwind::read_bounds(&too_big, &mut reader, &mut run).is_empty());
    assert_eq!(reader.used(), before);
    assert!(run
        .into_gaps()
        .iter()
        .any(|g| g.contains("metadata byte limit")));
    // VM addresses stay unchanged when a linked image is placed inside a universal artifact.
    let linked = fixture("arm64-classic");
    let mut bytes = vec![0; base];
    bytes.extend(&linked);
    let f = file(&bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let v = view(&mut reader, base as u64, linked.len() as u64);
    assert_eq!(
        ranges(&unwind::read_bounds(
            &v,
            &mut reader,
            &mut Run::new(CodeBudgets::default())
        )),
        [(0x520, 0x544), (0x544, 0x568)]
    );
}
#[test]
fn representative_section_and_record_truncations_are_gaps() {
    for name in ["compact-object.o", "arm64-classic"] {
        let original = fixture(name);
        for section in if name.ends_with(".o") {
            vec![b"__compact_unwind".as_slice()]
        } else {
            vec![b"__eh_frame".as_slice(), b"__unwind_info".as_slice()]
        } {
            let s = section_header(&original, section);
            let size = u64::from_le_bytes(original[s + 40..s + 48].try_into().unwrap());
            let last_needed = if section == b"__unwind_info" {
                let u = section_at(&original, section);
                let index = u + get32(&original, u + 20) as usize;
                let page = u + get32(&original, index + 4) as usize;
                let offsets = get32(&original, page + 4);
                (page - u) as u64 + u64::from(offsets & 0xffff) + u64::from(offsets >> 16) * 4
            } else {
                size
            };
            for cut in [1, 3, 7, 15, last_needed - 1] {
                let mut b = original.clone();
                put64(&mut b, s + 40, cut);
                let (got, gaps) = analyze(&b);
                assert!(!gaps.is_empty(), "{name} {section:?} {cut}");
                assert!(got.len() < 2, "{name} {section:?} {cut}: {got:?}");
            }
        }
    }
}

#[test]
fn x86_linked_dwarf_mode_uses_its_own_architecture_encoding() {
    let (got, gaps) = analyze(&fixture("x86-classic"));
    assert_eq!(ranges(&got), [(0x520, 0x533), (0x540, 0x556)]);
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn linked_entry_limit_does_not_accept_a_partially_validated_table() {
    let bytes = fixture("arm64-classic");
    let f = file(&bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let v = view(&mut reader, 0, bytes.len() as u64);
    let mut run = Run::new(CodeBudgets {
        fdes: 3,
        ..CodeBudgets::default()
    });
    assert!(unwind::read_bounds(&v, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    assert!(run.into_gaps().iter().any(|g| g.contains("FDE limit 3")));
}

#[test]
fn regular_duplicates_compressed_overflow_and_image_base_overflow_are_gaps() {
    let mut bytes = regular(fixture("arm64-classic"));
    let u = section_at(&bytes, b"__unwind_info");
    let index = u + get32(&bytes, u + 20) as usize;
    let page = u + get32(&bytes, index + 4) as usize;
    let first = get32(&bytes, page + 8);
    put32(&mut bytes, page + 16, first);
    let (got, gaps) = analyze(&bytes);
    assert!(got.is_empty());
    assert!(gaps.iter().any(|g| g.contains("unsorted/duplicate")));
    let mut bytes = fixture("arm64-classic");
    put32(&mut bytes, index, 0xfffffff0);
    put32(&mut bytes, index + 12, u32::MAX);
    let (got, gaps) = analyze(&bytes);
    assert!(got.is_empty());
    assert!(
        gaps.iter()
            .any(|g| g.contains("compressed address overflow")),
        "{gaps:?}"
    );
    let bytes = fixture("arm64-classic");
    let f = file(&bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let mut v = view(&mut reader, 0, bytes.len() as u64);
    v.image_base = Some(u64::MAX - 0x100);
    let mut run = Run::new(CodeBudgets::default());
    assert!(unwind::read_bounds(&v, &mut reader, &mut run).is_empty());
    assert!(run
        .into_gaps()
        .iter()
        .any(|g| g.contains("function offset overflow")));
}

#[test]
fn unrelocated_object_fdes_translate_section_vms_and_agree_with_explicit_compact_extents() {
    let bytes = fixture("x86-object.o");
    let (got, gaps) = analyze(&bytes);
    assert_eq!(ranges(&got), [(0x1d8, 0x1eb), (0x1f8, 0x20e)]);
    assert!(gaps.is_empty(), "{gaps:?}");
    assert!(got.iter().all(|b| b.source == BoundsSource::EhFrameFde));
    let compact = section_at(&bytes, b"__compact_unwind");
    let mut duplicate = bytes.clone();
    put64(&mut duplicate, compact + 32, 0);
    put32(&mut duplicate, compact + 40, 0x13);
    let (duplicate_bounds, gaps) = analyze(&duplicate);
    assert_eq!(ranges(&duplicate_bounds), [(0x1f8, 0x20e)]);
    assert!(gaps.iter().any(|g| g.contains("overlapping")));
    let mut changed = bytes.clone();
    put32(&mut changed, compact + 8, 0x14);
    let (got, gaps) = analyze(&changed);
    assert_eq!(ranges(&got), [(0x1f8, 0x20e)]);
    assert!(gaps.iter().any(|g| g.contains("overlapping")));
    let base = 4096;
    let mut fat = vec![0; base];
    fat.extend(bytes);
    let f = file(&fat);
    let mut reader = Reader::new(f.as_file(), fat.len() as u64, 1 << 20);
    let v = view(&mut reader, base as u64, (fat.len() - base) as u64);
    let got = unwind::read_bounds(&v, &mut reader, &mut Run::new(CodeBudgets::default()));
    assert_eq!(ranges(&got), [(0x11d8, 0x11eb), (0x11f8, 0x120e)]);
}

fn embedded_cie_fixture() -> Vec<u8> {
    let mut bytes = fixture("arm64-classic");
    let eh = section_at(&bytes, b"__eh_frame");
    // Copy a well-formed CIE into the first FDE's instruction bytes. The actual
    // sequential record boundaries remain CIE0, FDE0x14, FDE0x48.
    let cie = bytes[eh..eh + 0x14].to_vec();
    bytes[eh + 0x30..eh + 0x44].copy_from_slice(&cie);
    bytes
}

#[test]
fn walked_cie_boundary_control_keeps_both_exact_fdes() {
    let bytes = embedded_cie_fixture();
    // Both FDE pointers still name the actual CIE record at offset0.
    let (bounds, gaps) = analyze(&bytes);
    assert_eq!(ranges(&bounds), [(0x520, 0x544), (0x544, 0x568)]);
    assert!(gaps.is_empty(), "{gaps:?}");
}

#[test]
fn embedded_cie_inside_another_fde_is_rejected_without_changing_legacy_elf_lookup() {
    let mut bytes = embedded_cie_fixture();
    let eh = section_at(&bytes, b"__eh_frame");
    // The second FDE now points backwards from0x4c to interior pseudo-CIE0x30.
    put32(&mut bytes, eh + 0x4c, 0x1c);
    let (bounds, gaps) = analyze(&bytes);
    assert_eq!(ranges(&bounds), [(0x520, 0x544)]);
    assert!(
        gaps.iter().any(|g| g.contains("CIE") && g.contains("0x30")),
        "{gaps:?}"
    );

    // Compatibility control: the existing ELF entry point retains its historical
    // permissive CIE lookup; the new record-boundary rule is Mach-O-only.
    let header = section_header(&bytes, b"__eh_frame");
    let size = u64::from_le_bytes(bytes[header + 40..header + 48].try_into().unwrap()) as usize;
    let vm = u64::from_le_bytes(bytes[header + 32..header + 40].try_into().unwrap());
    let mut run = Run::new(CodeBudgets::default());
    assert_eq!(
        fde::parse(&bytes[eh..eh + size], vm, &mut run),
        [(0x520, 0x544), (0x544, 0x568)]
    );
    assert!(run.into_gaps().is_empty());
}

#[test]
fn walked_cies_charge_the_exact_record_entry_budget_without_changing_legacy_fde_limits() {
    let bytes = fixture("arm64-classic");
    let header = section_header(&bytes, b"__eh_frame");
    let eh = section_at(&bytes, b"__eh_frame");
    let size = u64::from_le_bytes(bytes[header + 40..header + 48].try_into().unwrap()) as usize;
    let vm = u64::from_le_bytes(bytes[header + 32..header + 40].try_into().unwrap());
    for (limit, expected, stopped) in [(1, 0, true), (2, 1, true), (3, 2, false)] {
        let mut run = Run::new(CodeBudgets {
            fdes: limit,
            ..CodeBudgets::default()
        });
        assert_eq!(
            fde::parse_records(&bytes[eh..eh + size], vm, &mut run).len(),
            expected
        );
        assert_eq!(run.stopped(), stopped);
    }
    let mut legacy = Run::new(CodeBudgets {
        fdes: 2,
        ..CodeBudgets::default()
    });
    assert_eq!(fde::parse(&bytes[eh..eh + size], vm, &mut legacy).len(), 2);
    assert!(!legacy.stopped());
    assert!(legacy.into_gaps().is_empty());
}
