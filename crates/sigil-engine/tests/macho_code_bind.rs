//! Private binding adapter, exercised on the same production reader and aggregate counters.
#[allow(dead_code)]
#[path = "../src/code/macho/bind.rs"]
mod bind;
#[allow(dead_code)]
#[path = "../src/code/macho/image.rs"]
mod image;
#[allow(dead_code)]
#[path = "../src/code/reader.rs"]
pub(crate) mod reader;
#[allow(dead_code)]
#[path = "../src/code/run.rs"]
mod run;
use reader::{Reader, SliceWindow};
use run::{Run, Work};
use sigil_engine::code::{CodeBudgets, CodeOutcome};
#[allow(unused_imports)]
mod code {
    pub(crate) use crate::{reader, CodeBudgets, Run, Work};
}
use sigil_engine::binary::{parse_artifact, BinaryBudgets};
use sigil_model::{Arch, ArtifactId, ContainerFacts, MachOLibrary, Sha256Hex, SliceId};
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
fn view(reader: &mut Reader<'_>, bytes: &[u8], base: u64, len: u64) -> image::MachCodeView {
    let arch = if get32(bytes, base as usize + 4) == 0x01000007 {
        Arch::X86_64
    } else {
        Arch::Aarch64
    };
    let mut v = image::build(
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
    .unwrap();
    let f = file(bytes);
    let p = parse_artifact(
        f.as_file(),
        bytes.len() as u64,
        &Sha256Hex::new("1".repeat(64)).unwrap(),
        &bytes[..4],
        BinaryBudgets::default(),
        None,
    )
    .unwrap();
    let s = p.slices.iter().find(|s| s.offset == base).unwrap();
    let Some(ContainerFacts::MachO(facts)) = &s.container else {
        panic!()
    };
    v.imports = facts.imports.clone();
    v
}
fn analyze(
    bytes: &[u8],
) -> (
    std::collections::BTreeMap<u64, bind::MachImportWitness>,
    Vec<String>,
) {
    let f = file(bytes);
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    let v = view(&mut reader, bytes, 0, bytes.len() as u64);
    let mut run = Run::new(CodeBudgets::default());
    let got = bind::read_bindings(&v, &mut reader, &mut run);
    (got, run.into_gaps())
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
#[test]
fn real_classic_chained_and_same_name_different_dylibs_have_exact_slot_witnesses() {
    for (name, slot) in [
        ("arm64-classic", 0x8000),
        ("x86-classic", 0x3000),
        ("arm64-chained", 0x4000),
        ("x86-chained", 0x2000),
        ("duplicate-name-dylibs", 0x8000),
    ] {
        let (got, gaps) = analyze(&fixture(name));
        assert!(gaps.is_empty(), "{name}: {gaps:?}");
        let w = got.get(&slot).unwrap_or_else(|| panic!("{name}: {got:?}"));
        assert_eq!(w.symbol.as_bytes(), b"_connect");
        assert!(!w.weak);
        assert!(
            matches!(&w.library,MachOLibrary::Dylib{ordinal:1,name:Some(n)} if n.as_bytes()==b"/usr/lib/libSystem.B.dylib")
        );
        if name == "duplicate-name-dylibs" {
            let w = got.get(&(slot + 8)).unwrap();
            assert_eq!(w.symbol.as_bytes(), b"_connect");
            assert!(
                matches!(&w.library,MachOLibrary::Dylib{ordinal:2,name:Some(n)} if n.as_bytes()==b"/sigil/libfoo.dylib")
            );
        }
    }
}
fn command(b: &[u8], kind: u32) -> usize {
    let mut at = 32;
    for _ in 0..get32(b, 16) {
        if get32(b, at) == kind {
            return at;
        }
        at += get32(b, at + 4) as usize;
    }
    panic!("missing command {kind:x}")
}
fn stream_body() -> Vec<u8> {
    let mut s = vec![0x11, 0x40];
    s.extend_from_slice(b"_connect\0");
    s.extend_from_slice(&[0x51, 0x72, 0, 0x90, 0]);
    s
}
fn with_stream(s: &[u8], lazy: bool) -> Vec<u8> {
    let mut b = fixture("arm64-classic");
    let c = command(&b, 0x80000022);
    put32(&mut b, c + 20, 0);
    put32(&mut b, c + 36, 0);
    // Opcode tests isolate stream semantics; indirect corroboration is exercised separately.
    let mut at = 32;
    for _ in 0..get32(&b, 16) {
        if get32(&b, at) == 0x19 {
            for j in 0..get32(&b, at + 64) as usize {
                let sec = at + 72 + j * 80;
                if matches!(get32(&b, sec + 64) & 0xff, 6 | 7 | 8 | 0x10) {
                    put32(&mut b, sec + 64, 0);
                }
            }
        }
        at += get32(&b, at + 4) as usize;
    }
    let off = b.len() as u32;
    let pair = if lazy { 32 } else { 16 };
    put32(&mut b, c + pair, off);
    put32(&mut b, c + pair + 4, s.len() as u32);
    b.extend_from_slice(s);
    b
}
#[test]
fn classic_steps_bind_only_actual_slots_and_duplicate_claims_stay_rejected() {
    for op in [vec![0x90], vec![0xa0, 0], vec![0xb0], vec![0xc0, 1, 0]] {
        let mut s = stream_body();
        s.splice(s.len() - 2..s.len() - 1, op);
        let (g, gaps) = analyze(&with_stream(&s, false));
        assert_eq!(g.keys().copied().collect::<Vec<_>>(), [0x8000]);
        assert!(gaps.is_empty(), "{gaps:?}");
    }
    let mut s = stream_body();
    s.splice(s.len() - 2..s.len() - 1, [0xc0, 2, 0]);
    let (g, gaps) = analyze(&with_stream(&s, false));
    assert_eq!(g.len(), 2);
    assert!(gaps.is_empty());
    let mut s = stream_body();
    s.pop();
    s.extend_from_slice(&[0x72, 0, 0x90, 0x72, 0, 0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&s, false));
    assert!(g.is_empty());
    assert!(gaps.iter().any(|s| s.contains("duplicate")));
    let mut s = stream_body();
    s.splice(s.len() - 2..s.len() - 1, [0xc0, 0, 0]);
    assert!(analyze(&with_stream(&s, false)).0.is_empty());
}
#[test]
fn malformed_classic_streams_never_keep_a_partial_named_map() {
    let good = stream_body();
    let prefix = &good[..good.len() - 2];
    let tails: Vec<Vec<u8>> = vec![
        vec![0x60, 0x80],
        vec![
            0x60, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2,
        ],
        vec![0x70, 0x80],
        vec![
            0x70, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2,
        ],
        vec![0x60, 1, 0x90, 0],
        vec![0x52, 0x90, 0],
        vec![0x7f, 0, 0x90, 0],
        vec![
            0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0x90, 0,
        ],
        vec![0x90, 0xf0],
        vec![0xd0, 0, 0x90, 0],
        vec![0x90],
    ];
    for tail in tails {
        let mut s = prefix.to_vec();
        s.extend(tail);
        let (g, gaps) = analyze(&with_stream(&s, false));
        assert!(g.is_empty(), "{s:x?}: {g:?}");
        assert!(!gaps.is_empty(), "{s:x?}");
    }
    for s in [
        vec![0x90, 0],
        vec![0x11, 0x40, b'x', 0, 0x90, 0],
        vec![0x40, b'x', 0],
    ] {
        let (g, gaps) = analyze(&with_stream(&s, true));
        assert!(g.is_empty());
        assert!(!gaps.is_empty());
    }
    for ordinal in [
        vec![0x1f],
        vec![0x3c],
        vec![0x20, 0xff, 0xff, 0xff, 0xff, 0xf],
    ] {
        let mut s = good.clone();
        s.splice(..1, ordinal);
        let (g, gaps) = analyze(&with_stream(&s, false));
        assert!(g.is_empty());
        assert!(!gaps.is_empty());
    }
    let mut s = vec![0x11, 0x40];
    s.extend(std::iter::repeat_n(b'x', 65_537));
    s.extend_from_slice(&[0, 0x72, 0, 0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&s, false));
    assert!(g.is_empty());
    assert!(!gaps.is_empty());
}
#[test]
fn special_and_weak_ordinals_preserve_witnesses_without_policy_inference() {
    for (opcode, expected) in [
        (0x30, MachOLibrary::SelfImage),
        (0x3f, MachOLibrary::MainExecutable),
        (0x3e, MachOLibrary::FlatLookup),
        (0x3d, MachOLibrary::WeakLookup),
    ] {
        let mut s = stream_body();
        s[0] = opcode;
        let (g, gaps) = analyze(&with_stream(&s, false));
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(g[&0x8000].library, expected);
    }
    let mut s = stream_body();
    s[1] = 0x41;
    let (g, gaps) = analyze(&with_stream(&s, false));
    assert!(gaps.is_empty());
    assert!(g[&0x8000].weak);
}
fn chained_blob(b: &[u8]) -> usize {
    get32(b, command(b, 0x80000034) + 8) as usize
}
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
#[test]
fn malformed_chains_headers_starts_formats_ordinals_and_addends_are_transactional() {
    let original = fixture("arm64-chained");
    let blob = chained_blob(&original);
    let starts = blob + get32(&original, blob + 4) as usize;
    let seg = starts + get32(&original, starts + 8) as usize;
    let mut cases = vec![];
    for (off, value) in [
        (0, 1),
        (4, 0xfffffff0),
        (8, 0xfffffff0),
        (12, 0xfffffff0),
        (16, 0xffffffff),
        (20, 4),
        (24, 1),
    ] {
        let mut b = original.clone();
        put32(&mut b, blob + off, value);
        cases.push(b);
    }
    for format in [1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 0xffff] {
        let mut b = original.clone();
        put16(&mut b, seg + 6, format);
        cases.push(b);
    }
    for (off, value) in [
        (4, 0),
        (4, 0x2000),
        (20, 2),
        (22, 0x8000),
        (22, 0x3ffc),
        (22, 1),
    ] {
        let mut b = original.clone();
        put16(&mut b, seg + off, value);
        cases.push(b);
    }
    for raw in [
        (1u64 << 63) | 1,
        (1u64 << 63) | (1 << 24),
        (1u64 << 63) | (1 << 32),
        (1u64 << 63) | (1 << 51),
        (1u64 << 63) | (0xfff << 51),
        1 << 44,
    ] {
        let mut b = original.clone();
        put64(&mut b, 0x4000, raw);
        cases.push(b);
    }
    let mut b = original.clone();
    put64(&mut b, seg + 8, 0x8000);
    cases.push(b);
    for b in cases {
        let (g, gaps) = analyze(&b);
        assert!(g.is_empty(), "{g:?}");
        assert!(!gaps.is_empty());
    }
}
#[test]
fn format_64_offset_uses_four_byte_stride_and_keeps_rebase_distinct() {
    let mut b = fixture("arm64-chained");
    let blob = chained_blob(&b);
    let starts = blob + get32(&b, blob + 4) as usize;
    let seg = starts + get32(&b, starts + 8) as usize;
    put16(&mut b, seg + 6, 6);
    // Rebase then bind eight bytes later: next=2, not the arm64e eight-byte stride.
    put64(&mut b, 0x4000, 2u64 << 51);
    put64(&mut b, 0x4008, 1u64 << 63);
    let (g, gaps) = analyze(&b);
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(g.keys().copied().collect::<Vec<_>>(), [0x4008]);
}
#[test]
fn indirect_table_corroboration_rejects_wrong_name_library_weak_and_extents() {
    let original = fixture("duplicate-name-dylibs");
    let sym = command(&original, 2);
    let dysym = command(&original, 0xb);
    let syms = get32(&original, sym + 8) as usize;
    let ind = get32(&original, dysym + 56) as usize;
    // Pointer entries use symbol indexes 3,4 (read from the section's reserved1).
    let mut ptr = None;
    let mut at = 32;
    for _ in 0..get32(&original, 16) {
        if get32(&original, at) == 0x19 {
            for j in 0..get32(&original, at + 64) as usize {
                let sec = at + 72 + j * 80;
                if get32(&original, sec + 64) & 0xff == 7 {
                    ptr = Some(sec);
                }
            }
        }
        at += get32(&original, at + 4) as usize;
    }
    let sec = ptr.unwrap();
    let first = get32(&original, sec + 68) as usize;
    let idx = get32(&original, ind + first * 4) as usize;
    for desc in [0x240, 0x200] {
        let mut b = original.clone();
        put16(&mut b, syms + idx * 16 + 6, desc);
        let (g, gaps) = analyze(&b);
        assert!(!g.contains_key(&0x8000));
        assert!(!gaps.is_empty());
    }
    for (off, n) in [
        (sec + 68, u32::MAX),
        (sec + 72, 1),
        (ind + first * 4, u32::MAX),
        (dysym + 60, 0),
    ] {
        let mut b = original.clone();
        put32(&mut b, off, n);
        let (g, gaps) = analyze(&b);
        assert!(g.is_empty());
        assert!(!gaps.is_empty());
    }
    let mut b = original.clone();
    put32(&mut b, ind + first * 4, 0x80000000);
    let (g, gaps) = analyze(&b);
    assert!(!g.contains_key(&0x8000));
    assert!(!gaps.is_empty());
}
#[test]
fn inventory_is_exact_and_required_including_raw_name_library_and_weak() {
    let b = fixture("duplicate-name-dylibs");
    let f = file(&b);
    let mut reader = Reader::new(f.as_file(), b.len() as u64, 1 << 20);
    let mut v = view(&mut reader, &b, 0, b.len() as u64);
    v.imports
        .retain(|i| matches!(i.library, MachOLibrary::Dylib { ordinal: 1, .. }));
    let mut run = Run::new(CodeBudgets::default());
    let g = bind::read_bindings(&v, &mut reader, &mut run);
    assert!(g.contains_key(&0x8000));
    assert!(!g.contains_key(&0x8008));
    assert!(!run.into_gaps().is_empty());
    v.imports.clear();
    let mut run = Run::new(CodeBudgets::default());
    assert!(bind::read_bindings(&v, &mut reader, &mut run).is_empty());
}
#[test]
fn sibling_slice_windows_and_actual_aggregate_limits_are_shared() {
    let b = fixture("universal");
    let f = file(&b);
    let mut reader = Reader::new(f.as_file(), b.len() as u64, 1 << 20);
    let x = view(&mut reader, &b, 4096, 16624);
    let a = view(&mut reader, &b, 32768, 33008);
    let mut run = Run::new(CodeBudgets {
        slots: 2,
        ..CodeBudgets::default()
    });
    let g = bind::read_bindings(&x, &mut reader, &mut run);
    assert!(g.contains_key(&0x3000));
    assert!(bind::read_bindings(&a, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    let mut run = Run::new(CodeBudgets::default());
    let g = bind::read_bindings(&a, &mut reader, &mut run);
    assert_eq!(g[&0x4000].symbol.as_bytes(), b"_connect");
    let mut broken = b.clone();
    let command = 32768 + command(&b[32768..], 0x80000034);
    put32(&mut broken, command + 8, 33008);
    put32(&mut broken, command + 12, 8);
    let f = file(&broken);
    let mut reader = Reader::new(f.as_file(), broken.len() as u64, 1 << 20);
    let a = view(&mut reader, &broken, 32768, 33008);
    let mut run = Run::new(CodeBudgets::default());
    assert!(bind::read_bindings(&a, &mut reader, &mut run).is_empty());
    assert!(run.into_gaps().iter().any(|g| g.contains("outside")));
}
fn import_format(mut b: Vec<u8>, format: u32, addend: i64) -> Vec<u8> {
    let c = command(&b, 0x80000034);
    let at = chained_blob(&b);
    let len = get32(&b, c + 12) as usize;
    let imp = get32(&b, at + 8) as usize;
    let sym = get32(&b, at + 12) as usize;
    let raw = get32(&b, at + imp);
    let mut blob = b[at..at + imp].to_vec();
    if format == 2 {
        blob.extend_from_slice(&raw.to_le_bytes());
        blob.extend_from_slice(&(addend as i32).to_le_bytes());
    } else {
        let raw64 =
            u64::from(raw & 0xff) | (u64::from((raw >> 8) & 1) << 16) | (u64::from(raw >> 9) << 32);
        blob.extend_from_slice(&raw64.to_le_bytes());
        blob.extend_from_slice(&addend.to_le_bytes());
    }
    let names = blob.len() as u32;
    put32(&mut blob, 12, names);
    put32(&mut blob, 20, format);
    blob.extend_from_slice(&b[at + sym..at + len]);
    let off = b.len() as u32;
    put32(&mut b, c + 8, off);
    put32(&mut b, c + 12, blob.len() as u32);
    b.extend(blob);
    b
}
#[test]
fn chained_import_addend_formats_are_supported_with_exact_zero_total() {
    for format in [2, 3] {
        let b = import_format(fixture("arm64-chained"), format, 0);
        let (g, gaps) = analyze(&b);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(g[&0x4000].symbol.as_bytes(), b"_connect");
        let b = import_format(fixture("arm64-chained"), format, 1);
        let (g, gaps) = analyze(&b);
        assert!(g.is_empty());
        assert!(gaps.iter().any(|g| g.contains("addend")));
    }
    let mut b = import_format(fixture("arm64-chained"), 3, 0);
    let at = chained_blob(&b);
    let imp = at + get32(&b, at + 8) as usize;
    b[imp + 2] |= 2;
    assert!(analyze(&b).0.is_empty());
}
#[test]
fn partial_overlapping_pointer_claims_and_lazy_reuse_are_distinct() {
    let mut s = stream_body();
    s.pop();
    s.extend_from_slice(&[0x72, 4, 0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&s, false));
    assert!(g.is_empty());
    assert!(gaps.iter().any(|g| g.contains("overlapping")));
    let mut s = stream_body();
    s.extend_from_slice(&[0x72, 8, 0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&s, true));
    assert_eq!(g.len(), 2);
    assert!(gaps.is_empty(), "{gaps:?}");
}
#[test]
fn shared_entry_name_and_read_limits_refuse_before_retaining_witnesses() {
    let b = fixture("arm64-classic");
    let f = file(&b);
    for budget in [
        CodeBudgets {
            references: 0,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            relocations: 0,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            slots: 0,
            ..CodeBudgets::default()
        },
        CodeBudgets {
            name_bytes: 0,
            ..CodeBudgets::default()
        },
    ] {
        let mut reader = Reader::new(f.as_file(), b.len() as u64, 1 << 20);
        let v = view(&mut reader, &b, 0, b.len() as u64);
        let mut run = Run::new(budget);
        assert!(bind::read_bindings(&v, &mut reader, &mut run).is_empty());
        assert!(run.stopped());
    }
    let mut reader = Reader::new(f.as_file(), b.len() as u64, 32 + get32(&b, 20) as u64 + 16);
    let v = view(&mut reader, &b, 0, b.len() as u64);
    let mut run = Run::new(CodeBudgets::default());
    assert!(bind::read_bindings(&v, &mut reader, &mut run).is_empty());
    assert!(run.stopped());
    assert!(run
        .into_gaps()
        .iter()
        .any(|g| g.contains("binary_code_bytes")));
}
#[test]
fn lazy_done_preserves_segment_offset_name_library_and_weak_state() {
    let mut s = stream_body();
    s[1] = 0x41;
    s.extend_from_slice(&[0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&s, true));
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(g.keys().copied().collect::<Vec<_>>(), [0x8000, 0x8008]);
    assert!(g
        .values()
        .all(|w| w.weak && w.symbol.as_bytes() == b"_connect"));
    assert_eq!(g[&0x8000].library, g[&0x8008].library);
}
#[test]
fn lazy_done_preserves_nonzero_addend_and_explicit_unsupported_type() {
    for state in [vec![0x60, 1], vec![0x52]] {
        let mut s = stream_body();
        s.pop();
        s.extend(state);
        s.extend_from_slice(&[0, 0x72, 8, 0x90, 0]);
        let (g, gaps) = analyze(&with_stream(&s, true));
        assert!(g.is_empty(), "{s:x?}: {g:?}");
        assert!(
            gaps.iter().any(|g| g.contains("type or nonzero addend")),
            "{gaps:?}"
        );
    }
}
#[test]
fn classic_pointer_type_and_library_ordinal_must_be_explicit() {
    // This stream deliberately has no SET_TYPE, even after the common helper is corrected.
    let mut missing_type = vec![0x11, 0x40];
    missing_type.extend_from_slice(b"_connect\0");
    missing_type.extend_from_slice(&[0x72, 0, 0x90, 0]);
    let (g, gaps) = analyze(&with_stream(&missing_type, false));
    assert!(g.is_empty());
    assert!(!gaps.is_empty());
    // Lazy type alone is implicit. An omitted ordinal is never explicit SelfImage.
    let (g, gaps) = analyze(&with_stream(&missing_type, true));
    assert!(gaps.is_empty(), "{gaps:?}");
    assert!(g.contains_key(&0x8000));
    for lazy in [false, true] {
        let mut s = missing_type[1..].to_vec();
        s.insert(s.len() - 4, 0x51);
        let (g, gaps) = analyze(&with_stream(&s, lazy));
        assert!(g.is_empty(), "{lazy}: {g:?}");
        assert!(
            gaps.iter().any(|g| g.contains("without library ordinal")),
            "{gaps:?}"
        );
        for explicit_zero in [0x10, 0x30] {
            let mut s = s.clone();
            s.insert(0, explicit_zero);
            let (g, gaps) = analyze(&with_stream(&s, lazy));
            assert!(gaps.is_empty(), "{gaps:?}");
            assert_eq!(g[&0x8000].library, MachOLibrary::SelfImage);
        }
    }
}
