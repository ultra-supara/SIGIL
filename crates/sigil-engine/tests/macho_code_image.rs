//! Same-fd Mach-O image and descriptor boundaries; no decoder dispatch.
mod common;
use sha2::{Digest, Sha256};
use sigil_engine::binary::{parse_artifact, BinaryBudgets};
use sigil_engine::code::CodeBudgets;
use sigil_model::{CodeSliceInventory, ContainerFacts, Sha256Hex};

fn parse(bytes: &[u8], code: bool, parse_bytes: u64) -> sigil_engine::binary::ParsedArtifact {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    parse_artifact(
        f.as_file(),
        bytes.len() as u64,
        &Sha256Hex::new(format!("{:x}", Sha256::digest(bytes))).unwrap(),
        &bytes[..4],
        BinaryBudgets {
            code: code.then(CodeBudgets::default),
            parse_bytes,
            ..BinaryBudgets::default()
        },
        None,
    )
    .unwrap()
}

#[test]
fn marked_inner_byte_order_is_observed_and_legacy_bytes_stay_absent() {
    use common::macho::*;
    let bytes = fat32(&[
        (thin(true, false, AARCH64, 0, &[]), AARCH64, 0),
        (thin(true, true, X86_64, 3, &[]), X86_64, 3),
    ]);
    for code in [false, true] {
        let parsed = parse(&bytes, code, 64 << 20);
        for (i, little) in [true, false].into_iter().enumerate() {
            let Some(ContainerFacts::MachO(m)) = &parsed.slices[i].container else {
                panic!()
            };
            assert_eq!(m.little_endian, code.then_some(little));
        }
    }
}

#[test]
fn table_budget_exhaustion_is_partial_inventory_even_with_a_hashable_sibling() {
    use common::macho::*;
    let bytes = fat32(&[
        (thin(true, false, AARCH64, 0, &[]), AARCH64, 0),
        (thin(true, false, X86_64, 3, &[]), X86_64, 3),
    ]);
    assert!(matches!(parse(&bytes, true, 8).code_inventory,
        CodeSliceInventory::Partial { missing } if !missing.is_empty()));
}

// Compile the production private metadata reader, as the decoder adapter tests do.
#[allow(dead_code)]
#[path = "../src/code/reader.rs"]
pub(crate) mod reader;
mod code {
    pub(crate) use crate::reader;
}
#[allow(dead_code)]
#[path = "../src/code/macho/image.rs"]
mod image;

use image::Error;
use reader::{Reader, SliceWindow};
use sigil_model::{Arch, ArtifactId, SliceId};
fn view(bytes: &[u8], base: u64, len: u64, arch: Arch) -> Result<image::MachCodeView, Error> {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 1 << 20);
    image::build(
        &mut reader,
        id(arch, base),
        SliceWindow { base, len },
        arch,
        None,
    )
}
fn id(arch: Arch, base: u64) -> SliceId {
    SliceId::from_parts(
        &ArtifactId::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        arch,
        base,
    )
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn synthetic(is_object: bool, protection: u32, flags: u32) -> Vec<u8> {
    use common::macho::*;
    let mut seg = command(0x19, 152, false);
    seg[8..14].copy_from_slice(b"__TEXT");
    put64(&mut seg, 24, 0x1000);
    put64(&mut seg, 32, 0x2000);
    put64(&mut seg, 40, 0);
    put64(&mut seg, 48, 0x300);
    put32(&mut seg, 56, 7);
    put32(&mut seg, 60, protection);
    put32(&mut seg, 64, 1);
    seg[72..78].copy_from_slice(b"__text");
    seg[88..94].copy_from_slice(b"__TEXT");
    put64(&mut seg, 104, 0x1200);
    put64(&mut seg, 112, 16);
    put32(&mut seg, 120, 0x200);
    put32(&mut seg, 124, 2);
    put32(&mut seg, 136, flags);
    let mut bytes = thin(true, false, AARCH64, 0, &[seg]);
    put32(&mut bytes, 12, if is_object { 1 } else { 2 });
    bytes.resize(0x300, 0);
    bytes[0x200..0x210].copy_from_slice(b"hello\0abcdefghij");
    bytes
}
#[test]
fn object_and_linked_addresses_and_cross_slice_payload_reads() {
    use std::io::Write;
    for object in [false, true] {
        let thin = synthetic(object, 5, 0x8000_0000);
        let mut bytes = vec![0x55; 0x400];
        bytes.extend_from_slice(&thin);
        bytes.extend_from_slice(&thin);
        let v = view(&bytes, 0x400, thin.len() as u64, Arch::Aarch64).unwrap();
        let address = if object { 0x600 } else { 0x1200 };
        assert_eq!(v.executable[0].address, address..address + 16);
        assert_eq!(v.executable[0].relative, 0x200..0x210);
        assert_eq!(v.executable[0].file, 0x600..0x610);
        assert!(v.code_at(address + 12, 8).is_err());
        assert!(v.code_at(address + 1, 4).is_err());
        assert!(v.code_at(address, 2).is_err());
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&bytes).unwrap();
        let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 100);
        assert_eq!(v.read_code(&mut reader, address, 4).unwrap(), b"hell");
        assert_eq!(v.string(&mut reader, address).unwrap(), None);
        assert!(matches!(
            view(&bytes, 0x400, 32, Arch::Aarch64),
            Err(Error::Read(reader::Refusal::OutsideFile))
        ));
    }
}
#[test]
fn strings_require_readable_nonwritable_nonexecutable_segments() {
    use std::io::Write;
    for object in [false, true] {
        for protection in [1, 5, 3] {
            for flags in [0, 0x8000_0000] {
                let bytes = synthetic(object, protection, flags);
                let v = view(&bytes, 0, bytes.len() as u64, Arch::Aarch64).unwrap();
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(&bytes).unwrap();
                let mut reader = Reader::new(file.as_file(), bytes.len() as u64, 100);
                let address = if object { 0x200 } else { 0x1200 };
                assert_eq!(
                    v.string(&mut reader, address).unwrap(),
                    (protection == 1).then(|| b"hello".to_vec()),
                    "object={object}, protection={protection}, flags={flags:#x}"
                );
                assert_eq!(reader.used(), if protection == 1 { 16 } else { 0 });
                assert_eq!(v.executable.is_empty(), protection != 5 || flags == 0);
            }
        }
    }
}
#[test]
fn permissions_instruction_flags_and_zero_fill_do_not_supply_code_or_strings() {
    assert!(
        view(&synthetic(false, 1, 0x8000_0000), 0, 0x300, Arch::Aarch64)
            .unwrap()
            .executable
            .is_empty()
    );
    assert!(view(&synthetic(false, 5, 0), 0, 0x300, Arch::Aarch64)
        .unwrap()
        .executable
        .is_empty());
    assert!(
        view(&synthetic(false, 7, 0x8000_0000), 0, 0x300, Arch::Aarch64)
            .unwrap()
            .readonly
            .is_empty()
    );
    let v = view(&synthetic(false, 5, 0x8000_0000), 0, 0x300, Arch::Aarch64).unwrap();
    assert!(v.code_at(0x2000, 4).is_err(), "VM-only tail is not code");
}
#[test]
fn section_tables_conflicting_mappings_and_data_in_code_fail_closed() {
    let good = synthetic(false, 5, 0x8000_0000);
    for (at, value) in [(32 + 64, 2), (32 + 120, 0x204), (32 + 124, 64)] {
        let mut bad = good.clone();
        put32(&mut bad, at, value);
        assert!(view(&bad, 0, bad.len() as u64, Arch::Aarch64).is_err());
    }
    for at in [32 + 32, 32 + 68] {
        let mut bad = good.clone();
        if at == 32 + 32 {
            put64(&mut bad, at, 0);
        } else {
            put32(&mut bad, at, 1);
        }
        assert!(view(&bad, 0, bad.len() as u64, Arch::Aarch64).is_err());
    }
    let mut bad = good.clone();
    let segment = bad[32..184].to_vec();
    bad.splice(184..184, segment);
    put32(&mut bad, 16, 2);
    put32(&mut bad, 20, 304);
    assert_eq!(
        view(&bad, 0, bad.len() as u64, Arch::Aarch64).unwrap_err(),
        Error::Invalid("overlapping segments")
    );
    let mut data = good.clone();
    let mut cmd = common::macho::command(0x29, 16, false);
    put32(&mut cmd, 8, 0x280);
    put32(&mut cmd, 12, 8);
    data[184..200].copy_from_slice(&cmd);
    put32(&mut data, 16, 2);
    put32(&mut data, 20, 168);
    put32(&mut data, 0x280, 0x204);
    data[0x284..0x286].copy_from_slice(&4u16.to_le_bytes());
    let v = view(&data, 0, data.len() as u64, Arch::Aarch64).unwrap();
    assert!(v.code_at(0x1200, 4).is_ok());
    assert_eq!(
        v.code_at(0x1204, 4).unwrap_err(),
        Error::Invalid("candidate intersects data-in-code")
    );
    put32(&mut data, 192, 0x2fc);
    put32(&mut data, 196, 8);
    assert_eq!(
        view(&data, 0, data.len() as u64, Arch::Aarch64).unwrap_err(),
        Error::Read(reader::Refusal::OutsideFile)
    );
}

#[test]
fn thin_and_universal_fixture_hashes_and_mappings_agree() {
    let fixture = |name: &str| {
        std::fs::read(format!(
            "{}/tests/fixtures/code-macho/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    };
    for name in [
        "arm64-classic",
        "arm64-chained",
        "x86-classic",
        "arm64-object.o",
        "x86-object.o",
        "universal",
    ] {
        let bytes = fixture(name);
        let p = parse(&bytes, true, 64 << 20);
        assert!(
            matches!(p.code_inventory, CodeSliceInventory::Complete),
            "{name}"
        );
        for s in p.slices {
            let inner = &bytes[s.offset as usize..(s.offset + s.size) as usize];
            if name == "universal" {
                let source = if s.arch == Arch::Aarch64 {
                    "arm64-chained"
                } else {
                    "x86-classic"
                };
                assert_eq!(inner, fixture(source));
            }
            assert_eq!(s.sha256.as_str(), format!("{:x}", Sha256::digest(inner)));
            let v =
                view(&bytes, s.offset, s.size, s.arch).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert!(!v.executable.is_empty(), "{name}");
            let standalone = view(inner, 0, s.size, s.arch).unwrap();
            for (a, b) in v.executable.iter().zip(&standalone.executable) {
                assert_eq!(a.relative, b.relative);
                assert_eq!(a.file.start, b.file.start + s.offset);
                assert_eq!(
                    a.address.start,
                    b.address.start + if v.file_type == 1 { s.offset } else { 0 }
                );
            }
        }
    }
}

#[test]
fn invalid_and_unparsed_descriptors_keep_independent_sibling_and_typed_inventory() {
    use common::macho::*;
    let arm = synthetic(false, 5, 0x8000_0000);
    let x86 = thin(true, false, X86_64, 3, &[]);
    let good = fat32(&[(arm, AARCH64, 0), (x86.clone(), X86_64, 3)]);
    for (field, value) in [(8, u32::MAX), (12, 0), (16, 64), (16, 31)] {
        let mut bytes = good.clone();
        bytes[28 + field..32 + field].copy_from_slice(&value.to_be_bytes());
        let p = parse(&bytes, true, 64 << 20);
        assert_eq!(p.slices.len(), 1);
        assert_eq!(p.slices[0].arch, Arch::Aarch64);
        assert!(
            matches!(p.code_inventory, CodeSliceInventory::Partial{ ref missing } if !missing.is_empty())
        );
        assert!(
            !view(&bytes, p.slices[0].offset, p.slices[0].size, Arch::Aarch64)
                .unwrap()
                .executable
                .is_empty()
        );
    }
    let unparsed = fat32(&[
        (synthetic(false, 5, 0x8000_0000), AARCH64, 0),
        (x86[..8].to_vec(), X86_64, 3),
    ]);
    let p = parse(&unparsed, true, 64 << 20);
    assert_eq!(p.slices.len(), 2);
    assert!(p.slices[1].container.is_none());
    assert!(matches!(p.code_inventory, CodeSliceInventory::Complete));
    assert!(
        !p.slices[0].gaps.is_empty(),
        "legacy sibling diagnostic retained"
    );
    check_collection(&unparsed, 2, false);
    let mut invalid = good;
    invalid[40..44].copy_from_slice(&0u32.to_be_bytes());
    check_collection(&invalid, 1, true);
}

fn check_collection(bytes: &[u8], slices: usize, partial_inventory: bool) {
    use sigil_engine::{
        analyze::install_code,
        collect::install::{collect_with_code, InstallBudgets},
    };
    use sigil_model::{CoverageState, Ref};
    let tree = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::write(tree.path().join("bin/ollama"), bytes).unwrap();
    let mut budgets = InstallBudgets::default();
    budgets.binary.code = Some(CodeBudgets::default());
    let facts = collect_with_code(tree.path(), budgets).unwrap();
    let artifact = facts
        .artifacts
        .iter()
        .find(|a| a.format == sigil_model::Format::MachOFat)
        .unwrap();
    assert_eq!(artifact.slices.len(), slices);
    assert_eq!(
        matches!(
            artifact.code_slice_inventory,
            Some(CodeSliceInventory::Partial { .. })
        ),
        partial_inventory
    );
    let round: sigil_model::Artifact =
        serde_json::from_str(&serde_json::to_string(artifact).unwrap()).unwrap();
    assert_eq!(round.code_slice_inventory, artifact.code_slice_inventory);
    let coverage = install_code::coverage(&facts, CodeBudgets::default().bytes).unwrap();
    for c in coverage
        .iter()
        .filter(|c| matches!(c.scope, Ref::Root(_) | Ref::Artifact(_)))
    {
        assert!(matches!(c.state, CoverageState::Partial { .. }));
        if matches!(c.scope, Ref::Artifact(_)) {
            assert_eq!(c.budget.as_ref().unwrap().used, 0);
        }
    }
    if !partial_inventory {
        let child = coverage
            .iter()
            .find(|c| c.scope == Ref::Slice(artifact.slices[1].id.clone()))
            .unwrap();
        assert!(
            matches!(&child.state, CoverageState::Partial{missing} if missing == &["code: slice not parsed"])
        );
        assert_eq!(child.budget.as_ref().unwrap().used, 0);
        assert!(!facts
            .binaries
            .iter()
            .any(|b| b.slice == artifact.slices[1].id));
    }
    assert!(facts
        .code
        .iter()
        .all(|(_, c)| matches!(c, sigil_engine::code::CodeOutcome::Unsupported)));
    let session = sigil_engine::inspect::binary_session(
        &sigil_engine::inspect::BinaryRequest {
            paths: vec![tree.path().join("bin/ollama")],
            deps_budgets: Default::default(),
            budgets: sigil_engine::collect::named::NamedBudgets {
                binary: budgets.binary,
                ..Default::default()
            },
        },
        &sigil_engine::policy::Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert!(session.code.is_empty());
    assert!(session
        .coverage
        .iter()
        .any(|c| c.check.as_str() == "binary.code"
            && matches!(c.scope, Ref::Instance(_))
            && matches!(c.state, CoverageState::Partial { .. })));
    let json = session.to_canonical_json().unwrap();
    let round: sigil_model::Session = serde_json::from_str(&json).unwrap();
    round.validate().unwrap();
}

#[test]
fn unhashable_overflow_overlap_cpu_and_slice_count_fail_closed() {
    use common::macho::*;
    let a = thin(true, false, AARCH64, 0, &[]);
    let x = thin(true, false, X86_64, 3, &[]);
    let mut overlap = fat32(&[
        (a.clone(), AARCH64, 0),
        (x.clone(), X86_64, 3),
        (x.clone(), X86_64, 8),
    ]);
    let second_range = overlap[36..44].to_vec();
    overlap[56..64].copy_from_slice(&second_range);
    let p = parse(&overlap, true, 64 << 20);
    assert_eq!(p.slices.len(), 1);
    assert_eq!(p.slices[0].arch, Arch::Aarch64);
    assert!(matches!(
        p.code_inventory,
        CodeSliceInventory::Partial { .. }
    ));
    let duplicate = fat32(&[
        (a.clone(), AARCH64, 0),
        (x.clone(), X86_64, 3),
        (x.clone(), X86_64, 3),
    ]);
    assert!(matches!(
        parse(&duplicate, true, 64 << 20).code_inventory,
        CodeSliceInventory::Partial { .. }
    ));
    let mismatch = fat32(&[(a.clone(), AARCH64, 0), (a.clone(), X86_64, 3)]);
    assert!(matches!(
        parse(&mismatch, true, 64 << 20).code_inventory,
        CodeSliceInventory::Partial { .. }
    ));
    let mut overflow = vec![0u8; 40];
    overflow[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbf]);
    overflow[4..8].copy_from_slice(&1u32.to_be_bytes());
    overflow[8..12].copy_from_slice(&(AARCH64 as u32).to_be_bytes());
    overflow[16..24].copy_from_slice(&(u64::MAX - 3).to_be_bytes());
    overflow[24..32].copy_from_slice(&8u64.to_be_bytes());
    assert!(parse(&overflow, true, 64 << 20).slices.is_empty());
    for count in [64, 65] {
        let many = fat32(
            &(0..count)
                .map(|_| (a.clone(), AARCH64, 0))
                .collect::<Vec<_>>(),
        );
        let p = parse(&many, true, 64 << 20);
        assert_eq!(p.slices.len(), if count == 64 { 64 } else { 0 });
        assert!(matches!(
            p.code_inventory,
            CodeSliceInventory::Partial { .. }
        ));
    }
    // A shrink after fstat leaves a structurally valid descriptor that cannot be hashed.
    use std::io::Write;
    let full = fat32(&[(a, AARCH64, 0), (x, X86_64, 3)]);
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&full[..full.len() - 32]).unwrap();
    let p = parse_artifact(
        f.as_file(),
        full.len() as u64,
        &Sha256Hex::new(format!("{:x}", Sha256::digest(&full))).unwrap(),
        &full[..4],
        BinaryBudgets {
            code: Some(CodeBudgets::default()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(p.slices.len(), 1);
    assert!(
        matches!(p.code_inventory, CodeSliceInventory::Partial{missing} if missing.iter().any(|m| m.contains("hash:")))
    );
}

#[test]
fn shared_reader_keeps_slice_cost_and_rejects_endian_cpu_and_pac_disagreement() {
    use std::io::Write;
    let arm = synthetic(false, 5, 0x8000_0000);
    let mut x86 = arm.clone();
    put32(&mut x86, 4, common::macho::X86_64 as u32);
    put32(&mut x86, 8, 3);
    let bytes = [arm.as_slice(), x86.as_slice()].concat();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&bytes).unwrap();
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 350);
    let first = image::build(
        &mut reader,
        id(Arch::Aarch64, 0),
        SliceWindow {
            base: 0,
            len: arm.len() as u64,
        },
        Arch::Aarch64,
        None,
    )
    .unwrap();
    assert_eq!(reader.used(), 184);
    assert_eq!(
        image::build(
            &mut reader,
            id(Arch::X86_64, arm.len() as u64),
            SliceWindow {
                base: arm.len() as u64,
                len: x86.len() as u64
            },
            Arch::X86_64,
            None
        )
        .unwrap_err(),
        Error::Read(reader::Refusal::Budget)
    );
    assert_eq!(reader.used(), 216);
    assert_eq!(first.read_code(&mut reader, 0x1200, 4).unwrap(), b"hell");
    assert_eq!(reader.used(), 220);
    for (cpu, subtype, arch) in [
        (common::macho::X86_64 as u32, 3, Arch::Aarch64),
        (common::macho::AARCH64 as u32, 2, Arch::Aarch64),
    ] {
        let mut bad = arm.clone();
        put32(&mut bad, 4, cpu);
        put32(&mut bad, 8, subtype);
        assert!(view(&bad, 0, bad.len() as u64, arch).is_err());
    }
    let big = common::macho::thin(true, true, common::macho::AARCH64, 0, &[]);
    assert_eq!(
        view(&big, 0, big.len() as u64, Arch::Aarch64).unwrap_err(),
        Error::Unsupported
    );
    let mut reader = Reader::new(f.as_file(), bytes.len() as u64, 350);
    assert_eq!(
        image::build(
            &mut reader,
            id(Arch::Aarch64, 0),
            SliceWindow {
                base: 0,
                len: arm.len() as u64
            },
            Arch::Aarch64,
            Some((common::macho::X86_64, 3))
        )
        .unwrap_err(),
        Error::Invalid("CPU header/table disagreement")
    );
}
