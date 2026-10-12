//! Regression coverage for the Mach-O parser using synthetic and compiler-produced bytes.

mod common;

use std::fs::File;
use std::path::Path;

use sha2::{Digest, Sha256};
use sigil_engine::binary::{parse_artifact, BinaryBudgets, ParsedArtifact};
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, InstallRequest, StoreRequest,
};
use sigil_engine::policy::Policy;
use sigil_model::{ContainerFacts, Format, ObservationMeta, Sha256Hex, Timestamp, ToolInfo};
use tempfile::TempDir;

fn parse(bytes: &[u8]) -> Option<ParsedArtifact> {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("input");
    std::fs::write(&path, bytes).unwrap();
    let file = File::open(path).unwrap();
    let digest = Sha256Hex::new(format!("{:x}", Sha256::digest(bytes))).unwrap();
    parse_artifact(
        &file,
        bytes.len() as u64,
        &digest,
        &bytes[..bytes.len().min(4)],
        BinaryBudgets::default(),
    )
}

fn macho_facts(parsed: &ParsedArtifact, index: usize) -> &sigil_model::MachOFacts {
    let Some(ContainerFacts::MachO(facts)) = parsed.slices[index].container.as_ref() else {
        panic!("expected Mach-O facts: {parsed:?}");
    };
    facts
}

#[test]
fn thin_headers_parse_in_both_widths_and_byte_orders() {
    for (is_64, big_endian, cpu_type) in [
        (false, false, 7),
        (false, true, 7),
        (true, false, common::macho::X86_64),
        (true, true, common::macho::X86_64),
    ] {
        let bytes = common::macho::thin(is_64, big_endian, cpu_type, 3, &[]);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.format, Format::MachO);
        assert_eq!(parsed.slices.len(), 1);
        let facts = macho_facts(&parsed, 0);
        assert_eq!(facts.is_64, is_64);
        assert_eq!(facts.cpu_type, cpu_type);
        assert_eq!(facts.cpu_subtype, 3);
        assert!(parsed.slices[0].gaps.is_empty(), "{parsed:?}");
    }
}

#[test]
fn compiler_generated_macho_object_is_parsed_without_macos_ci() {
    let bytes = common::macho::decode_hex(include_str!("fixtures/macho/clang-x86_64.o.hex"));
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.format, Format::MachO);
    assert_eq!(parsed.slices.len(), 1);
    assert_eq!(macho_facts(&parsed, 0).cpu_type, common::macho::X86_64);
    assert!(parsed.slices[0].gaps.is_empty(), "{parsed:?}");
}

#[test]
fn load_commands_extract_dylibs_rpaths_and_uuid() {
    let commands = [
        common::macho::dylib_command(0x0c, "@rpath/libsample.dylib", false, 8),
        common::macho::rpath_command(0x8000_001c, "@loader_path", false, 8),
        common::macho::uuid_command(false),
    ];
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &commands);
    let parsed = parse(&bytes).unwrap();
    let facts = macho_facts(&parsed, 0);
    assert_eq!(
        facts.load_dylibs[0].as_str(),
        Some("@rpath/libsample.dylib")
    );
    assert_eq!(facts.rpaths[0].as_str(), Some("@loader_path"));
    assert_eq!(
        facts.uuid.as_deref(),
        Some("000102030405060708090a0b0c0d0e0f")
    );
    assert!(parsed.slices[0].gaps.is_empty(), "{parsed:?}");
}

#[test]
fn fat_slices_keep_hashes_and_mask_only_subtype_capabilities_for_comparison() {
    let x86 = common::macho::thin(true, false, common::macho::X86_64, 3, &[]);
    let arm = common::macho::thin(true, false, common::macho::AARCH64, 0, &[]);
    let bytes = common::macho::fat32(&[
        (x86.clone(), common::macho::X86_64, 0x8000_0003u32 as i32),
        (arm.clone(), common::macho::AARCH64, 0),
    ]);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.format, Format::MachOFat);
    assert_eq!(parsed.slices.len(), 2);
    for (index, expected) in [x86, arm].iter().enumerate() {
        let slice = &parsed.slices[index];
        assert_eq!(
            slice.sha256.as_str(),
            format!("{:x}", Sha256::digest(expected))
        );
        assert_eq!(
            &bytes[slice.offset as usize..(slice.offset + slice.size) as usize],
            expected
        );
        assert!(slice.gaps.is_empty(), "{parsed:?}");
    }
    assert_eq!(macho_facts(&parsed, 0).cpu_subtype, 3);
    assert_eq!(
        macho_facts(&parsed, 0).fat_cpu_subtype,
        Some(0x8000_0003u32 as i32)
    );
    assert_eq!(macho_facts(&parsed, 1).cpu_type, common::macho::AARCH64);
}

#[test]
fn truncated_duplicate_overlapping_and_out_of_range_fat_tables_are_partial() {
    let mut truncated = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
    truncated.extend_from_slice(&[0; 20]);
    let parsed = parse(&truncated).unwrap();
    assert_eq!(parsed.format, Format::MachOFat);
    assert!(parsed.slices.is_empty());

    let x86 = common::macho::thin(true, false, common::macho::X86_64, 3, &[]);
    let arm = common::macho::thin(true, false, common::macho::AARCH64, 0, &[]);
    let mut overlapping = common::macho::fat32(&[
        (x86.clone(), common::macho::X86_64, 3),
        (arm, common::macho::AARCH64, 0),
    ]);
    let first_descriptor = overlapping[8..28].to_vec();
    overlapping[28..48].copy_from_slice(&first_descriptor);
    let parsed = parse(&overlapping).unwrap();
    assert!(parsed.slices.is_empty(), "{parsed:?}");

    let mut outside = common::macho::fat32(&[(x86, common::macho::X86_64, 3)]);
    outside[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    let parsed = parse(&outside).unwrap();
    assert!(parsed.slices.is_empty(), "{parsed:?}");
}

#[test]
fn an_invalid_java_constant_pool_does_not_hide_malformed_fat_macho() {
    let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 2, 5];
    bytes.extend_from_slice(&[0; 14]);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.format, Format::MachOFat);
    assert!(parsed.slices.is_empty());
}

#[test]
fn malformed_command_sizes_string_offsets_and_required_commands_leave_gaps() {
    let misaligned = common::macho::command(0x1b, 25, false);
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[misaligned]);
    let parsed = parse(&bytes).unwrap();
    assert!(parsed.slices[0]
        .gaps
        .iter()
        .any(|gap| gap.contains("invalid command size")));

    let command = common::macho::uuid_command(false);
    let mut too_large = common::macho::thin(true, false, common::macho::X86_64, 3, &[command]);
    too_large[20..24].copy_from_slice(&32u32.to_le_bytes());
    too_large.extend_from_slice(&[0; 8]);
    let parsed = parse(&too_large).unwrap();
    assert!(parsed.slices[0]
        .gaps
        .iter()
        .any(|gap| gap.contains("does not cover sizeofcmds")));

    let mut bad_offset = common::macho::rpath_command(0x8000_001c, "/tmp", false, 8);
    bad_offset[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[bad_offset]);
    let parsed = parse(&bytes).unwrap();
    assert!(parsed.slices[0]
        .gaps
        .iter()
        .any(|gap| gap.contains("string offset outside")));

    let wrong_rpath = common::macho::rpath_command(0x1c, "/not-a-rpath", false, 8);
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[wrong_rpath]);
    let parsed = parse(&bytes).unwrap();
    assert!(macho_facts(&parsed, 0).rpaths.is_empty());

    let required = common::macho::command(0x8000_1234, 8, false);
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[required]);
    let parsed = parse(&bytes).unwrap();
    assert!(parsed.slices[0]
        .gaps
        .iter()
        .any(|gap| gap.contains("unknown required command")));
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-10T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-10T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

fn binary_inspection(path: &Path) -> sigil_model::Session {
    let observation = observation();
    binary_session(
        &BinaryRequest {
            paths: vec![path.to_path_buf()],
            budgets: NamedBudgets::default(),
        },
        &Policy::builtin_default().unwrap(),
        ToolInfo {
            name: "sigil".into(),
            version: "0.0.0-test".into(),
            git_rev: None,
        },
        observation.clone(),
        observation.started_at,
    )
    .unwrap()
}

fn install_inspection(directory: &Path) -> sigil_model::Session {
    let models = TempDir::new().unwrap();
    let observation = observation();
    store_session(
        &StoreRequest {
            models_dir: models.path().to_path_buf(),
            model_filter: None,
            budgets: FsBudgets::default(),
            manifest_limit: DEFAULT_MANIFEST_LIMIT,
            install: Some(InstallRequest {
                dir: directory.to_path_buf(),
                budgets: InstallBudgets::default(),
            }),
        },
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        ToolInfo {
            name: "sigil".into(),
            version: "0.0.0-test".into(),
            git_rev: None,
        },
        observation.clone(),
        observation.started_at,
    )
    .unwrap()
}

#[test]
fn binary_inspect_and_install_scan_record_the_same_macho_facts() {
    let commands = [
        common::macho::dylib_command(0x0c, "@rpath/libsample.dylib", false, 8),
        common::macho::rpath_command(0x8000_001c, "@loader_path", false, 8),
        common::macho::uuid_command(false),
    ];
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &commands);
    let binary_directory = TempDir::new().unwrap();
    let binary_path = binary_directory.path().join("libsample.dylib");
    std::fs::write(&binary_path, &bytes).unwrap();
    let direct = binary_inspection(&binary_path);

    let install_directory = TempDir::new().unwrap();
    std::fs::create_dir_all(install_directory.path().join("bin")).unwrap();
    std::fs::write(install_directory.path().join("bin/ollama"), &bytes).unwrap();
    let installed = install_inspection(install_directory.path());

    assert_eq!(direct.validate(), Ok(()));
    assert_eq!(installed.validate(), Ok(()));
    assert_eq!(direct.binaries.len(), 1);
    assert_eq!(installed.binaries.len(), 1);
    assert_eq!(
        direct.binaries[0].container,
        installed.binaries[0].container
    );
    assert_eq!(direct.binaries[0].gaps, installed.binaries[0].gaps);
}
