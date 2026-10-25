//! Regression coverage for the Mach-O parser using synthetic and compiler-produced bytes.

mod common;

use std::fs::File;
use std::path::Path;

use common::macho::{
    chained_fixups, dyld_info_command, executable, linkedit_command, LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LIBSYSTEM,
};
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
use sigil_model::{
    ContainerFacts, Format, MachOImport, MachOLibrary, ObservationMeta, Sha256Hex, Timestamp,
    ToolInfo, UntrustedText,
};
use tempfile::TempDir;

fn parse(bytes: &[u8]) -> Option<ParsedArtifact> {
    parse_with(bytes, BinaryBudgets::default())
}

fn parse_with(bytes: &[u8], budgets: BinaryBudgets) -> Option<ParsedArtifact> {
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
        budgets,
        None,
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
    // PR-4c-3b: its symbol table was read; it defines `_sigil_fixture`, and imports nothing.
    assert!(macho_facts(&parsed, 0).imports.is_empty());
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
fn a_fat_table_that_lists_one_architecture_twice_is_partial() {
    // Two valid x86_64 slices at different offsets that do not overlap. lipo refuses to build
    // this, and dyld would load only one of them.
    let first = common::macho::thin(true, false, common::macho::X86_64, 3, &[]);
    let second = common::macho::thin(
        true,
        false,
        common::macho::X86_64,
        3,
        &[common::macho::uuid_command(false)],
    );
    for second_subtype in [3, 0x8000_0003u32 as i32] {
        let bytes = common::macho::fat32(&[
            (first.clone(), common::macho::X86_64, 3),
            (second.clone(), common::macho::X86_64, second_subtype),
        ]);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.slices.len(), 2, "{parsed:?}");
        assert_ne!(parsed.slices[0].offset, parsed.slices[1].offset);
        for slice in &parsed.slices {
            assert!(
                slice
                    .gaps
                    .contains(&sigil_model::FAT_DUPLICATE_ARCH_GAP.to_string()),
                "{parsed:?}"
            );
        }
    }

    // x86_64 and x86_64h are two architectures (subtypes 3 and 8).
    let bytes = common::macho::fat32(&[
        (first.clone(), common::macho::X86_64, 3),
        (
            common::macho::thin(true, false, common::macho::X86_64, 8, &[]),
            common::macho::X86_64,
            8,
        ),
    ]);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.slices.len(), 2);
    assert!(
        parsed.slices.iter().all(|slice| slice.gaps.is_empty()),
        "{parsed:?}"
    );
}

#[test]
fn a_slice_header_that_disagrees_with_its_table_entry_is_partial() {
    let arm = common::macho::thin(true, false, common::macho::AARCH64, 0, &[]);
    let bytes = common::macho::fat32(&[(arm, common::macho::X86_64, 0)]);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(
        parsed.slices[0].gaps,
        [sigil_model::FAT_CPU_MISMATCH_GAP.to_string()]
    );
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

/// A universal executable that ld64.lld linked (`fixtures/macho/build.sh`); the expected values
/// are in `hello-universal.otool`.
const HELLO_UNIVERSAL: &[u8] = include_bytes!("fixtures/macho/hello-universal");

#[test]
fn known_required_commands_are_skipped_and_later_commands_are_read() {
    // LC_DYLD_INFO_ONLY, LC_MAIN, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, and
    // LC_FILESET_ENTRY, each at its structure's size, before the commands SIGIL reads.
    for (is_64, big_endian) in [(true, false), (true, true), (false, false), (false, true)] {
        let alignment = if is_64 { 8 } else { 4 };
        let commands = [
            common::macho::command(0x8000_0022, 48, big_endian),
            common::macho::command(0x8000_0028, 24, big_endian),
            common::macho::command(0x8000_0034, 16, big_endian),
            common::macho::command(0x8000_0033, 16, big_endian),
            common::macho::command(0x8000_0035, 32, big_endian),
            common::macho::dylib_command(0x0c, "/usr/lib/libSystem.B.dylib", big_endian, alignment),
            common::macho::rpath_command(0x8000_001c, "@loader_path/../lib", big_endian, alignment),
        ];
        let bytes = common::macho::thin(is_64, big_endian, common::macho::X86_64, 3, &commands);
        let parsed = parse(&bytes).unwrap();
        assert!(parsed.slices[0].gaps.is_empty(), "{parsed:?}");
        let facts = macho_facts(&parsed, 0);
        assert_eq!(
            facts.load_dylibs[0].as_str(),
            Some("/usr/lib/libSystem.B.dylib")
        );
        assert_eq!(facts.rpaths[0].as_str(), Some("@loader_path/../lib"));
    }
}

#[test]
fn a_known_required_command_shorter_than_its_structure_is_a_gap_but_not_the_end() {
    let commands = [
        common::macho::command(0x8000_0028, 16, false),
        common::macho::dylib_command(0x0c, "/usr/lib/libSystem.B.dylib", false, 8),
    ];
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &commands);
    let parsed = parse(&bytes).unwrap();
    assert_eq!(
        parsed.slices[0].gaps,
        ["LC_MAIN: command is too short".to_string()]
    );
    assert_eq!(
        macho_facts(&parsed, 0).load_dylibs[0].as_str(),
        Some("/usr/lib/libSystem.B.dylib")
    );
}

#[test]
fn an_unknown_required_command_ends_the_walk() {
    let commands = [
        common::macho::command(0x8000_1234, 8, false),
        common::macho::dylib_command(0x0c, "/usr/lib/libSystem.B.dylib", false, 8),
    ];
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &commands);
    let parsed = parse(&bytes).unwrap();
    assert!(macho_facts(&parsed, 0).load_dylibs.is_empty(), "{parsed:?}");
    assert_eq!(
        parsed.slices[0].gaps,
        [
            "load commands: command count does not cover sizeofcmds".to_string(),
            "load commands: unknown required command 0x80001234".to_string(),
        ]
    );
}

#[test]
fn a_linked_universal_executable_is_read_in_full() {
    let parsed = parse(HELLO_UNIVERSAL).unwrap();
    assert_eq!(parsed.format, Format::MachOFat);
    assert_eq!(parsed.slices.len(), 2);
    let expected = [
        (
            4096,
            12_560,
            common::macho::X86_64,
            "@loader_path/../lib",
            "4c4c442d55553144a149c2a40805f99b",
        ),
        (
            32_768,
            33_472,
            common::macho::AARCH64,
            "@executable_path/../Frameworks",
            "4c4c44e455553144a1c6aa2fc11dc892",
        ),
    ];
    for (index, (offset, size, cpu_type, rpath, uuid)) in expected.into_iter().enumerate() {
        let slice = &parsed.slices[index];
        assert_eq!((slice.offset, slice.size), (offset, size));
        assert!(slice.gaps.is_empty(), "{parsed:?}");
        let facts = macho_facts(&parsed, index);
        assert_eq!(
            (facts.cpu_type, facts.fat_cpu_type),
            (cpu_type, Some(cpu_type))
        );
        assert_eq!(facts.file_type, 2, "MH_EXECUTE");
        let names = |names: &[sigil_model::UntrustedText]| -> Vec<String> {
            names
                .iter()
                .map(|name| name.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(names(&facts.load_dylibs), ["/usr/lib/libSystem.B.dylib"]);
        assert_eq!(names(&facts.rpaths), [rpath]);
        assert_eq!(
            facts.dylinker.as_ref().and_then(|name| name.as_str()),
            Some("/usr/lib/dyld")
        );
        assert_eq!(facts.uuid.as_deref(), Some(uuid));
        // PR-4c-3b: x86_64 binds `dyld_stub_binder` and lazily binds `_puts`; arm64 has one
        // chained import, `_puts`. Each from libSystem, ordinal 1.
        let libsystem = || dylib(1, LIBSYSTEM);
        let expected = if index == 0 {
            vec![
                import("_puts", libsystem(), false),
                import("dyld_stub_binder", libsystem(), false),
            ]
        } else {
            vec![import("_puts", libsystem(), false)]
        };
        assert_eq!(facts.imports, expected);

        // The slice alone is the thin executable `lipo -thin` would extract.
        let thin = &HELLO_UNIVERSAL[offset as usize..(offset + size) as usize];
        let alone = parse(thin).unwrap();
        assert_eq!(alone.format, Format::MachO);
        assert!(alone.slices[0].gaps.is_empty(), "{alone:?}");
        let thin_facts = macho_facts(&alone, 0);
        assert_eq!(thin_facts.load_dylibs, facts.load_dylibs);
        assert_eq!(thin_facts.rpaths, facts.rpaths);
        assert_eq!(thin_facts.uuid, facts.uuid);
        assert_eq!(thin_facts.imports, facts.imports);
    }
}

// --- Imports (PR-4c-3b) ------------------------------------------------------------------------

fn import(name: &str, library: MachOLibrary, weak: bool) -> MachOImport {
    MachOImport {
        name: UntrustedText::new(name),
        library,
        weak,
    }
}

fn dylib(ordinal: u32, name: &str) -> MachOLibrary {
    MachOLibrary::Dylib {
        ordinal,
        name: Some(UntrustedText::new(name)),
    }
}

/// The imports and gaps of the one slice of `bytes`.
fn imports_of(bytes: &[u8]) -> (Vec<MachOImport>, Vec<String>) {
    let parsed = parse(bytes).unwrap();
    (
        macho_facts(&parsed, 0).imports.clone(),
        parsed.slices[0].gaps.clone(),
    )
}

/// An executable that loads libSystem and `@rpath/libfoo.dylib`, with `blob` as its chained
/// fixups.
fn chained_executable(blob: &[u8]) -> Vec<u8> {
    executable(
        &[LIBSYSTEM, "@rpath/libfoo.dylib"],
        |base| {
            vec![linkedit_command(
                LC_DYLD_CHAINED_FIXUPS,
                base,
                blob.len() as u32,
                false,
            )]
        },
        blob,
    )
}

/// Six imports, each through another library: libSystem, libfoo (weak), flat lookup, the main
/// executable, this image, and weak lookup.
fn six_imports(flat: u64, main: u64, weak: u64) -> Vec<(u64, bool, &'static str)> {
    vec![
        (1, false, "_connect"),
        (2, true, "_socket"),
        (flat, false, "_getenv"),
        (main, false, "_main_thing"),
        (0, false, "_own"),
        (weak, false, "__ZdlPv"),
    ]
}

fn six_expected() -> Vec<MachOImport> {
    vec![
        import("__ZdlPv", MachOLibrary::WeakLookup, false),
        import("_connect", dylib(1, LIBSYSTEM), false),
        import("_getenv", MachOLibrary::FlatLookup, false),
        import("_main_thing", MachOLibrary::MainExecutable, false),
        import("_own", MachOLibrary::SelfImage, false),
        import("_socket", dylib(2, "@rpath/libfoo.dylib"), true),
    ]
}

#[test]
fn chained_imports_name_their_libraries_in_each_format() {
    for format in [1, 2] {
        let blob = chained_fixups(format, &six_imports(0xfe, 0xff, 0xfd));
        let (imports, gaps) = imports_of(&chained_executable(&blob));
        assert!(gaps.is_empty(), "format {format}: {gaps:?}");
        assert_eq!(imports, six_expected(), "format {format}");
    }
    // DYLD_CHAINED_IMPORT_ADDEND64: 16-bit ordinals, sign-extended above 0xfff0.
    let blob = chained_fixups(3, &six_imports(0xfffe, 0xffff, 0xfffd));
    let (imports, gaps) = imports_of(&chained_executable(&blob));
    assert!(gaps.is_empty(), "{gaps:?}");
    assert_eq!(imports, six_expected());
}

#[test]
fn chained_fixups_not_understood_are_gaps() {
    let blob = chained_fixups(1, &[(1, false, "_connect"), (1, false, "_dlopen")]);
    let with = |at: usize, value: u32| {
        let mut b = blob.clone();
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        b
    };
    let gap = |why: &str| vec![format!("imports: chained fixups: {why}")];
    for (bytes, why) in [
        (with(0, 1), "fixups_version 1 not read"),
        (with(24, 1), "symbols_format 1 not read (compressed)"),
        (with(20, 4), "imports_format 4 not read"),
        (with(16, 1000), "the imports past the blob"),
        // One entry more than the blob holds, ending past it by less than an entry.
        (
            with(16, ((blob.len() - 32) / 4 + 1) as u32),
            "the imports past the blob",
        ),
        (with(12, blob.len() as u32), "a name out of the blob"),
        (blob[..20].to_vec(), "a header past the blob"),
    ] {
        assert_eq!(
            imports_of(&chained_executable(&bytes)),
            (vec![], gap(why)),
            "{why}"
        );
    }
    // The last name without its NUL: the first is kept.
    let (imports, gaps) = imports_of(&chained_executable(&blob[..blob.len() - 1]));
    assert_eq!(imports, [import("_connect", dylib(1, LIBSYSTEM), false)]);
    assert_eq!(gaps, gap("a name without its NUL"));
    // The blob out of the slice.
    let bytes = executable(
        &[LIBSYSTEM],
        |_| {
            vec![linkedit_command(
                LC_DYLD_CHAINED_FIXUPS,
                0x10_0000,
                64,
                false,
            )]
        },
        &[],
    );
    assert_eq!(imports_of(&bytes), (vec![], gap("range outside slice")));
    // A big-endian image.
    let bytes = common::macho::with_tail(
        true,
        true,
        common::macho::X86_64,
        common::macho::MH_EXECUTE,
        |base| {
            vec![
                common::macho::dylib_command(0x0c, LIBSYSTEM, true, 8),
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, base, blob.len() as u32, true),
            ]
        },
        &blob,
    );
    assert_eq!(imports_of(&bytes), (vec![], gap("a big-endian image")));
}

#[test]
fn a_linked_image_s_imports_come_from_one_dyld_command() {
    let blob = chained_fixups(1, &[(1, false, "_connect")]);
    let len = blob.len() as u32;
    let none = || dyld_info_command(LC_DYLD_INFO_ONLY, (0, 0), (0, 0), false);
    for (commands, gap) in [
        (
            vec![
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, 0, len, false),
                none(),
            ],
            "imports: both LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS",
        ),
        (
            vec![
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, 0, len, false),
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, 0, len, false),
            ],
            "imports: more than one LC_DYLD_CHAINED_FIXUPS",
        ),
        (
            vec![
                dyld_info_command(LC_DYLD_INFO, (0, 0), (0, 0), false),
                none(),
            ],
            "imports: more than one LC_DYLD_INFO",
        ),
        (vec![], "imports: no LC_DYLD_INFO or LC_DYLD_CHAINED_FIXUPS"),
    ] {
        let bytes = executable(&[LIBSYSTEM], |_| commands.clone(), &blob);
        assert_eq!(imports_of(&bytes), (vec![], vec![gap.to_string()]), "{gap}");
    }
    // Neither, and no dylib loaded: nothing to bind.
    assert_eq!(
        imports_of(&executable(&[], |_| vec![], &[])),
        (vec![], vec![])
    );
    // No loader reads an object file: its dyld commands are not read.
    let object = common::macho::with_tail(
        true,
        false,
        common::macho::X86_64,
        1,
        |base| vec![linkedit_command(LC_DYLD_CHAINED_FIXUPS, base, len, false)],
        &blob,
    );
    assert_eq!(imports_of(&object), (vec![], vec![]));
}

#[test]
fn an_ordinal_past_the_dylibs_binds_nowhere_and_a_dylib_not_read_has_no_name() {
    let blob = chained_fixups(
        1,
        &[
            (1, false, "_a"),
            (2, false, "_b"),
            (3, false, "_past"),
            (0xf5, false, "_special"),
        ],
    );
    let mut unread = common::macho::dylib_command(0x0c, "/usr/lib/libz.1.dylib", false, 8);
    unread[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let bytes = common::macho::with_tail(
        true,
        false,
        common::macho::X86_64,
        common::macho::MH_EXECUTE,
        |base| {
            vec![
                unread.clone(),
                common::macho::dylib_command(0x0c, LIBSYSTEM, false, 8),
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, base, blob.len() as u32, false),
            ]
        },
        &blob,
    );
    let (imports, gaps) = imports_of(&bytes);
    assert_eq!(
        imports,
        [
            import(
                "_a",
                MachOLibrary::Dylib {
                    ordinal: 1,
                    name: None
                },
                false
            ),
            import("_b", dylib(2, LIBSYSTEM), false),
        ]
    );
    assert_eq!(
        gaps,
        [
            "imports: an ordinal past the 2 dylibs",
            "imports: an unknown special ordinal",
            "load dylib: string offset outside load command",
        ]
    );
}

#[test]
fn binary_imports_keeps_the_smallest_imports() {
    let blob = chained_fixups(1, &six_imports(0xfe, 0xff, 0xfd));
    let budgets = BinaryBudgets {
        imports: 2,
        ..BinaryBudgets::default()
    };
    let thin = chained_executable(&blob);
    let parsed = parse_with(&thin, budgets).unwrap();
    assert_eq!(macho_facts(&parsed, 0).imports, six_expected()[..2]);
    assert_eq!(parsed.slices[0].gaps, ["imports: over binary_imports 2"]);
    // In each slice of a fat file.
    let mut arm = thin.clone();
    arm[4..8].copy_from_slice(&(common::macho::AARCH64 as u32).to_le_bytes());
    let fat = common::macho::fat32(&[
        (thin, common::macho::X86_64, 0),
        (arm, common::macho::AARCH64, 0),
    ]);
    let parsed = parse_with(&fat, budgets).unwrap();
    for index in 0..2 {
        assert_eq!(macho_facts(&parsed, index).imports, six_expected()[..2]);
        assert_eq!(
            parsed.slices[index].gaps,
            ["imports: over binary_imports 2"]
        );
    }
}

#[test]
fn an_import_name_over_65536_bytes_is_a_gap() {
    let longest = format!("_{}", "a".repeat(65_535));
    let over = format!("_{}", "b".repeat(65_536));
    let blob = chained_fixups(1, &[(1, false, &longest), (1, false, &over)]);
    assert_eq!(
        imports_of(&chained_executable(&blob)),
        (
            vec![import(&longest, dylib(1, LIBSYSTEM), false)],
            vec!["imports: a name over 65536 bytes".to_string()]
        )
    );
}

/// `SET_SYMBOL_TRAILING_FLAGS_IMM` of `name` with `flags`.
fn symbol(flags: u8, name: &str) -> Vec<u8> {
    let mut opcodes = vec![0x40 | flags];
    opcodes.extend_from_slice(name.as_bytes());
    opcodes.push(0);
    opcodes
}

/// An executable that loads libSystem and `@rpath/libfoo.dylib`, with `bind` and `lazy` as the
/// bind and lazy-bind streams of its `id` (`LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY`).
fn opcode_executable(id: u32, bind: &[u8], lazy: &[u8]) -> Vec<u8> {
    let (b, l) = (bind.len() as u32, lazy.len() as u32);
    executable(
        &[LIBSYSTEM, "@rpath/libfoo.dylib"],
        |base| vec![dyld_info_command(id, (base, b), (base + b, l), false)],
        &[bind, lazy].concat(),
    )
}

#[test]
fn bind_opcodes_bind_each_name() {
    let bind = [
        vec![0x11],
        symbol(0, "_connect"),
        vec![0x51, 0x72, 0x10, 0x90],
        symbol(1, "_dlopen"),
        vec![0xa0, 0x08, 0x20, 0x02, 0x60, 0x7f],
        symbol(0, "_socket"),
        // DO_BIND_ULEB_TIMES_SKIPPING_ULEB: a count, and a skip of two bytes.
        vec![0xc0, 0x02, 0x90, 0x01, 0x3e],
        symbol(0, "_getenv"),
        // DO_BIND_ADD_ADDR_IMM_SCALED, then DONE: what follows is not read.
        vec![0xb1, 0x00, 0xff],
    ]
    .concat();
    // Each lazy entry ends with DONE; the ordinal carries over to the next (as dyld4 and LLVM
    // read it; Task 2 review).
    let lazy = [
        vec![0x72, 0x00, 0x11],
        symbol(0, "_puts"),
        vec![0x90, 0x00],
        symbol(0, "_open"),
        vec![0x90, 0x00],
    ]
    .concat();
    let expected = vec![
        import("_connect", dylib(1, LIBSYSTEM), false),
        import("_dlopen", dylib(1, LIBSYSTEM), true),
        import("_getenv", MachOLibrary::FlatLookup, false),
        import("_open", dylib(1, LIBSYSTEM), false),
        import("_puts", dylib(1, LIBSYSTEM), false),
        import("_socket", dylib(2, "@rpath/libfoo.dylib"), false),
    ];
    for id in [LC_DYLD_INFO_ONLY, LC_DYLD_INFO] {
        assert_eq!(
            imports_of(&opcode_executable(id, &bind, &lazy)),
            (expected.clone(), vec![]),
            "{id:#x}"
        );
    }
    // Threaded binds: the ordinal table's size, binds, then APPLY.
    let threaded = [
        vec![0xd0, 0x02, 0x11],
        symbol(0, "_connect"),
        vec![0x90, 0x12],
        symbol(0, "_socket"),
        vec![0x90, 0xd1, 0x00],
    ]
    .concat();
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &threaded, &[])),
        (
            vec![
                import("_connect", dylib(1, LIBSYSTEM), false),
                import("_socket", dylib(2, "@rpath/libfoo.dylib"), false),
            ],
            vec![]
        )
    );
}

/// PR-4c-3b plan review P2: DO_BIND_ULEB_TIMES_SKIPPING_ULEB binds as many times as its count
/// says. A count of 0 binds nothing: no import, and no hint.
#[test]
fn a_bind_repeated_zero_times_binds_nothing() {
    for (count, expected) in [
        (0, vec![]),
        (1, vec![import("_connect", dylib(1, LIBSYSTEM), false)]),
        (2, vec![import("_connect", dylib(1, LIBSYSTEM), false)]),
    ] {
        let bind = [
            vec![0x11],
            symbol(0, "_connect"),
            vec![0xc0, count, 0x00, 0x00],
        ]
        .concat();
        assert_eq!(
            imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &bind, &[])),
            (expected, vec![]),
            "count {count}"
        );
    }
}

/// Task 2 review: SET_DYLIB_SPECIAL_IMM's four values, and SET_DYLIB_ORDINAL_ULEB's low 32 bits,
/// as dyld keeps them (`int`): 0xfffffffe is flat lookup, and 2^32 + 1 is ordinal 1.
#[test]
fn bind_opcodes_set_every_special_ordinal_and_a_ulebs_low_32_bits() {
    let bind = [
        vec![0x30],
        symbol(0, "_own"),
        vec![0x90, 0x3f],
        symbol(0, "_main_thing"),
        vec![0x90, 0x3e],
        symbol(0, "_getenv"),
        vec![0x90, 0x3d],
        symbol(0, "__ZdlPv"),
        vec![0x90, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x0f],
        symbol(0, "_dlopen"),
        vec![0x90, 0x20, 0x81, 0x80, 0x80, 0x80, 0x10],
        symbol(0, "_connect"),
        vec![0x90, 0x00],
    ]
    .concat();
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &bind, &[])),
        (
            vec![
                import("__ZdlPv", MachOLibrary::WeakLookup, false),
                import("_connect", dylib(1, LIBSYSTEM), false),
                import("_dlopen", MachOLibrary::FlatLookup, false),
                import("_getenv", MachOLibrary::FlatLookup, false),
                import("_main_thing", MachOLibrary::MainExecutable, false),
                import("_own", MachOLibrary::SelfImage, false),
            ],
            vec![]
        )
    );
}

/// Task 2 review: the sign-extension thresholds of chained ordinals. 0xf0 and 0xfff0 are ordinals
/// past the dylibs, 0xf1 and 0xfff1 are special ones dyld does not know, and 0x102 is a 16-bit
/// ordinal. Each alone, since the gaps name no ordinal.
#[test]
fn chained_ordinals_sign_extend_only_above_their_thresholds() {
    let past = "imports: an ordinal past the 2 dylibs";
    let special = "imports: an unknown special ordinal";
    for (format, ordinal, gap) in [
        (1, 0xf0, past),
        (1, 0xf1, special),
        (3, 0x102, past),
        (3, 0xfff0, past),
        (3, 0xfff1, special),
    ] {
        let blob = chained_fixups(format, &[(ordinal, false, "_a")]);
        assert_eq!(
            imports_of(&chained_executable(&blob)),
            (vec![], vec![gap.to_string()]),
            "format {format}, ordinal {ordinal:#x}"
        );
    }
}

/// Task 2 review: a bind that repeats the last one is no new import, and costs nothing, however
/// long its name; binds that are not repeats cost their names, within 64 MiB.
#[test]
fn bind_opcodes_past_64_mib_of_names_bound_are_a_gap() {
    let name = format!("_{}", "a".repeat(59_999));
    let repeats = [vec![0x11], symbol(0, &name), vec![0x90; 2_000], vec![0x00]].concat();
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &repeats, &[])),
        (vec![import(&name, dylib(1, LIBSYSTEM), false)], vec![])
    );
    let alternating = [
        vec![0x11],
        symbol(0, &name),
        [0x90, 0x12, 0x90, 0x11].repeat(600),
        vec![0x00],
    ]
    .concat();
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &alternating, &[])),
        (
            vec![
                import(&name, dylib(1, LIBSYSTEM), false),
                import(&name, dylib(2, "@rpath/libfoo.dylib"), false),
            ],
            vec!["imports: bind opcodes: over 67108864 bytes of names bound".to_string()]
        )
    );
}

/// Task 2 review: a gap repeated through a stream is one gap, and its text names no ordinal, so
/// the gaps stay bounded.
#[test]
fn a_gap_repeated_through_a_stream_is_one_gap() {
    let bind = [
        vec![0x19],
        symbol(0, "_connect"),
        vec![0x90; 1000],
        vec![0x1a, 0x90, 0x00],
    ]
    .concat();
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &bind, &[])),
        (
            vec![],
            vec!["imports: an ordinal past the 2 dylibs".to_string()]
        )
    );
}

/// Task 2 review: chained imports may all point at one name; each scan stops at its NUL, and all
/// of them at 64 MiB, after which the names are not read.
#[test]
fn chained_import_names_past_64_mib_of_scanning_are_a_gap() {
    let name = format!("_{}", "a".repeat(59_999));
    let count = 1_200u32;
    let mut blob = vec![];
    for value in [0, 28, 32, 32 + 4 * count, count, 1, 0] {
        blob.extend_from_slice(&value.to_le_bytes());
    }
    blob.resize(32, 0);
    for _ in 0..count {
        blob.extend_from_slice(&1u32.to_le_bytes());
    }
    blob.extend_from_slice(name.as_bytes());
    blob.push(0);
    assert_eq!(
        imports_of(&chained_executable(&blob)),
        (
            vec![import(&name, dylib(1, LIBSYSTEM), false)],
            vec!["imports: chained fixups: over 67108864 bytes of names scanned".to_string()]
        )
    );
}

/// Task 2 review: a dyld command shorter than its structure is a gap, and not read.
#[test]
fn a_dyld_command_shorter_than_its_structure_is_a_gap() {
    let bytes = executable(
        &[],
        |_| {
            vec![
                common::macho::command(LC_DYLD_INFO, 40, false),
                common::macho::command(LC_DYLD_INFO_ONLY, 40, false),
                common::macho::command(LC_DYLD_CHAINED_FIXUPS, 8, false),
            ]
        },
        &[],
    );
    assert_eq!(
        imports_of(&bytes),
        (
            vec![],
            vec![
                "LC_DYLD_CHAINED_FIXUPS: command is too short".to_string(),
                "LC_DYLD_INFO: command is too short".to_string(),
                "LC_DYLD_INFO_ONLY: command is too short".to_string(),
            ]
        )
    );
}

#[test]
fn bind_opcodes_not_understood_are_gaps() {
    let connect = [vec![0x11], symbol(0, "_connect"), vec![0x90]].concat();
    let kept = || vec![import("_connect", dylib(1, LIBSYSTEM), false)];
    let over_uleb = [vec![0x20], vec![0xff; 9], vec![0x7f]].concat();
    let over_sleb = [vec![0x60], vec![0x80; 10], vec![0x00]].concat();
    for (tail, gap) in [
        (vec![0xe0], "imports: bind opcodes: an unknown opcode 0xe0"),
        (vec![0xd2], "imports: bind opcodes: an unknown opcode 0xd2"),
        (
            vec![0x20, 0x80],
            "imports: bind opcodes: a ULEB128 past the stream",
        ),
        (over_uleb, "imports: bind opcodes: a ULEB128 over 64 bits"),
        (over_sleb, "imports: bind opcodes: an SLEB128 over 64 bits"),
        (
            vec![0x60, 0x80],
            "imports: bind opcodes: an SLEB128 past the stream",
        ),
        (
            vec![0x41, b'_', b'x'],
            "imports: bind opcodes: a name without its NUL",
        ),
        (
            [vec![0x3c], symbol(0, "_y"), vec![0x90]].concat(),
            "imports: an unknown special ordinal",
        ),
    ] {
        let bind = [connect.clone(), tail].concat();
        assert_eq!(
            imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &bind, &[])),
            (kept(), vec![gap.to_string()]),
            "{gap}"
        );
    }
    assert_eq!(
        imports_of(&opcode_executable(LC_DYLD_INFO_ONLY, &[0x11, 0x90], &[])),
        (
            vec![],
            vec!["imports: bind opcodes: a bind before any name".to_string()]
        )
    );
    // A stream out of the slice; the lazy one is still read.
    let lazy = [vec![0x11], symbol(0, "_connect"), vec![0x90, 0x00]].concat();
    let bytes = executable(
        &[LIBSYSTEM],
        |base| {
            vec![dyld_info_command(
                LC_DYLD_INFO_ONLY,
                (0x10_0000, 4),
                (base, lazy.len() as u32),
                false,
            )]
        },
        &lazy,
    );
    assert_eq!(
        imports_of(&bytes),
        (
            kept(),
            vec!["imports: bind opcodes: range outside slice".to_string()]
        )
    );
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

/// The symbols of the object-file tests: two imports (one weak), a private external import, and
/// what is not an import: a common symbol, a definition, a local undefined symbol, and two stabs
/// (`N_FUN`, and one whose low bits look like an undefined external).
const OBJECT_SYMBOLS: [(&str, u8, u16, u64); 8] = [
    ("_connect", 0x01, 0, 0),
    ("_dlopen", 0x01, 0x40, 0),
    ("_common", 0x01, 0, 8),
    ("_main", 0x0f, 0, 0x10),
    ("_local", 0x00, 0, 0),
    ("_stab", 0x24, 0, 0),
    ("_gsym", 0x21, 0, 0),
    ("_private", 0x11, 0, 0),
];

#[test]
fn an_object_file_s_imports_are_its_undefined_external_symbols() {
    let expected = vec![
        import("_connect", MachOLibrary::Unbound, false),
        import("_dlopen", MachOLibrary::Unbound, true),
        import("_private", MachOLibrary::Unbound, false),
    ];
    for (is_64, big_endian) in [(true, false), (true, true), (false, false), (false, true)] {
        let (table, strings) = common::macho::nlists(is_64, big_endian, &OBJECT_SYMBOLS);
        let bytes = common::macho::object(is_64, big_endian, &table, &strings);
        assert_eq!(
            imports_of(&bytes),
            (expected.clone(), vec![]),
            "64-bit {is_64}, big-endian {big_endian}"
        );
    }
    // A 64-bit common symbol whose value is above 2^32: its high word counts.
    let (table, strings) = common::macho::nlists(true, false, &[("_big", 0x01, 0, 1 << 32)]);
    assert_eq!(
        imports_of(&common::macho::object(true, false, &table, &strings)),
        (vec![], vec![])
    );
}

#[test]
fn an_object_file_s_symbol_table_not_read_is_a_gap() {
    let (table, strings) = common::macho::nlists(true, false, &OBJECT_SYMBOLS[..2]);
    let gap = |why: &str| vec![format!("imports: symbol table: {why}")];
    // The first name past the strings.
    let mut outside = table.clone();
    outside[..4].copy_from_slice(&(strings.len() as u32).to_le_bytes());
    assert_eq!(
        imports_of(&common::macho::object(true, false, &outside, &strings)),
        (
            vec![import("_dlopen", MachOLibrary::Unbound, true)],
            gap("a name out of the strings")
        )
    );
    // The last name without its NUL.
    assert_eq!(
        imports_of(&common::macho::object(
            true,
            false,
            &table,
            &strings[..strings.len() - 1]
        )),
        (
            vec![import("_connect", MachOLibrary::Unbound, false)],
            gap("a name without its NUL")
        )
    );
    // The table out of the slice.
    let bytes = common::macho::with_tail(
        true,
        false,
        common::macho::X86_64,
        common::macho::MH_OBJECT,
        |base| vec![common::macho::symtab_command(0x10_0000, 2, base, 4, false)],
        &[0; 4],
    );
    assert_eq!(imports_of(&bytes), (vec![], gap("range outside slice")));
    // A command shorter than its structure, and two commands.
    let short = common::macho::command(common::macho::LC_SYMTAB, 16, false);
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[short]);
    assert_eq!(imports_of(&bytes), (vec![], gap("command is too short")));
    let full = common::macho::symtab_command(0, 0, 0, 0, false);
    let bytes = common::macho::thin(true, false, common::macho::X86_64, 3, &[full.clone(), full]);
    assert_eq!(
        imports_of(&bytes),
        (vec![], vec!["imports: more than one LC_SYMTAB".to_string()])
    );
}

/// D1: a linked image's symbol table is not what dyld binds, and is not read.
#[test]
fn a_linked_image_s_symbol_table_is_not_read() {
    let blob = chained_fixups(1, &[(1, false, "_puts")]);
    let (table, strings) = common::macho::nlists(true, false, &OBJECT_SYMBOLS[..1]);
    let len = blob.len() as u32;
    let bytes = executable(
        &[LIBSYSTEM],
        |base| {
            vec![
                linkedit_command(LC_DYLD_CHAINED_FIXUPS, base, len, false),
                common::macho::symtab_command(
                    base + len,
                    1,
                    base + len + table.len() as u32,
                    strings.len() as u32,
                    false,
                ),
            ]
        },
        &[blob.as_slice(), &table, &strings].concat(),
    );
    assert_eq!(
        imports_of(&bytes),
        (vec![import("_puts", dylib(1, LIBSYSTEM), false)], vec![])
    );
}

/// Task 2 review: an object file's symbols may all name the same string; each scan stops at its
/// NUL, and all of them at 64 MiB, after which the names are not read.
#[test]
fn object_symbol_names_past_64_mib_of_scanning_are_a_gap() {
    let name = format!("_{}", "a".repeat(59_999));
    let mut table = vec![];
    for _ in 0..1_200 {
        // n_strx 1, N_UNDF | N_EXT, n_sect 0, n_desc 0, n_value 0.
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(&[0x01, 0, 0, 0]);
        table.extend_from_slice(&0u64.to_le_bytes());
    }
    let strings = [&[0u8][..], name.as_bytes(), &[0]].concat();
    assert_eq!(
        imports_of(&common::macho::object(true, false, &table, &strings)),
        (
            vec![import(&name, MachOLibrary::Unbound, false)],
            vec!["imports: symbol table: over 67108864 bytes of names scanned".to_string()]
        )
    );
}
// --- The import fixtures (PR-4c-3b) -------------------------------------------------------------

/// `fixture` (under `tests/fixtures/`), copied to a temporary directory and inspected: the session
/// validates.
fn inspected(fixture: &str) -> sigil_model::Session {
    let directory = TempDir::new().unwrap();
    let path = directory
        .path()
        .join(Path::new(fixture).file_name().unwrap());
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
        &path,
    )
    .unwrap();
    let s = binary_inspection(&path);
    assert_eq!(s.validate(), Ok(()));
    s
}

/// The imports, gaps, and capability hints (feature, value) of the slice of `arch` in `s`.
fn slice_of(
    s: &sigil_model::Session,
    arch: sigil_model::Arch,
) -> (Vec<MachOImport>, Vec<String>, Vec<(String, String)>) {
    let slice = s
        .artifacts
        .iter()
        .flat_map(|a| &a.slices)
        .find(|x| x.arch == arch)
        .unwrap()
        .id
        .clone();
    let b = s.binaries.iter().find(|b| b.slice == slice).unwrap();
    let ContainerFacts::MachO(facts) = &b.container else {
        panic!("{b:?}")
    };
    let hints = s
        .hints
        .iter()
        .filter(|h| h.subject == slice)
        .map(|h| {
            (
                h.feature.as_str().to_string(),
                h.value.as_str().unwrap().to_string(),
            )
        })
        .collect();
    (facts.imports.clone(), b.gaps.clone(), hints)
}

fn hints(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(f, v)| (f.to_string(), v.to_string()))
        .collect()
}

/// The capability imports of the C fixtures: from libSystem in an executable.
const LIBSYSTEM_HINTS: [(&str, &str); 3] = [
    ("posix.dynamic_loading", "_dlopen"),
    ("posix.environment_access", "_getenv"),
    ("posix.network", "_connect"),
];

/// #53's acceptance criterion: an arm64 Mach-O that imports `_connect` gets `posix.network`. Both
/// slices of `macho-imports/imports-universal` (`build.sh`; their imports are in its `.otool`):
/// x86_64 binds through opcodes, arm64 through chained fixups. Each imports `_socket` from libfoo,
/// another dylib: recorded, and no hint (D2).
#[test]
fn a_universal_executable_s_hints_are_its_libsystem_capability_imports() {
    let s = inspected("macho-imports/imports-universal");
    let libfoo = || dylib(2, "@rpath/libfoo.dylib");
    let both = || {
        vec![
            import("_connect", dylib(1, LIBSYSTEM), false),
            import("_dlopen", dylib(1, LIBSYSTEM), false),
            import("_getenv", dylib(1, LIBSYSTEM), false),
            import("_puts", dylib(1, LIBSYSTEM), false),
            import("_sigil_weak", libfoo(), true),
            import("_socket", libfoo(), false),
        ]
    };
    let mut x86_64 = both();
    x86_64.push(import("dyld_stub_binder", dylib(1, LIBSYSTEM), false));
    for (arch, imports) in [
        (sigil_model::Arch::X86_64, x86_64),
        (sigil_model::Arch::Aarch64, both()),
    ] {
        assert_eq!(
            slice_of(&s, arch),
            (imports, vec![], hints(&LIBSYSTEM_HINTS)),
            "{arch:?}"
        );
    }
}

/// The arm64 object file the fixture is linked from: its undefined symbols, left for the linker,
/// are all looked up, `_socket` too: an object file does not say which dylib will define it.
#[test]
fn a_real_object_file_s_hints_are_its_undefined_capability_symbols() {
    let s = inspected("macho-imports/imports-arm64.o");
    let unbound = |name: &str, weak: bool| import(name, MachOLibrary::Unbound, weak);
    let mut expected = hints(&LIBSYSTEM_HINTS);
    expected.push(("posix.network".to_string(), "_socket".to_string()));
    assert_eq!(
        slice_of(&s, sigil_model::Arch::Aarch64),
        (
            vec![
                unbound("_connect", false),
                unbound("_dlopen", false),
                unbound("_getenv", false),
                unbound("_puts", false),
                unbound("_sigil_weak", true),
                unbound("_socket", false),
            ],
            vec![],
            expected
        )
    );
}

/// D7: Go 1.25.6's darwin/arm64 build of the 3a program (`go-darwin/build.sh`) binds its
/// libSystem functions through bind opcodes: each import is one LLVM reads
/// (`capabilities-darwin-arm64.bind`), and its hints are the runtime's and the standard library's,
/// whatever the program uses them for.
#[test]
fn a_go_darwin_executable_s_hints_are_its_runtime_s_capability_imports() {
    let s = inspected("go-darwin/capabilities-darwin-arm64");
    let (imports, gaps, got) = slice_of(&s, sigil_model::Arch::Aarch64);
    assert!(gaps.is_empty(), "{gaps:?}");
    let dump = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/go-darwin/capabilities-darwin-arm64.bind"),
    )
    .unwrap();
    let mut llvm: Vec<&str> = dump
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace().rev();
            match (words.next(), words.next()) {
                (Some(symbol), Some("libSystem")) => Some(symbol),
                _ => None,
            }
        })
        .collect();
    llvm.sort_unstable();
    llvm.dedup();
    assert_eq!(llvm.len(), 83);
    assert_eq!(
        imports,
        llvm.iter()
            .map(|name| import(name, dylib(1, LIBSYSTEM), false))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        got,
        hints(&[
            ("posix.anti_debug", "_ptrace"),
            ("posix.file_read", "_open"),
            ("posix.file_read", "_read"),
            ("posix.file_write", "_write"),
            ("posix.network", "_connect"),
            ("posix.network", "_getaddrinfo"),
            ("posix.network", "_socket"),
            ("posix.process_spawn", "_execve"),
            ("posix.process_spawn", "_fork"),
        ])
    );
}
