//! The assembled binary inspection (PR-4b-2a spec §4.3, §4.5): it validates, evaluates its
//! policy's binary scope, and has exactly one `binary.container` per input.

mod common;

use std::path::{Path, PathBuf};

use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest, InspectError};
use sigil_engine::policy::{outcome, Policy};
use sigil_model::*;
use tempfile::TempDir;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/elf")
            .join(name),
    )
    .unwrap()
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-10T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-10T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: String::new(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

fn session(paths: &[PathBuf]) -> Result<Session, InspectError> {
    session_with(paths, NamedBudgets::default())
}

fn session_with(paths: &[PathBuf], budgets: NamedBudgets) -> Result<Session, InspectError> {
    let o = observation();
    binary_session(
        &BinaryRequest {
            paths: paths.to_vec(),
            budgets,
        },
        &Policy::builtin_default().unwrap(),
        ToolInfo {
            name: "sigil".into(),
            version: "0.0.0-test".into(),
            git_rev: None,
        },
        o.clone(),
        o.started_at,
    )
}

fn state(s: &Session, inst: &str) -> CoverageState {
    s.coverage
        .iter()
        .find(|c| c.scope == Ref::Instance(InstanceId::new(inst).unwrap()))
        .unwrap()
        .state
        .clone()
}

#[test]
fn an_elf_and_a_relocatable_object_are_complete() {
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("libdata.so"), fixture("libdata.so")).unwrap();
    std::fs::write(d.path().join("net.o"), fixture("net.o")).unwrap();
    let s = session(&[d.path().join("libdata.so"), d.path().join("net.o")]).unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(s.request.mode, Mode::Static);
    assert_eq!(
        s.request
            .audit
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>(),
        ["binary"]
    );
    for key in ["binary_bytes", "binary_parse_bytes", "binary_imports"] {
        assert!(s.request.budgets.contains_key(key), "{key}");
    }
    assert_eq!(
        state(&s, "inst:binary-1/libdata.so"),
        CoverageState::Complete
    );
    assert_eq!(state(&s, "inst:binary-2/net.o"), CoverageState::Complete);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(s.relations.iter().any(
        |r| matches!(r, Relation::Declares { needed, .. } if needed.as_str() == Some("libc.so.6"))
    ));
}

#[test]
fn an_unsupported_input_is_incomplete_and_passes() {
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("NOTES.txt"), b"notes").unwrap();
    let s = session(&[d.path().join("NOTES.txt")]).unwrap();
    assert_eq!(
        state(&s, "inst:binary-1/NOTES.txt"),
        CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string()
        }
    );
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

#[test]
fn compiled_java_class_versions_are_unsupported_not_fat_macho() {
    let d = TempDir::new().unwrap();
    let versions = [
        (
            "java8.class",
            include_str!("fixtures/macho/java8.class.hex"),
        ),
        (
            "java17.class",
            include_str!("fixtures/macho/java17.class.hex"),
        ),
        (
            "java21.class",
            include_str!("fixtures/macho/java21.class.hex"),
        ),
    ];
    let paths: Vec<PathBuf> = versions
        .iter()
        .map(|(name, bytes)| {
            let path = d.path().join(name);
            std::fs::write(&path, common::macho::decode_hex(bytes)).unwrap();
            path
        })
        .collect();
    let s = session(&paths).unwrap();
    for name in ["java8.class", "java17.class", "java21.class"] {
        assert_eq!(
            state(
                &s,
                &format!(
                    "inst:binary-{}/{}",
                    paths
                        .iter()
                        .position(|p| p.file_name().unwrap() == name)
                        .unwrap()
                        + 1,
                    name
                )
            ),
            CoverageState::Unsupported {
                what: BINARY_UNSUPPORTED.to_string()
            }
        );
    }
}

#[test]
fn a_malformed_fat_macho_remains_partial_in_binary_inspect() {
    let d = TempDir::new().unwrap();
    let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1];
    bytes.extend_from_slice(&[0; 8]);
    let path = d.path().join("truncated-fat");
    std::fs::write(&path, bytes).unwrap();
    let s = session(&[path]).unwrap();
    assert!(matches!(
        state(&s, "inst:binary-1/truncated-fat"),
        CoverageState::Partial { .. }
    ));
}

#[test]
fn a_linked_universal_executable_is_complete_in_binary_inspect() {
    // fixtures/macho/build.sh: LC_DYLD_INFO_ONLY (x86_64), LC_DYLD_CHAINED_FIXUPS and
    // LC_DYLD_EXPORTS_TRIE (arm64), and LC_MAIN in both slices, before LC_LOAD_DYLIB.
    let d = TempDir::new().unwrap();
    let path = d.path().join("hello");
    std::fs::write(&path, include_bytes!("fixtures/macho/hello-universal")).unwrap();
    let s = session(&[path]).unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(state(&s, "inst:binary-1/hello"), CoverageState::Complete);
    assert_eq!(s.binaries.len(), 2);
    assert!(
        s.binaries.iter().all(|f| f.gaps.is_empty()),
        "{:?}",
        s.binaries
    );
    let declared: Vec<_> = s
        .relations
        .iter()
        .filter_map(|r| match r {
            Relation::Declares {
                needed,
                kind: DeclKind::MachOLoadDylib,
                ..
            } => needed.as_str(),
            _ => None,
        })
        .collect();
    assert_eq!(
        declared,
        ["/usr/lib/libSystem.B.dylib", "/usr/lib/libSystem.B.dylib"]
    );
}

#[test]
fn fat_tables_with_a_repeated_or_mismatched_architecture_are_partial_and_valid() {
    // The validator's B2 accepts the engine's own gaps for both. `mismatched`'s table entry is
    // the architecture `twice` lists twice: another artifact's slices do not count.
    let x86 = common::macho::thin(true, false, common::macho::X86_64, 3, &[]);
    let arm = common::macho::thin(true, false, common::macho::AARCH64, 0, &[]);
    let d = TempDir::new().unwrap();
    let twice = d.path().join("twice");
    std::fs::write(
        &twice,
        common::macho::fat32(&[
            (x86.clone(), common::macho::X86_64, 3),
            (x86, common::macho::X86_64, 3),
        ]),
    )
    .unwrap();
    let mismatched = d.path().join("mismatched");
    std::fs::write(
        &mismatched,
        common::macho::fat32(&[(arm, common::macho::X86_64, 3)]),
    )
    .unwrap();
    let s = session(&[twice, mismatched]).unwrap();
    assert_eq!(s.validate(), Ok(()));
    for (inst, gap) in [
        ("inst:binary-1/twice", FAT_DUPLICATE_ARCH_GAP),
        ("inst:binary-2/mismatched", FAT_CPU_MISMATCH_GAP),
    ] {
        let CoverageState::Partial { missing } = state(&s, inst) else {
            panic!("{inst}: {:?}", state(&s, inst));
        };
        assert!(missing.iter().any(|m| m == gap), "{inst}: {missing:?}");
    }
}

#[test]
fn a_dropped_coverage_entry_would_close_the_check_but_validate_refuses_it() {
    // The review's case (P1-2): a complete input and a partial one; the partial entry removed.
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("good.so"), fixture("libdata.so")).unwrap();
    std::fs::write(d.path().join("cut.so"), &fixture("libdata.so")[..300]).unwrap();
    let mut s = session(&[d.path().join("good.so"), d.path().join("cut.so")]).unwrap();
    assert!(matches!(
        state(&s, "inst:binary-2/cut.so"),
        CoverageState::Partial { .. }
    ));
    s.coverage
        .retain(|c| c.scope != Ref::Instance(InstanceId::new("inst:binary-2/cut.so").unwrap()));
    let t = s.outcome.policy_time.clone();
    assert_eq!(outcome(&s, t).completeness, Completeness::Complete);
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("0 binary.container entries")),
        "{errors:?}"
    );
}

#[test]
fn a_missing_input_is_an_input_error() {
    let d = TempDir::new().unwrap();
    let e = session(&[d.path().join("missing")]).unwrap_err();
    assert!(
        matches!(&e, InspectError::Input(m) if m.contains("not found")),
        "{e}"
    );
}

/// Review of Part B: an input over `binary_bytes`, end to end. It is `BudgetExceeded` with the
/// bytes hashed before it as `used`; a later input that fits is read; the session validates.
#[test]
fn an_input_over_binary_bytes_is_budget_exceeded_with_its_used() {
    let d = TempDir::new().unwrap();
    let so = fixture("libdata.so");
    std::fs::write(d.path().join("libdata.so"), &so).unwrap();
    std::fs::write(d.path().join("net.o"), fixture("net.o")).unwrap();
    std::fs::write(d.path().join("NOTES.txt"), b"notes").unwrap();
    let limit = so.len() as u64 + 10;
    let s = session_with(
        &[
            d.path().join("libdata.so"),
            d.path().join("net.o"),
            d.path().join("NOTES.txt"),
        ],
        NamedBudgets {
            bytes: limit,
            ..NamedBudgets::default()
        },
    )
    .unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(
        state(&s, "inst:binary-2/net.o"),
        CoverageState::BudgetExceeded {
            budget: BINARY_BYTES.to_string(),
            used: so.len() as u64,
            limit,
        }
    );
    assert!(matches!(
        state(&s, "inst:binary-3/NOTES.txt"),
        CoverageState::Unsupported { .. }
    ));
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

/// Two inputs with one content: one artifact and one record, two coverage entries.
#[test]
fn one_content_under_two_inputs_has_one_record_and_two_entries() {
    let d = TempDir::new().unwrap();
    std::fs::write(d.path().join("a.so"), fixture("libdata.so")).unwrap();
    std::fs::write(d.path().join("b.so"), fixture("libdata.so")).unwrap();
    let s = session(&[d.path().join("a.so"), d.path().join("b.so")]).unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(s.artifacts.len(), 1);
    assert_eq!(s.binaries.len(), 1);
    assert_eq!(state(&s, "inst:binary-1/a.so"), CoverageState::Complete);
    assert_eq!(state(&s, "inst:binary-2/b.so"), CoverageState::Complete);
    let md = sigil_model::render::markdown::render_session(&s);
    assert_eq!(md.matches("Facts of").count(), 1, "{md}");
}

#[test]
fn no_input_is_an_input_error() {
    let e = session(&[]).unwrap_err();
    assert!(
        matches!(&e, InspectError::Input(m) if m.contains("no input")),
        "{e}"
    );
}
