//! The assembled session with container facts (PR-4b-1): it validates and verifies, and
//! `artifacts.container` follows spec §4.6.

mod common;

use common::elf::{set_dynamic, without_known_symbols, DT_RELASZ};
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{store_session, ActiveInput, InstallRequest, StoreRequest};
use sigil_engine::policy::Policy;
use sigil_engine::reference::{official, verify_reference_matches};
use sigil_model::*;
use tempfile::TempDir;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// An install of real ELF fixtures only: bin/ollama is the non-PIE executable, lib/ollama holds
/// the shared objects.
fn install() -> TempDir {
    let d = TempDir::new().unwrap();
    let p = d.path();
    std::fs::create_dir_all(p.join("bin")).unwrap();
    std::fs::create_dir_all(p.join("lib/ollama")).unwrap();
    std::fs::write(p.join("bin/ollama"), fixture("elf/exe-nopie")).unwrap();
    std::fs::write(p.join("lib/ollama/libdata.so.1"), fixture("elf/libdata.so")).unwrap();
    d
}

fn session(dir: &std::path::Path) -> Session {
    let models = TempDir::new().unwrap();
    let observation = ObservationMeta {
        started_at: Timestamp::new("2026-10-10T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-10T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    };
    let s = store_session(
        &StoreRequest {
            models_dir: models.path().to_path_buf(),
            model_filter: None,
            budgets: FsBudgets::default(),
            manifest_limit: DEFAULT_MANIFEST_LIMIT,
            install: Some(InstallRequest {
                dir: dir.to_path_buf(),
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
    .unwrap();
    assert_eq!(s.validate(), Ok(()));
    verify_reference_matches(&s, official().unwrap()).unwrap();
    s
}

fn container(s: &Session) -> &CoverageState {
    &s.coverage
        .iter()
        .find(|c| c.check.as_str() == ARTIFACTS_CONTAINER)
        .unwrap()
        .state
}

#[test]
fn real_elf_files_give_facts_declares_and_a_complete_container_check() {
    let d = install();
    let s = session(d.path());
    assert_eq!(container(&s), &CoverageState::Complete, "{:?}", s.binaries);
    assert_eq!(s.binaries.len(), 2);
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == ARTIFACTS_CONTAINER));
    for name in ["binary_parse_bytes", "binary_imports"] {
        assert!(s.request.budgets.contains_key(name), "{name}");
    }
    let declares: Vec<&UntrustedText> = s
        .relations
        .iter()
        .filter_map(|r| match r {
            Relation::Declares {
                needed,
                kind: DeclKind::ElfNeeded,
                ..
            } => Some(needed),
            _ => None,
        })
        .collect();
    assert!(declares.iter().any(|n| n.as_str() == Some("libc.so.6")));
}

#[test]
fn a_gap_makes_the_check_partial_with_the_path() {
    let d = install();
    std::fs::write(
        d.path().join("lib/ollama/libbroken.so"),
        &fixture("elf/libdata.so")[..300],
    )
    .unwrap();
    let s = session(d.path());
    let CoverageState::Partial { missing } = container(&s) else {
        panic!("{:?}", container(&s));
    };
    assert!(
        missing
            .iter()
            .any(|m| m.starts_with("lib/ollama/libbroken.so: ")),
        "{missing:?}"
    );
}

/// The review of the PR-4b-1 plan: a relocation table size that is not whole entries keeps the
/// check from `Complete` even in a file with no known data symbol.
#[test]
fn a_malformed_relocation_size_makes_the_check_partial_without_data_symbols() {
    let d = install();
    let mut bytes = without_known_symbols(&fixture("elf/libdata.so"));
    set_dynamic(&mut bytes, DT_RELASZ, 241);
    std::fs::write(d.path().join("lib/ollama/libbad.so"), bytes).unwrap();
    let s = session(d.path());
    let CoverageState::Partial { missing } = container(&s) else {
        panic!("{:?}", container(&s));
    };
    assert_eq!(
        missing,
        &["lib/ollama/libbad.so: dynamic: malformed: DT_RELASZ is not a whole number of entries"]
    );
}

#[test]
fn release_and_discovery_are_unchanged_by_the_container_check() {
    let d = install();
    let s = session(d.path());
    for check in [ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE] {
        assert!(s.coverage.iter().any(|c| c.check.as_str() == check));
    }
    assert_eq!(
        s.coverage
            .iter()
            .find(|c| c.check.as_str() == ARTIFACTS_DISCOVERY)
            .unwrap()
            .state,
        CoverageState::Complete
    );
}
