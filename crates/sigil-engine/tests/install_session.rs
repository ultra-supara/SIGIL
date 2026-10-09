//! The assembled session with `--install-dir` (PR-4a): it validates and verifies against the
//! embedded set, a policy that requires the install's checks without one is incomplete, and the
//! verifier rejects what `validate` cannot re-derive. Synthetic trees only: no test reads a real
//! installation.

use std::os::unix::fs::symlink;
use std::path::Path;

use sigil_engine::analyze::release::analyze;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::{collect, InstallBudgets};
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{store_session, ActiveInput, InstallRequest, StoreRequest};
use sigil_engine::policy::{evaluate, Policy};
use sigil_engine::reference::{official, parse_set, verify_reference_matches, RefSet};
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::{blob, manifest, LIB, MODEL_MEDIA};

fn tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: "0.0.0-test".to_string(),
        git_rev: None,
    }
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-09T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-09T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

/// `bin/ollama` and `lib/ollama/` with a library, a symlink to it, and a subdirectory with one
/// non-ELF file: synthetic bytes, so no file matches an official member.
fn install() -> TempDir {
    let d = TempDir::new().unwrap();
    let p = d.path();
    std::fs::create_dir_all(p.join("bin")).unwrap();
    std::fs::create_dir_all(p.join("lib/ollama/cuda_v12")).unwrap();
    std::fs::write(p.join("bin/ollama"), elf(2)).unwrap();
    std::fs::write(p.join("lib/ollama/libggml.so.0.13.1"), elf(3)).unwrap();
    symlink("libggml.so.0.13.1", p.join("lib/ollama/libggml.so.0")).unwrap();
    std::fs::write(
        p.join("lib/ollama/cuda_v12/libcudart.so.12.8.90"),
        b"weights",
    )
    .unwrap();
    d
}

fn elf(e_type: u16) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[6] = 1;
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h[18..20].copy_from_slice(&62u16.to_le_bytes());
    h
}

fn request(models: &Path, install: Option<&Path>) -> StoreRequest {
    StoreRequest {
        models_dir: models.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: install.map(|dir| InstallRequest {
            dir: dir.to_path_buf(),
            budgets: InstallBudgets::default(),
        }),
    }
}

fn session(req: &StoreRequest, policy: &Policy) -> Session {
    let s = store_session(
        req,
        &ActiveInput::default(),
        policy,
        tool(),
        observation(),
        observation().started_at,
    )
    .unwrap();
    assert_eq!(s.validate(), Ok(()));
    s
}

fn inspect_with_install(tree: &TempDir) -> Session {
    let models = TempDir::new().unwrap();
    session(
        &request(models.path(), Some(tree.path())),
        &Policy::builtin_default().unwrap(),
    )
}

fn inspect_without_install(policy: Policy) -> Session {
    let models = TempDir::new().unwrap();
    session(&request(models.path(), None), &policy)
}

fn state<'a>(s: &'a Session, check: &str) -> &'a CoverageState {
    &s.coverage
        .iter()
        .find(|c| c.check.as_str() == check)
        .unwrap_or_else(|| panic!("no coverage for {check}"))
        .state
}

#[test]
fn a_session_with_an_install_validates_and_verifies() {
    let tree = install();
    let s = inspect_with_install(&tree);
    verify_reference_matches(&s, official().unwrap()).unwrap();
    assert!(s
        .request
        .audit
        .iter()
        .any(|a| a.as_str() == "runtime_artifacts"));
    for check in [ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE] {
        assert!(s
            .request
            .required_checks
            .iter()
            .any(|c| c.as_str() == check));
    }
    assert!(s
        .knowledge
        .iter()
        .any(|k| k.kind == KnowledgeKind::ReferenceManifest && k.id == "ollama-official"));
    assert!(s
        .request
        .roots
        .iter()
        .any(|r| r.id.as_str() == INSTALL_ROOT));
    for name in [
        "install_files_discovered",
        "install_entries_listed",
        "install_directory_entries",
        "install_walk_depth",
        "install_link_hops",
        "install_bytes",
    ] {
        assert!(s.request.budgets.contains_key(name), "{name}");
    }
    // Discovery is complete, no file matches: no claim, and every release gets its Absent rows.
    assert_eq!(state(&s, ARTIFACTS_DISCOVERY), &CoverageState::Complete);
    assert!(matches!(
        state(&s, ARTIFACTS_RELEASE),
        CoverageState::Partial { .. }
    ));
    assert!(s.releases.is_empty());
    for tag in ["v0.30.5", "v0.30.6", "v0.30.7"] {
        assert!(
            s.reference_matches
                .iter()
                .any(|r| r.release == tag && matches!(r.result, MemberResult::Absent { .. })),
            "{tag}"
        );
    }
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

#[test]
fn a_missing_install_directory_is_unavailable_and_has_no_rows() {
    let tree = TempDir::new().unwrap();
    let models = TempDir::new().unwrap();
    let s = session(
        &request(models.path(), Some(&tree.path().join("nonexistent"))),
        &Policy::builtin_default().unwrap(),
    );
    verify_reference_matches(&s, official().unwrap()).unwrap();
    assert_eq!(
        state(&s, ARTIFACTS_DISCOVERY),
        &CoverageState::Unavailable {
            why: Unavailability::NotFound
        }
    );
    assert!(s.reference_matches.is_empty());
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

#[test]
fn an_artifact_in_both_roots_is_recorded_once() {
    // The model store's weights and an install file have the same bytes.
    let models = TempDir::new().unwrap();
    let weights = blob(models.path(), b"weights");
    manifest(models.path(), LIB, None, &[(MODEL_MEDIA, &weights)]);
    let tree = install();
    let s = session(
        &request(models.path(), Some(tree.path())),
        &Policy::builtin_default().unwrap(),
    );
    let shared: Vec<&Artifact> = s
        .artifacts
        .iter()
        .filter(|a| a.id.as_str() == weights)
        .collect();
    assert_eq!(shared.len(), 1);
    let placed: Vec<&RootId> = s
        .instances
        .iter()
        .filter(|i| {
            i.content
                == (InstanceContent::Read {
                    artifact: shared[0].id.clone(),
                })
        })
        .map(|i| &i.root)
        .collect();
    assert_eq!(placed.len(), 2, "one placement under each root");
}

#[test]
fn an_elf_in_both_roots_keeps_the_install_s_format_and_slice() {
    // The model store does not parse executables: its reading of the same bytes is `Other`.
    let models = TempDir::new().unwrap();
    let weights = blob(models.path(), &elf(3));
    manifest(models.path(), LIB, None, &[(MODEL_MEDIA, &weights)]);
    let tree = install();
    let s = session(
        &request(models.path(), Some(tree.path())),
        &Policy::builtin_default().unwrap(),
    );
    let shared: Vec<&Artifact> = s
        .artifacts
        .iter()
        .filter(|a| a.id.as_str() == weights)
        .collect();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].format, Format::Elf { kind: ElfType::Dyn });
    assert_eq!(shared[0].slices.len(), 1);
    let placed: Vec<&RootId> = s
        .instances
        .iter()
        .filter(|i| {
            i.content
                == (InstanceContent::Read {
                    artifact: shared[0].id.clone(),
                })
        })
        .map(|i| &i.root)
        .collect();
    assert_eq!(placed.len(), 2, "one placement under each root");
}

#[test]
fn without_an_install_the_default_requires_nothing_new_and_a_custom_policy_is_skipped() {
    let s = inspect_without_install(Policy::builtin_default().unwrap());
    assert!(!s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str().starts_with("artifacts.")));
    assert!(!s
        .coverage
        .iter()
        .any(|c| c.check.as_str().starts_with("artifacts.")));
    assert!(s
        .knowledge
        .iter()
        .all(|k| k.kind != KnowledgeKind::ReferenceManifest));

    let custom = Policy::load(
        "schema = \"sigil-policy/1\"\nname = \"c\"\n[scope]\naudit = [\"model_store\", \"runtime_artifacts\"]\n",
    )
    .unwrap();
    let s = inspect_without_install(custom);
    for check in [ARTIFACTS_DISCOVERY, ARTIFACTS_RELEASE] {
        let c = s
            .coverage
            .iter()
            .find(|c| c.check.as_str() == check)
            .unwrap();
        assert_eq!(c.scope, Ref::Audit);
        assert!(
            matches!(&c.state, CoverageState::Skipped { by: SkipReason::Flag { flag } } if flag == "--install-dir"),
            "{c:?}"
        );
    }
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

#[test]
fn the_verifier_rejects_tampering_that_validate_cannot_see() {
    let tree = install();
    let s = inspect_with_install(&tree);
    let set = official().unwrap();
    let absent = |t: &Session| {
        t.reference_matches
            .iter()
            .position(
                |r| matches!(r.result, MemberResult::Absent { kind } if kind == MemberKind::File),
            )
            .unwrap()
    };
    // A tampered expected value: an absent file member recorded as a directory.
    let mut t = s.clone();
    let at = absent(&t);
    t.reference_matches[at].result = MemberResult::Absent {
        kind: MemberKind::Directory,
    };
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&t, set).is_err());
    // A removed Absent row.
    let mut t = s.clone();
    let at = absent(&t);
    t.reference_matches.remove(at);
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&t, set).is_err());
    // Every row of one release removed.
    let mut t = s.clone();
    t.reference_matches.retain(|r| r.release != "v0.30.7");
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&t, set).is_err());
}

/// Two releases whose manifests both describe `install()` exactly.
fn identical_pair() -> RefSet {
    use serde_json::json;
    let hex = |b: &[u8]| common::hex(b);
    let manifest = |tag: &str| {
        json!({"tag": tag, "entries": [
            {"name": "bin/ollama", "type": "0", "mode": "0o755", "sha256": hex(&elf(2)), "size": 64},
            {"name": "lib/ollama/cuda_v12", "type": "5", "mode": "0o755"},
            {"name": "lib/ollama/cuda_v12/libcudart.so.12.8.90", "type": "0", "mode": "0o644", "sha256": hex(b"weights"), "size": 7},
            {"name": "lib/ollama/libggml.so.0", "type": "2", "mode": "0o777", "link": "libggml.so.0.13.1"},
            {"name": "lib/ollama/libggml.so.0.13.1", "type": "0", "mode": "0o644", "sha256": hex(&elf(3)), "size": 64},
        ]})
        .to_string()
    };
    let (a, b) = (manifest("vA"), manifest("vB"));
    parse_set("ollama-official", "test", &[("a.json", &a), ("b.json", &b)]).unwrap()
}

/// The review's case: two identical releases, a claim for both; with every vB row removed and the
/// candidates set to `[vA]`, `validate` re-derives `[vA]` from what is left and passes. Only the
/// verifier, which knows vB lists the same members, rejects it.
#[test]
fn removing_one_identical_release_passes_validate_and_fails_the_verifier() {
    let tree = install();
    let mut s = inspect_with_install(&tree);
    let refs = identical_pair();
    let r = analyze(
        &collect(tree.path(), InstallBudgets::default()).unwrap(),
        &refs,
    )
    .unwrap();
    for k in &mut s.knowledge {
        if k.kind == KnowledgeKind::ReferenceManifest {
            *k = refs.knowledge();
        }
    }
    s.reference_matches = r.rows;
    s.releases = r.claim.into_iter().collect();
    for c in &mut s.coverage {
        if c.check.as_str() == ARTIFACTS_RELEASE {
            *c = r.coverage.clone();
        }
    }
    let policy = Policy::builtin_default().unwrap();
    let time = s.outcome.policy_time.clone();
    evaluate(&mut s, &policy, time).unwrap();
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
    verify_reference_matches(&s, &refs).unwrap();
    assert_eq!(s.releases[0].candidates, ["vA", "vB"]);
    assert_eq!(state(&s, ARTIFACTS_RELEASE), &CoverageState::Complete);

    s.reference_matches.retain(|r| r.release != "vB");
    s.releases[0].candidates = vec!["vA".to_string()];
    assert_eq!(s.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&s, &refs).is_err());
}
