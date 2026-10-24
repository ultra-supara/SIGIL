//! The assembled session with `--install-dir` (PR-4a): it validates and verifies against the
//! embedded set, a policy that requires the install's checks without one is incomplete, and the
//! verifier rejects what `validate` cannot re-derive. Its ELF files carry component claims whose
//! known hashes are their reference rows (PR-4c-1). A self-reported commit gives an open release
//! claim (PR-4c-2c). Synthetic trees only: no test reads a real installation.

use std::os::unix::fs::symlink;
use std::path::Path;

use sigil_engine::analyze::identity::derive;
use sigil_engine::analyze::release::{analyze, claims, open};
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::{collect, InstallBudgets};
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{store_session, ActiveInput, InstallRequest, StoreRequest};
use sigil_engine::policy::{evaluate, Policy};
use sigil_engine::reference::{
    names, official, parse_set, verify_reference_matches, verify_release_claims, RefSet,
};
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
    verify_release_claims(&s, official().unwrap()).unwrap();
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
    // PR-4c-2a: discovery could not run, so artifacts.identity is its state.
    assert_eq!(
        state(&s, ARTIFACTS_IDENTITY),
        state(&s, ARTIFACTS_DISCOVERY)
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
    for check in [
        ARTIFACTS_DISCOVERY,
        ARTIFACTS_RELEASE,
        ARTIFACTS_CONTAINER,
        ARTIFACTS_IDENTITY,
    ] {
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
    // Every row of one release removed, with the known hashes that rest on them (PR-4c-1).
    let mut t = s.clone();
    t.reference_matches.retain(|r| r.release != "v0.30.7");
    drop_known_hashes(&mut t, "v0.30.7");
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&t, set).is_err());
}

/// Removes the claims' `KnownHash` assertions of `release`: a removed row takes the hash that
/// rests on it (PR-4c-1 I1).
fn drop_known_hashes(s: &mut Session, release: &str) {
    for c in &mut s.components {
        c.assertions.retain(
            |a| !matches!(a, IdentityAssertion::KnownHash { release: r, .. } if r == release),
        );
    }
}

/// Two releases whose manifests both describe `install()` exactly.
fn identical_pair() -> RefSet {
    identical_pair_with(&[])
}

/// Two releases whose manifests both describe `install()` and the `extra` entries exactly.
fn identical_pair_with(extra: &[serde_json::Value]) -> RefSet {
    identical_pair_with_commits(extra, None)
}

/// [`identical_pair_with`], with the `commits.toml` given.
fn identical_pair_with_commits(extra: &[serde_json::Value], commits: Option<&str>) -> RefSet {
    pair_named("ollama-official", extra, commits)
}

/// [`identical_pair_with_commits`] for the set `id`.
fn pair_named(id: &str, extra: &[serde_json::Value], commits: Option<&str>) -> RefSet {
    use serde_json::json;
    let hex = |b: &[u8]| common::hex(b);
    let manifest = |tag: &str| {
        let mut entries = vec![
            json!({"name": "bin/ollama", "type": "0", "mode": "0o755", "sha256": hex(&elf(2)), "size": 64}),
            json!({"name": "lib/ollama/cuda_v12", "type": "5", "mode": "0o755"}),
            json!({"name": "lib/ollama/cuda_v12/libcudart.so.12.8.90", "type": "0", "mode": "0o644", "sha256": hex(b"weights"), "size": 7}),
            json!({"name": "lib/ollama/libggml.so.0", "type": "2", "mode": "0o777", "link": "libggml.so.0.13.1"}),
            json!({"name": "lib/ollama/libggml.so.0.13.1", "type": "0", "mode": "0o644", "sha256": hex(&elf(3)), "size": 64}),
        ];
        entries.extend(extra.iter().cloned());
        json!({"tag": tag, "entries": entries}).to_string()
    };
    let (a, b) = (manifest("vA"), manifest("vB"));
    let mut files = vec![("a.json", a.as_str()), ("b.json", b.as_str())];
    if let Some(toml) = commits {
        files.push(("commits.toml", toml));
    }
    parse_set(id, "test", &files).unwrap()
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
    // The claims rest on the rows (PR-4c-1).
    s.components = derive(&s.instances, &s.binaries, &s.reference_matches).unwrap();
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
    drop_known_hashes(&mut s, "vB");
    s.releases[0].candidates = vec!["vA".to_string()];
    assert_eq!(s.validate(), Ok(()), "validate cannot see it");
    assert!(verify_reference_matches(&s, &refs).is_err());
}

/// PR-4c-1: each ELF of the tree gets a claim; the non-ELF file gets none. `libggml.so.0.13.1`
/// is named by itself and by its link, and its known hashes are its rows, none matched
/// (synthetic bytes).
#[test]
fn each_elf_of_the_install_gets_a_claim_with_its_rows() {
    let tree = install();
    let s = inspect_with_install(&tree);
    assert_eq!(s.components.len(), 2, "{:?}", s.components);
    let claim = |key: &str| {
        s.components
            .iter()
            .find(|c| c.component.as_str() == key)
            .unwrap_or_else(|| panic!("no {key} claim: {:?}", s.components))
    };
    let ggml = claim("ggml");
    assert_eq!(ggml.status, IdentityStatus::NameOnly);
    let names: Vec<&str> = ggml
        .assertions
        .iter()
        .filter_map(|a| match a {
            IdentityAssertion::SelfName { value, .. } => value.as_str(),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["libggml.so.0", "libggml.so.0.13.1"]);
    let known: Vec<(&str, &str, bool)> = ggml
        .assertions
        .iter()
        .filter_map(|a| match a {
            IdentityAssertion::KnownHash {
                release,
                member,
                matched,
                ..
            } => Some((release.as_str(), member.as_str(), *matched)),
            _ => None,
        })
        .collect();
    let member = "lib/ollama/libggml.so.0.13.1";
    assert_eq!(
        known,
        [
            ("v0.30.5", member, false),
            ("v0.30.6", member, false),
            ("v0.30.7", member, false)
        ]
    );
    let versions: Vec<&str> = ggml
        .versions
        .iter()
        .map(|v| v.value.as_str().unwrap())
        .collect();
    assert_eq!(versions, ["0", "0.13.1"]);
    assert_eq!(claim("ollama").status, IdentityStatus::NameOnly);
}

/// PR-4c-1: against a set that lists the tree's bytes, both ELF files are reference-matched for
/// both releases. This calls `derive` directly on the collected facts and the set's rows: an
/// assembled install session checks against the embedded official set only, so `ReferenceMatched`
/// through a real install session is checked by the manual R-1 run on the local install.
#[test]
fn a_matching_reference_set_makes_the_claims_reference_matched() {
    let tree = install();
    let facts = collect(tree.path(), InstallBudgets::default()).unwrap();
    let r = analyze(&facts, &identical_pair()).unwrap();
    let claims = derive(&facts.instances, &facts.binaries, &r.rows).unwrap();
    assert_eq!(claims.len(), 2, "{claims:?}");
    for c in &claims {
        assert_eq!(c.status, IdentityStatus::ReferenceMatched, "{c:?}");
        let matched: Vec<&str> = c
            .assertions
            .iter()
            .filter_map(|a| match a {
                IdentityAssertion::KnownHash {
                    release,
                    matched: true,
                    ..
                } => Some(release.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(matched, ["vA", "vB"], "{}", c.component);
    }
}

/// `install()` with the fixture `libdata.so`, which reports `LLAMA_COMMIT` `6f3a9f3de`, as
/// `lib/ollama/libllama-common.so.0.0.1`.
fn install_with_a_commit() -> TempDir {
    let tree = install();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so");
    std::fs::copy(
        fixture,
        tree.path().join("lib/ollama/libllama-common.so.0.0.1"),
    )
    .unwrap();
    tree
}

/// PR-4c-2c: the fixture `libdata.so` placed as `libllama-common.so.0.0.1` matches no reference,
/// and reports `LLAMA_COMMIT` `6f3a9f3de`, as the official releases' files do: an open claim for
/// all three, resting on that commit. `artifacts.release` stays `Partial`.
#[test]
fn a_self_reported_commit_gives_an_open_release_claim() {
    let tree = install_with_a_commit();
    let s = inspect_with_install(&tree);
    verify_reference_matches(&s, official().unwrap()).unwrap();
    verify_release_claims(&s, official().unwrap()).unwrap();
    let [claim] = s.releases.as_slice() else {
        panic!("one claim: {:?}", s.releases);
    };
    assert_eq!(claim.product.as_str(), "ollama");
    assert_eq!(claim.candidates, ["v0.30.5", "v0.30.6", "v0.30.7"]);
    let ReleaseBasis::SelfReportedCommit { commits } = &claim.basis else {
        panic!("an open claim: {:?}", claim.basis);
    };
    let common = s
        .components
        .iter()
        .find(|c| c.component.as_str() == "llama.cpp/common")
        .unwrap();
    let shown: Vec<(&str, Option<&str>)> = commits
        .iter()
        .map(|c| (c.field.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(shown, [("LLAMA_COMMIT", Some("6f3a9f3de"))]);
    assert!(
        matches!(&commits[0].at, EvidenceRef::Code { slice, .. } if *slice == common.subject),
        "{:?}",
        commits[0].at
    );
    assert!(matches!(
        state(&s, ARTIFACTS_RELEASE),
        CoverageState::Partial { .. }
    ));
}

/// PR-4c-2c: `validate` checks that an open claim rests on the session's own commits; only the
/// verifier knows which releases report them.
#[test]
fn the_verifier_recomputes_the_open_release_claim() {
    let tree = install_with_a_commit();
    let s = inspect_with_install(&tree);
    let set = official().unwrap();
    // Other candidates.
    let mut t = s.clone();
    t.releases[0].candidates = vec!["v0.30.6".to_string()];
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_release_claims(&t, set).is_err());
    // The claim dropped.
    let mut t = s.clone();
    t.releases.clear();
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_release_claims(&t, set).is_err());
    // A commit no release reports, in the claim and in the assertion it rests on.
    let mut t = s.clone();
    let other = UntrustedText::new("1111111");
    for c in &mut t.components {
        for a in &mut c.assertions {
            if let IdentityAssertion::Embedded { field, value, .. } = a {
                if field == "LLAMA_COMMIT" {
                    *value = other.clone();
                }
            }
        }
    }
    if let ReleaseBasis::SelfReportedCommit { commits } = &mut t.releases[0].basis {
        commits[0].value = other;
    }
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_release_claims(&t, set).is_err());
    // A session made with another version of the set (its id, another SHA-256) is not checked,
    // whatever its claim; it passes `validate`.
    let mut t = s.clone();
    for k in &mut t.knowledge {
        if k.kind == KnowledgeKind::ReferenceManifest {
            k.sha256 = Sha256Hex::new("0".repeat(64)).unwrap();
        }
    }
    t.releases[0].candidates = vec!["v0.30.6".to_string()];
    assert_eq!(t.validate(), Ok(()), "an older set version is legitimate");
    assert!(verify_release_claims(&t, set).is_ok());
    // A closed claim the rows do not give is refused (a genuine one passes:
    // `a_closed_claim_relabelled_to_another_product_is_refused`).
    let mut t = s.clone();
    t.releases[0].basis = ReleaseBasis::ReferenceMatches {
        reference: set.id.clone(),
        files: vec![],
    };
    assert!(verify_release_claims(&t, set).is_err());
}

/// PR-4c-2c: `names` tells a session that names the set, one made with another version of it
/// (not checked), and one that has the set's SHA-256 under another id (refused).
#[test]
fn names_tells_the_set_another_version_and_another_id() {
    let tree = install_with_a_commit();
    let s = inspect_with_install(&tree);
    let set = official().unwrap();
    assert_eq!(names(&s, set), Ok(true));
    let mut t = s.clone();
    for k in &mut t.knowledge {
        if k.kind == KnowledgeKind::ReferenceManifest {
            k.sha256 = Sha256Hex::new("0".repeat(64)).unwrap();
        }
    }
    assert_eq!(names(&t, set), Ok(false));
    assert_eq!(verify_release_claims(&t, set), Ok(()));
    let mut t = s.clone();
    for k in &mut t.knowledge {
        if k.kind == KnowledgeKind::ReferenceManifest {
            k.id = "x".to_string();
        }
    }
    assert!(names(&t, set).is_err());
    assert!(verify_release_claims(&t, set).is_err());
    assert!(verify_reference_matches(&t, set).is_err());
    let mut t = s.clone();
    t.knowledge
        .retain(|k| k.kind != KnowledgeKind::ReferenceManifest);
    assert_eq!(names(&t, set), Ok(false));
}

/// PR-4c-2c: a closed claim counts only when it rests on this set, and a session that names the
/// set has no row of another reference. A session as a run with `another-set` writes it, with the
/// embedded set's knowledge entry added: it validates, and both verifiers refuse it.
#[test]
fn a_closed_claim_against_another_set_is_refused() {
    let tree = install_with_a_commit();
    let mut s = inspect_with_install(&tree);
    let lib = std::fs::read(tree.path().join("lib/ollama/libllama-common.so.0.0.1")).unwrap();
    let other = pair_named(
        "another-set",
        &[serde_json::json!({
            "name": "lib/ollama/libllama-common.so.0.0.1", "type": "0", "mode": "0o644",
            "sha256": common::hex(&lib), "size": lib.len(),
        })],
        None,
    );
    install_as_a_run_with(&mut s, &tree, &other);
    assert_eq!(s.releases[0].candidates, ["vA", "vB"]);
    let set = official().unwrap();
    s.knowledge.push(set.knowledge());
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()));
    let errors = verify_reference_matches(&s, set).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("a row names reference set another-set")),
        "{errors:?}"
    );
    assert!(verify_release_claims(&s, set).is_err());
}

/// A session as a run writes it with a set that lists `libllama-common` and its commit, so that
/// the closed claim is `[vA, vB]` and the open claim `open` gives is the same two releases.
fn closed_session_with_commits() -> (Session, RefSet) {
    let tree = install_with_a_commit();
    let mut s = inspect_with_install(&tree);
    let lib = std::fs::read(tree.path().join("lib/ollama/libllama-common.so.0.0.1")).unwrap();
    let member = "lib/ollama/libllama-common.so.0.0.1";
    let commits: String = ["vA", "vB"]
        .iter()
        .map(|tag| {
            format!(
                "[[release]]\ntag = \"{tag}\"\ncommits = [{{ field = \"LLAMA_COMMIT\", \
             member = \"{member}\", value = \"6f3a9f3de\" }}]\n"
            )
        })
        .collect();
    let refs = identical_pair_with_commits(
        &[serde_json::json!({
            "name": member, "type": "0", "mode": "0o644",
            "sha256": common::hex(&lib), "size": lib.len(),
        })],
        Some(&commits),
    );
    install_as_a_run_with(&mut s, &tree, &refs);
    (s, refs)
}

/// PR-4c-2c: the verifier recomputes the closed claim too. A genuine closed claim passes; V10
/// does not look at the product of a closed claim, so one relabelled to another product, with the
/// open claim the commits give beside it, passes `validate` and is refused by the verifier.
#[test]
fn a_closed_claim_relabelled_to_another_product_is_refused() {
    let (s, refs) = closed_session_with_commits();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(s.releases[0].candidates, ["vA", "vB"]);
    verify_reference_matches(&s, &refs).unwrap();
    assert_eq!(
        verify_release_claims(&s, &refs),
        Ok(()),
        "a genuine closed claim"
    );
    let mut t = s.clone();
    t.releases[0].product = ComponentKey::new("another-product").unwrap();
    t.releases.extend(open(&t.components, &refs).unwrap());
    t.canonicalize();
    assert_eq!(t.releases.len(), 2);
    assert_eq!(t.validate(), Ok(()), "V10 does not check the product");
    verify_reference_matches(&t, &refs).unwrap();
    assert!(verify_release_claims(&t, &refs).is_err());
}

/// PR-4c-2c: a closed claim dropped, `artifacts.release` set to `Partial` (V11 ties only
/// `Complete` to a closed claim), and the open claim the commits give added: `validate` passes,
/// the verifier recomputes the closed claim from the rows and refuses it.
#[test]
fn a_closed_claim_downgraded_to_an_open_one_is_refused() {
    let (s, refs) = closed_session_with_commits();
    let mut t = s.clone();
    t.releases.clear();
    for c in &mut t.coverage {
        if c.check.as_str() == ARTIFACTS_RELEASE {
            c.state = CoverageState::Partial {
                missing: vec!["a reason".to_string()],
            };
        }
    }
    t.releases.extend(open(&t.components, &refs).unwrap());
    // The policy requires `artifacts.release`: the outcome follows the coverage.
    let policy = Policy::builtin_default().unwrap();
    let time = t.outcome.policy_time.clone();
    evaluate(&mut t, &policy, time).unwrap();
    t.canonicalize();
    assert_eq!(t.releases.len(), 1);
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    verify_reference_matches(&t, &refs).unwrap();
    assert!(verify_release_claims(&t, &refs).is_err());
}

/// PR-4c-2c: a closed claim's `files` are compared in canonical order, as a saved session may
/// list them.
#[test]
fn a_closed_claim_with_its_files_reversed_is_accepted() {
    let (s, refs) = closed_session_with_commits();
    let mut t = s.clone();
    let ReleaseBasis::ReferenceMatches { files, .. } = &mut t.releases[0].basis else {
        panic!("a closed claim: {:?}", t.releases);
    };
    assert!(files.len() > 1);
    files.reverse();
    assert_ne!(t.releases, s.releases);
    assert_eq!(t.validate(), Ok(()));
    assert_eq!(verify_release_claims(&t, &refs), Ok(()));
}

/// PR-4c-2c: the engine makes no release claim without an install root (and V12 forbids an open
/// one), so the verifier refuses a session that has one. `validate` need not accept it.
#[test]
fn a_release_claim_without_an_install_root_is_refused() {
    let tree = install_with_a_commit();
    let s = inspect_with_install(&tree);
    let set = official().unwrap();
    assert_eq!(verify_release_claims(&s, set), Ok(()));
    let mut t = s.clone();
    t.request.roots.retain(|r| r.id.as_str() != INSTALL_ROOT);
    assert_eq!(t.releases.len(), 1);
    assert!(verify_release_claims(&t, set).is_err());
}

/// PR-4c-2c: after a discovery that ran out of budget the engine makes no closed claim, even when
/// every placement found matches a release, and the open claim of the commits stands. The
/// verifier takes `complete` from the discovery coverage.
#[test]
fn an_open_claim_after_a_partial_discovery_verifies() {
    let tree = install_with_a_commit();
    let (_, refs) = closed_session_with_commits();
    let models = TempDir::new().unwrap();
    let mut found = None;
    for n in (1..=6).rev() {
        let mut req = request(models.path(), Some(tree.path()));
        let budgets = InstallBudgets {
            files: n,
            ..InstallBudgets::default()
        };
        req.install.as_mut().unwrap().budgets = budgets;
        let s = session(&req, &Policy::builtin_default().unwrap());
        let partial = matches!(
            state(&s, ARTIFACTS_DISCOVERY),
            CoverageState::BudgetExceeded { .. }
        );
        let has_lib = s
            .instances
            .iter()
            .any(|i| i.path.as_bytes().ends_with(b"libllama-common.so.0.0.1"));
        if partial && has_lib {
            found = Some((s, budgets));
            break;
        }
    }
    let (mut s, budgets) = found.expect("a budget that cuts the discovery short, past the library");
    // The engine's own session: an open claim, no closed one.
    let [claim] = s.releases.as_slice() else {
        panic!("one claim: {:?}", s.releases);
    };
    assert!(matches!(
        claim.basis,
        ReleaseBasis::SelfReportedCommit { .. }
    ));
    // The same run against a set that lists every file found: all of them match, and no claim
    // is closed.
    install_as_a_run_with_budgets(&mut s, &tree, &refs, budgets);
    assert!(s.releases.is_empty(), "{:?}", s.releases);
    s.releases = claims(None, &s.components, &refs).unwrap();
    s.canonicalize();
    let [claim] = s.releases.as_slice() else {
        panic!("an open claim: {:?}", s.releases);
    };
    assert!(matches!(
        claim.basis,
        ReleaseBasis::SelfReportedCommit { .. }
    ));
    assert_eq!(s.validate(), Ok(()));
    verify_reference_matches(&s, &refs).unwrap();
    assert_eq!(verify_release_claims(&s, &refs), Ok(()));
}

/// PR-4c-2c: `validate` does not tie `components` to the binary facts, so the verifier derives
/// the claims again. An assertion that no binary fact gives, with the open claim it supports,
/// passes `validate` and fails the verifier.
#[test]
fn a_fabricated_commit_assertion_fails_the_verifier() {
    let tree = install_with_a_commit();
    let s = inspect_with_install(&tree);
    let set = official().unwrap();
    // `ggml_commit` is reported by no placement of this install.
    let (at, method) = s
        .components
        .iter()
        .flat_map(|c| &c.assertions)
        .find_map(|a| match a {
            IdentityAssertion::Embedded { at, method, .. } => Some((at.clone(), method.clone())),
            _ => None,
        })
        .unwrap();
    let mut t = s.clone();
    let i = t
        .components
        .iter()
        .position(|c| {
            !c.assertions
                .iter()
                .any(|a| matches!(a, IdentityAssertion::Embedded { .. }))
        })
        .unwrap();
    t.components[i]
        .assertions
        .push(IdentityAssertion::Embedded {
            field: "ggml_commit".to_string(),
            value: UntrustedText::new("6f3a9f3de"),
            at,
            method,
        });
    t.releases = open(&t.components, set).unwrap().into_iter().collect();
    t.canonicalize();
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    assert!(verify_release_claims(&t, set).is_err());
}

/// Makes `s` the session of a run with `refs` over `tree`: its rows, a closed claim, and what
/// rests on them.
fn install_as_a_run_with(s: &mut Session, tree: &TempDir, refs: &RefSet) {
    install_as_a_run_with_budgets(s, tree, refs, InstallBudgets::default());
}

/// [`install_as_a_run_with`] for a run with these discovery budgets.
fn install_as_a_run_with_budgets(
    s: &mut Session,
    tree: &TempDir,
    refs: &RefSet,
    budgets: InstallBudgets,
) {
    // The session as a run with `refs` writes it: a closed claim for both releases.
    let r = analyze(&collect(tree.path(), budgets).unwrap(), refs).unwrap();
    for k in &mut s.knowledge {
        if k.kind == KnowledgeKind::ReferenceManifest {
            *k = refs.knowledge();
        }
    }
    s.reference_matches = r.rows;
    s.releases = r.claim.into_iter().collect();
    s.components = derive(&s.instances, &s.binaries, &s.reference_matches).unwrap();
    for c in &mut s.coverage {
        if c.check.as_str() == ARTIFACTS_RELEASE {
            *c = r.coverage.clone();
        }
    }
    let policy = Policy::builtin_default().unwrap();
    let time = s.outcome.policy_time.clone();
    evaluate(s, &policy, time).unwrap();
    s.canonicalize();
}

/// Plan review P2: beside a closed claim, an open claim of another product that rests on the
/// session's own commit passes `validate` (V12 checks claims per product) and fails the
/// verifier, which admits no open claim beside a closed one.
#[test]
fn an_open_claim_of_another_product_beside_a_closed_one_fails_the_verifier() {
    let tree = install_with_a_commit();
    let mut s = inspect_with_install(&tree);
    let lib = std::fs::read(tree.path().join("lib/ollama/libllama-common.so.0.0.1")).unwrap();
    let refs = identical_pair_with(&[serde_json::json!({
        "name": "lib/ollama/libllama-common.so.0.0.1", "type": "0", "mode": "0o644",
        "sha256": common::hex(&lib), "size": lib.len(),
    })]);
    install_as_a_run_with(&mut s, &tree, &refs);
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(s.releases[0].candidates, ["vA", "vB"]);
    verify_reference_matches(&s, &refs).unwrap();
    verify_release_claims(&s, &refs).unwrap();
    // Another product's open claim, on the session's own LLAMA_COMMIT.
    let commit = s
        .components
        .iter()
        .flat_map(|c| &c.assertions)
        .find_map(|a| match a {
            IdentityAssertion::Embedded {
                field, value, at, ..
            } if field == "LLAMA_COMMIT" => Some(ReportedCommit {
                field: field.clone(),
                value: value.clone(),
                at: at.clone(),
            }),
            _ => None,
        })
        .unwrap();
    s.releases.push(ReleaseClaim {
        product: ComponentKey::new("another-product").unwrap(),
        candidates: vec!["v999".to_string()],
        basis: ReleaseBasis::SelfReportedCommit {
            commits: vec![commit],
        },
    });
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "V12 checks claims per product");
    assert!(verify_release_claims(&s, &refs).is_err());
}

/// PR-4c-2c: an install with two reporting libraries gives two commits, and the session's claim is
/// the one `open` derives from the session's own component claims, as written (canonical order).
#[test]
fn an_open_claim_with_two_commits_equals_the_one_derived_from_the_claims() {
    let tree = install();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::copy(
        fixtures.join("elf/libdata.so"),
        tree.path().join("lib/ollama/libllama-common.so.0.0.1"),
    )
    .unwrap();
    std::fs::copy(
        fixtures.join("returns/version-gcc-O2.so"),
        tree.path().join("lib/ollama/libggml-base.so.0.13.1"),
    )
    .unwrap();
    let s = inspect_with_install(&tree);
    let [claim] = s.releases.as_slice() else {
        panic!("one claim: {:?}", s.releases);
    };
    let ReleaseBasis::SelfReportedCommit { commits } = &claim.basis else {
        panic!("an open claim: {:?}", claim.basis);
    };
    let shown: Vec<(&str, Option<&str>)> = commits
        .iter()
        .map(|c| (c.field.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(
        shown,
        [
            ("LLAMA_COMMIT", Some("6f3a9f3de")),
            ("ggml_commit", Some("6f3a9f3de"))
        ]
    );
    let derived = open(&s.components, official().unwrap()).unwrap();
    assert_eq!(s.releases, derived.into_iter().collect::<Vec<_>>());
    let set = official().unwrap();
    verify_release_claims(&s, set).unwrap();
    // The commits in another order are the same claim.
    let mut t = s.clone();
    if let ReleaseBasis::SelfReportedCommit { commits } = &mut t.releases[0].basis {
        commits.reverse();
    }
    assert_eq!(verify_release_claims(&t, set), Ok(()));
    // A commit dropped from the claim: `validate` cannot see it, the verifier does.
    let mut t = s.clone();
    if let ReleaseBasis::SelfReportedCommit { commits } = &mut t.releases[0].basis {
        commits.retain(|c| c.field != "ggml_commit");
        assert_eq!(commits.len(), 1);
    }
    assert_eq!(t.validate(), Ok(()), "validate cannot see it");
    let errors = verify_release_claims(&t, set).unwrap_err();
    assert!(errors[0].contains("ggml_commit"), "{errors:?}");
}

/// PR-4c-2c: a closed claim comes first. The set describes the install exactly, `libllama-common`
/// included, and lists the same commit; `claims` gives the closed claim, while `open` alone would
/// give an open one.
#[test]
fn a_closed_claim_comes_before_an_open_one() {
    use serde_json::json;
    let tree = install();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so");
    let lib = "lib/ollama/libllama-common.so.0.0.1";
    std::fs::copy(&fixture, tree.path().join(lib)).unwrap();
    let bytes = std::fs::read(&fixture).unwrap();
    let hex = |b: &[u8]| common::hex(b);
    let manifest = |tag: &str| {
        json!({"tag": tag, "entries": [
            {"name": "bin/ollama", "type": "0", "mode": "0o755", "sha256": hex(&elf(2)), "size": 64},
            {"name": "lib/ollama/cuda_v12", "type": "5", "mode": "0o755"},
            {"name": "lib/ollama/cuda_v12/libcudart.so.12.8.90", "type": "0", "mode": "0o644", "sha256": hex(b"weights"), "size": 7},
            {"name": "lib/ollama/libggml.so.0", "type": "2", "mode": "0o777", "link": "libggml.so.0.13.1"},
            {"name": "lib/ollama/libggml.so.0.13.1", "type": "0", "mode": "0o644", "sha256": hex(&elf(3)), "size": 64},
            {"name": lib, "type": "0", "mode": "0o644", "sha256": hex(&bytes), "size": bytes.len()},
        ]})
        .to_string()
    };
    let (a, b) = (manifest("vA"), manifest("vB"));
    let commits = format!(
        "[[release]]\ntag = \"vA\"\ncommits = [{{ field = \"LLAMA_COMMIT\", member = \"{lib}\", \
         value = \"6f3a9f3de\" }}]\n[[release]]\ntag = \"vB\"\ncommits = [{{ field = \
         \"LLAMA_COMMIT\", member = \"{lib}\", value = \"6f3a9f3de\" }}]\n"
    );
    let refs = parse_set(
        "ollama-official",
        "test",
        &[("a.json", &a), ("b.json", &b), ("commits.toml", &commits)],
    )
    .unwrap();
    let facts = collect(tree.path(), InstallBudgets::default()).unwrap();
    let r = analyze(&facts, &refs).unwrap();
    let components = derive(&facts.instances, &facts.binaries, &r.rows).unwrap();
    let closed = r.claim.clone().unwrap();
    assert_eq!(closed.candidates, ["vA", "vB"]);
    assert!(matches!(
        closed.basis,
        ReleaseBasis::ReferenceMatches { .. }
    ));
    assert_eq!(
        claims(r.claim, &components, &refs),
        Ok(vec![closed.clone()])
    );
    let open = open(&components, &refs).unwrap().unwrap();
    assert!(matches!(
        open.basis,
        ReleaseBasis::SelfReportedCommit { .. }
    ));
    assert_eq!(open.candidates, ["vA", "vB"]);
}
