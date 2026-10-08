//! Findings and per-model coverage derived from collected model-store facts (plan §4.6.7, §6.3).
//! Every finding rests on observed files: each condition is `Observed` with instance or artifact
//! facts only.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use sigil_engine::analyze::model_store::{analyze, INTEGRITY, LICENSE};
use sigil_engine::collect::fs::{FsBudgets, SafeFs};
use sigil_engine::collect::ollama_store::{collect, StoreFacts, DEFAULT_MANIFEST_LIMIT};
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::*;

fn run(dir: &Path, filter: Option<&str>) -> (StoreFacts, Vec<Finding>, Vec<Coverage>) {
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_root(root(), dir).unwrap();
    let facts = collect(&fs, &root(), filter, DEFAULT_MANIFEST_LIMIT);
    let (findings, coverage) = analyze(&facts, &root());
    (facts, findings, coverage)
}

fn rules(findings: &[Finding]) -> Vec<(&str, Severity)> {
    findings
        .iter()
        .map(|f| (f.rule.as_str(), f.default_severity))
        .collect()
}

fn state<'a>(coverage: &'a [Coverage], check: &str, scope: &Ref) -> Option<&'a CoverageState> {
    coverage
        .iter()
        .find(|c| c.check.as_str() == check && c.scope == *scope)
        .map(|c| &c.state)
}

fn model_ref(facts: &StoreFacts) -> Ref {
    Ref::Model(facts.models[0].id.clone())
}

/// A store with one model: a config, the weights, and an MIT license, all present.
fn good_store(d: &Path) {
    let config = blob(d, b"{}");
    let weights = blob(d, b"weights");
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        Some(&config),
        &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
    );
}

#[test]
fn a_verified_model_has_no_finding_and_closes_its_checks() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let (facts, findings, coverage) = run(dir.path(), None);
    assert!(findings.is_empty(), "{:?}", rules(&findings));
    let m = model_ref(&facts);
    assert_eq!(
        state(&coverage, INTEGRITY, &m),
        Some(&CoverageState::Complete)
    );
    assert_eq!(
        state(&coverage, LICENSE, &m),
        Some(&CoverageState::Complete)
    );
}

#[test]
fn integrity_problems_are_findings_or_gaps() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"weights");
    // Tampered: the file named for one digest holds other bytes.
    let tampered = format!("sha256:{}", hex(b"original"));
    fs::write(
        d.join(format!("blobs/sha256-{}", hex(b"original"))),
        b"changed",
    )
    .unwrap();
    let missing = format!("sha256:{}", hex(b"never written"));
    let malformed = format!("sha256:{}", hex(b"x").to_uppercase());
    manifest(
        d,
        LIB,
        None,
        &[
            (MODEL_MEDIA, &weights),
            (MODEL_MEDIA, &tampered),
            (MODEL_MEDIA, &missing),
            (MODEL_MEDIA, &malformed),
        ],
    );
    let (facts, findings, coverage) = run(d, None);
    assert_eq!(
        rules(&findings),
        [
            ("model.blob_digest_mismatch", Severity::Fail),
            ("model.blob_missing", Severity::Warn),
            ("model.manifest_digest_malformed", Severity::Fail),
            ("model.license_missing", Severity::Warn),
        ]
    );
    let m = model_ref(&facts);
    // A mismatch was checked; a missing blob and a malformed digest leave integrity open.
    assert_eq!(
        state(&coverage, INTEGRITY, &m),
        Some(&CoverageState::Partial {
            missing: vec![
                "layer 2: no blob".to_string(),
                "layer 3: malformed digest".to_string()
            ]
        })
    );
    assert_eq!(
        state(&coverage, LICENSE, &m),
        Some(&CoverageState::Complete)
    );
    // Each finding is about the model, one per layer.
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "finding:model.blob_digest_mismatch@model:models/registry.ollama.ai/library/m/latest#1",
            "finding:model.blob_missing@model:models/registry.ollama.ai/library/m/latest#2",
            "finding:model.manifest_digest_malformed@model:models/registry.ollama.ai/library/m/latest#3",
            "finding:model.license_missing@model:models/registry.ollama.ai/library/m/latest",
        ]
    );
}

#[test]
fn a_blob_that_was_not_read_is_a_gap_not_a_finding() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let d = dir.path();
    fs::create_dir_all(d.join("blobs")).unwrap();
    fs::write(outside.path().join("w"), b"w").unwrap();
    symlink(
        outside.path().join("w"),
        d.join(format!("blobs/sha256-{}", hex(b"w"))),
    )
    .unwrap();
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        None,
        &[
            (MODEL_MEDIA, &format!("sha256:{}", hex(b"w"))),
            (LICENSE_MEDIA_TYPE, &license),
        ],
    );
    let (facts, findings, coverage) = run(d, None);
    assert!(findings.is_empty(), "{:?}", rules(&findings));
    assert_eq!(
        state(&coverage, INTEGRITY, &model_ref(&facts)),
        Some(&CoverageState::Partial {
            missing: vec!["layer 0: blob not read (OutsideScanRoots)".to_string()]
        })
    );
}

#[test]
fn a_license_layer_that_cannot_be_read_leaves_the_license_check_open() {
    // Its blob is missing: the license check is partial.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"weights");
    let absent = format!("sha256:{}", hex(b"license never written"));
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &absent)],
    );
    let (facts, findings, coverage) = run(d, None);
    assert_eq!(rules(&findings), [("model.blob_missing", Severity::Warn)]);
    assert_eq!(
        state(&coverage, LICENSE, &model_ref(&facts)),
        Some(&CoverageState::Partial {
            missing: vec!["license blob".to_string()]
        })
    );

    // Its blob exists but cannot be read: a read failure is an error for that model only.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    if privileged(d) {
        eprintln!("SKIPPED: an unreadable license blob needs an unprivileged user");
        return;
    }
    let weights = blob(d, b"weights");
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
    );
    let path = d.join(format!("blobs/sha256-{}", hex(b"MIT")));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let (facts, findings, coverage) = run(d, None);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(findings.is_empty(), "{:?}", rules(&findings));
    assert!(matches!(
        state(&coverage, LICENSE, &model_ref(&facts)),
        Some(CoverageState::Error { .. })
    ));
}

#[test]
fn manifests_that_are_not_models_are_findings_on_the_manifest() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    fs::create_dir_all(d.join("manifests/orphaned")).unwrap();
    fs::write(d.join("manifests/orphaned/loose"), b"{}").unwrap();
    fs::create_dir_all(d.join("manifests/registry.ollama.ai/library/broken")).unwrap();
    fs::write(
        d.join("manifests/registry.ollama.ai/library/broken/latest"),
        b"{",
    )
    .unwrap();
    let (_, findings, _) = run(d, None);
    let on: Vec<(&str, &Ref)> = findings
        .iter()
        .map(|f| (f.rule.as_str(), &f.subject))
        .collect();
    assert_eq!(
        on,
        [
            (
                "model.provenance_unknown",
                &Ref::Instance(inst("manifests/orphaned/loose"))
            ),
            (
                "model.manifest_unparseable",
                &Ref::Instance(inst("manifests/registry.ollama.ai/library/broken/latest"))
            ),
        ]
    );
}

#[test]
fn a_filter_that_matches_nothing_is_not_found_on_the_listing() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let (_, findings, coverage) = run(dir.path(), Some("absent:latest"));
    assert_eq!(rules(&findings), [("model.not_found", Severity::Warn)]);
    assert_eq!(findings[0].subject, Ref::Root(root()));
    assert_eq!(
        findings[0].evidence,
        [EvidenceRef::Instance {
            instance: inst("manifests")
        }]
    );
    assert!(coverage.is_empty(), "no model, so no per-model check");
}

#[test]
fn every_condition_is_observed_from_files() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"weights");
    let tampered = format!("sha256:{}", hex(b"original"));
    fs::write(
        d.join(format!("blobs/sha256-{}", hex(b"original"))),
        b"changed",
    )
    .unwrap();
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &weights), (MODEL_MEDIA, &tampered)],
    );
    let (_, findings, _) = run(d, None);
    assert!(!findings.is_empty());
    for f in &findings {
        assert_eq!(f.conditions.len(), 1, "{}", f.id);
        let CondState::Met {
            evidence: CondEvidence::Observed { facts },
        } = &f.conditions[0].state
        else {
            panic!("{}: not an observed condition", f.id);
        };
        assert!(!facts.is_empty());
        assert!(facts.iter().all(|e| matches!(
            e,
            EvidenceRef::Instance { .. } | EvidenceRef::Artifact { .. }
        )));
    }
    // The mismatch names the manifest, the blob, and what the blob holds.
    let mismatch = findings
        .iter()
        .find(|f| f.rule.as_str() == "model.blob_digest_mismatch")
        .unwrap();
    let CondState::Met {
        evidence: CondEvidence::Observed { facts },
    } = &mismatch.conditions[0].state
    else {
        unreachable!()
    };
    assert_eq!(facts.len(), 3);
    assert!(facts.contains(&EvidenceRef::Artifact {
        artifact: ArtifactId::new(format!("sha256:{}", hex(b"changed"))).unwrap()
    }));
}

#[test]
fn a_blob_that_cannot_be_resolved_is_a_gap_not_missing() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    fs::create_dir_all(d.join("blobs")).unwrap();
    let looped = format!("sha256-{}", hex(b"loop"));
    symlink(&looped, d.join("blobs").join(&looped)).unwrap();
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        None,
        &[
            (MODEL_MEDIA, &format!("sha256:{}", hex(b"loop"))),
            (LICENSE_MEDIA_TYPE, &license),
        ],
    );
    let (facts, findings, coverage) = run(d, None);
    assert!(findings.is_empty(), "{:?}", rules(&findings));
    let Some(CoverageState::Partial { missing }) = state(&coverage, INTEGRITY, &model_ref(&facts))
    else {
        panic!("integrity must stay open");
    };
    assert_eq!(missing.len(), 1);
    assert!(
        missing[0].starts_with("layer 0: blob not resolved"),
        "{missing:?}"
    );
}
