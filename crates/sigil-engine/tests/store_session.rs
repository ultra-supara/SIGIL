//! A static model-store session with the built-in policy (plan §4.6.7, §6.3). The migration rows
//! and the v0.1 cases are stated on the outcome, and every session passes `Session::validate`.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{store_session, ActiveInput, StoreRequest};
use sigil_engine::policy::{evaluate, Policy};
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::*;

const INVENTORY: &str = "model_store.inventory";
const INTEGRITY: &str = "model_store.integrity";
const LICENSE: &str = "model_store.license";

fn tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: "0.0.0-test".to_string(),
        git_rev: None,
    }
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-08T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

fn request(dir: &Path, filter: Option<&str>) -> StoreRequest {
    StoreRequest {
        models_dir: dir.to_path_buf(),
        model_filter: filter.map(str::to_string),
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: None,
    }
}

/// A session with the built-in policy; it must validate.
fn session(dir: &Path, filter: Option<&str>) -> Session {
    session_for(&request(dir, filter))
}

fn session_for(req: &StoreRequest) -> Session {
    session_with(req, &ActiveInput::default())
}

fn session_with(req: &StoreRequest, active: &ActiveInput) -> Session {
    let policy = Policy::builtin_default().unwrap();
    let s = store_session(
        req,
        active,
        &policy,
        tool(),
        observation(),
        observation().started_at,
    )
    .unwrap();
    if let Err(errors) = s.validate() {
        let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
        panic!("invalid session:\n{}", text.join("\n"));
    }
    s
}

fn rules(s: &Session) -> Vec<&str> {
    s.findings.iter().map(|f| f.rule.as_str()).collect()
}

fn missing(checks: &[&str]) -> Completeness {
    Completeness::Incomplete {
        missing_required: checks.iter().map(|c| CheckId::new(*c).unwrap()).collect(),
        gaps: vec![],
    }
}

fn outcome(s: &Session) -> (Verdict, Completeness) {
    (s.outcome.verdict, s.outcome.completeness.clone())
}

/// One model with a config, weights, and an MIT license, all present.
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

// --- migration table rows (§6.3) -------------------------------------------------------------

#[test]
fn a_missing_models_directory_is_incomplete_not_pass() {
    // I-01: v0.1 returned PASS with no findings.
    let dir = TempDir::new().unwrap();
    let s = session(&dir.path().join("nonexistent"), None);
    assert_eq!(
        outcome(&s),
        (Verdict::Pass, missing(&[INTEGRITY, INVENTORY, LICENSE]))
    );
    assert_eq!(
        s.coverage[0].state,
        CoverageState::Unavailable {
            why: Unavailability::NotFound
        }
    );
    // The same for a directory without `manifests/`.
    let s = session(dir.path(), None);
    assert_eq!(
        outcome(&s),
        (Verdict::Pass, missing(&[INTEGRITY, INVENTORY, LICENSE]))
    );
}

#[test]
fn a_missing_blob_is_warn_and_leaves_integrity_open() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    fs::remove_file(d.join(format!("blobs/sha256-{}", hex(b"weights")))).unwrap();
    let s = session(d, None);
    assert_eq!(rules(&s), ["model.blob_missing"]);
    assert_eq!(outcome(&s), (Verdict::Warn, missing(&[INTEGRITY])));
}

#[test]
fn a_malformed_digest_is_fail_and_leaves_integrity_open() {
    for digest in [
        // I-06: uppercase hex is malformed, never a false mismatch.
        format!("sha256:{}", hex(b"weights").to_uppercase()),
        "sha256:foo/../../secret".to_string(),
    ] {
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        let license = blob(d, b"MIT");
        manifest(
            d,
            LIB,
            None,
            &[(MODEL_MEDIA, &digest), (LICENSE_MEDIA_TYPE, &license)],
        );
        let s = session(d, None);
        assert_eq!(rules(&s), ["model.manifest_digest_malformed"], "{digest}");
        assert_eq!(outcome(&s), (Verdict::Fail, missing(&[INTEGRITY])));
    }
}

#[test]
fn a_blob_symlinked_out_of_the_store_is_not_read() {
    // I-07: v0.1 followed the link and hashed a file outside the store.
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    let weights = d.join(format!("blobs/sha256-{}", hex(b"weights")));
    fs::rename(&weights, outside.path().join("w")).unwrap();
    symlink(outside.path().join("w"), &weights).unwrap();
    let s = session(d, None);
    assert!(s.findings.is_empty());
    assert_eq!(outcome(&s), (Verdict::Pass, missing(&[INTEGRITY])));
}

#[test]
fn an_unparseable_manifest_is_warn_and_the_other_models_remain() {
    // I-04: v0.1 aborted the whole run.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    fs::create_dir_all(d.join("manifests/registry.ollama.ai/library/broken")).unwrap();
    fs::write(
        d.join("manifests/registry.ollama.ai/library/broken/latest"),
        b"{",
    )
    .unwrap();
    let s = session(d, None);
    assert_eq!(s.models.len(), 1);
    assert_eq!(rules(&s), ["model.manifest_unparseable"]);
    assert_eq!(outcome(&s), (Verdict::Warn, missing(&[INVENTORY])));
}

#[test]
fn an_unreadable_license_blob_leaves_the_license_check_open() {
    // I-04: v0.1 aborted the whole run.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    if privileged(d) {
        eprintln!("SKIPPED: an unreadable license blob needs an unprivileged user");
        return;
    }
    good_store(d);
    let path = d.join(format!("blobs/sha256-{}", hex(b"MIT")));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let s = session(d, None);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(s.findings.is_empty());
    // The unread blob also leaves integrity open.
    assert_eq!(outcome(&s), (Verdict::Pass, missing(&[INTEGRITY, LICENSE])));
}

#[test]
fn provenance_unknown_is_reported_only_without_a_filter() {
    // I-05: v0.1 reported it for other manifests even with `--model`.
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    fs::create_dir_all(d.join("manifests/orphaned")).unwrap();
    fs::write(d.join("manifests/orphaned/loose"), b"{}").unwrap();
    assert_eq!(rules(&session(d, None)), ["model.provenance_unknown"]);
    let s = session(d, Some("m:latest"));
    assert!(s.findings.is_empty());
    assert_eq!(outcome(&s), (Verdict::Pass, Completeness::Complete));
    assert_eq!(s.request.model_filter.as_deref(), Some("m:latest"));
}

// --- v0.1 cases (sigil-core/tests/ollama.rs, removed in PR-3b-3c-1), on the v2 outcome -------

#[test]
fn a_complete_store_passes_and_is_complete() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let s = session(dir.path(), None);
    assert_eq!(outcome(&s), (Verdict::Pass, Completeness::Complete));
    assert_eq!(s.models.len(), 1);
    assert_eq!(s.models[0].name.as_str(), Some("m:latest"));
    let p = &s.models[0].provenance;
    assert_eq!(
        (
            p.registry.as_str(),
            p.namespace.as_ref().and_then(|n| n.as_str())
        ),
        (Some("registry.ollama.ai"), Some("library"))
    );
    assert_eq!(
        s.models[0].license.as_ref().and_then(|l| l.spdx.as_deref()),
        Some("MIT")
    );
    // The request records what the policy required.
    assert_eq!(s.request.mode, Mode::Static);
    assert_eq!(
        s.request.required_checks,
        [INTEGRITY, INVENTORY, LICENSE].map(|c| CheckId::new(c).unwrap())
    );
}

#[test]
fn a_tampered_blob_fails() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    fs::write(
        d.join(format!("blobs/sha256-{}", hex(b"weights"))),
        b"tampered",
    )
    .unwrap();
    let s = session(d, None);
    assert_eq!(rules(&s), ["model.blob_digest_mismatch"]);
    assert_eq!(outcome(&s), (Verdict::Fail, Completeness::Complete));
}

#[test]
fn license_bodies_are_identified() {
    let bsd3 = format!(
        "Redistribution and use in source and binary forms, with or without modification, are \
         permitted provided that the following conditions are met:\n{}\nNeither the name of the \
         copyright holder may be used.",
        "x ".repeat(300)
    );
    for (text, spdx) in [
        (
            "                                 Apache License\n                           Version 2.0, January 2004\n"
                .to_string(),
            "Apache-2.0",
        ),
        (bsd3, "BSD-3-Clause"),
    ] {
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        let weights = blob(d, b"weights");
        let license = blob(d, text.as_bytes());
        manifest(
            d,
            LIB,
            None,
            &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
        );
        let s = session(d, None);
        let found = s.models[0].license.as_ref().unwrap();
        assert_eq!(found.spdx.as_deref(), Some(spdx));
        assert!(found.excerpt.as_bytes().len() <= 256);
    }
}

#[test]
fn a_missing_license_layer_warns_and_the_check_is_complete() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"weights");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    let s = session(d, None);
    assert_eq!(rules(&s), ["model.license_missing"]);
    assert_eq!(outcome(&s), (Verdict::Warn, Completeness::Complete));
}

#[test]
fn the_filter_round_trips_display_names() {
    for (path, name) in [
        ("registry.ollama.ai/acme/gemma4/e2b", "acme/gemma4:e2b"),
        (
            "registry.ollama.ai/acme/sub/gemma4/e2b",
            "acme/sub/gemma4:e2b",
        ),
        ("hf.co/acme/gemma4/e2b", "hf.co/acme/gemma4:e2b"),
        ("hf.co/library/gemma4/e2b", "hf.co/library/gemma4:e2b"),
    ] {
        let dir = TempDir::new().unwrap();
        let d = dir.path();
        let weights = blob(d, b"weights");
        let license = blob(d, b"MIT");
        manifest(
            d,
            path,
            None,
            &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
        );
        let s = session(d, Some(name));
        assert_eq!(s.models.len(), 1, "{name}");
        assert_eq!(s.models[0].name.as_str(), Some(name));
        assert_eq!(outcome(&s), (Verdict::Pass, Completeness::Complete));
    }
}

#[test]
fn a_filter_that_matches_nothing_is_not_found_and_incomplete() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let s = session(dir.path(), Some("gemma4"));
    assert_eq!(rules(&s), ["model.not_found"]);
    assert_eq!(outcome(&s), (Verdict::Warn, missing(&[INTEGRITY, LICENSE])));
}

#[test]
fn a_filter_is_not_found_only_after_a_complete_listing() {
    // The model exists, but the listing never got to it: that is a gap, not an absence.
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let s = session_for(&StoreRequest {
        budgets: FsBudgets {
            max_entries: 0,
            ..FsBudgets::default()
        },
        ..request(dir.path(), Some("m:latest"))
    });
    assert!(s.findings.is_empty(), "{:?}", rules(&s));
    assert_eq!(
        outcome(&s),
        (Verdict::Pass, missing(&[INTEGRITY, INVENTORY, LICENSE]))
    );
}

#[test]
fn a_root_path_that_is_not_utf8_keeps_its_bytes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new().unwrap();
    let store = dir.path().join(OsStr::from_bytes(b"models-\xff"));
    fs::create_dir(&store).unwrap();
    good_store(&store);
    // `session` fails the test unless the session validates.
    let s = session(&store, None);
    assert_eq!(outcome(&s), (Verdict::Pass, Completeness::Complete));
    let root = s.request.roots[0].path.as_bytes();
    assert!(root.ends_with(b"/models-\xff"));
    let weights = s
        .instances
        .iter()
        .find(|i| i.id.as_str().ends_with(&hex(b"weights")))
        .unwrap();
    assert!(weights.path.as_bytes().starts_with(root));
}

// --- determinism -----------------------------------------------------------------------------

#[test]
fn a_session_is_reproducible_and_re_evaluates_after_a_round_trip() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    good_store(d);
    manifest(
        d,
        "registry.ollama.ai/library/n/latest",
        None,
        &[(MODEL_MEDIA, &format!("sha256:{}", hex(b"never written")))],
    );
    let first = session(d, None).to_canonical_json().unwrap();
    let second = session(d, None).to_canonical_json().unwrap();
    assert_eq!(first, second);

    let mut reloaded: Session = serde_json::from_str(&first).unwrap();
    let policy = Policy::builtin_default().unwrap();
    let time = reloaded.outcome.policy_time.clone();
    evaluate(&mut reloaded, &policy, time).unwrap();
    assert_eq!(reloaded.to_canonical_json().unwrap(), first);
}

// --- the active API probe (PR-3b-2) -----------------------------------------------------------

/// A requested probe of 127.0.0.1:11434 that ended with `result`, and its bounds.
fn probed(result: ProbeResult) -> ActiveInput {
    let target: std::net::SocketAddr = "127.0.0.1:11434".parse().unwrap();
    ActiveInput {
        features: vec![ActiveFeature::ApiProbe {
            address: "127.0.0.1".to_string(),
            port: 11434,
            allow_remote: false,
        }],
        probes: vec![ApiProbe {
            id: ProbeId::api(target),
            address: "127.0.0.1".to_string(),
            port: 11434,
            at: Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
            result,
        }],
        budgets: std::collections::BTreeMap::from([
            ("api_connect_ms".to_string(), 2000),
            ("api_io_ms".to_string(), 2000),
            ("api_response_bytes".to_string(), 65536),
        ]),
    }
}

#[test]
fn a_refused_probe_closes_runtime_api() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let s = session_with(&request(dir.path(), None), &probed(ProbeResult::Refused));
    assert_eq!(outcome(&s), (Verdict::Pass, Completeness::Complete));
    assert!(s.request.audit.iter().any(|a| a.as_str() == "runtime_api"));
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == "runtime_api.version"));
    assert_eq!(s.request.active.len(), 1);
    assert_eq!(s.probes.len(), 1);
    assert_eq!(s.request.budgets["api_io_ms"], 2000);
    assert!(s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == "runtime_api.version"
            && matches!(c.state, CoverageState::NotPresent { .. })));
}

#[test]
fn a_timed_out_probe_leaves_runtime_api_open() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let timed_out = ProbeResult::TimedOut {
        phase: ProbePhase::Read,
    };
    let s = session_with(&request(dir.path(), None), &probed(timed_out));
    assert_eq!(
        outcome(&s),
        (Verdict::Pass, missing(&["runtime_api.version"]))
    );
}

#[test]
fn without_an_active_feature_nothing_is_probed() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let s = session(dir.path(), None);
    assert!(s.request.active.is_empty() && s.probes.is_empty());
    assert!(!s.request.audit.iter().any(|a| a.as_str() == "runtime_api"));
    assert!(!s.request.budgets.keys().any(|k| k.starts_with("api_")));
}

#[test]
fn every_probe_outcome_assembles_a_session_its_coverage_agrees_with() {
    let dir = TempDir::new().unwrap();
    good_store(dir.path());
    let results = [
        ProbeResult::Answered {
            status: 200,
            version: Some(UntrustedText::new("0.12.3")),
        },
        ProbeResult::Answered {
            status: 200,
            version: None,
        },
        ProbeResult::Answered {
            status: 404,
            version: None,
        },
        ProbeResult::Refused,
        ProbeResult::TimedOut {
            phase: ProbePhase::Connect,
        },
        ProbeResult::TimedOut {
            phase: ProbePhase::Write,
        },
        ProbeResult::TimedOut {
            phase: ProbePhase::Read,
        },
        ProbeResult::TooLarge { limit: 65536 },
        ProbeResult::Malformed {
            why: "transfer-encoding not supported".to_string(),
        },
        ProbeResult::Failed {
            message: UntrustedText::new("Connection reset by peer (os error 104)"),
        },
    ];
    for result in results {
        // `session_with` asserts that the session validates, including the agreement rule.
        let s = session_with(&request(dir.path(), None), &probed(result.clone()));
        let closed = s
            .coverage
            .iter()
            .filter(|c| c.check.as_str() == "runtime_api.version")
            .all(|c| c.state.can_close());
        let expected = matches!(
            result,
            ProbeResult::Refused
                | ProbeResult::Answered {
                    status: 200,
                    version: Some(_)
                }
        );
        assert_eq!(closed, expected, "{result:?}");
    }
}
