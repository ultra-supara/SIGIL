//! `policy::verify` (#51, plan review P2-2): a session is what its policy gives, or each
//! difference is named. `validate` alone cannot tell: a session whose violation was removed and
//! whose outcome was set to PASS still validates.

mod common;

use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, StoreRequest,
};
use sigil_engine::policy::{verify, Policy};
use sigil_model::*;

const DENY_SPAWN: &str = "schema = \"sigil-policy/1\"\nname = \"no-spawn\"\n[[capabilities.deny]]\nfeature = \"posix.process_spawn\"\naction = \"fail\"\nreason = \"no processes\"\n";

/// `binary inspect --code` of spawn.so (one call of execve, one of connect) under `policy`.
fn spawn(policy: &Policy) -> Session {
    let req = BinaryRequest {
        paths: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code/spawn.so")],
        budgets: NamedBudgets {
            binary: BinaryBudgets {
                code: Some(CodeBudgets::default()),
                ..BinaryBudgets::default()
            },
            ..NamedBudgets::default()
        },
    };
    let s = binary_session(
        &req,
        policy,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    s
}

#[test]
fn a_session_is_what_its_policy_gives() {
    let p = Policy::load(DENY_SPAWN).unwrap();
    let s = spawn(&p);
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert_eq!(verify(&s, &p), Ok(()));
    // Saved and loaded again: canonical order changes nothing.
    let saved: Session = serde_json::from_str(&s.to_canonical_json().unwrap()).unwrap();
    assert_eq!(verify(&saved, &p), Ok(()));
    // And under the built-in policy, a session made with it.
    let default = Policy::builtin_default().unwrap();
    assert_eq!(verify(&spawn(&default), &default), Ok(()));
}

#[test]
fn a_removed_violation_validates_but_does_not_verify() {
    let p = Policy::load(DENY_SPAWN).unwrap();
    let mut s = spawn(&p);
    let slice = s.binaries[0].slice.clone();
    s.policy_violations.clear();
    s.outcome.verdict = Verdict::Pass;
    s.validate().unwrap();
    assert_eq!(
        verify(&s, &p),
        Err(vec![
            format!(
                "policy violations the policy gives, and the session lacks: \
                 policy:capabilities.deny.posix.process_spawn on {slice}"
            ),
            "the outcome is PASS + COMPLETE, and the policy gives FAIL + COMPLETE".to_string(),
        ])
    );
}

#[test]
fn a_changed_decision_and_another_policy_are_named() {
    let p = Policy::load(DENY_SPAWN).unwrap();
    let mut s = spawn(&p);
    let slice = s.binaries[0].slice.clone();
    s.policy_violations[0].decision.action = Action::Warn;
    s.outcome.verdict = Verdict::Warn;
    s.validate().unwrap();
    assert_eq!(
        verify(&s, &p),
        Err(vec![
            format!(
                "policy violations the session records otherwise than the policy gives: \
                 policy:capabilities.deny.posix.process_spawn on {slice}"
            ),
            "the outcome is WARN + COMPLETE, and the policy gives FAIL + COMPLETE".to_string(),
        ])
    );

    // A session made with another policy is not this one's.
    let default = Policy::builtin_default().unwrap();
    let s = spawn(&p);
    let errors = verify(&s, &default).unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].starts_with("the session records the policy no-spawn sigil-policy/1 ("),
        "{errors:?}"
    );
}

/// Task 7 review: a violation the policy does not give, and a session that does not name the
/// policy once, are named too.
#[test]
fn a_fabricated_violation_and_a_missing_policy_entry_are_named() {
    let p = Policy::load(DENY_SPAWN).unwrap();
    let mut s = spawn(&p);
    let slice = s.binaries[0].slice.clone();
    // A violation of posix.network, citing connect's real call: consistent, and not the policy's.
    let mut fabricated = s.policy_violations[0].clone();
    let rule = PolicyRuleRef::new("policy:capabilities.deny.posix.network").unwrap();
    fabricated.policy_rule = rule.clone();
    fabricated.decision.source = rule;
    fabricated.evidence = vec![EvidenceRef::Code {
        slice: slice.clone(),
        loc: Loc::CallSite(CallId::new("cs:0x1148").unwrap()),
    }];
    s.policy_violations.push(fabricated);
    s.validate().unwrap();
    assert_eq!(
        verify(&s, &p),
        Err(vec![format!(
            "policy violations the session has, and the policy does not give: \
             policy:capabilities.deny.posix.network on {slice}"
        )])
    );

    let mut s = spawn(&p);
    s.knowledge.retain(|k| k.kind != KnowledgeKind::Policy);
    let errors = verify(&s, &p).unwrap_err();
    assert!(
        errors[0].starts_with("the session records the policy none, not no-spawn sigil-policy/1 ("),
        "{errors:?}"
    );
}

/// Task 7 review: a finding's default decision rests on its rule's default severity, which the
/// session only records. One downgraded from FAIL to WARN validates and re-evaluates to itself;
/// this build's catalog says otherwise.
#[test]
fn a_finding_s_rule_is_this_build_s() {
    let dir = tempfile::TempDir::new().unwrap();
    let d = dir.path();
    let config = common::blob(d, b"{}");
    let weights = common::blob(d, b"weights");
    let license = common::blob(d, b"MIT");
    common::manifest(
        d,
        common::LIB,
        Some(&config),
        &[
            (common::MODEL_MEDIA, &weights),
            (LICENSE_MEDIA_TYPE, &license),
        ],
    );
    std::fs::write(
        d.join(format!("blobs/sha256-{}", common::hex(b"weights"))),
        b"tampered",
    )
    .unwrap();
    let req = StoreRequest {
        models_dir: d.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: None,
    };
    let p = Policy::builtin_default().unwrap();
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &p,
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert_eq!(verify(&s, &p), Ok(()));

    let mut t = s.clone();
    let f = &mut t.findings[0];
    assert_eq!(f.rule.as_str(), "model.blob_digest_mismatch");
    f.default_severity = Severity::Warn;
    f.decision.action = Action::Warn;
    t.outcome.verdict = Verdict::Warn;
    t.outcome.confirmed_failures = 0;
    t.outcome.confirmed_warnings = 1;
    t.validate().unwrap();
    assert_eq!(
        verify(&t, &p),
        Err(vec![format!(
            "finding {}: the session records rule model.blob_digest_mismatch as integrity warn, \
             and this build's catalog as integrity fail",
            t.findings[0].id
        )])
    );
}

/// PR review: `verify` judges only a valid session, whoever calls it: a session that does not
/// agree with itself gets its validation errors as differences.
#[test]
fn an_invalid_session_does_not_verify() {
    let p = Policy::load(DENY_SPAWN).unwrap();
    let mut s = spawn(&p);
    let v = s.policy_violations[0].clone();
    s.policy_violations.push(v);
    let errors = verify(&s, &p).unwrap_err();
    assert!(
        errors
            .iter()
            .all(|e| e.starts_with("the session is not valid: ")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("a second violation of posix.process_spawn")),
        "{errors:?}"
    );
}

#[test]
fn a_session_the_policy_cannot_judge_does_not_verify() {
    // Made before #51: no capability table, so a denial cannot judge it.
    let p = Policy::load(DENY_SPAWN).unwrap();
    let mut s = spawn(&p);
    s.knowledge.retain(|k| k.kind != KnowledgeKind::SignatureDb);
    s.policy_violations.clear();
    s.outcome.verdict = Verdict::Pass;
    s.validate().unwrap();
    let errors = verify(&s, &p).unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].starts_with("the policy cannot evaluate the session: the policy denies"),
        "{errors:?}"
    );
}
