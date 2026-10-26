//! `policy::verify` (#51, plan review P2-2): a session is what its policy gives, or each
//! difference is named. `validate` alone cannot tell: a session whose violation was removed and
//! whose outcome was set to PASS still validates.

mod common;

use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::inspect::{binary_session, BinaryRequest};
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
        errors[0].starts_with("the session records the policy no-spawn ("),
        "{errors:?}"
    );
}

#[test]
fn a_session_the_policy_cannot_judge_does_not_verify() {
    // Made before #51: no capability table. The default policy judges it; a denial cannot.
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
