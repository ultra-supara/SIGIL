//! Capability denials on real files (#51): a direct call of a denied capability's import is a
//! policy violation citing its call site; an import of one without a direct call site is an open
//! question, with or without code analysis, and on an installation too. A session made with
//! another capability table is refused, never judged by its old hints.

mod common;

use std::path::PathBuf;

use sigil_engine::binary::BinaryBudgets;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::named::NamedBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, InstallRequest, StoreRequest,
};
use sigil_engine::policy::{evaluate, EvaluateError, Policy};
use sigil_model::*;
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code")
        .join(name)
}

/// The default policy with `deny` added: `binary_audit` and `binary_code_audit` as built in.
fn policy(deny: &str) -> Policy {
    Policy::load(&format!(
        "schema = \"sigil-policy/1\"\nname = \"capabilities\"\n{deny}"
    ))
    .unwrap()
}

const SPAWN_FAILS: &str = "[[capabilities.deny]]\nfeature = \"posix.process_spawn\"\naction = \"fail\"\nreason = \"no processes\"\n";
const NETWORK_FAILS: &str =
    "[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"no network\"\n";

fn inspect(name: &str, code: bool, deny: &str) -> Session {
    let req = BinaryRequest {
        paths: vec![fixture(name)],
        budgets: NamedBudgets {
            binary: BinaryBudgets {
                code: code.then(CodeBudgets::default),
                ..BinaryBudgets::default()
            },
            ..NamedBudgets::default()
        },
    };
    let s = binary_session(
        &req,
        &policy(deny),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    s
}

/// The rules and subjects of the violations, and the ids of the open questions.
fn results(s: &Session) -> (Vec<(String, Ref)>, Vec<String>) {
    (
        s.policy_violations
            .iter()
            .map(|v| (v.policy_rule.to_string(), v.subject.clone()))
            .collect(),
        s.open_questions.iter().map(|q| q.id.to_string()).collect(),
    )
}

fn unknown(s: &Session) -> &UnknownReason {
    match &s.open_questions[0].conditions[0].state {
        CondState::Unknown { reason, .. } => reason,
        other => panic!("{other:?}"),
    }
}

/// #51's acceptance criterion: under `process_spawn = fail` and `network = allow`, a file that
/// calls `execve` FAILs, citing the call site; a file that calls only `connect` PASSes.
#[test]
fn a_call_of_execve_fails_and_a_call_of_connect_alone_passes() {
    let s = inspect("spawn.so", true, SPAWN_FAILS);
    let slice = s.binaries[0].slice.clone();
    assert_eq!(
        results(&s),
        (
            vec![(
                "policy:capabilities.deny.posix.process_spawn".to_string(),
                Ref::Slice(slice.clone())
            )],
            vec![]
        )
    );
    assert_eq!(
        s.policy_violations[0].evidence,
        [EvidenceRef::Code {
            slice,
            loc: Loc::CallSite(CallId::new("cs:0x1124").unwrap()),
        }]
    );
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert_eq!(s.outcome.completeness, Completeness::Complete);

    let s = inspect("net-plt-gcc.so", true, SPAWN_FAILS);
    assert_eq!(results(&s), (vec![], vec![]));
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
}

/// Each denied capability is judged on its own: both of spawn.so's calls are violations (in the
/// canonical order of a saved session).
#[test]
fn each_denied_capability_is_its_own_violation() {
    let s = inspect("spawn.so", true, &format!("{SPAWN_FAILS}{NETWORK_FAILS}"));
    let (violations, questions) = results(&s);
    assert_eq!(
        violations
            .iter()
            .map(|(r, _)| r.as_str())
            .collect::<Vec<_>>(),
        [
            "policy:capabilities.deny.posix.network",
            "policy:capabilities.deny.posix.process_spawn"
        ]
    );
    assert!(questions.is_empty());
    assert_eq!(
        s.policy_violations[0].evidence,
        [EvidenceRef::Code {
            slice: s.binaries[0].slice.clone(),
            loc: Loc::CallSite(CallId::new("cs:0x1148").unwrap()),
        }]
    );
}

/// #51 D4: an import of a denied capability without a direct call site is an open question,
/// whatever code analysis says, with the reason it is not known.
#[test]
fn an_import_without_a_direct_call_site_is_an_open_question() {
    // net-data.so: connect only in .data.rel.ro; binary.code Complete.
    let s = inspect("net-data.so", true, NETWORK_FAILS);
    let slice = s.binaries[0].slice.clone();
    assert_eq!(
        results(&s),
        (vec![], vec![format!("capability:posix.network@{slice}")])
    );
    assert_eq!(
        unknown(&s),
        &UnknownReason::NotModeled {
            what: "calls that are not direct (through a function pointer, or from data)".into()
        }
    );
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        &s.outcome.completeness,
        Completeness::Incomplete { missing_required, gaps }
            if missing_required.is_empty() && gaps.len() == 1
    ));

    // net-addr.so: connect's address is taken; binary.code Partial.
    let s = inspect("net-addr.so", true, NETWORK_FAILS);
    assert_eq!(
        unknown(&s),
        &UnknownReason::CheckIncomplete {
            check: CheckId::new(BINARY_CODE).unwrap()
        }
    );
    assert!(matches!(
        &s.outcome.completeness,
        Completeness::Incomplete { missing_required, gaps }
            if missing_required.iter().any(|c| c.as_str() == BINARY_CODE) && gaps.len() == 1
    ));

    // spawn.so without code analysis: its call is not known, so it is a question, not a pass.
    let s = inspect("spawn.so", false, SPAWN_FAILS);
    assert!(s.policy_violations.is_empty());
    assert_eq!(
        unknown(&s),
        &UnknownReason::NotModeled {
            what: "calls in code that was not analyzed".into()
        }
    );
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

/// Each slice's reason is its own input's `binary.code`: in one inspection, net-data.so's
/// (`Complete`) and net-addr.so's (`Partial`).
#[test]
fn each_slice_s_reason_is_its_own_input_s() {
    let req = BinaryRequest {
        paths: vec![fixture("net-data.so"), fixture("net-addr.so")],
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
        &policy(NETWORK_FAILS),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    // The slice of the input named `name`, through its instance's content.
    let slice = |name: &str| {
        let artifact = s
            .instances
            .iter()
            .find_map(|i| match &i.content {
                InstanceContent::Read { artifact }
                    if i.path.as_bytes().ends_with(name.as_bytes()) =>
                {
                    Some(artifact.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("no input {name}"));
        let b = s.binaries.iter().find(|b| b.slice.artifact() == artifact);
        Ref::Slice(
            b.unwrap_or_else(|| panic!("no facts of {name}"))
                .slice
                .clone(),
        )
    };
    let reason = |name: &str| {
        let q = s
            .open_questions
            .iter()
            .find(|q| q.subject == slice(name))
            .unwrap_or_else(|| panic!("no question on {name}"));
        match &q.conditions[0].state {
            CondState::Unknown { reason, .. } => reason.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        reason("net-data.so"),
        UnknownReason::NotModeled {
            what: "calls that are not direct (through a function pointer, or from data)".into()
        }
    );
    assert_eq!(
        reason("net-addr.so"),
        UnknownReason::CheckIncomplete {
            check: CheckId::new(BINARY_CODE).unwrap()
        }
    );
}

/// An installation has no code analysis yet (#9): a denied capability its files import is an open
/// question on each of their slices, and the result is INCOMPLETE, never a silent PASS.
#[test]
fn an_installation_s_denied_imports_are_open_questions() {
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::copy(fixture("spawn.so"), tree.path().join("bin/ollama")).unwrap();
    let models = TempDir::new().unwrap();
    let req = StoreRequest {
        models_dir: models.path().to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest {
            dir: tree.path().to_path_buf(),
            budgets: InstallBudgets::default(),
        }),
    };
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &policy(SPAWN_FAILS),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    s.validate().unwrap();
    // The install's binaries were analyzed with this build's table, which the session records.
    assert!(s
        .knowledge
        .contains(sigil_engine::code::data::signatures().unwrap().knowledge()));
    assert!(s.policy_violations.is_empty());
    assert_eq!(s.open_questions.len(), 1);
    assert_eq!(
        s.open_questions[0].subject,
        Ref::Slice(s.binaries[0].slice.clone())
    );
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));

    // Without the denial, the same installation has no capability result.
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
}

/// Plan review P2-1: PR #103 recorded no `cxx.*` hints for libstdc++'s imports (#104 mapped
/// them), and its code facts no call sites of them. Re-evaluating such a session under a denial
/// of `cxx.file_write` is refused, so it is never PASS + COMPLETE; analyzed again with this
/// build, the same file is judged by its call sites.
#[test]
fn a_session_from_before_a_table_change_is_refused_not_passed() {
    const FILE_WRITE_FAILS: &str = "[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"fail\"\nreason = \"read-only\"\n";
    let req = BinaryRequest {
        paths: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cxx-capabilities/cxx-capabilities")],
        budgets: NamedBudgets {
            binary: BinaryBudgets {
                code: Some(CodeBudgets::default()),
                ..BinaryBudgets::default()
            },
            ..NamedBudgets::default()
        },
    };
    let session = |deny: &str| {
        let s = binary_session(
            &req,
            &policy(deny),
            common::tool(),
            common::observation(),
            common::policy_time(),
        )
        .unwrap();
        s.validate().unwrap();
        s
    };
    let now = session("");
    let cxx = |feature: &FeatureKey| feature.as_str().starts_with("cxx.");
    let names: Vec<UntrustedText> = now
        .hints
        .iter()
        .filter(|h| cxx(&h.feature))
        .map(|h| h.value.clone())
        .collect();
    assert_eq!(names.len(), 9);

    // As PR #103 saved it: no cxx.* hints, no call sites of those names, no table.
    let mut old = now.clone();
    old.hints.retain(|h| !cxx(&h.feature));
    for facts in &mut old.code {
        facts.call_sites.retain(
            |c| !matches!(&c.target, CallTarget::Import { symbol, .. } if names.contains(symbol)),
        );
    }
    old.knowledge
        .retain(|k| k.kind != KnowledgeKind::SignatureDb);
    old.validate().unwrap();
    let before = old.clone();
    let time = old.outcome.policy_time.clone();
    assert!(matches!(
        evaluate(&mut old, &policy(FILE_WRITE_FAILS), time.clone()),
        Err(EvaluateError::CapabilityTable { recorded, .. }) if recorded.is_empty()
    ));
    assert_eq!(old, before, "refused, and left as it was");

    // The table recorded, but the hints of an older one: refused too.
    let mut stale = now.clone();
    stale.hints.retain(|h| !cxx(&h.feature));
    assert_eq!(
        evaluate(&mut stale, &policy(FILE_WRITE_FAILS), time),
        Err(EvaluateError::CapabilityHints {
            missing: 9,
            extra: 0
        })
    );

    // Analyzed again: a violation citing each of the 7 direct calls of a cxx.file_write import.
    let judged = session(FILE_WRITE_FAILS);
    assert_eq!(judged.policy_violations.len(), 1);
    assert_eq!(judged.policy_violations[0].evidence.len(), 7);
    assert_eq!(judged.outcome.verdict, Verdict::Fail);
}
