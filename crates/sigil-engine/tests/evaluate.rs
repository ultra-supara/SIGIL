//! Policy evaluation and Outcome computation (plan §4.7): decisions are the policy's, technical
//! content is untouched, `verdict` and `completeness` are independent, and every evaluated session
//! passes `Session::validate`. A policy that would change the analysis itself (accepted
//! assumptions, required checks) is refused, and the session is left unchanged.

use std::fs;
use std::path::{Path, PathBuf};

use sigil_engine::policy::{evaluate, EvaluateError, Policy, PolicyWarning};
use sigil_model::*;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/session-v1")
}

fn example(name: &str) -> Session {
    let text = fs::read_to_string(examples_dir().join(format!("{name}.json"))).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn policy(body: &str) -> Policy {
    Policy::load(&format!(
        "schema = \"sigil-policy/1\"\nname = \"test\"\n{body}"
    ))
    .unwrap()
}

fn ts(text: &str) -> Timestamp {
    Timestamp::new(text).unwrap()
}

fn assert_valid(s: &Session) {
    if let Err(errors) = s.validate() {
        let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
        panic!("evaluated session is invalid:\n{}", text.join("\n"));
    }
}

/// A policy from `body` that requires exactly the checks `s` was collected for. The list is set
/// directly rather than through TOML because example 06 names a check the catalog does not have
/// yet.
fn policy_for(s: &Session, body: &str) -> Policy {
    let mut p = policy(body);
    p.audit.clear();
    p.observe_audit.clear();
    p.extra_required = s.request.required_checks.clone();
    p
}

/// Evaluates with `policy_for(s, body)` at the session's recorded policy time and checks that the
/// result validates.
fn run(s: &mut Session, body: &str) -> Vec<PolicyWarning> {
    let p = policy_for(s, body);
    let time = s.outcome.policy_time.clone();
    let warnings = evaluate(s, &p, time).unwrap();
    assert_valid(s);
    warnings
}

/// Overwrites every decision and the outcome with wrong values. Assumption acceptance is left
/// alone: it is an input to the analysis, not a decision.
fn scramble(s: &mut Session) {
    for f in &mut s.findings {
        f.decision = PolicyDecision {
            action: Action::Ignore,
            source: PolicyRuleRef::new("scrambled").unwrap(),
            reason: Some("scrambled".into()),
            expires: None,
        };
    }
    for q in &mut s.open_questions {
        q.decision = OpenQuestionDecision {
            treatment: OqTreatment::Fail,
            source: PolicyRuleRef::new("scrambled").unwrap(),
            reason: None,
        };
    }
    s.outcome.verdict = Verdict::Fail;
    s.outcome.completeness = Completeness::Complete;
    s.outcome.confirmed_failures = 99;
    s.outcome.confirmed_warnings = 99;
}

#[test]
fn re_evaluating_every_golden_example_reproduces_it() {
    let mut seen = 0;
    for entry in fs::read_dir(examples_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let mut expected: Session =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut s = expected.clone();
        scramble(&mut s);
        let warnings = run(&mut s, "");
        assert!(warnings.is_empty());
        // Everything is reproduced, and the session records the policy that was applied.
        for k in &mut expected.knowledge {
            if k.kind == KnowledgeKind::Policy {
                *k = policy_for(&s, "").knowledge();
            }
        }
        assert_eq!(s, expected, "{}", path.display());
        seen += 1;
    }
    assert_eq!(seen, 13);
}

#[test]
fn verdict_and_completeness_are_independent() {
    let outcome = |name: &str, edit: &dyn Fn(&mut Session)| {
        let mut s = example(name);
        edit(&mut s);
        run(&mut s, "");
        (s.outcome.verdict, s.outcome.completeness)
    };
    let complete = Completeness::Complete;
    let missing = |checks: &[&str]| Completeness::Incomplete {
        missing_required: checks.iter().map(|c| CheckId::new(*c).unwrap()).collect(),
        gaps: vec![],
    };
    let warn = |s: &mut Session| s.findings[0].default_severity = Severity::Warn;

    assert_eq!(
        outcome("01-complete-pass", &|_| {}),
        (Verdict::Pass, complete.clone())
    );
    assert_eq!(
        outcome("02-complete-fail", &|_| {}),
        (Verdict::Fail, complete.clone())
    );
    assert_eq!(
        outcome("02-complete-fail", &warn),
        (Verdict::Warn, complete.clone())
    );
    // A gap never lowers a confirmed Fail, and never hides a Warn.
    assert_eq!(
        outcome("04-fail-incomplete", &|_| {}),
        (Verdict::Fail, missing(&["exposure.binds"]))
    );
    assert_eq!(
        outcome("04-fail-incomplete", &warn),
        (Verdict::Warn, missing(&["exposure.binds"]))
    );
    // Nothing found, but a required check has no coverage at all: not a clean pass.
    assert_eq!(
        outcome("01-complete-pass", &|s| s
            .coverage
            .retain(|c| c.check.as_str() != "loader.identify")),
        (Verdict::Pass, missing(&["loader.identify"]))
    );
    // A check is closed only when every coverage entry for it closes it.
    assert_eq!(
        outcome("01-complete-pass", &|s| {
            let instance = s.instances[0].id.clone();
            s.coverage.push(Coverage {
                check: CheckId::new("loader.identify").unwrap(),
                scope: Ref::Instance(instance),
                state: CoverageState::Partial {
                    missing: vec!["one symbol".into()],
                },
                budget: None,
            });
        }),
        (Verdict::Pass, missing(&["loader.identify"]))
    );
    // An open question counted as a gap.
    let (verdict, completeness) = outcome("07-open-question", &|_| {});
    assert_eq!(verdict, Verdict::Pass);
    assert!(
        matches!(completeness, Completeness::Incomplete { ref gaps, ref missing_required } if gaps.len() == 1 && missing_required.is_empty())
    );
}

/// Example 01 with a `model.license_missing` finding (Warn) on its libggml instance.
fn with_license_finding() -> Session {
    let mut s = example("01-complete-pass");
    let instance = s.instances[0].id.clone();
    s.findings.push(Finding {
        id: FindingId::new("finding:model.license_missing@m").unwrap(),
        rule: RuleId::new("model.license_missing").unwrap(),
        kind: FindingKind::Integrity,
        subject: Ref::Instance(instance.clone()),
        summary: "The manifest has no license layer (test)".into(),
        conditions: vec![Condition {
            id: CondId::new("license_layer_absent").unwrap(),
            state: CondState::Met {
                evidence: CondEvidence::Observed {
                    facts: vec![EvidenceRef::Instance {
                        instance: instance.clone(),
                    }],
                },
            },
            unresolved: vec![],
        }],
        evidence: vec![EvidenceRef::Instance { instance }],
        limits: vec![],
        default_severity: Severity::Warn,
        decision: PolicyDecision {
            action: Action::Warn,
            source: PolicyRuleRef::new("unset").unwrap(),
            reason: None,
            expires: None,
        },
    });
    s
}

#[test]
fn rule_overrides_change_the_decision_not_the_finding() {
    let mut s = with_license_finding();
    run(&mut s, "");
    let d = &s.findings[0].decision;
    assert_eq!(
        (d.action, d.source.as_str()),
        (Action::Warn, "default:model.license_missing")
    );
    assert_eq!(
        (s.outcome.verdict, s.outcome.confirmed_warnings),
        (Verdict::Warn, 1)
    );

    let mut s = with_license_finding();
    run(
        &mut s,
        "[rules.\"model.license_missing\"]\naction = \"fail\"\n",
    );
    let f = &s.findings[0];
    assert_eq!(
        f.default_severity,
        Severity::Warn,
        "technical severity unchanged"
    );
    assert_eq!(
        (f.decision.action, f.decision.source.as_str()),
        (Action::Fail, "policy:rules.model.license_missing")
    );
    assert_eq!(
        (s.outcome.verdict, s.outcome.confirmed_failures),
        (Verdict::Fail, 1)
    );

    let mut s = with_license_finding();
    run(
        &mut s,
        "[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"internal models\"\n",
    );
    assert_eq!(s.findings.len(), 1, "an ignored finding stays");
    assert_eq!(s.findings[0].decision.action, Action::Ignore);
    assert_eq!(
        s.findings[0].decision.reason.as_deref(),
        Some("internal models")
    );
    assert_eq!(
        (
            s.outcome.verdict,
            s.outcome.confirmed_warnings,
            s.outcome.confirmed_failures
        ),
        (Verdict::Pass, 0, 0)
    );
}

#[test]
fn an_expired_override_reverts_to_the_default_and_warns() {
    let p = policy_for(
        &with_license_finding(),
        "[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"until the audit\"\nexpires = \"2027-03-31\"\n",
    );
    let mut s = with_license_finding();
    let warnings = evaluate(&mut s, &p, ts("2027-03-31T23:59:59Z")).unwrap();
    assert!(warnings.is_empty());
    assert_eq!(s.findings[0].decision.action, Action::Ignore);
    assert_eq!(
        s.findings[0].decision.expires.as_ref().map(Date::as_str),
        Some("2027-03-31")
    );
    assert_eq!(s.outcome.policy_time.as_str(), "2027-03-31T23:59:59Z");
    assert_valid(&s);

    let mut s = with_license_finding();
    let warnings = evaluate(&mut s, &p, ts("2027-04-01T00:00:00Z")).unwrap();
    assert_eq!(
        warnings,
        [PolicyWarning::OverrideExpired {
            rule: RuleId::new("model.license_missing").unwrap(),
            expires: Date::new("2027-03-31").unwrap(),
        }]
    );
    let d = &s.findings[0].decision;
    assert_eq!(
        (d.action, d.source.as_str()),
        (Action::Warn, "default:model.license_missing")
    );
    assert_eq!(d.reason.as_deref(), Some("override expired 2027-03-31"));
    assert_eq!(s.outcome.verdict, Verdict::Warn);
    assert_valid(&s);
}

#[test]
fn open_question_treatment_comes_from_the_policy() {
    let mut s = example("07-open-question");
    run(&mut s, "[open_questions]\ndefault = \"warn\"\n");
    assert_eq!(s.open_questions[0].decision.treatment, OqTreatment::Warn);
    assert_eq!(
        (s.outcome.verdict, &s.outcome.completeness),
        (Verdict::Warn, &Completeness::Complete)
    );

    let mut s = example("07-open-question");
    run(&mut s, "[open_questions]\ndefault = \"fail\"\n");
    assert_eq!(
        (s.outcome.verdict, &s.outcome.completeness),
        (Verdict::Fail, &Completeness::Complete)
    );

    let mut s = example("07-open-question");
    run(
        &mut s,
        "[open_questions]\ndefault = \"ignore\"\nreason = \"reviewed manually\"\n",
    );
    let d = &s.open_questions[0].decision;
    assert_eq!(
        (d.treatment, d.reason.as_deref()),
        (OqTreatment::Ignore, Some("reviewed manually"))
    );
    assert_eq!(
        (s.outcome.verdict, &s.outcome.completeness),
        (Verdict::Pass, &Completeness::Complete)
    );
}

#[test]
fn the_policy_states_which_assumptions_are_accepted() {
    let p = policy("[assumptions]\naccept = [\"A-3\"]\n");
    assert_eq!(
        p.acceptance(&AssumptionId::new("A-3").unwrap()),
        AssumptionAcceptance::Accepted {
            source: PolicyRuleRef::new("policy:assumptions.accept").unwrap()
        }
    );
    assert_eq!(
        p.acceptance(&AssumptionId::new("A-4").unwrap()),
        AssumptionAcceptance::NotAccepted
    );
}

/// Example 07 with its `evaluate` rule resting on assumption A-3, accepted: the open question's
/// `rule_supported:evaluate` condition is `Met` only because A-3 is accepted.
fn resting_on_accepted_a3() -> Session {
    let a3 = AssumptionId::new("A-3").unwrap();
    let mut s = example("07-open-question");
    for r in &mut s.rule_support {
        if r.rule.as_str() == "evaluate" {
            r.support = Support::Assumed {
                assumption: a3.clone(),
            };
        }
    }
    s.assumptions[0].acceptance = policy("[assumptions]\naccept = [\"A-3\"]\n").acceptance(&a3);
    assert_valid(&s);
    s
}

#[test]
fn a_change_in_accepted_assumptions_requires_reanalysis() {
    let a3 = AssumptionId::new("A-3").unwrap();

    // Withdrawn: the condition resting on A-3 could no longer be `Met`.
    let original = resting_on_accepted_a3();
    // Flipping only the acceptance, as evaluation used to, leaves a `Met` condition unsettled.
    let mut flipped = original.clone();
    flipped.assumptions[0].acceptance = AssumptionAcceptance::NotAccepted;
    assert!(flipped.validate().is_err());
    let mut s = original.clone();
    let p = policy_for(&s, "");
    let time = s.outcome.policy_time.clone();
    assert_eq!(
        evaluate(&mut s, &p, time.clone()),
        Err(EvaluateError::AssumptionsChanged(vec![a3.clone()]))
    );
    assert_eq!(
        s, original,
        "a refused evaluation leaves the session unchanged"
    );
    // The policy the analysis rested on evaluates it.
    run(&mut s, "[assumptions]\naccept = [\"A-3\"]\n");

    // Newly accepted: a condition left open because of A-3 might now be settled.
    let original = example("07-open-question");
    let mut s = original.clone();
    let p = policy_for(&s, "[assumptions]\naccept = [\"A-3\"]\n");
    assert_eq!(
        evaluate(&mut s, &p, time),
        Err(EvaluateError::AssumptionsChanged(vec![a3]))
    );
    assert_eq!(s, original);
}

#[test]
fn a_change_in_required_checks_requires_reanalysis() {
    let original = example("01-complete-pass");
    let time = original.outcome.policy_time.clone();
    let check = |c: &str| CheckId::new(c).unwrap();
    let refused = |required: Vec<CheckId>| {
        let mut s = original.clone();
        let mut p = policy_for(&s, "");
        p.extra_required = required.clone();
        assert_eq!(
            evaluate(&mut s, &p, time.clone()),
            Err(EvaluateError::RequiredChecksChanged {
                request: original.request.required_checks.clone(),
                policy: required,
            })
        );
        assert_eq!(
            s, original,
            "a refused evaluation leaves the session unchanged"
        );
    };
    let recorded = original.request.required_checks.clone();
    assert_eq!(
        recorded,
        [check("artifacts.discovery"), check("loader.identify")]
    );

    // A check added, a check removed, and one replaced by another (the same count).
    let mut added = recorded.clone();
    added.push(check("loader.search_paths"));
    refused(added);
    refused(vec![check("artifacts.discovery")]);
    refused(vec![
        check("artifacts.discovery"),
        check("loader.search_paths"),
    ]);

    // The same checks in another order are the same requirement.
    let mut s = original.clone();
    let mut p = policy_for(&s, "");
    p.extra_required.reverse();
    evaluate(&mut s, &p, time).unwrap();
    assert_valid(&s);
}

#[test]
fn a_canonical_round_trip_keeps_a_session_evaluable_with_the_same_policy() {
    let policy = Policy::builtin_default().unwrap();
    let mut s = example("01-complete-pass");
    let (audit, required) = policy.scope(s.request.mode);
    s.request.audit = audit;
    s.request.required_checks = required.clone();
    let time = s.outcome.policy_time.clone();
    evaluate(&mut s, &policy, time.clone()).unwrap();
    assert_valid(&s);
    let saved = s.to_canonical_json().unwrap();

    let mut reloaded: Session = serde_json::from_str(&saved).unwrap();
    // Canonical order sorts the checks: the request no longer lists them in the policy's order.
    assert_ne!(reloaded.request.required_checks, required);
    evaluate(&mut reloaded, &policy, time).unwrap();
    assert_valid(&reloaded);
    assert_eq!(reloaded.to_canonical_json().unwrap(), saved);
}

#[test]
fn evaluation_records_the_policy_it_applied() {
    let body = "[open_questions]\ndefault = \"warn\"\n";
    let mut s = example("01-complete-pass");
    run(&mut s, body);
    let recorded: Vec<&KnowledgeRef> = s
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::Policy)
        .collect();
    assert_eq!(
        recorded,
        [&policy_for(&example("01-complete-pass"), body).knowledge()]
    );
}

#[test]
fn denied_components_become_policy_violations() {
    let deny =
        "[[components.deny]]\ncomponent = \"ggml\"\naction = \"fail\"\nreason = \"not approved\"\n";
    let mut s = example("01-complete-pass");
    run(&mut s, deny);
    assert_eq!(s.policy_violations.len(), 1);
    let v = &s.policy_violations[0];
    assert_eq!(v.policy_rule.as_str(), "policy:components.deny.ggml");
    assert_eq!(
        v.subject,
        Ref::Component {
            slice: s.components[0].subject.clone(),
            component: ComponentKey::new("ggml").unwrap()
        }
    );
    assert_eq!(
        v.evidence,
        [EvidenceRef::Artifact {
            artifact: s.components[0].subject.artifact()
        }]
    );
    assert_eq!(
        (v.decision.action, v.decision.reason.as_deref()),
        (Action::Fail, Some("not approved"))
    );
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert!(s.findings.is_empty(), "a policy violation is not a finding");

    // A name-only claim is enough for an organizational ban; an unidentified one is not.
    let mut s = example("01-complete-pass");
    s.components[0].status = IdentityStatus::NameOnly;
    run(&mut s, deny);
    assert_eq!(s.policy_violations.len(), 1);
    let mut s = example("01-complete-pass");
    s.components[0].status = IdentityStatus::Unidentified;
    run(&mut s, deny);
    assert!(s.policy_violations.is_empty());
    assert_eq!(s.outcome.verdict, Verdict::Pass);

    // Only claims for the denied component match.
    let mut s = example("01-complete-pass");
    run(
        &mut s,
        "[[components.deny]]\ncomponent = \"ggml-backend/rpc\"\naction = \"fail\"\nreason = \"not approved\"\n",
    );
    assert!(s.policy_violations.is_empty());
    assert_eq!(s.outcome.verdict, Verdict::Pass);
}

#[test]
fn the_verdict_is_the_highest_action_whatever_its_source() {
    let deny = |action: &str| {
        format!("[[components.deny]]\ncomponent = \"ggml\"\naction = \"{action}\"\nreason = \"not approved\"\n")
    };
    // A Warn finding, then a Fail policy violation.
    let mut s = with_license_finding();
    run(&mut s, &deny("fail"));
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    // A Fail finding, then a Warn policy violation.
    let mut s = with_license_finding();
    let body = format!(
        "[rules.\"model.license_missing\"]\naction = \"fail\"\n{}",
        deny("warn")
    );
    run(&mut s, &body);
    assert_eq!(s.outcome.verdict, Verdict::Fail);
}
