//! Policy evaluation and Outcome computation (plan §4.7): decisions are the policy's, technical
//! content is untouched, `verdict` and `completeness` are independent, and every evaluated session
//! passes `Session::validate`.

use std::fs;
use std::path::{Path, PathBuf};

use sigil_engine::policy::{evaluate, Policy, PolicyWarning};
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

/// Evaluates at the session's recorded policy time and checks the result validates.
fn run(s: &mut Session, p: &Policy) -> Vec<PolicyWarning> {
    let time = s.outcome.policy_time.clone();
    let warnings = evaluate(s, p, time);
    assert_valid(s);
    warnings
}

/// Overwrites every decision and the outcome with wrong values.
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
    for a in &mut s.assumptions {
        a.acceptance = AssumptionAcceptance::Accepted {
            source: PolicyRuleRef::new("scrambled").unwrap(),
        };
    }
    s.outcome.verdict = Verdict::Fail;
    s.outcome.completeness = Completeness::Complete;
    s.outcome.confirmed_failures = 99;
    s.outcome.confirmed_warnings = 99;
}

#[test]
fn re_evaluating_every_golden_example_reproduces_it() {
    let defaults = policy("");
    let mut seen = 0;
    for entry in fs::read_dir(examples_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let expected: Session = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut s = expected.clone();
        scramble(&mut s);
        let warnings = run(&mut s, &defaults);
        assert!(warnings.is_empty());
        assert_eq!(s, expected, "{}", path.display());
        seen += 1;
    }
    assert_eq!(seen, 13);
}

#[test]
fn verdict_and_completeness_are_independent() {
    let defaults = policy("");
    let outcome = |name: &str, edit: &dyn Fn(&mut Session)| {
        let mut s = example(name);
        edit(&mut s);
        run(&mut s, &defaults);
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
    run(&mut s, &policy(""));
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
        &policy("[rules.\"model.license_missing\"]\naction = \"fail\"\n"),
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
        &policy("[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"internal models\"\n"),
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
    let p = policy(
        "[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"until the audit\"\nexpires = \"2027-03-31\"\n",
    );
    let mut s = with_license_finding();
    let warnings = evaluate(&mut s, &p, ts("2027-03-31T23:59:59Z"));
    assert!(warnings.is_empty());
    assert_eq!(s.findings[0].decision.action, Action::Ignore);
    assert_eq!(
        s.findings[0].decision.expires.as_ref().map(Date::as_str),
        Some("2027-03-31")
    );
    assert_eq!(s.outcome.policy_time.as_str(), "2027-03-31T23:59:59Z");
    assert_valid(&s);

    let mut s = with_license_finding();
    let warnings = evaluate(&mut s, &p, ts("2027-04-01T00:00:00Z"));
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
    run(&mut s, &policy("[open_questions]\ndefault = \"warn\"\n"));
    assert_eq!(s.open_questions[0].decision.treatment, OqTreatment::Warn);
    assert_eq!(
        (s.outcome.verdict, &s.outcome.completeness),
        (Verdict::Warn, &Completeness::Complete)
    );

    let mut s = example("07-open-question");
    run(
        &mut s,
        &policy("[open_questions]\ndefault = \"ignore\"\nreason = \"reviewed manually\"\n"),
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
fn accepted_assumptions_are_marked() {
    let mut s = example("07-open-question");
    run(&mut s, &policy("[assumptions]\naccept = [\"A-3\"]\n"));
    assert_eq!(
        s.assumptions[0].acceptance,
        AssumptionAcceptance::Accepted {
            source: PolicyRuleRef::new("policy:assumptions.accept").unwrap()
        }
    );
}

#[test]
fn denied_components_become_policy_violations() {
    let deny = policy(
        "[[components.deny]]\ncomponent = \"ggml\"\naction = \"fail\"\nreason = \"not approved\"\n",
    );
    let mut s = example("01-complete-pass");
    run(&mut s, &deny);
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
    run(&mut s, &deny);
    assert_eq!(s.policy_violations.len(), 1);
    let mut s = example("01-complete-pass");
    s.components[0].status = IdentityStatus::Unidentified;
    run(&mut s, &deny);
    assert!(s.policy_violations.is_empty());
    assert_eq!(s.outcome.verdict, Verdict::Pass);
}
