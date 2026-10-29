//! Policy evaluation and Outcome computation (plan §4.7): decisions are the policy's, technical
//! content is untouched, `verdict` and `completeness` are independent, and every evaluated session
//! passes `Session::validate`. A policy that would change the analysis itself (accepted
//! assumptions, required checks) is refused, and the session is left unchanged.

use std::fs;
use std::path::{Path, PathBuf};

use sigil_engine::policy::{evaluate, EvaluateError, Policy, PolicyWarning, ScopeInput};
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
/// yet. A binary inspection's checks come from `binary_audit` (PR-4b-2a), and with code from
/// `binary_code_audit` too (PR-5a), so its whole audit is given in `binary_audit`.
fn policy_for(s: &Session, body: &str) -> Policy {
    let mut p = policy(body);
    p.audit.clear();
    p.observe_audit.clear();
    p.active_audit.clear();
    p.install_audit.clear();
    p.binary_audit.clear();
    p.binary_code_audit.clear();
    if ScopeInput::of(&s.request).binary {
        p.binary_audit = s.request.audit.clone();
    } else {
        p.extra_required = s.request.required_checks.clone();
    }
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
        // Example 18 records the results of its denials (#51); every other example, none.
        let body = if path.ends_with("18-capability-policy.json") {
            EXAMPLE_18_POLICY
        } else {
            ""
        };
        let warnings = run(&mut s, body);
        assert!(warnings.is_empty());
        // Everything is reproduced, and the session records the policy that was applied.
        for k in &mut expected.knowledge {
            if k.kind == KnowledgeKind::Policy {
                *k = policy_for(&s, body).knowledge();
            }
        }
        // In canonical form, as SIGIL writes a session: evaluation appends its capability open
        // questions after the analysis's, and a saved session sorts them (#51).
        s.canonicalize();
        expected.canonicalize();
        assert_eq!(s, expected, "{}", path.display());
        seen += 1;
    }
    assert_eq!(seen, 18);
}

/// The policy example 18 was evaluated under: it denies `posix.network` and
/// `posix.process_spawn`.
const EXAMPLE_18_POLICY: &str = "[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"The runtime must not open connections\"\n[[capabilities.deny]]\nfeature = \"posix.process_spawn\"\naction = \"fail\"\nreason = \"The runtime must not start processes\"\n";

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
    let (audit, required) = policy.scope(&ScopeInput::of(&s.request));
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

    // A name-only claim is enough for an organizational ban; an unidentified one is not. Each
    // claim keeps only the assertions its status allows (PR-4c-1 spec §5).
    let mut s = example("01-complete-pass");
    s.components[0]
        .assertions
        .retain(|a| !matches!(a, IdentityAssertion::KnownHash { .. }));
    s.components[0].status = IdentityStatus::NameOnly;
    run(&mut s, deny);
    assert_eq!(s.policy_violations.len(), 1);
    let mut s = example("01-complete-pass");
    s.components[0]
        .assertions
        .retain(|a| matches!(a, IdentityAssertion::Signature { .. }));
    s.components[0].versions.clear();
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

/// PR-4c-2b spec §6: a deny entry matches a `Conflicting` claim through any of its names, and
/// the violation's subject is the claim in the session, never the denied key (design review P2).
#[test]
fn a_denied_name_of_a_conflicting_claim_is_a_violation_of_that_claim() {
    let deny = |component: &str| {
        format!(
            "[[components.deny]]\ncomponent = \"{component}\"\naction = \"fail\"\nreason = \"not approved\"\n"
        )
    };
    // Example 1's ggml claim, also named by the SONAME of the RPC backend.
    let conflicting = || {
        let mut s = example("01-complete-pass");
        let claim = &mut s.components[0];
        claim.assertions.insert(
            1,
            IdentityAssertion::SelfName {
                kind: NameKind::Soname,
                value: UntrustedText::new("libggml-rpc.so"),
                at: EvidenceRef::Artifact {
                    artifact: claim.subject.artifact(),
                },
            },
        );
        claim.status = IdentityStatus::Conflicting;
        s
    };
    let mut s = conflicting();
    run(&mut s, &deny("ggml-backend/rpc"));
    assert_eq!(s.policy_violations.len(), 1);
    let v = &s.policy_violations[0];
    assert_eq!(
        v.policy_rule.as_str(),
        "policy:components.deny.ggml-backend/rpc"
    );
    assert_eq!(
        v.subject,
        Ref::Component {
            slice: s.components[0].subject.clone(),
            component: ComponentKey::new("ggml").unwrap()
        }
    );
    assert!(s.components.iter().any(|c| matches!(
        &v.subject,
        Ref::Component { slice, component } if *slice == c.subject && *component == c.component
    )));
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    // Its own component still matches, once.
    let mut s = conflicting();
    run(&mut s, &deny("ggml"));
    assert_eq!(s.policy_violations.len(), 1);
    // Both entries: one violation each, of the one claim.
    let mut s = conflicting();
    run(
        &mut s,
        &format!("{}{}", deny("ggml"), deny("ggml-backend/rpc")),
    );
    assert_eq!(s.policy_violations.len(), 2);
    assert!(s
        .policy_violations
        .iter()
        .all(|v| v.subject == s.policy_violations[0].subject));
    let mut rules: Vec<&str> = s
        .policy_violations
        .iter()
        .map(|v| v.policy_rule.as_str())
        .collect();
    rules.sort_unstable();
    assert_eq!(
        rules,
        [
            "policy:components.deny.ggml",
            "policy:components.deny.ggml-backend/rpc"
        ]
    );
    // A name the database maps to no component matches nothing more.
    let mut s = example("01-complete-pass");
    let artifact = s.components[0].subject.artifact();
    s.components[0].assertions.insert(
        1,
        IdentityAssertion::SelfName {
            kind: NameKind::Soname,
            value: UntrustedText::new("libunknown.so"),
            at: EvidenceRef::Artifact { artifact },
        },
    );
    run(&mut s, &deny("ggml-backend/rpc"));
    assert!(s.policy_violations.is_empty());
    // An embedded value is not a name: only self-names name a component.
    let mut s = example("01-complete-pass");
    let artifact = s.components[0].subject.artifact();
    s.components[0].assertions.insert(
        1,
        IdentityAssertion::Embedded {
            field: "LLAMA_COMMIT".into(),
            value: UntrustedText::new("libggml-rpc.so"),
            method: ExtractMethod::DataSymbolPointer {
                symbol: UntrustedText::new("LLAMA_COMMIT"),
            },
            at: EvidenceRef::Artifact { artifact },
        },
    );
    run(&mut s, &deny("ggml-backend/rpc"));
    assert!(s.policy_violations.is_empty());
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

#[test]
fn an_active_request_changed_after_assembly_is_refused() {
    let policy = Policy::builtin_default().unwrap();
    let mut s = example("01-complete-pass");
    let (audit, required) = policy.scope(&ScopeInput::of(&s.request));
    s.request.audit = audit;
    s.request.required_checks = required;
    // The required checks were derived without the probe; a request that now lists one needs
    // `runtime_api.version` too.
    s.request.active.push(ActiveFeature::ApiProbe {
        address: "127.0.0.1".to_string(),
        port: 11434,
        allow_remote: false,
    });
    let time = s.outcome.policy_time.clone();
    assert!(matches!(
        evaluate(&mut s, &policy, time),
        Err(EvaluateError::RequiredChecksChanged { .. })
    ));
}

#[test]
fn an_install_root_removed_after_assembly_is_refused() {
    let policy = Policy::builtin_default().unwrap();
    let mut s = example("01-complete-pass");
    let (audit, required) = policy.scope(&ScopeInput::of(&s.request));
    assert!(required
        .iter()
        .any(|c| c.as_str() == sigil_model::ARTIFACTS_RELEASE));
    s.request.audit = audit;
    s.request.required_checks = required;
    // Without its install root the request no longer implies the runtime_artifacts checks.
    s.request
        .roots
        .retain(|r| r.id.as_str() != sigil_model::INSTALL_ROOT);
    let time = s.outcome.policy_time.clone();
    assert!(matches!(
        evaluate(&mut s, &policy, time),
        Err(EvaluateError::RequiredChecksChanged { .. })
    ));
}

// --- #51: capability denials ---------------------------------------------------------------------

const DENY_NETWORK: &str =
    "[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"fail\"\nreason = \"no network\"\n";
const DENY_LOADING: &str = "[[capabilities.deny]]\nfeature = \"posix.dynamic_loading\"\naction = \"warn\"\nreason = \"no plugins\"\n";
const DENY_CXX_WRITE: &str = "[[capabilities.deny]]\nfeature = \"cxx.file_write\"\naction = \"fail\"\nreason = \"no file writes\"\n";

fn the_slice(s: &Session) -> SliceId {
    s.binaries[0].slice.clone()
}

/// This build's capability-table entry, which a session with binary facts records.
fn table() -> KnowledgeRef {
    sigil_engine::code::data::signatures()
        .unwrap()
        .knowledge()
        .clone()
}

/// Example `name`, analyzed with this build's capability table, as `binary inspect` records it.
fn analyzed(name: &str) -> Session {
    let mut s = example(name);
    if !s
        .knowledge
        .iter()
        .any(|k| k.kind == KnowledgeKind::SignatureDb && k.id == CAPABILITY_TABLE_ID)
    {
        s.knowledge.push(table());
    }
    s
}

/// #51 spec §3: a slice that calls a denied capability's import directly is a violation, citing
/// every such call site; a capability it does not import gives nothing.
#[test]
fn a_denied_capability_that_is_called_is_a_violation_citing_its_call_sites() {
    // Example 16: suspicious_kernel-gcc-O2.o calls connect once (cs:0x4d).
    let mut s = analyzed("16-binary-code");
    let slice = the_slice(&s);
    run(&mut s, DENY_NETWORK);
    assert_eq!(s.policy_violations.len(), 1);
    let v = &s.policy_violations[0];
    assert_eq!(
        v.policy_rule.as_str(),
        "policy:capabilities.deny.posix.network"
    );
    assert_eq!(v.subject, Ref::Slice(slice.clone()));
    assert_eq!(
        v.evidence,
        [EvidenceRef::Code {
            slice: slice.clone(),
            loc: Loc::CallSite(CallId::new("cs:0x4d").unwrap()),
        }]
    );
    assert_eq!(
        (
            v.decision.action,
            v.decision.source.as_str(),
            v.decision.reason.as_deref(),
            v.decision.expires.as_ref()
        ),
        (
            Action::Fail,
            "policy:capabilities.deny.posix.network",
            Some("no network"),
            None
        )
    );
    assert!(
        s.open_questions.is_empty(),
        "a call is a violation, not a question"
    );
    assert!(s.findings.is_empty(), "a policy violation is not a finding");
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert_eq!(s.outcome.completeness, Completeness::Complete);

    // `warn` warns.
    let mut s = analyzed("16-binary-code");
    run(
        &mut s,
        "[[capabilities.deny]]\nfeature = \"posix.network\"\naction = \"warn\"\nreason = \"r\"\n",
    );
    assert_eq!(s.outcome.verdict, Verdict::Warn);

    // A capability the slice does not import gives nothing: no violation, no question.
    let mut s = analyzed("16-binary-code");
    run(
        &mut s,
        "[[capabilities.deny]]\nfeature = \"posix.process_spawn\"\naction = \"fail\"\nreason = \"r\"\n",
    );
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
}

/// #51 spec §3 (D4): a slice that imports a denied capability with no direct call site of it is an
/// open question, whatever `binary.code` says, never "absent".
#[test]
fn a_denied_capability_imported_without_a_call_site_is_an_open_question() {
    // Example 15: libggml-base.so imports dlopen and getenv; no code analysis.
    let mut s = analyzed("15-binary-inspect");
    let slice = the_slice(&s);
    run(&mut s, DENY_LOADING);
    assert!(s.policy_violations.is_empty());
    assert_eq!(s.open_questions.len(), 1);
    let q = &s.open_questions[0];
    assert_eq!(
        q.id.as_str(),
        format!("capability:posix.dynamic_loading@{slice}")
    );
    assert_eq!(q.rule.as_str(), CAPABILITY_RULE);
    assert_eq!(q.subject, Ref::Slice(slice.clone()));
    assert_eq!(
        q.conditions,
        [Condition {
            id: CondId::new("calls:posix.dynamic_loading").unwrap(),
            state: CondState::Unknown {
                reason: UnknownReason::NotModeled {
                    what: "calls in code that was not analyzed".into()
                },
                evidence: None,
            },
            unresolved: vec![],
        }]
    );
    assert_eq!(
        q.evidence,
        [EvidenceRef::Code {
            slice: slice.clone(),
            loc: Loc::Symbol(UntrustedText::new("dlopen")),
        }]
    );
    assert_eq!(
        (q.decision.treatment, q.decision.source.as_str()),
        (OqTreatment::CountAsGap, "policy:open_questions.default")
    );
    // Counted as a gap: never a clean pass.
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    let Completeness::Incomplete { gaps, .. } = &s.outcome.completeness else {
        panic!("{:?}", s.outcome.completeness);
    };
    assert_eq!(gaps, std::slice::from_ref(&q.id));

    // The policy's treatment of open questions applies to it.
    let mut s = analyzed("15-binary-inspect");
    run(
        &mut s,
        &format!("{DENY_LOADING}[open_questions]\ndefault = \"fail\"\n"),
    );
    assert_eq!(s.open_questions[0].decision.treatment, OqTreatment::Fail);
    assert_eq!(s.outcome.verdict, Verdict::Fail);

    // With code analysis complete and no call site, the question stays: a call that is not
    // direct is not followed.
    let mut s = analyzed("16-binary-code");
    s.code.clear();
    run(&mut s, DENY_NETWORK);
    assert!(s.policy_violations.is_empty());
    assert_eq!(
        s.open_questions[0].conditions[0].state,
        CondState::Unknown {
            reason: UnknownReason::NotModeled {
                what: "calls that are not direct (through a function pointer, or from data)".into()
            },
            evidence: None,
        }
    );
}

/// #51 spec §3 (D5): evaluation owns its capability results. Re-evaluating with another policy
/// replaces them, keeps every other open question, and evaluating twice changes nothing.
#[test]
fn re_evaluation_replaces_the_capability_results_and_keeps_the_others() {
    let mut s = analyzed("16-binary-code");
    run(&mut s, DENY_NETWORK);
    assert_eq!(s.policy_violations.len(), 1);
    let once = s.clone();
    run(&mut s, DENY_NETWORK);
    assert_eq!(s, once, "evaluating twice changes nothing");
    run(&mut s, "");
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
    assert_eq!(s.outcome.verdict, Verdict::Pass);

    let mut s = analyzed("15-binary-inspect");
    run(&mut s, DENY_LOADING);
    assert_eq!(s.open_questions.len(), 1);
    let once = s.clone();
    run(&mut s, DENY_LOADING);
    assert_eq!(s, once, "a capability question re-evaluates to itself");
    run(&mut s, "");
    assert!(s.open_questions.is_empty());

    // Example 7's loader question is the analysis's: a denial leaves it as it is.
    let mut s = example("07-open-question");
    let before = s.open_questions.clone();
    run(&mut s, DENY_NETWORK);
    assert_eq!(s.open_questions, before);
}

/// Plan review P2-1: under a capability denial, a session with binary facts is judged only when
/// it records this build's capability table; otherwise it is refused and left unchanged, never a
/// PASS on hints that another table made.
#[test]
fn a_session_not_analyzed_with_this_table_is_refused_under_a_capability_denial() {
    let p = |s: &Session| policy_for(s, DENY_NETWORK);
    // Recorded before #51: no table.
    let mut s = analyzed("16-binary-code");
    s.knowledge.retain(|k| k.kind != KnowledgeKind::SignatureDb);
    let before = s.clone();
    let time = s.outcome.policy_time.clone();
    assert_eq!(
        evaluate(&mut s, &p(&before), time.clone()),
        Err(EvaluateError::CapabilityTable {
            recorded: vec![],
            embedded: table().sha256,
        })
    );
    assert_eq!(s, before, "a refused evaluation changes nothing");
    // Another table.
    let other = Sha256Hex::new("e".repeat(64)).unwrap();
    let mut t = analyzed("16-binary-code");
    for k in &mut t.knowledge {
        if k.kind == KnowledgeKind::SignatureDb {
            k.sha256 = other.clone();
        }
    }
    let err = evaluate(&mut t.clone(), &p(&t), time.clone()).unwrap_err();
    assert_eq!(
        err,
        EvaluateError::CapabilityTable {
            recorded: vec![other],
            embedded: table().sha256,
        }
    );
    assert!(err
        .to_string()
        .contains("analyze the files again with this build"));
    // The table twice, even this build's: not exactly one table.
    let mut twice = analyzed("16-binary-code");
    twice.knowledge.push(table());
    assert_eq!(
        evaluate(&mut twice.clone(), &p(&twice), time.clone()),
        Err(EvaluateError::CapabilityTable {
            recorded: vec![table().sha256, table().sha256],
            embedded: table().sha256,
        })
    );
    // The entry's version only says which build wrote it: the SHA-256 is what is compared.
    let mut older = analyzed("16-binary-code");
    for k in &mut older.knowledge {
        if k.kind == KnowledgeKind::SignatureDb {
            k.version = "0.0.0".to_string();
        }
    }
    run(&mut older, DENY_NETWORK);
    assert_eq!(older.policy_violations.len(), 1);
    // Without a denial, the same sessions re-evaluate as before.
    let mut s = before;
    run(&mut s, "");
    run(&mut t, "");
    // A session without binary facts used no table: a denial has nothing to judge.
    let mut s = example("01-complete-pass");
    run(&mut s, DENY_NETWORK);
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
}

/// #105, #106's contract: a session saved before libc++'s names were added
/// (`tests/fixtures/pre-105/`) records the old table. Under a capability denial it is refused
/// with the re-inspection guidance and left unchanged: its hints are never re-read with this
/// table's names. Without a denial it evaluates as before.
#[test]
fn a_session_saved_with_the_table_before_libcxx_is_refused_only_under_a_denial() {
    const PRE_105: &str = "432f71b2a3c5f25663e699d5447db24b27590a4dad5ed1186b0f30ac89b26944";
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pre-105/16-binary-code.json");
    let saved: Session = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    saved.validate().unwrap();
    let old = Sha256Hex::new(PRE_105).unwrap();
    let recorded: Vec<Sha256Hex> = saved
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::SignatureDb && k.id == CAPABILITY_TABLE_ID)
        .map(|k| k.sha256.clone())
        .collect();
    assert_eq!(recorded, [old.clone()]);
    assert_ne!(table().sha256, old, "#105 changed the table");
    let time = saved.outcome.policy_time.clone();
    for deny in [DENY_NETWORK, DENY_CXX_WRITE] {
        let mut s = saved.clone();
        let err = evaluate(&mut s, &policy_for(&saved, deny), time.clone()).unwrap_err();
        assert_eq!(
            err,
            EvaluateError::CapabilityTable {
                recorded: vec![old.clone()],
                embedded: table().sha256,
            },
            "{deny}"
        );
        assert!(
            err.to_string()
                .contains("analyze the files again with this build"),
            "{err}"
        );
        assert_eq!(s, saved, "a refused evaluation changes nothing");
    }
    // Without a denial: as before.
    let mut s = saved;
    run(&mut s, "");
}

/// Plan review P2-1: the hints are the ones the table gives the import facts. `validate` cannot
/// tell that one is missing; evaluation refuses such a session.
#[test]
fn import_hints_that_are_not_the_table_s_are_refused() {
    let mut s = analyzed("16-binary-code");
    s.hints.retain(|h| h.signal != Signal::Import);
    s.validate().unwrap();
    let time = s.outcome.policy_time.clone();
    let before = s.clone();
    let p = policy_for(&s, DENY_NETWORK);
    let err = evaluate(&mut s, &p, time.clone()).unwrap_err();
    assert_eq!(
        err,
        EvaluateError::CapabilityHints {
            missing: 1,
            extra: 0
        }
    );
    assert!(err
        .to_string()
        .ends_with("analyze the files again with this build"));
    assert_eq!(s, before, "a refused evaluation changes nothing");
    let mut t = analyzed("16-binary-code");
    let mut moved = t.hints[0].clone();
    moved.feature = FeatureKey::new("posix.file_read").unwrap();
    t.hints.push(moved);
    assert_eq!(
        evaluate(&mut t.clone(), &policy_for(&t, DENY_NETWORK), time),
        Err(EvaluateError::CapabilityHints {
            missing: 0,
            extra: 1
        })
    );
}

/// A violation cites its call sites by ID, whatever order the code facts list them in, so a
/// canonical session (whose call sites are sorted by their JSON) re-evaluates to the same bytes.
#[test]
fn a_violation_cites_its_call_sites_by_id() {
    let mut s = analyzed("16-binary-code");
    let mut first = s.code[0].call_sites[0].clone();
    first.id = CallId::new("cs:0x10").unwrap();
    first.addr = 0x10;
    s.code[0].call_sites.push(first);
    run(&mut s, DENY_NETWORK);
    let slice = the_slice(&s);
    let cited: Vec<&EvidenceRef> = s.policy_violations[0].evidence.iter().collect();
    assert_eq!(
        cited,
        [
            &EvidenceRef::Code {
                slice: slice.clone(),
                loc: Loc::CallSite(CallId::new("cs:0x10").unwrap()),
            },
            &EvidenceRef::Code {
                slice,
                loc: Loc::CallSite(CallId::new("cs:0x4d").unwrap()),
            },
        ]
    );
}
