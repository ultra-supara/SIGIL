//! The model's hardest invariants (brief tests A–J, plan §4.4.7/§4.4.9/§4.5/§4.7, AC-12), and the
//! under-modeling check: the ten sentences of brief §40 expressed in structured fields only.

mod common;

use common::*;
use sigil_model::*;

fn round_trip(s: &Session) -> Session {
    serde_json::from_str(&serde_json::to_string(s).unwrap()).unwrap()
}

#[test]
fn every_example_is_valid() {
    for (name, s) in examples() {
        if let Err(errors) = s.validate() {
            panic!("{name} is invalid:\n{}", render(&errors));
        }
    }
}

// --- A: verdict and completeness are independent ----------------------------------------------

#[test]
fn a_confirmed_fail_with_an_unrelated_gap_is_fail_and_incomplete() {
    let s = round_trip(&fail_incomplete());
    assert_valid(&s);
    assert_eq!(s.outcome.verdict, Verdict::Fail);
    assert!(matches!(
        &s.outcome.completeness,
        Completeness::Incomplete { missing_required, gaps }
            if missing_required == &ids::<CheckId>(&["exposure.binds"]) && gaps.is_empty()
    ));
    let json = serde_json::to_value(&s.outcome).unwrap();
    assert_eq!(json["verdict"], "Fail");
    assert!(json["completeness"]["Incomplete"].is_object());
}

#[test]
fn a_gap_cannot_erase_a_confirmed_fail() {
    let mut s = fail_incomplete();
    s.outcome.verdict = Verdict::Pass;
    s.outcome.confirmed_failures = 0;
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::VerdictInconsistent {
                    recorded: Verdict::Pass,
                    expected: Verdict::Fail
                }
            )
        },
        "a PASS verdict contradicting a recorded FAIL decision",
    );
}

#[test]
fn pass_with_an_incomplete_audit_is_representable_but_not_complete() {
    let s = round_trip(&incomplete_pass());
    assert_valid(&s);
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));

    let mut claimed_complete = incomplete_pass();
    claimed_complete.outcome.completeness = Completeness::Complete;
    assert_rejected(
        &claimed_complete,
        |e| matches!(e, ValidationError::RequiredCheckNotClosed { check } if check.as_str() == "loader.search_paths"),
        "COMPLETE with a required check that is only Partial",
    );
}

#[test]
fn a_required_check_without_any_coverage_is_not_closed() {
    let mut s = complete_pass();
    s.request.required_checks.push(id("loader.search_paths"));
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::RequiredCheckNotClosed { check } if check.as_str() == "loader.search_paths"),
        "a required check that disappeared",
    );
}

#[test]
fn incomplete_must_name_exactly_the_open_checks_and_gaps() {
    let mut s = incomplete_pass();
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: vec![],
        gaps: vec![],
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::IncompleteWithoutReason),
        "an empty Incomplete",
    );

    let mut s = incomplete_pass();
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["loader.identify"]),
        gaps: vec![],
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::ListedCheckClosed { .. }),
        "a closed check listed as missing",
    );
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::RequiredCheckNotClosed { .. }),
        "the open check left unlisted",
    );

    let mut s = open_question();
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["artifacts.discovery"]),
        gaps: vec![],
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::GapNotListed { .. }),
        "a count-as-gap question left unlisted",
    );
}

#[test]
fn confirmed_counts_match_the_decisions() {
    let mut s = complete_fail();
    s.outcome.confirmed_failures = 0;
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::CountInconsistent {
                    field: "confirmed_failures",
                    recorded: 0,
                    expected: 1
                }
            )
        },
        "a wrong failure count",
    );
}

// --- B: a feature match is not verification -------------------------------------------------

#[test]
fn b_feature_match_stays_distinct_after_a_round_trip() {
    let s = round_trip(&feature_match_only());
    assert_valid(&s);
    let select = s
        .rule_support
        .iter()
        .find(|r| r.rule.as_str() == "select")
        .unwrap();
    assert!(
        matches!(&select.support, Support::FeatureMatch { unverified, .. } if !unverified.is_empty())
    );
    assert!(!select.support.is_verified());
    let filter = s
        .rule_support
        .iter()
        .find(|r| r.rule.as_str() == "filter")
        .unwrap();
    assert!(matches!(filter.support, Support::TargetVerified { .. }));
    assert!(
        s.findings.is_empty(),
        "a feature match must not produce a finding"
    );
}

#[test]
fn b_a_feature_match_cannot_make_a_finding_condition_met() {
    // The condition names the rule support; weakening the record weakens the condition.
    let mut s = complete_fail();
    let evaluate = s
        .rule_support
        .iter_mut()
        .find(|r| r.rule.as_str() == "evaluate")
        .unwrap();
    evaluate.support = Support::FeatureMatch {
        matched: ids(&["evaluate.score_call"]),
        unverified: ids(&["candidate.operands"]),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::InsufficientEvidence { condition, .. } if condition.as_str() == "rule_supported:evaluate"),
        "a Met condition resting on FeatureMatch",
    );
}

#[test]
fn feature_match_must_say_what_is_unverified() {
    let mut s = feature_match_only();
    let select = s
        .rule_support
        .iter_mut()
        .find(|r| r.rule.as_str() == "select")
        .unwrap();
    select.support = Support::FeatureMatch {
        matched: vec![],
        unverified: vec![],
    };
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::Empty {
                    what: "FeatureMatch.unverified",
                    ..
                }
            )
        },
        "an empty FeatureMatch",
    );
}

// --- C: conflicting identities survive ------------------------------------------------------

#[test]
fn c_conflicting_versions_coexist() {
    let s = round_trip(&conflicting_identity());
    assert_valid(&s);
    let claim = &s.components[0];
    assert_eq!(claim.status, IdentityStatus::Conflicting);
    let versions: Vec<_> = claim
        .versions
        .iter()
        .map(|v| v.value.as_str().unwrap())
        .collect();
    assert_eq!(versions, ["0.13.1", "0.12.0"]);
    assert!(claim.assertions.iter().any(|a| matches!(a, IdentityAssertion::KnownHash { matched: true, release, .. } if release == "v0.30.6")));
}

#[test]
fn an_identity_status_cannot_exceed_its_assertions() {
    let mut s = profile_mismatch();
    s.components[0].status = IdentityStatus::ReferenceMatched;
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::StatusUnsupported {
                    status: IdentityStatus::ReferenceMatched,
                    ..
                }
            )
        },
        "ReferenceMatched without a KnownHash match",
    );
    s.components[0].status = IdentityStatus::Corroborated;
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::StatusUnsupported {
                    status: IdentityStatus::Corroborated,
                    ..
                }
            )
        },
        "Corroborated without a matching code check",
    );
}

// --- D: mapped is not used ------------------------------------------------------------------

#[test]
fn d_present_and_mapped_but_use_unknown() {
    let mut s = feature_match_only();
    add_observed_zen4_mapping(&mut s);
    let s = round_trip(&s);
    assert_valid(&s);
    let load = &s.loads[0];
    assert!(load.present);
    assert_eq!(load.mapped.len(), 1);
    assert!(matches!(
        load.used_for_inference,
        Tri::Unknown {
            reason: UnknownReason::RequiresActive { .. }
        }
    ));
    assert!(matches!(load.selectable, Tri::Unknown { .. }));
}

#[test]
fn a_mapping_must_belong_to_its_process() {
    let mut s = feature_match_only();
    let p = |pid| ProcessRef {
        pid,
        start_ticks: 1,
        boot_id: "b".to_string(),
    };
    let mapping = MappingObs {
        process: p(2),
        at: ts("2026-10-07T07:00:01Z"),
        dev: 1,
        ino: 1,
        path_text: t("/x"),
        deleted: false,
        instance: None,
        same_mount_ns: Tri::Unknown {
            reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
        },
    };
    s.processes.push(ProcessObs {
        process: p(1),
        at: ts("2026-10-07T07:00:01Z"),
        roles: vec![],
        exe: ProcessExe::NotObservable(NotObservable::PermissionDenied),
        mappings: vec![mapping],
    });
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::MappingOfAnotherProcess { .. }),
        "a mapping of another process",
    );
}

// --- E/F: unsupported and budget are gaps, not results --------------------------------------

#[test]
fn e_an_unsupported_check_survives_as_a_gap() {
    let s = round_trip(&unsupported_check());
    assert_valid(&s);
    assert!(s
        .coverage
        .iter()
        .any(|c| matches!(c.state, CoverageState::Unsupported { .. })));
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    let mut complete = unsupported_check();
    complete.outcome.completeness = Completeness::Complete;
    assert_rejected(
        &complete,
        |e| matches!(e, ValidationError::RequiredCheckNotClosed { .. }),
        "Unsupported counted as closed",
    );
}

#[test]
fn f_a_budget_hit_is_a_truncated_analysis() {
    let s = round_trip(&budget_exceeded());
    assert_valid(&s);
    let c = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == "identity.strings")
        .unwrap();
    assert!(matches!(c.state, CoverageState::BudgetExceeded { used, limit, .. } if used == limit));
    assert!(!c.state.can_close());
    let mut complete = budget_exceeded();
    complete.outcome.completeness = Completeness::Complete;
    assert_rejected(
        &complete,
        |e| matches!(e, ValidationError::RequiredCheckNotClosed { .. }),
        "BudgetExceeded counted as closed",
    );
}

#[test]
fn only_complete_not_present_and_out_of_scope_can_close_a_check() {
    let closing = [
        CoverageState::Complete,
        CoverageState::NotPresent {
            evidence: vec![],
            scope: "dynsym".to_string(),
            basis: AbsenceBasis::SymbolsAbsent {
                names: vec!["x".to_string()],
            },
        },
        CoverageState::OutOfScope {
            why: "not requested".to_string(),
        },
    ];
    let open = [
        CoverageState::Partial { missing: vec![] },
        CoverageState::ProfileMismatch {
            profile: id(PROFILE),
            failed: vec![],
        },
        CoverageState::Skipped {
            by: SkipReason::ModeDisabled,
        },
        CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
        CoverageState::Unsupported {
            what: "x".to_string(),
        },
        CoverageState::BudgetExceeded {
            budget: "b".to_string(),
            used: 1,
            limit: 1,
        },
        CoverageState::Error { message: t("boom") },
    ];
    assert!(closing.iter().all(CoverageState::can_close));
    assert!(!open.iter().any(CoverageState::can_close));
}

// --- G: an open question is not a finding ---------------------------------------------------

#[test]
fn g_an_open_question_keeps_met_and_unknown_conditions_without_a_finding() {
    let s = round_trip(&open_question());
    assert_valid(&s);
    assert!(s.findings.is_empty());
    let oq = &s.open_questions[0];
    let states: Vec<&str> = oq
        .conditions
        .iter()
        .map(|c| match c.state {
            CondState::Met { .. } => "Met",
            CondState::NotMet { .. } => "NotMet",
            CondState::Unknown { .. } => "Unknown",
        })
        .collect();
    assert_eq!(states, ["Met", "Met", "Unknown", "Unknown"]);
    assert_eq!(oq.decision.treatment, OqTreatment::CountAsGap);
    assert_eq!(s.outcome.verdict, Verdict::Pass);
}

#[test]
fn an_open_question_with_every_condition_established_is_rejected() {
    let mut s = open_question();
    s.open_questions[0].conditions.truncate(2);
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::OpenQuestionSettled { .. }),
        "an open question with nothing open",
    );
}

#[test]
fn an_open_question_with_a_refuted_condition_is_rejected() {
    let mut s = open_question();
    // The runtime user is known, so "the runtime user is absent" is refuted.
    s.open_questions[0].conditions[1].state = CondState::NotMet {
        evidence: CondEvidence::Value {
            value: id("val:llama-server (per model)/user/predicted"),
            needs: ValueNeed::Absent,
        },
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::OpenQuestionRefuted { .. }),
        "a refuted rule kept as an open question",
    );
}

#[test]
fn a_finding_needs_every_condition_established() {
    let mut s = complete_fail();
    s.findings[0].conditions[1].state = CondState::Unknown {
        reason: UnknownReason::NotObservable(NotObservable::PermissionDenied),
        evidence: None,
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::FindingNotEstablished { .. }),
        "a finding with an Unknown condition",
    );

    let mut s = complete_fail();
    s.findings[0].conditions[1].unresolved = ids(&["candidate.operands"]);
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::FindingNotEstablished { .. }),
        "a finding with an unresolved premise",
    );

    let mut s = complete_fail();
    s.findings[0].evidence.clear();
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::Empty {
                    what: "Finding.evidence",
                    ..
                }
            )
        },
        "a finding without evidence",
    );
}

// --- H: technical finding vs. policy --------------------------------------------------------

#[test]
fn h_policy_raises_a_warn_finding_to_fail_without_changing_it() {
    let mut s = complete_fail();
    s.findings[0].default_severity = Severity::Warn;
    s.findings[0].decision = PolicyDecision {
        action: Action::Fail,
        source: id("policy:rules.loader.candidate_or_library_replaceable"),
        reason: Some("library replacement is never acceptable here".to_string()),
        expires: None,
    };
    let s = round_trip(&s);
    assert_valid(&s);
    assert_eq!(s.findings[0].default_severity, Severity::Warn);
    assert_eq!(s.findings[0].decision.action, Action::Fail);
    assert_eq!(s.outcome.verdict, Verdict::Fail);
}

#[test]
fn ignoring_needs_a_reason_and_keeps_the_entry() {
    let mut s = complete_fail();
    s.findings[0].decision = decision(
        Action::Ignore,
        "policy:rules.loader.candidate_or_library_replaceable",
    );
    s.outcome.verdict = Verdict::Pass;
    s.outcome.confirmed_failures = 0;
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::IgnoreWithoutReason { .. }),
        "Ignore without a reason",
    );
    s.findings[0].decision.reason = Some("accepted risk".to_string());
    s.findings[0].decision.expires = Some(id("2027-03-31"));
    assert_valid(&s);
    assert_eq!(
        s.findings.len(),
        1,
        "an ignored finding stays in the output"
    );
}

// --- I/J: content vs. placement -------------------------------------------------------------

#[test]
fn i_one_artifact_at_two_placements() {
    let mut s = complete_pass();
    let artifact = s.artifacts[0].id.clone();
    s.instances.push(instance(
        &id("inst:lib/ollama/libggml.so"),
        "install",
        "/usr/local/lib/ollama/libggml.so",
        &artifact,
        1011,
    ));
    let s = round_trip(&s);
    assert_valid(&s);
    let placements = s
        .instances
        .iter()
        .filter(|i| matches!(&i.content, InstanceContent::Read { artifact: a } if *a == artifact))
        .count();
    assert_eq!(placements, 2);
}

#[test]
fn j_one_path_with_different_contents_in_two_sessions() {
    let before = complete_pass();
    let mut after = base(&["artifacts.discovery", "loader.identify"]);
    add_ggml(&mut after, &hex(0x77));
    for check in ["artifacts.discovery", "loader.identify"] {
        after.coverage.push(complete(check));
    }
    assert_valid(&before);
    assert_valid(&after);
    assert_eq!(before.instances[0].id, after.instances[0].id);
    assert_ne!(before.instances[0].content, after.instances[0].content);
}

// --- Sufficiency (plan §4.4.9) ---------------------------------------------------------------

#[test]
fn sufficiency_follows_the_per_kind_table() {
    let mut s = complete_fail();
    let g = placed(&s, GGML);
    s.assumptions.extend([
        Assumption {
            id: id("A-3"),
            statement: "not accepted".to_string(),
            acceptance: AssumptionAcceptance::NotAccepted,
        },
        Assumption {
            id: id("A-4"),
            statement: "accepted".to_string(),
            acceptance: AssumptionAcceptance::Accepted {
                source: id("policy:assumptions.accept"),
            },
        },
    ]);
    let check = |s: &Session, e: &CondEvidence, expected: Option<Settles>| {
        assert_eq!(s.settles(e), expected, "{e:?}")
    };

    // Behavior: the support recorded for the rule on the slice.
    let behavior = CondEvidence::Behavior(loader_rule(&g, "evaluate"));
    let set_support = |s: &mut Session, support: Support| {
        let record = s
            .rule_support
            .iter_mut()
            .find(|r| r.rule.as_str() == "evaluate")
            .unwrap();
        record.support = support;
    };
    check(&s, &behavior, Some(Settles::Met));
    for (support, expected) in [
        (
            Support::ReferenceVerified {
                reference: g.artifact.clone(),
                verification: id("gt"),
                rule: id("evaluate"),
            },
            Settles::Met,
        ),
        (
            Support::Assumed {
                assumption: id("A-4"),
            },
            Settles::Met,
        ),
        (
            Support::Assumed {
                assumption: id("A-3"),
            },
            Settles::Neither,
        ),
        (
            Support::FeatureMatch {
                matched: vec![],
                unverified: ids(&["p"]),
            },
            Settles::Neither,
        ),
    ] {
        set_support(&mut s, support);
        check(&s, &behavior, Some(expected));
    }
    check(
        &s,
        &CondEvidence::Behavior(loader_rule(&g, "not_applied")),
        None,
    );

    // Access: the conclusion for the named capability.
    let access = CondEvidence::Access {
        access: s.access[0].id.clone(),
        capability: replace_libggml(),
    };
    for (conclusion, expected) in [
        (anyone_via_libdir(), Settles::Met),
        (AccessConclusion::TrustedOnly, Settles::NotMet),
        (
            AccessConclusion::Undetermined {
                missing: vec!["ACL".to_string()],
            },
            Settles::Neither,
        ),
    ] {
        s.access[0].capabilities[0].conclusion = conclusion;
        check(&s, &access, Some(expected));
    }
    check(
        &s,
        &CondEvidence::Access {
            access: s.access[0].id.clone(),
            capability: WriteCapability::CreateEntry {
                dir: t("/usr/local/lib/ollama"),
            },
        },
        None,
    );

    // Value: the needed state of an effective (not configured) value.
    let predicted = |needs| CondEvidence::Value {
        value: id("val:llama-server (per model)/user/predicted"),
        needs,
    };
    check(&s, &predicted(ValueNeed::Known), Some(Settles::Met));
    check(&s, &predicted(ValueNeed::Absent), Some(Settles::NotMet));
    check(
        &s,
        &CondEvidence::Value {
            value: id("val:ollama serve/user/configured"),
            needs: ValueNeed::Known,
        },
        Some(Settles::Neither),
    );
    s.values[1].value = TriValue::Absent;
    check(&s, &predicted(ValueNeed::Absent), Some(Settles::Met));
    s.values[1].value = TriValue::Unknown {
        reason: UnknownReason::InsufficientEvidence,
    };
    check(&s, &predicted(ValueNeed::Known), Some(Settles::Neither));
    check(&s, &predicted(ValueNeed::Absent), Some(Settles::Neither));

    // Binding: the state of the binding premise.
    let binding = binding_of_loader(&g);
    for (state, expected) in [
        (
            BindingState::Verified {
                scope: vec![g.inst.clone()],
            },
            Settles::Met,
        ),
        (
            BindingState::Assumed {
                assumption: id("A-4"),
            },
            Settles::Met,
        ),
        (
            BindingState::Assumed {
                assumption: id("A-3"),
            },
            Settles::Neither,
        ),
        (
            BindingState::Unknown {
                reason: UnknownReason::PremiseUnresolved,
            },
            Settles::Neither,
        ),
        (
            BindingState::Mismatch {
                first_definer: id("inst:x"),
            },
            Settles::NotMet,
        ),
    ] {
        s.bindings[0].state = state;
        check(&s, &binding, Some(expected));
    }

    // Identity: only a reference match.
    let identity = CondEvidence::Identity {
        slice: g.slice.clone(),
        component: id("ggml"),
    };
    check(&s, &identity, Some(Settles::Met));
    for status in [
        IdentityStatus::Conflicting,
        IdentityStatus::Corroborated,
        IdentityStatus::NameOnly,
        IdentityStatus::Unidentified,
    ] {
        s.components[0].status = status;
        check(&s, &identity, Some(Settles::Neither));
    }

    // Observed: either way, from observations only.
    check(
        &s,
        &CondEvidence::Observed {
            facts: vec![EvidenceRef::Artifact {
                artifact: g.artifact.clone(),
            }],
        },
        Some(Settles::Either),
    );
    for facts in [
        vec![],
        vec![EvidenceRef::Code {
            slice: g.slice.clone(),
            loc: Loc::VAddr(1),
        }],
        vec![EvidenceRef::Value { value: id("v") }],
    ] {
        check(
            &s,
            &CondEvidence::Observed { facts },
            Some(Settles::Neither),
        );
    }

    // Load: a decided fact with a sufficient basis and no unresolved premise.
    let mut s = feature_match_only();
    let zen4 = |fact| CondEvidence::Load {
        instance: s.loads[0].instance.clone(),
        context: s.loads[0].context.clone(),
        fact,
    };
    let (would_evaluate, selectable) = (zen4(LoadFact::WouldEvaluate), zen4(LoadFact::Selectable));
    check(&s, &would_evaluate, Some(Settles::Neither));
    check(&s, &selectable, Some(Settles::Neither));
    if let Tri::Yes { unresolved, .. } = &mut s.loads[0].would_evaluate {
        unresolved.clear();
    }
    check(&s, &would_evaluate, Some(Settles::Met));
    s.loads[0].would_evaluate = Tri::No {
        basis: Basis::Observed {
            source: ObsSource::File,
        },
        unresolved: vec![],
    };
    check(&s, &would_evaluate, Some(Settles::NotMet));
    s.loads[0].would_evaluate = Tri::No {
        basis: Basis::Modeled(loader_rule(&g, "select")),
        unresolved: vec![],
    };
    check(&s, &would_evaluate, Some(Settles::Neither));
}

#[test]
fn an_assumption_supports_a_condition_only_once_accepted() {
    let mut s = complete_fail();
    s.assumptions.push(Assumption {
        id: id("A-4"),
        statement: "the binding scope prefix is resolved".to_string(),
        acceptance: AssumptionAcceptance::NotAccepted,
    });
    s.bindings[0].state = BindingState::Assumed {
        assumption: id("A-4"),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::InsufficientEvidence { .. }),
        "a condition resting on an unaccepted assumption",
    );
    s.assumptions[0].acceptance = AssumptionAcceptance::Accepted {
        source: id("policy:assumptions.accept"),
    };
    assert_valid(&s);
}

#[test]
fn an_unknown_reason_must_match_its_evidence() {
    let mut s = open_question();
    let evaluate = &s.rule_support[2];
    assert_eq!(evaluate.rule.as_str(), "evaluate");
    s.open_questions[0].conditions[2].state = CondState::Unknown {
        reason: UnknownReason::InsufficientEvidence,
        evidence: Some(CondEvidence::Behavior(RuleSupportRef {
            profile: evaluate.profile.clone(),
            rule: evaluate.rule.clone(),
            slice: evaluate.slice.clone(),
        })),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::UnknownReasonInconsistent { .. }),
        "InsufficientEvidence with sufficient evidence",
    );
    s.open_questions[0].conditions[2].state = CondState::Unknown {
        reason: UnknownReason::PremiseUnresolved,
        evidence: None,
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::UnknownReasonInconsistent { .. }),
        "PremiseUnresolved without a premise",
    );
}

// --- Premises are carried (plan §4.4.7, AC-12) -----------------------------------------------

#[test]
fn a_fact_with_unresolved_premises_cannot_settle_a_condition() {
    // The loader's evaluate rule is TargetVerified, but this file's would_evaluate fact rests on
    // unresolved premises (weakest link), so a condition on it stays open.
    let mut s = feature_match_only();
    let candidate_evaluated = &mut s.open_questions[0].conditions[0];
    assert_eq!(candidate_evaluated.id.as_str(), "candidate_evaluated");
    let evidence = match &candidate_evaluated.state {
        CondState::Unknown {
            evidence: Some(e), ..
        } => e.clone(),
        other => panic!("{other:?}"),
    };
    candidate_evaluated.state = CondState::Met {
        evidence: evidence.clone(),
    };
    candidate_evaluated.unresolved.clear();
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::InsufficientEvidence { condition, .. } if condition.as_str() == "candidate_evaluated"),
        "a Met condition on a fact with unresolved premises",
    );

    // Once the premises of the fact (and of the candidate fact it rests on) are resolved, it does.
    if let Tri::Yes { unresolved, .. } = &mut s.loads[0].candidate {
        unresolved.clear();
    }
    if let Tri::Yes { unresolved, .. } = &mut s.loads[0].would_evaluate {
        unresolved.clear();
    }
    assert_eq!(s.settles(&evidence), Some(Settles::Met));
    assert_valid(&s);
}

#[test]
fn a_premise_is_never_dropped() {
    // A fact resting on a FeatureMatch carries its unverified premises.
    let mut s = feature_match_only();
    let g = placed(&s, GGML);
    if let Tri::Yes { basis, .. } = &mut s.loads[0].candidate {
        *basis = Basis::Modeled(loader_rule(&g, "select"));
    }
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::PremiseDropped { premise, .. } if premise.as_str() == "select"),
        "a fact that drops the premise of its FeatureMatch",
    );

    // A condition resting on a fact carries the fact's premises.
    let mut s = feature_match_only();
    s.open_questions[0].conditions[0]
        .unresolved
        .retain(|p| p.as_str() == "candidate.operands");
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::PremiseDropped { premise, .. } if premise.as_str().starts_with("binding:")),
        "a condition that drops a premise of its fact",
    );

    // A condition resting on a FeatureMatch carries its unverified premises.
    let mut s = feature_match_only();
    s.open_questions[0].conditions[1].unresolved.clear();
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::PremiseDropped { premise, .. } if premise.as_str() == "select"),
        "a condition that drops the premise of its FeatureMatch",
    );
}

#[test]
fn would_evaluate_is_never_stronger_than_candidate() {
    let mut s = feature_match_only();
    if let Tri::Yes { unresolved, .. } = &mut s.loads[0].would_evaluate {
        unresolved.clear();
    }
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::WouldEvaluateStrongerThanCandidate { .. }
            )
        },
        "a would_evaluate without the candidate's premises",
    );

    let mut s = feature_match_only();
    let select = RuleSupportRef {
        profile: id(PROFILE),
        rule: id("select"),
        slice: s.artifacts[0].slices[0].id.clone(),
    };
    if let Tri::Yes {
        basis, unresolved, ..
    } = &mut s.loads[0].candidate
    {
        *basis = Basis::Modeled(select);
        unresolved.push(id("select"));
    }
    if let Tri::Yes { unresolved, .. } = &mut s.loads[0].would_evaluate {
        unresolved.push(id("select"));
    }
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::WouldEvaluateStrongerThanCandidate { .. }
            )
        },
        "a verified would_evaluate on a feature-matched candidate",
    );

    let mut s = feature_match_only();
    s.loads[0].candidate = Tri::Unknown {
        reason: UnknownReason::CheckIncomplete {
            check: id("loader.identify"),
        },
    };
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::WouldEvaluateStrongerThanCandidate { .. }
            )
        },
        "would_evaluate Yes without a candidate",
    );
}

// --- Support vs. obligations (plan §4.5) -----------------------------------------------------

#[test]
fn target_verified_needs_passing_obligations_with_locations() {
    let mut s = target_verified();
    s.rule_support[1].support = Support::TargetVerified {
        obligations: ids(&["filter.not_in_profile_match"]),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::ObligationNotPassed { .. }),
        "TargetVerified on an obligation that did not pass",
    );

    let mut s = target_verified();
    if let Relation::ProfileMatch { obligations, .. } = &mut s.relations[0] {
        obligations[0].at.clear();
    }
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::Empty {
                    what: "ObligationResult.at",
                    ..
                }
            )
        },
        "a Pass without a location",
    );

    let mut s = target_verified();
    s.rule_support[0].support = Support::TargetVerified {
        obligations: vec![],
    };
    assert_rejected(
        &s,
        |e| {
            matches!(
                e,
                ValidationError::Empty {
                    what: "TargetVerified.obligations",
                    ..
                }
            )
        },
        "an empty TargetVerified",
    );
}

#[test]
fn reference_verified_needs_the_reference_artifact() {
    let mut s = reference_verified();
    if let Support::ReferenceVerified { reference, .. } = &mut s.rule_support[0].support {
        *reference = id(&format!("sha256:{}", hex(0x99)));
    }
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::NotTheReference { .. }),
        "ReferenceVerified on a different artifact",
    );
}

// --- Referential integrity ------------------------------------------------------------------

#[test]
fn references_must_resolve_and_ids_must_be_unique() {
    let mut s = complete_fail();
    s.findings[0].evidence.push(EvidenceRef::Instance {
        instance: id("inst:missing"),
    });
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::Dangling { id, .. } if id == "inst:missing"),
        "a dangling instance reference",
    );

    let mut s = complete_fail();
    s.findings[0].evidence.push(EvidenceRef::Code {
        slice: s.code[0].slice.clone(),
        loc: Loc::CallSite(id("cs:0xdead")),
    });
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::Dangling { id, .. } if id == "cs:0xdead"),
        "a dangling call site",
    );

    let mut s = complete_pass();
    let dup = s.instances[0].clone();
    s.instances.push(dup);
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::DuplicateId { .. }),
        "a duplicate instance",
    );

    let mut s = target_verified();
    s.knowledge.retain(|k| k.kind != KnowledgeKind::Profile);
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::Dangling { id, .. } if id == PROFILE),
        "a profile missing from knowledge",
    );

    let mut s = complete_pass();
    s.instances[0].root = id("models");
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::Dangling { id, .. } if id == "models"),
        "an undeclared scan root",
    );
}

#[test]
fn slices_agree_with_their_artifact() {
    let mut s = complete_pass();
    s.artifacts[0].slices[0].offset = 4096;
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::SliceMismatch { .. }),
        "a slice ID that disagrees with its offset",
    );
}

#[test]
fn errors_name_the_offending_ids() {
    let mut s = complete_fail();
    s.findings[0].evidence.push(EvidenceRef::Instance {
        instance: id("inst:missing"),
    });
    let message = errors(&s)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(message.contains("inst:missing"), "{message}");
    assert!(
        message.contains("finding:loader.candidate_or_library_replaceable"),
        "{message}"
    );
}

// --- Brief §40: ten sentences, structured fields only -----------------------------------------

#[test]
fn the_ten_sentences_are_representable_without_message_strings() {
    // 1. "This file claims to be version X, but a reference hash says it belongs to release Y."
    let s = conflicting_identity();
    let claim = &s.components[0];
    assert!(claim
        .versions
        .iter()
        .any(|v| matches!(v.source, VersionSource::Embedded { .. })
            && v.value.as_str() == Some("0.12.0")));
    assert!(claim.assertions.iter().any(|a| matches!(a, IdentityAssertion::KnownHash { matched: true, release, .. } if release == "v0.30.6")));

    // 2. "The import exists, but a call has not been established."
    let mut s = complete_pass();
    let slice = s.artifacts[0].slices[0].id.clone();
    s.hints.push(FeatureHint {
        subject: slice.clone(),
        feature: id("posix.network"),
        signal: Signal::Import,
        value: t("connect"),
        at: Loc::Symbol(t("connect")),
    });
    assert_valid(&s);
    assert!(
        s.code.iter().all(|c| c.slice != slice),
        "no call-site facts exist for it"
    );

    // 3. "The call is established, but one path condition is Unknown."
    let mut s = target_verified();
    s.code[0].guard_regions.push(GuardRegion {
        function: id("fn:0xc590"),
        from: Loc::CallSite(id("cs:0xd303")),
        to: id("cs:0xe26d"),
        region: RegionKind::PerIteration,
        guards: vec![GuardBranch {
            at: 0xd4c0,
            cond: GuardCond::Unmodeled {
                detail: "bit test on an atom".to_string(),
            },
            dominates_to: true,
            exit: ExitKind::Skip,
        }],
        converging: 0,
        indirect: vec![],
        complete: TriState::Unknown,
    });
    assert_valid(&s);

    // 4. "The behavior is TargetVerified."
    assert!(target_verified()
        .rule_support
        .iter()
        .all(|r| matches!(r.support, Support::TargetVerified { .. })));

    // 5. "The feature only matches heuristically and cannot support a confirmed finding."
    let s = feature_match_only();
    let CondState::Unknown {
        reason: UnknownReason::InsufficientEvidence,
        evidence: Some(evidence @ CondEvidence::Behavior(key)),
    } = &s.open_questions[0].conditions[1].state
    else {
        panic!("expected an open condition on a rule support");
    };
    assert!(matches!(
        s.rule_support.iter().find(|r| r.is(key)).unwrap().support,
        Support::FeatureMatch { .. }
    ));
    assert_eq!(s.settles(evidence), Some(Settles::Neither));

    // 6. "A directory permission condition is directly observed."
    let s = complete_fail();
    let CondState::Met {
        evidence: evidence @ CondEvidence::Access { .. },
    } = &s.findings[0].conditions[1].state
    else {
        panic!("expected a Met access condition");
    };
    assert_eq!(s.settles(evidence), Some(Settles::Met));
    assert!(matches!(
        s.access[0].capabilities[0].conclusion,
        AccessConclusion::UntrustedHolder {
            who: Principal::Anyone,
            ..
        }
    ));
    assert!(s.access[0].chain.iter().any(|n| n.mode & 0o002 != 0));

    // 7. "A dangerous condition is confirmed."
    assert!(s.findings[0]
        .conditions
        .iter()
        .all(|c| matches!(c.state, CondState::Met { .. }) && c.unresolved.is_empty()));

    // 8. "A different required check was not possible because of permission denial."
    let mut s = complete_pass();
    s.request.required_checks.push(id("exposure.binds"));
    s.coverage.push(coverage(
        "exposure.binds",
        Ref::Audit,
        CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
    ));
    s.outcome.completeness = Completeness::Incomplete {
        missing_required: ids(&["exposure.binds"]),
        gaps: vec![],
    };
    assert_valid(&s);

    // 9. "Result: FAIL and INCOMPLETE."
    let s = fail_incomplete();
    assert!(
        s.outcome.verdict == Verdict::Fail
            && matches!(s.outcome.completeness, Completeness::Incomplete { .. })
    );

    // 10. "Policy changed a technical WARN to FAIL without altering the technical finding."
    let mut s = complete_fail();
    s.findings[0].default_severity = Severity::Warn;
    assert_valid(&s);
    assert_eq!(
        (
            s.findings[0].default_severity,
            s.findings[0].decision.action
        ),
        (Severity::Warn, Action::Fail)
    );
}
