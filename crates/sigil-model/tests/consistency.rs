//! Records that describe the same thing cannot disagree.
//!
//! - A condition names the record that decides it and claims no more than that record settles,
//!   so a changed record changes what the condition may claim.
//! - The keys records are found by are unique: one result per obligation, one support per rule,
//!   one knowledge entry per revision, and so on. A duplicate is rejected, never resolved by
//!   picking the favorable entry.
//! - A check result, a profile mismatch, and a listed mapping agree with the record they repeat.

mod common;

use common::*;
use sigil_model::*;

fn condition_error(
    s: &Session,
    condition: &str,
    matches: impl Fn(&ValidationError) -> bool,
    what: &str,
) {
    assert_rejected(
        s,
        |e| {
            matches(e)
                && match e {
                    ValidationError::InsufficientEvidence { condition: c, .. }
                    | ValidationError::ContradictedByEvidence { condition: c, .. }
                    | ValidationError::DecidedWithUnresolved { condition: c, .. } => {
                        c.as_str() == condition
                    }
                    _ => true,
                }
        },
        what,
    );
}

fn insufficient(e: &ValidationError) -> bool {
    matches!(e, ValidationError::InsufficientEvidence { .. })
}

fn contradicted(e: &ValidationError) -> bool {
    matches!(e, ValidationError::ContradictedByEvidence { .. })
}

fn dangling(kind: &'static str) -> impl Fn(&ValidationError) -> bool {
    move |e| matches!(e, ValidationError::Dangling { kind: k, .. } if *k == kind)
}

fn duplicate(kind: &'static str) -> impl Fn(&ValidationError) -> bool {
    move |e| matches!(e, ValidationError::DuplicateId { kind: k, .. } if *k == kind)
}

/// A session builder and a mutation of it.
type Build = fn() -> Session;
type Mutate = fn(&mut Session);

fn rule_support<'s>(s: &'s mut Session, rule: &str) -> &'s mut RuleSupport {
    s.rule_support
        .iter_mut()
        .find(|r| r.rule.as_str() == rule)
        .unwrap()
}

// --- A condition follows the record it names ------------------------------------------------

#[test]
fn a_behavior_condition_is_checked_through_its_rule_support() {
    // The confirmed finding names the evaluate rule's support; a rule nobody recorded is dangling.
    let mut s = complete_fail();
    let g = placed(&s, GGML);
    s.findings[0].conditions[0].state = CondState::Met {
        evidence: CondEvidence::Behavior(loader_rule(&g, "not_applied")),
    };
    assert_rejected(&s, dangling("rule support"), "an unrecorded rule support");

    // The support it names gets every check, wherever it is used.
    let mut s = complete_fail();
    rule_support(&mut s, "evaluate").support = Support::TargetVerified {
        obligations: ids(&["evaluate.nonexistent_obligation"]),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::ObligationNotPassed { obligation, .. } if obligation.as_str() == "evaluate.nonexistent_obligation"),
        "TargetVerified on an obligation that does not exist",
    );

    let mut s = complete_fail();
    rule_support(&mut s, "evaluate").support = Support::ReferenceVerified {
        reference: id(&format!("sha256:{}", hex(0x99))),
        verification: id("groundtruth:ollama-0.30.6-loader#G-2"),
        rule: id("evaluate"),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::NotTheReference { .. }),
        "ReferenceVerified for an unrelated artifact",
    );

    let mut s = complete_fail();
    let g = placed(&s, GGML);
    rule_support(&mut s, "evaluate").support = Support::ReferenceVerified {
        reference: g.artifact,
        verification: id("groundtruth:ollama-0.30.6-loader#G-2"),
        rule: id("filter"),
    };
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::RuleMismatch { .. }),
        "ReferenceVerified for another rule",
    );
}

#[test]
fn a_value_condition_follows_the_value_record() {
    let mut s = complete_fail();
    let predicted = s
        .values
        .iter_mut()
        .find(|v| v.id.as_str().ends_with("/predicted"))
        .unwrap();
    predicted.value = TriValue::Unknown {
        reason: UnknownReason::InsufficientEvidence,
    };
    condition_error(
        &s,
        "runtime_principal_known",
        insufficient,
        "a known-user condition on an unknown user",
    );

    let mut s = complete_fail();
    s.findings[0].conditions[2].state = CondState::Met {
        evidence: CondEvidence::Value {
            value: id("val:ollama serve/user/configured"),
            needs: ValueNeed::Known,
        },
    };
    condition_error(
        &s,
        "runtime_principal_known",
        insufficient,
        "a condition on a configured (not effective) value",
    );

    let mut s = complete_fail();
    s.findings[0].conditions[2].state = CondState::Met {
        evidence: CondEvidence::Value {
            value: id("val:llama-server (per model)/user/predicted"),
            needs: ValueNeed::Absent,
        },
    };
    condition_error(
        &s,
        "runtime_principal_known",
        contradicted,
        "an absent-value condition on a known value",
    );

    let mut s = complete_fail();
    s.findings[0].conditions[2].state = CondState::Met {
        evidence: CondEvidence::Value {
            value: id("val:missing"),
            needs: ValueNeed::Known,
        },
    };
    assert_rejected(&s, dangling("value"), "an unrecorded value");
}

#[test]
fn an_access_condition_follows_the_access_record() {
    let mut s = complete_fail();
    s.access[0].capabilities[0].conclusion = AccessConclusion::Undetermined {
        missing: vec!["the ACL of /usr/local/lib/ollama is not readable".to_string()],
    };
    condition_error(
        &s,
        "untrusted_write:library",
        insufficient,
        "an untrusted-write condition on an undetermined capability",
    );

    let mut s = complete_fail();
    s.access[0].capabilities[0].conclusion = AccessConclusion::TrustedOnly;
    condition_error(
        &s,
        "untrusted_write:library",
        contradicted,
        "an untrusted-write condition on a trusted-only capability",
    );

    let mut s = complete_fail();
    s.findings[0].conditions[1].state = CondState::Met {
        evidence: CondEvidence::Access {
            access: s.access[0].id.clone(),
            capability: WriteCapability::CreateEntry {
                dir: t("/usr/local/lib/ollama"),
            },
        },
    };
    assert_rejected(
        &s,
        dangling("write capability"),
        "a capability the access record did not analyze",
    );
}

#[test]
fn binding_identity_and_load_conditions_follow_their_records() {
    let mut s = complete_fail();
    s.bindings[0].state = BindingState::Unknown {
        reason: UnknownReason::PremiseUnresolved,
    };
    condition_error(
        &s,
        &format!("binding:{ROLE}"),
        insufficient,
        "a binding condition on an unknown binding",
    );
    s.bindings[0].state = BindingState::Mismatch {
        first_definer: id("inst:lib/ollama/libggml.so.0.13.1"),
    };
    condition_error(
        &s,
        &format!("binding:{ROLE}"),
        contradicted,
        "a binding condition on a mismatched binding",
    );

    let mut s = complete_fail();
    let g = placed(&s, GGML);
    s.findings[0].conditions.push(met(
        "identity:ggml",
        CondEvidence::Identity {
            slice: g.slice.clone(),
            component: id("ggml"),
        },
    ));
    assert_valid(&s);
    s.components[0].status = IdentityStatus::NameOnly;
    condition_error(
        &s,
        "identity:ggml",
        insufficient,
        "an identity condition on a name-only claim",
    );

    let mut s = feature_match_only();
    if let CondState::Unknown {
        evidence: Some(CondEvidence::Load { context, .. }),
        ..
    } = &mut s.open_questions[0].conditions[0].state
    {
        context.process_role = id("ollama serve");
    }
    assert_rejected(&s, dangling("load facts"), "unrecorded load facts");
}

#[test]
fn a_decided_condition_has_no_unresolved_premise() {
    let mut s = complete_fail();
    s.findings[0].conditions[1].unresolved = ids(&["candidate.operands"]);
    condition_error(
        &s,
        "untrusted_write:library",
        |e| matches!(e, ValidationError::DecidedWithUnresolved { .. }),
        "a Met condition with an unresolved premise",
    );
}

// --- One record per key ---------------------------------------------------------------------

#[test]
fn an_obligation_has_one_result_per_profile_and_slice() {
    // A Fail next to the Pass that TargetVerified rests on: rejected, not resolved to the Pass.
    let mut s = complete_fail();
    let Relation::ProfileMatch { obligations, .. } = &mut s.relations[0] else {
        panic!("expected the loader's profile match");
    };
    obligations.push(ObligationResult {
        id: id("evaluate.score_call"),
        result: ObligationState::Fail,
        at: vec![],
    });
    assert_rejected(
        &s,
        duplicate("obligation result"),
        "Pass and Fail for one obligation",
    );

    // The same in a second profile match for the same profile and slice.
    let mut s = complete_fail();
    let Relation::ProfileMatch { profile, slice, .. } = s.relations[0].clone() else {
        panic!("expected the loader's profile match");
    };
    s.relations.push(Relation::ProfileMatch {
        profile,
        slice,
        obligations: vec![ObligationResult {
            id: id("evaluate.score_call"),
            result: ObligationState::Fail,
            at: vec![],
        }],
    });
    assert_rejected(
        &s,
        duplicate("obligation result"),
        "a second result in another profile match",
    );
}

#[test]
fn records_that_others_refer_to_have_one_entry_per_key() {
    let cases: Vec<(&'static str, Build, Mutate)> = vec![
        ("knowledge", complete_fail, |s| {
            let mut other = s
                .knowledge
                .iter()
                .find(|k| k.kind == KnowledgeKind::Profile)
                .unwrap()
                .clone();
            other.sha256 = id(&hex(0x77));
            s.knowledge.push(other);
        }),
        ("rule support", complete_fail, |s| {
            let mut other = s.rule_support[2].clone();
            other.support = Support::FeatureMatch {
                matched: vec![],
                unverified: ids(&["candidate.operands"]),
            };
            s.rule_support.push(other);
        }),
        ("component claim", complete_fail, |s| {
            let mut other = s.components[0].clone();
            other.status = IdentityStatus::NameOnly;
            s.components.push(other);
        }),
        ("binding premise", complete_fail, |s| {
            let mut other = s.bindings[0].clone();
            other.state = BindingState::Unknown {
                reason: UnknownReason::PremiseUnresolved,
            };
            s.bindings.push(other);
        }),
        ("load facts", feature_match_only, |s| {
            let other = s.loads[0].clone();
            s.loads.push(other);
        }),
        ("coverage", complete_fail, |s| {
            s.coverage.push(coverage(
                "loader.identify",
                Ref::Audit,
                CoverageState::Error {
                    message: t("decode failure"),
                },
            ));
        }),
        ("write capability", complete_fail, |s| {
            let mut other = s.access[0].capabilities[0].clone();
            other.conclusion = AccessConclusion::TrustedOnly;
            s.access[0].capabilities.push(other);
        }),
    ];
    for (kind, build, mutate) in cases {
        let mut s = build();
        mutate(&mut s);
        assert_rejected(&s, duplicate(kind), &format!("a duplicate {kind}"));
    }
}

// --- Repeated results agree ------------------------------------------------------------------

#[test]
fn a_check_result_agrees_with_the_obligation_it_decides() {
    let mismatch = || CheckResult::Mismatch {
        counterexample: None,
        detail: "the target call is reached when the filter fails".to_string(),
    };
    let disagrees = |e: &ValidationError| matches!(e, ValidationError::ObligationResultDisagrees { obligation, .. } if obligation.as_str() == "filter.reach_predicate");

    let mut s = complete_fail();
    s.code[0].predicate_checks[0].result = mismatch();
    assert_rejected(
        &s,
        disagrees,
        "a mismatched predicate check for a passed obligation",
    );

    let mut s = complete_fail();
    let code_check = |result| IdentityAssertion::CodeCheck {
        profile: id(PROFILE),
        check: id("filter.reach_predicate"),
        result,
        at: vec![],
    };
    s.components[0]
        .assertions
        .push(code_check(CheckResult::Match));
    assert_valid(&s);
    s.components[0].assertions.pop();
    s.components[0].assertions.push(code_check(mismatch()));
    assert_rejected(
        &s,
        disagrees,
        "a mismatched identity code check for a passed obligation",
    );
}

#[test]
fn a_profile_mismatch_names_failed_obligations_of_its_slice() {
    let s = profile_mismatch();
    assert_valid(&s);

    let index = s
        .coverage
        .iter()
        .position(|c| matches!(c.state, CoverageState::ProfileMismatch { .. }))
        .unwrap();
    let set_failed = |s: &mut Session, failed: &[&str]| {
        if let CoverageState::ProfileMismatch { failed: f, .. } = &mut s.coverage[index].state {
            *f = ids(failed);
        }
    };

    let mut passed = s.clone();
    set_failed(&mut passed, &["entry.name_sequence"]);
    assert_rejected(
        &passed,
        |e| matches!(e, ValidationError::ObligationResultDisagrees { .. }),
        "a ProfileMismatch naming an obligation that passed",
    );

    let mut empty = s.clone();
    set_failed(&mut empty, &[]);
    assert_rejected(
        &empty,
        |e| {
            matches!(
                e,
                ValidationError::Empty {
                    what: "ProfileMismatch.failed",
                    ..
                }
            )
        },
        "a ProfileMismatch naming nothing",
    );

    let mut audit = s.clone();
    audit.coverage[index].scope = Ref::Audit;
    assert_rejected(
        &audit,
        |e| matches!(e, ValidationError::ScopeNotASlice { .. }),
        "a ProfileMismatch not scoped to a slice",
    );
}

#[test]
fn load_facts_list_only_mappings_observed_for_that_file() {
    let mut s = feature_match_only();
    add_observed_zen4_mapping(&mut s);
    assert_valid(&s);

    let mut altered = s.clone();
    altered.loads[0].mapped[0].ino += 1;
    assert_rejected(
        &altered,
        dangling("mapping observation"),
        "a mapping the process observation does not have",
    );

    let mut other_file = s.clone();
    other_file.loads[0].mapped[0].instance = Some(id(GGML));
    assert_rejected(
        &other_file,
        |e| matches!(e, ValidationError::MappingOfAnotherFile { .. }),
        "a mapping of another file",
    );

    let mut not_observable = s.clone();
    not_observable.loads[0].mapping_observability =
        Observability::NotObservable(NotObservable::ModeDisabled);
    assert_rejected(
        &not_observable,
        |e| matches!(e, ValidationError::MappedButNotObservable { .. }),
        "mappings listed as not observable",
    );
}

#[test]
fn a_relation_and_its_modeled_basis_name_one_rule() {
    let mut s = complete_fail();
    let g = placed(&s, GGML);
    let search_path = |rule: &str| Relation::SearchPath {
        role: id(ROLE),
        search_path: "exe_dir".to_string(),
        rule: ProfileRuleRef {
            profile: id(PROFILE),
            rule: id(rule),
        },
        dir: SearchDir::ExeDir {
            instance: g.inst.clone(),
        },
        basis: Basis::Modeled(loader_rule(&g, "filter")),
        unresolved: vec![],
    };
    s.relations.push(search_path("filter"));
    assert_valid(&s);
    *s.relations.last_mut().unwrap() = search_path("evaluate");
    assert_rejected(
        &s,
        |e| matches!(e, ValidationError::RuleMismatch { .. }),
        "a relation whose modeled basis is another rule",
    );
}
