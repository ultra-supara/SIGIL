//! Judging a diff under a compare policy (#16, PR-16b): the change kinds and causes, the default
//! table, complete tables only, the verdict and completeness a table gives, and how a diff
//! records and shows them.

mod common;

use common::diff_cases::*;
use common::*;
use sigil_model::diff::*;
use sigil_model::*;

#[test]
fn every_change_kind_is_named_as_its_variant_and_in_declared_order() {
    let mut seen: Vec<ChangeKind> = vec![];
    for change in every_change() {
        let kind = change.kind();
        assert_eq!(tag(&change), kind.name());
        if seen.last() != Some(&kind) {
            seen.push(kind);
        }
    }
    // `every_change` lists the kinds in declared order, some twice.
    assert_eq!(seen, ChangeKind::ALL);
    assert!(ChangeKind::ALL.windows(2).all(|w| w[0] < w[1]));
    for kind in ChangeKind::ALL {
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::json!(kind.name())
        );
        assert_eq!(ChangeKind::from_name(kind.name()), Some(kind));
    }
    assert_eq!(ChangeKind::from_name("LayerChange"), None);
}

#[test]
fn every_cause_is_named_as_its_variant_and_ordered() {
    assert_eq!(Cause::ALL, [Cause::Coverage, Cause::Request, Cause::Policy]);
    assert!(Cause::ALL.windows(2).all(|w| w[0] < w[1]));
    for cause in Cause::ALL {
        assert_eq!(
            serde_json::to_value(cause).unwrap(),
            serde_json::json!(cause.name())
        );
        assert_eq!(Cause::from_name(cause.name()), Some(cause));
    }
    assert_eq!(Cause::from_name("coverage"), None);
}

#[test]
fn a_new_or_changed_finding_or_violation_carries_its_current_decisions() {
    let mut missing = compare_store();
    blob_missing(&mut missing);
    let diff = diff_of(&compare_store(), &missing);
    let new = diff
        .changes
        .iter()
        .find(|c| c.kind() == ChangeKind::FindingNew)
        .unwrap();
    assert_eq!(
        new.decisions(),
        Some(&[decision(Action::Warn, "default:model.blob_missing")][..])
    );
    let diff = diff_of(&binary_inspect(), &binary_denied());
    let new = diff
        .changes
        .iter()
        .find(|c| c.kind() == ChangeKind::ViolationNew)
        .unwrap();
    assert_eq!(
        new.decisions(),
        Some(&[decision(Action::Fail, "policy:components.deny.ggml-base")][..])
    );
    // A changed decision carries its current side's; no other kind carries any.
    for change in every_change() {
        match &change {
            Change::FindingDecisionChanged { current, .. }
            | Change::ViolationDecisionChanged { current, .. } => {
                assert_eq!(change.decisions(), Some(&current[..]), "{change:?}");
            }
            Change::FindingNew { .. } | Change::ViolationNew { .. } => {}
            _ => assert_eq!(change.decisions(), None, "{change:?}"),
        }
    }
}

fn change_of(kind: ChangeKind) -> Change {
    every_change()
        .into_iter()
        .find(|c| c.kind() == kind)
        .unwrap_or_else(|| panic!("no {kind:?} sample"))
}

fn finding_new(actions: &[Action]) -> Change {
    Change::FindingNew {
        rule: id("model.blob_missing"),
        subject: SubjectKey::Model(id(MODEL_M)),
        at: "#1".to_string(),
        current: vec![id(&format!("finding:model.blob_missing@{MODEL_M}#1"))],
        decisions: actions
            .iter()
            .map(|a| decision(*a, "default:model.blob_missing"))
            .collect(),
    }
}

fn not_comparable(cause: Cause) -> NotComparable {
    NotComparable {
        item: Item::Model { model: id(MODEL_N) },
        cause,
        checks: vec![],
        open_in: Side::Both,
    }
}

fn with_action(r: &CompareRules, kind: ChangeKind, action: CompareAction) -> CompareRules {
    let mut changes = r.changes().clone();
    changes.get_mut(&kind).unwrap().action = action;
    CompareRules::new(r.policy().clone(), changes, r.not_comparable().clone()).unwrap()
}

fn with_treatment(r: &CompareRules, cause: Cause, treatment: OqTreatment) -> CompareRules {
    let mut causes = r.not_comparable().clone();
    causes.get_mut(&cause).unwrap().treatment = treatment;
    CompareRules::new(r.policy().clone(), r.changes().clone(), causes).unwrap()
}

#[test]
fn the_default_table_is_the_documented_one() {
    let r = builtin_rules();
    let by = |action: CompareAction| -> Vec<&'static str> {
        ChangeKind::ALL
            .into_iter()
            .filter(|k| r.changes()[k].action == action)
            .map(ChangeKind::name)
            .collect()
    };
    assert_eq!(
        by(CompareAction::Fail),
        ["LayerChanged", "FileContentChanged", "BindWidened"]
    );
    assert_eq!(
        by(CompareAction::Decided),
        [
            "VerdictChanged",
            "FindingNew",
            "FindingDecisionChanged",
            "ViolationNew",
            "ViolationDecisionChanged"
        ]
    );
    assert_eq!(
        by(CompareAction::Warn),
        [
            "PolicyChanged",
            "CheckOpened",
            "ModelAdded",
            "ModelRemoved",
            "LicenseChanged",
            "FileAdded",
            "FileRemoved",
            "ReleaseChanged",
            "ComponentChanged",
            "ListenerAdded",
        ]
    );
    assert_eq!(
        by(CompareAction::Ignore),
        [
            "CompletenessChanged",
            "CheckClosed",
            "FindingResolved",
            "ViolationResolved",
            "ListenerRemoved",
            "BindNarrowed",
        ]
    );
    for kind in ChangeKind::ALL {
        let t = &r.changes()[&kind];
        assert_eq!(t.action, kind.default_action());
        assert_eq!(
            t.source.as_str(),
            format!("default:compare.{}", kind.name())
        );
        assert_eq!(
            PolicyRuleRef::new(t.source.as_str()).ok().as_ref(),
            Some(&t.source)
        );
        assert_eq!(t.reason, None);
        assert_eq!(
            kind.takes_decided(),
            matches!(
                kind,
                ChangeKind::VerdictChanged
                    | ChangeKind::FindingNew
                    | ChangeKind::FindingDecisionChanged
                    | ChangeKind::ViolationNew
                    | ChangeKind::ViolationDecisionChanged
            )
        );
    }
    for cause in Cause::ALL {
        let t = &r.not_comparable()[&cause];
        assert_eq!(t.treatment, OqTreatment::CountAsGap);
        assert_eq!(
            t.source.as_str(),
            format!("default:compare.not_comparable.{}", cause.name())
        );
        assert_eq!(
            PolicyRuleRef::new(t.source.as_str()).ok().as_ref(),
            Some(&t.source)
        );
        assert_eq!(t.reason, None);
    }
    assert_eq!(r.policy(), &builtin_policy());
}

#[test]
fn a_table_needs_every_kind_and_cause_and_decided_only_where_it_applies() {
    let r = builtin_rules();
    let (changes, causes) = (r.changes().clone(), r.not_comparable().clone());
    let mut short = changes.clone();
    short.remove(&ChangeKind::BindNarrowed);
    assert_eq!(
        CompareRules::new(builtin_policy(), short, causes.clone()),
        Err(RulesError::MissingKind(ChangeKind::BindNarrowed))
    );
    let mut no_cause = causes.clone();
    no_cause.remove(&Cause::Policy);
    assert_eq!(
        CompareRules::new(builtin_policy(), changes.clone(), no_cause),
        Err(RulesError::MissingCause(Cause::Policy))
    );
    let mut decided = changes.clone();
    decided.get_mut(&ChangeKind::LayerChanged).unwrap().action = CompareAction::Decided;
    assert_eq!(
        CompareRules::new(builtin_policy(), decided, causes.clone()),
        Err(RulesError::Decided(ChangeKind::LayerChanged))
    );
    // A changed decision carries the current side's decisions, and a changed verdict what they
    // gave, so they may be decided too.
    for kind in [
        ChangeKind::VerdictChanged,
        ChangeKind::FindingDecisionChanged,
        ChangeKind::ViolationDecisionChanged,
    ] {
        let mut table = changes.clone();
        table.get_mut(&kind).unwrap().action = CompareAction::Decided;
        assert!(
            CompareRules::new(builtin_policy(), table, causes.clone()).is_ok(),
            "{kind:?}"
        );
    }
    assert_eq!(CompareRules::new(builtin_policy(), changes, causes), Ok(r));
    assert_eq!(
        RulesError::MissingKind(ChangeKind::BindNarrowed).to_string(),
        "no action for BindNarrowed"
    );
    assert_eq!(
        RulesError::MissingCause(Cause::Policy).to_string(),
        "no treatment for Policy"
    );
    assert_eq!(
        RulesError::Decided(ChangeKind::LayerChanged).to_string(),
        "LayerChanged carries no decisions and no verdict, so it cannot be decided"
    );
}

const COMPLETE: Completeness = Completeness::Complete;

/// A recorded completeness with one required check open.
fn incomplete() -> Completeness {
    Completeness::Incomplete {
        missing_required: vec![id(LICENSE)],
        gaps: vec![],
    }
}

/// `r`'s judgment of `changes` and `items` between two complete inputs.
fn judged(r: &CompareRules, changes: &[Change], items: &[NotComparable]) -> Evaluation {
    r.judge(&COMPLETE, &COMPLETE, changes, items)
}

#[test]
fn nothing_to_judge_is_a_pass_and_complete() {
    let r = builtin_rules();
    let e = judged(&r, &[], &[]);
    assert_eq!(e.verdict(), Verdict::Pass);
    assert_eq!(e.completeness(), &DiffCompleteness::Complete);
    assert_eq!(e.policy(), &builtin_policy());
    assert_eq!(e.rules(), &r);
    assert_eq!(e.changes(), r.changes());
    assert_eq!(e.not_comparable(), r.not_comparable());
}

#[test]
fn a_change_weighs_its_kind_s_action() {
    let r = builtin_rules();
    let layer = change_of(ChangeKind::LayerChanged);
    let closed = change_of(ChangeKind::CheckClosed);
    let added = change_of(ChangeKind::ModelAdded);
    assert_eq!(
        judged(&r, std::slice::from_ref(&closed), &[]).verdict(),
        Verdict::Pass
    );
    assert_eq!(
        judged(&r, &[closed.clone(), added.clone()], &[]).verdict(),
        Verdict::Warn
    );
    assert_eq!(
        judged(&r, &[added.clone(), layer.clone()], &[]).verdict(),
        Verdict::Fail
    );
    let e = judged(&r, std::slice::from_ref(&layer), &[]);
    assert_eq!(e.weigh(&layer), (Action::Fail, false));
    assert_eq!(e.weigh(&closed), (Action::Ignore, false));
    assert_eq!(r.weigh(&added), (Action::Warn, false));
    let lenient = with_action(&r, ChangeKind::LayerChanged, CompareAction::Ignore);
    assert_eq!(judged(&lenient, &[layer], &[]).verdict(), Verdict::Pass);
}

#[test]
fn decided_weighs_the_item_s_own_decisions() {
    let r = builtin_rules();
    assert_eq!(
        judged(&r, &[finding_new(&[Action::Ignore])], &[]).verdict(),
        Verdict::Pass
    );
    assert_eq!(
        judged(&r, &[finding_new(&[Action::Ignore, Action::Warn])], &[]).verdict(),
        Verdict::Warn
    );
    let violation = Change::ViolationNew {
        policy_rule: id("policy:components.deny.ggml-base"),
        subject: SubjectKey::Port(11434),
        current: vec![],
        decisions: vec![decision(Action::Fail, "policy:components.deny.ggml-base")],
    };
    let e = judged(&r, std::slice::from_ref(&violation), &[]);
    assert_eq!(e.verdict(), Verdict::Fail);
    assert_eq!(e.weigh(&violation), (Action::Fail, true));
    // An item without decisions is never lighter than it could be.
    assert_eq!(
        judged(&r, &[finding_new(&[])], &[]).verdict(),
        Verdict::Fail
    );
    let bare = Change::ViolationNew {
        policy_rule: id("policy:components.deny.ggml-base"),
        subject: SubjectKey::Port(11434),
        current: vec![],
        decisions: vec![],
    };
    assert_eq!(r.weigh(&bare), (Action::Fail, true));
    assert_eq!(judged(&r, &[bare], &[]).verdict(), Verdict::Fail);
    // A policy may weigh new findings itself.
    let strict = with_action(&r, ChangeKind::FindingNew, CompareAction::Fail);
    assert_eq!(
        judged(&strict, &[finding_new(&[Action::Ignore])], &[]).verdict(),
        Verdict::Fail
    );
}

/// One side's decisions of an item, each an action and its reason.
type Decisions<'a> = &'a [(Action, &'a str)];

/// A decision change of `kind` for one item: decided `baseline` before and `current` now.
fn decision_change(kind: ChangeKind, baseline: Decisions, current: Decisions) -> Change {
    let rule = "model.blob_digest_mismatch";
    let policy_rule = "policy:components.deny.ggml-base";
    let source = match kind {
        ChangeKind::FindingDecisionChanged => format!("policy:rules.{rule}"),
        _ => policy_rule.to_string(),
    };
    let says = |decisions: Decisions| -> Vec<PolicyDecision> {
        decisions
            .iter()
            .map(|(action, reason)| PolicyDecision {
                action: *action,
                source: id(&source),
                reason: Some(reason.to_string()),
                expires: None,
            })
            .collect()
    };
    let finding: FindingId = id(&format!("finding:{rule}@{MODEL_M}#1"));
    match kind {
        ChangeKind::FindingDecisionChanged => Change::FindingDecisionChanged {
            rule: id(rule),
            subject: SubjectKey::Model(id(MODEL_M)),
            at: "#1".to_string(),
            baseline: says(baseline),
            current: says(current),
            baseline_findings: vec![finding.clone()],
            current_findings: vec![finding],
        },
        ChangeKind::ViolationDecisionChanged => Change::ViolationDecisionChanged {
            policy_rule: id(policy_rule),
            subject: SubjectKey::Port(11434),
            baseline: says(baseline),
            current: says(current),
            baseline_subjects: vec![],
            current_subjects: vec![],
        },
        other => panic!("{other:?} is not a decision change"),
    }
}

#[test]
fn decided_weighs_a_changed_decision_only_when_it_got_heavier() {
    // User decision, 2026-11-13: an override that expires turns an ignored finding into a FAIL,
    // and the diff fails, as it does for a new FAIL finding. Controller's refinement: a change
    // that did not get heavier (another reason, source or expiry; a weakening) warns.
    use Action::{Fail, Ignore, Warn};
    let r = builtin_rules();
    let cases: [(Decisions, Decisions, Action); 8] = [
        // ignore to FAIL: an override that expired.
        (&[(Ignore, "waived")], &[(Fail, "override expired")], Fail),
        (&[(Warn, "tolerated")], &[(Fail, "denied")], Fail),
        // FAIL to FAIL with another reason: a rule's reason edited, or moved into a file.
        (&[(Fail, "denied")], &[(Fail, "denied, reworded")], Warn),
        // A weakening warns, and a decision that changed is never ignored.
        (&[(Fail, "denied")], &[(Ignore, "waived")], Warn),
        (&[(Warn, "tolerated")], &[(Ignore, "waived")], Warn),
        (&[(Ignore, "waived")], &[(Warn, "tolerated")], Warn),
        // A side without decisions counts as FAIL, as a new item without any does.
        (&[(Ignore, "waived")], &[], Fail),
        (&[], &[(Fail, "denied")], Warn),
    ];
    for kind in [
        ChangeKind::FindingDecisionChanged,
        ChangeKind::ViolationDecisionChanged,
    ] {
        for (baseline, current, weight) in cases {
            let change = decision_change(kind, baseline, current);
            let what = format!("{kind:?}: {baseline:?} to {current:?}");
            assert_eq!(r.weigh(&change), (weight, true), "{what}");
            let verdict = match weight {
                Fail => Verdict::Fail,
                Warn => Verdict::Warn,
                Ignore => Verdict::Pass,
            };
            assert_eq!(
                judged(&r, std::slice::from_ref(&change), &[]).verdict(),
                verdict,
                "{what}"
            );
        }
    }
    // `decisions()` is the current side.
    let expired = decision_change(
        ChangeKind::FindingDecisionChanged,
        &[(Ignore, "waived")],
        &[(Fail, "override expired")],
    );
    let Change::FindingDecisionChanged { current, .. } = &expired else {
        unreachable!()
    };
    assert_eq!(expired.decisions(), Some(&current[..]));
    // A new item has no floor: what its decisions ignore stays ignored.
    assert_eq!(r.weigh(&finding_new(&[Ignore])), (Ignore, true));
    // A policy may weigh decision changes itself.
    let lenient = with_action(
        &r,
        ChangeKind::FindingDecisionChanged,
        CompareAction::Ignore,
    );
    assert_eq!(lenient.weigh(&expired), (Ignore, false));
    // The Markdown says the decisions gave the weight.
    let reworded = decision_change(
        ChangeKind::ViolationDecisionChanged,
        &[(Fail, "denied")],
        &[(Fail, "denied, reworded")],
    );
    let mut d = diff_of(&compare_store(), &compare_store());
    d.changes = vec![expired, reworded];
    d.evaluation = r.judge(
        &d.baseline.completeness,
        &d.current.completeness,
        &d.changes,
        &d.not_comparable,
    );
    assert_eq!(d.evaluation.verdict(), Verdict::Fail);
    let md = markdown(&d);
    for word in ["FAIL (as decided)", "WARN (as decided)"] {
        assert!(
            md.contains(&format!("\n| {} | ", esc_md(word))),
            "{word}: {md}"
        );
    }
}

#[test]
fn decided_weighs_a_worse_verdict_as_what_it_now_is() {
    // Review P1 of PR #137 (user decision, 2026-11-13): open questions are not compared, so a new
    // one that the policy treats as `fail` shows only in the verdict. A verdict that got worse
    // weighs what it now is; one that stayed or got better is ignored.
    use Verdict::{Fail, Pass, Warn};
    let r = builtin_rules();
    let cases = [
        (Pass, Fail, Action::Fail),
        (Warn, Fail, Action::Fail),
        (Pass, Warn, Action::Warn),
        (Fail, Warn, Action::Ignore),
        (Fail, Pass, Action::Ignore),
        (Warn, Pass, Action::Ignore),
        (Warn, Warn, Action::Ignore),
    ];
    for (baseline, current, weight) in cases {
        let change = Change::VerdictChanged { baseline, current };
        let what = format!("{baseline:?} to {current:?}");
        assert_eq!(r.weigh(&change), (weight, true), "{what}");
        let verdict = if weight == Action::Ignore {
            Pass
        } else {
            current
        };
        assert_eq!(
            judged(&r, std::slice::from_ref(&change), &[]).verdict(),
            verdict,
            "{what}"
        );
    }
    // A policy may still ignore it.
    let lenient = with_action(&r, ChangeKind::VerdictChanged, CompareAction::Ignore);
    let worse = Change::VerdictChanged {
        baseline: Pass,
        current: Fail,
    };
    assert_eq!(lenient.weigh(&worse), (Action::Ignore, false));
    assert_eq!(
        judged(&lenient, std::slice::from_ref(&worse), &[]).verdict(),
        Pass
    );
}

#[test]
fn a_session_that_fails_only_by_an_open_question_fails_the_diff() {
    // Review P1 of PR #137: example 7 without its open question, then with it treated `fail`.
    // The sessions differ only in the question and the verdict it gives. The question is not
    // compared, so the diff holds the verdict's change alone, and it fails as the session does.
    let mut current = open_question();
    for q in &mut current.open_questions {
        q.decision.treatment = OqTreatment::Fail;
    }
    settle(&mut current);
    let mut baseline = current.clone();
    baseline.open_questions.clear();
    settle(&mut baseline);
    assert_eq!(current.outcome.completeness, Completeness::Complete);
    let diff = diff_of(&baseline, &current);
    assert_eq!(
        diff.changes,
        [Change::VerdictChanged {
            baseline: Verdict::Pass,
            current: Verdict::Fail
        }]
    );
    assert!(diff.not_comparable.is_empty());
    assert_eq!(diff.evaluation.verdict(), Verdict::Fail);
    assert_eq!(diff.evaluation.completeness(), &DiffCompleteness::Complete);
    let md = markdown(&diff);
    assert!(
        md.contains(&format!("\n| {} | ", esc_md("FAIL (as decided)"))),
        "{md}"
    );
    // Under an explicit `ignore`, it passes.
    let lenient = with_action(
        &builtin_rules(),
        ChangeKind::VerdictChanged,
        CompareAction::Ignore,
    );
    let diff = diff_under(&baseline, &current, &lenient);
    assert_eq!(diff.evaluation.verdict(), Verdict::Pass);
}

#[test]
fn each_treatment_of_an_item_not_comparable() {
    let r = builtin_rules();
    let items = [
        not_comparable(Cause::Coverage),
        not_comparable(Cause::Coverage),
        not_comparable(Cause::Request),
    ];
    let e = judged(&r, &[], &items);
    assert_eq!(e.verdict(), Verdict::Pass);
    assert_eq!(
        e.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: None,
            not_comparable: 3
        }
    );
    assert_eq!(e.treatment(&items[2]), OqTreatment::CountAsGap);
    assert_eq!(r.treatment(Cause::Policy), OqTreatment::CountAsGap);
    let warn = with_treatment(&r, Cause::Request, OqTreatment::Warn);
    let e = judged(&warn, &[], &items);
    assert_eq!(e.verdict(), Verdict::Warn);
    assert_eq!(
        e.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: None,
            not_comparable: 2
        }
    );
    let fail = with_treatment(&r, Cause::Coverage, OqTreatment::Fail);
    let e = judged(&fail, &[], &items);
    assert_eq!(e.verdict(), Verdict::Fail);
    assert_eq!(
        e.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: None,
            not_comparable: 1
        }
    );
    let ignore = with_treatment(
        &with_treatment(&r, Cause::Coverage, OqTreatment::Ignore),
        Cause::Request,
        OqTreatment::Ignore,
    );
    let e = judged(&ignore, &[], &items);
    assert_eq!(e.verdict(), Verdict::Pass);
    assert_eq!(e.completeness(), &DiffCompleteness::Complete);
}

#[test]
fn an_item_of_another_policy_takes_its_cause_s_treatment() {
    let r = builtin_rules();
    let other = not_comparable(Cause::Policy);
    let coverage = not_comparable(Cause::Coverage);
    let fail = with_treatment(&r, Cause::Policy, OqTreatment::Fail);
    let e = judged(&fail, &[], std::slice::from_ref(&other));
    assert_eq!(e.treatment(&other), OqTreatment::Fail);
    assert_eq!(e.verdict(), Verdict::Fail);
    assert_eq!(e.completeness(), &DiffCompleteness::Complete);
    // The other causes keep theirs.
    let e = judged(&fail, &[], &[other.clone(), coverage.clone()]);
    assert_eq!(e.treatment(&coverage), OqTreatment::CountAsGap);
    assert_eq!(e.verdict(), Verdict::Fail);
    assert_eq!(
        e.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: None,
            not_comparable: 1
        }
    );
    let ignore = with_treatment(&r, Cause::Policy, OqTreatment::Ignore);
    let e = judged(&ignore, &[], &[other]);
    assert_eq!(e.verdict(), Verdict::Pass);
    assert_eq!(e.completeness(), &DiffCompleteness::Complete);
}

#[test]
fn an_incomplete_input_makes_the_diff_incomplete() {
    let r = builtin_rules();
    for (baseline, current, side) in [
        (incomplete(), COMPLETE, Side::Baseline),
        (COMPLETE, incomplete(), Side::Current),
        (incomplete(), incomplete(), Side::Both),
    ] {
        let e = r.judge(&baseline, &current, &[], &[]);
        // Completeness never changes the verdict.
        assert_eq!(e.verdict(), Verdict::Pass);
        assert_eq!(
            e.completeness(),
            &DiffCompleteness::Incomplete {
                inputs: Some(side),
                not_comparable: 0
            }
        );
    }
    let e = r.judge(
        &COMPLETE,
        &incomplete(),
        &[],
        &[not_comparable(Cause::Coverage)],
    );
    assert_eq!(
        e.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: Some(Side::Current),
            not_comparable: 1
        }
    );
}

#[test]
fn the_judgment_does_not_depend_on_the_lists_order() {
    let r = with_treatment(&builtin_rules(), Cause::Request, OqTreatment::Warn);
    let changes = every_change();
    let items = [
        not_comparable(Cause::Coverage),
        not_comparable(Cause::Request),
        not_comparable(Cause::Policy),
    ];
    let forward = r.judge(&incomplete(), &COMPLETE, &changes, &items);
    assert_eq!(forward.verdict(), Verdict::Fail);
    assert_eq!(
        forward.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: Some(Side::Baseline),
            not_comparable: 2
        }
    );
    let mut reversed_changes = changes;
    reversed_changes.reverse();
    let mut reversed_items = items.to_vec();
    reversed_items.reverse();
    assert_eq!(
        r.judge(&incomplete(), &COMPLETE, &reversed_changes, &reversed_items),
        forward
    );
}

#[test]
fn an_evaluation_reads_back_only_with_a_complete_table() {
    let r = builtin_rules();
    let e = judged(&r, &[change_of(ChangeKind::LayerChanged)], &[]);
    let json = serde_json::to_value(&e).unwrap();
    // Flat: the table's parts, then the result.
    let keys: std::collections::BTreeSet<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "changes",
            "completeness",
            "not_comparable",
            "policy",
            "verdict"
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(json["verdict"], serde_json::json!("Fail"));
    assert_eq!(
        serde_json::from_value::<Evaluation>(json.clone()).unwrap(),
        e
    );
    let mut short = json.clone();
    short["changes"]
        .as_object_mut()
        .unwrap()
        .remove("BindNarrowed");
    let err = serde_json::from_value::<Evaluation>(short)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no action for BindNarrowed"), "{err}");
    let mut no_cause = json.clone();
    no_cause["not_comparable"]
        .as_object_mut()
        .unwrap()
        .remove("Policy");
    let err = serde_json::from_value::<Evaluation>(no_cause)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no treatment for Policy"), "{err}");
    let mut misplaced = json.clone();
    misplaced["changes"]["LayerChanged"]["action"] = serde_json::json!("Decided");
    let err = serde_json::from_value::<Evaluation>(misplaced)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("LayerChanged carries no decisions and no verdict"),
        "{err}"
    );
    let mut extra = json;
    extra["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Evaluation>(extra).is_err());
}

fn case_named(name: &str) -> DiffCase {
    diff_cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

#[test]
fn a_diff_records_its_evaluation_under_the_table_it_was_compared_with() {
    for case in diff_cases() {
        let diff = diff_of(&case.baseline, &case.current);
        assert_eq!(
            diff.evaluation,
            builtin_rules().judge(
                &diff.baseline.completeness,
                &diff.current.completeness,
                &diff.changes,
                &diff.not_comparable
            ),
            "{}",
            case.name
        );
    }
    let blob = case_named("03-blob-digest-changed");
    assert_eq!(
        diff_of(&blob.baseline, &blob.current).evaluation.verdict(),
        Verdict::Fail
    );
    let lenient = with_action(
        &builtin_rules(),
        ChangeKind::LayerChanged,
        CompareAction::Ignore,
    );
    let diff = diff_under(&blob.baseline, &blob.current, &lenient);
    assert_eq!(diff.evaluation.verdict(), Verdict::Pass);
    assert_eq!(
        diff.evaluation.changes()[&ChangeKind::LayerChanged].action,
        CompareAction::Ignore
    );
    // An item not comparable counts as a gap.
    let diff = diff_of(&static_store(), &compare_store());
    assert!(!diff.not_comparable.is_empty());
    let DiffCompleteness::Incomplete { not_comparable, .. } = diff.evaluation.completeness() else {
        panic!("{:?}", diff.evaluation.completeness());
    };
    assert_eq!(
        usize::try_from(*not_comparable).unwrap(),
        diff.not_comparable.len()
    );
}

#[test]
fn each_side_records_its_completeness_and_the_diff_counts_it() {
    // Review P1: the current session of case 10 is incomplete, so the comparison is too.
    let open = case_named("10-check-now-open");
    let diff = diff_of(&open.baseline, &open.current);
    let mut current = open.current.clone();
    current.canonicalize();
    assert_eq!(diff.current.completeness, current.outcome.completeness);
    assert!(matches!(
        diff.current.completeness,
        Completeness::Incomplete { .. }
    ));
    assert_eq!(diff.baseline.completeness, Completeness::Complete);
    assert_eq!(diff.evaluation.verdict(), Verdict::Warn);
    assert_eq!(
        diff.evaluation.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: Some(Side::Current),
            not_comparable: 0
        }
    );
    // One incomplete session on both sides: nothing changed, and what it could not see is still
    // unseen.
    let same = diff_of(&open.current, &open.current);
    assert!(same.changes.is_empty() && same.not_comparable.is_empty());
    assert_eq!(same.evaluation.verdict(), Verdict::Pass);
    assert_eq!(
        same.evaluation.completeness(),
        &DiffCompleteness::Incomplete {
            inputs: Some(Side::Both),
            not_comparable: 0
        }
    );
    let resolved = case_named("09-resolved-finding");
    assert_eq!(
        diff_of(&resolved.baseline, &resolved.current)
            .evaluation
            .completeness(),
        &DiffCompleteness::Incomplete {
            inputs: Some(Side::Baseline),
            not_comparable: 0
        }
    );
}

#[test]
fn the_markdown_names_the_result_and_each_line_s_action() {
    let blob = case_named("03-blob-digest-changed");
    let md = markdown(&diff_of(&blob.baseline, &blob.current));
    assert!(
        md.contains(&esc_md("Result: FAIL + COMPLETE, under the policy ")),
        "{md}"
    );
    assert!(
        md.contains(&esc_md(&format!(
            "default sigil-policy/1 (sha256:{})",
            builtin_policy().sha256
        ))),
        "{md}"
    );
    assert!(
        md.contains("| Completeness | COMPLETE | COMPLETE |"),
        "{md}"
    );
    assert!(
        md.contains("| Action | Change | Model | Baseline | Current |"),
        "{md}"
    );
    assert!(md.contains("\n| FAIL | "), "{md}");
    let new = case_named("08-new-finding");
    let md = markdown(&diff_of(&new.baseline, &new.current));
    assert!(
        md.contains(&format!("\n| {} | ", esc_md("WARN (as decided)"))),
        "{md}"
    );
    assert!(md.contains("\n| ignored | "), "{md}");
    // Review P1: an incomplete input is named in the result and in the header.
    let open = case_named("10-check-now-open");
    let md = markdown(&diff_of(&open.baseline, &open.current));
    assert!(
        md.contains(&esc_md(
            "Result: WARN + INCOMPLETE (the current session is incomplete), under the policy "
        )),
        "{md}"
    );
    assert!(
        md.contains("| Completeness | COMPLETE | INCOMPLETE |"),
        "{md}"
    );
    let both = markdown(&diff_of(&open.current, &open.current));
    assert!(
        both.contains(&esc_md(
            "Result: PASS + INCOMPLETE (both sessions are incomplete), under the policy "
        )),
        "{both}"
    );
    assert!(both.ends_with("No differences.\n"), "{both}");
    let md = markdown(&diff_of(&static_store(), &compare_store()));
    assert!(md.contains(&esc_md(" not comparable, counted as ")), "{md}");
    assert!(md.contains("| Item | Why | Treatment |"), "{md}");
    assert!(md.contains(" | gap |\n"), "{md}");
    let same = markdown(&diff_of(&compare_store(), &compare_store()));
    assert!(
        same.contains(&esc_md("Result: PASS + COMPLETE, under the policy ")),
        "{same}"
    );
    assert!(same.ends_with("No differences.\n"), "{same}");
}

#[test]
fn a_cause_treated_as_warn_reads_warn_in_the_markdown() {
    let (b, c) = (static_store(), compare_store());
    let cause = diff_of(&b, &c).not_comparable[0].cause;
    let rules = with_treatment(&builtin_rules(), cause, OqTreatment::Warn);
    let md = markdown(&diff_under(&b, &c, &rules));
    assert!(md.contains("| Item | Why | Treatment |"), "{md}");
    assert!(md.contains(" | WARN |\n"), "{md}");
    assert!(!md.contains(" | gap |\n"), "{md}");
    assert!(
        md.contains(&esc_md("Result: WARN + COMPLETE, under the policy ")),
        "{md}"
    );
}

#[test]
fn an_incomplete_input_and_a_gap_are_both_named_in_the_result() {
    let mut d = diff_of(&static_store(), &compare_store());
    d.baseline.completeness = incomplete();
    d.evaluation = builtin_rules().judge(
        &d.baseline.completeness,
        &d.current.completeness,
        &d.changes,
        &d.not_comparable,
    );
    let md = markdown(&d);
    assert!(
        md.contains(&esc_md(
            "INCOMPLETE (the baseline is incomplete; 1 item not comparable, counted as a gap), under the policy "
        )),
        "{md}"
    );
}
