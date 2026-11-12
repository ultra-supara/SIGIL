//! Judging a diff under a compare policy (#16, PR-16b): the change kinds and causes, the default
//! table, complete tables only, the verdict and completeness a table gives, and how a diff
//! records and shows them.

mod common;

use common::diff_cases::*;
use common::*;
use sigil_model::diff::*;
use sigil_model::*;

/// A change's externally tagged variant name.
fn tag(change: &Change) -> String {
    match serde_json::to_value(change).unwrap() {
        serde_json::Value::Object(m) => m.keys().next().unwrap().clone(),
        other => panic!("a change is a struct variant: {other}"),
    }
}

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
fn a_new_finding_and_a_new_violation_carry_their_current_decisions() {
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
    // No other kind carries decisions this way.
    assert!(every_change()
        .iter()
        .filter(|c| !matches!(c.kind(), ChangeKind::FindingNew | ChangeKind::ViolationNew))
        .all(|c| c.decisions().is_none()));
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
    assert_eq!(by(CompareAction::Decided), ["FindingNew", "ViolationNew"]);
    assert_eq!(
        by(CompareAction::Warn),
        [
            "PolicyChanged",
            "CheckOpened",
            "FindingDecisionChanged",
            "ViolationDecisionChanged",
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
            "VerdictChanged",
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
            matches!(kind, ChangeKind::FindingNew | ChangeKind::ViolationNew)
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
    assert_eq!(CompareRules::new(builtin_policy(), changes, causes), Ok(r));
}

#[test]
fn nothing_to_judge_is_a_pass_and_complete() {
    let r = builtin_rules();
    let e = r.judge(&[], &[]);
    assert_eq!(e.verdict, Verdict::Pass);
    assert_eq!(e.completeness, DiffCompleteness::Complete);
    assert_eq!(e.policy, builtin_policy());
    assert_eq!(&e.changes, r.changes());
    assert_eq!(&e.not_comparable, r.not_comparable());
}

#[test]
fn a_change_weighs_its_kind_s_action() {
    let r = builtin_rules();
    let layer = change_of(ChangeKind::LayerChanged);
    let closed = change_of(ChangeKind::CheckClosed);
    let added = change_of(ChangeKind::ModelAdded);
    assert_eq!(r.judge(&[closed.clone()], &[]).verdict, Verdict::Pass);
    assert_eq!(
        r.judge(&[closed.clone(), added.clone()], &[]).verdict,
        Verdict::Warn
    );
    assert_eq!(
        r.judge(&[added.clone(), layer.clone()], &[]).verdict,
        Verdict::Fail
    );
    let e = r.judge(&[layer.clone()], &[]);
    assert_eq!(e.weigh(&layer), Some((Action::Fail, false)));
    assert_eq!(e.weigh(&closed), Some((Action::Ignore, false)));
    let lenient = with_action(&r, ChangeKind::LayerChanged, CompareAction::Ignore);
    assert_eq!(lenient.judge(&[layer], &[]).verdict, Verdict::Pass);
}

#[test]
fn decided_weighs_the_item_s_own_decisions() {
    let r = builtin_rules();
    assert_eq!(
        r.judge(&[finding_new(&[Action::Ignore])], &[]).verdict,
        Verdict::Pass
    );
    assert_eq!(
        r.judge(&[finding_new(&[Action::Ignore, Action::Warn])], &[])
            .verdict,
        Verdict::Warn
    );
    let violation = Change::ViolationNew {
        policy_rule: id("policy:components.deny.ggml-base"),
        subject: SubjectKey::Port(11434),
        current: vec![],
        decisions: vec![decision(Action::Fail, "policy:components.deny.ggml-base")],
    };
    let e = r.judge(&[violation.clone()], &[]);
    assert_eq!(e.verdict, Verdict::Fail);
    assert_eq!(e.weigh(&violation), Some((Action::Fail, true)));
    // An item without decisions is never lighter than it could be.
    assert_eq!(r.judge(&[finding_new(&[])], &[]).verdict, Verdict::Fail);
    // A policy may weigh new findings itself.
    let strict = with_action(&r, ChangeKind::FindingNew, CompareAction::Fail);
    assert_eq!(
        strict.judge(&[finding_new(&[Action::Ignore])], &[]).verdict,
        Verdict::Fail
    );
}

#[test]
fn each_treatment_of_an_item_not_comparable() {
    let r = builtin_rules();
    let items = [
        not_comparable(Cause::Coverage),
        not_comparable(Cause::Coverage),
        not_comparable(Cause::Request),
    ];
    let e = r.judge(&[], &items);
    assert_eq!(e.verdict, Verdict::Pass);
    assert_eq!(
        e.completeness,
        DiffCompleteness::Incomplete { not_comparable: 3 }
    );
    assert_eq!(e.treatment(&items[2]), Some(OqTreatment::CountAsGap));
    let warn = with_treatment(&r, Cause::Request, OqTreatment::Warn);
    let e = warn.judge(&[], &items);
    assert_eq!(e.verdict, Verdict::Warn);
    assert_eq!(
        e.completeness,
        DiffCompleteness::Incomplete { not_comparable: 2 }
    );
    let fail = with_treatment(&r, Cause::Coverage, OqTreatment::Fail);
    let e = fail.judge(&[], &items);
    assert_eq!(e.verdict, Verdict::Fail);
    assert_eq!(
        e.completeness,
        DiffCompleteness::Incomplete { not_comparable: 1 }
    );
    let ignore = with_treatment(
        &with_treatment(&r, Cause::Coverage, OqTreatment::Ignore),
        Cause::Request,
        OqTreatment::Ignore,
    );
    let e = ignore.judge(&[], &items);
    assert_eq!(e.verdict, Verdict::Pass);
    assert_eq!(e.completeness, DiffCompleteness::Complete);
}
