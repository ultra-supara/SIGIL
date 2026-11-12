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
