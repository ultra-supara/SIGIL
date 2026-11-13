//! Open questions in a diff (#138): new, resolved and treatment-changed questions, their keys,
//! and when a question on one side only cannot be judged.

mod common;

use common::diff_cases::*;
use common::*;
use sigil_model::diff::*;
use sigil_model::*;

/// The kernel input's placement in example 18: its recorded path.
fn kernel() -> Placement {
    Placement::Path(t("/home/user/src/suspicious_kernel-gcc-O2.o"))
}

fn spawn_key() -> (RuleId, SubjectKey, String) {
    (
        id(CAPABILITY_RULE),
        SubjectKey::Slice {
            placement: kernel(),
            arch: Arch::X86_64,
        },
        "capability:posix.process_spawn@".to_string(),
    )
}

fn spawn_item() -> Item {
    let (rule, subject, at) = spawn_key();
    Item::OpenQuestion { rule, subject, at }
}

/// Example 18 with its question treated `fail`: FAIL + COMPLETE.
fn failing() -> Session {
    let mut s = capability_policy();
    treat_questions(&mut s, OqTreatment::Fail);
    s
}

/// Example 18 without the import that raises its question: FAIL + COMPLETE.
fn unimported() -> Session {
    let mut s = capability_policy();
    spawn_unimported(&mut s);
    s
}

fn question_id(s: &Session) -> OpenQuestionId {
    s.open_questions[0].id.clone()
}

#[test]
fn a_new_open_question_is_reported_with_its_decisions() {
    let (before, after) = (unimported(), failing());
    assert_eq!(before.outcome.verdict, Verdict::Fail);
    assert_eq!(before.outcome.completeness, Completeness::Complete);
    assert_eq!(after.outcome.completeness, Completeness::Complete);
    let diff = diff_of(&before, &after);
    let (rule, subject, at) = spawn_key();
    assert_eq!(
        diff.changes,
        [Change::OpenQuestionNew {
            rule,
            subject,
            at,
            current: vec![question_id(&after)],
            decisions: vec![question_decision(OqTreatment::Fail)],
        }]
    );
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
    // The baseline already fails (its network violation): only the question fails the diff.
    assert_eq!(
        diff.evaluation.weigh(&diff.changes[0]),
        (Action::Fail, true)
    );
    assert_eq!(diff.evaluation.verdict(), Verdict::Fail);
    assert_eq!(diff.evaluation.completeness(), &DiffCompleteness::Complete);
}

#[test]
fn a_resolved_open_question_is_reported() {
    let (before, after) = (failing(), unimported());
    let diff = diff_of(&before, &after);
    let (rule, subject, at) = spawn_key();
    assert_eq!(
        diff.changes,
        [Change::OpenQuestionResolved {
            rule,
            subject,
            at,
            baseline: vec![question_id(&before)],
        }]
    );
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
    assert_eq!(
        diff.evaluation.weigh(&diff.changes[0]),
        (Action::Ignore, false)
    );
}

#[test]
fn a_changed_treatment_is_reported_and_weighed() {
    // Another `[open_questions]` default: the policy file changed, so its digest did too.
    let gap = capability_policy();
    let mut fail = failing();
    policy_edited(&mut fail, 0xa5);
    let diff = diff_of(&gap, &fail);
    assert_eq!(
        kinds(&diff),
        [
            "PolicyChanged",
            "CompletenessChanged",
            "OpenQuestionTreatmentChanged"
        ]
    );
    let (rule, subject, at) = spawn_key();
    let changed = Change::OpenQuestionTreatmentChanged {
        rule,
        subject,
        at,
        baseline: vec![question_decision(OqTreatment::CountAsGap)],
        current: vec![question_decision(OqTreatment::Fail)],
        baseline_questions: vec![question_id(&gap)],
        current_questions: vec![question_id(&fail)],
    };
    assert_eq!(diff.changes[2], changed);
    assert_eq!(diff.evaluation.weigh(&changed), (Action::Fail, true));
    // The other way round it got lighter: it warns.
    let back = diff_of(&fail, &gap);
    let lighter = back
        .changes
        .iter()
        .find(|c| c.kind() == ChangeKind::OpenQuestionTreatmentChanged)
        .unwrap();
    assert_eq!(back.evaluation.weigh(lighter), (Action::Warn, true));
}

#[test]
fn a_new_slice_id_does_not_split_an_open_question() {
    // The file was rebuilt: its artifact and slice IDs changed, the question's key (rule,
    // placement and arch, `capability:<feature>@`) did not.
    let before = failing();
    let after = rehashed_kernel(&before, 0x5c);
    assert_ne!(question_id(&before), question_id(&after));
    let diff = diff_of(&before, &after);
    assert_eq!(kinds(&diff), ["FileContentChanged"], "{:?}", diff.changes);
    assert!(diff.not_comparable.is_empty(), "{:?}", diff.not_comparable);
}

#[test]
fn a_question_under_another_policy_is_not_comparable() {
    let before = unimported();
    let mut after = failing();
    policy_edited(&mut after, 0xa5);
    let diff = diff_of(&before, &after);
    assert!(!has(&diff, "OpenQuestionNew"), "{:?}", kinds(&diff));
    assert_eq!(
        diff.not_comparable,
        [NotComparable {
            item: spawn_item(),
            cause: Cause::Policy,
            checks: vec![],
            open_in: Side::Both,
        }]
    );
}

#[test]
fn an_open_container_check_leaves_a_question_not_comparable() {
    // The baseline's import list was cut short after `connect`: `execve` may be past the cut.
    // Validation wants the parser's gap on the slice and the same gap in `binary.container`.
    let mut before = unimported();
    let gap = imports_over_gap(1);
    before.binaries[0].gaps.push(gap.clone());
    cut_short(
        &mut before,
        "binary.container",
        &Ref::Instance(id(KERNEL_INPUT)),
        &gap,
    );
    let diff = diff_of(&before, &failing());
    assert!(!has(&diff, "OpenQuestionNew"), "{:?}", kinds(&diff));
    assert!(
        diff.not_comparable.contains(&NotComparable {
            item: spawn_item(),
            cause: Cause::Coverage,
            checks: ids(&["binary.container"]),
            open_in: Side::Baseline,
        }),
        "{:?}",
        diff.not_comparable
    );
}

#[test]
fn a_question_about_an_input_named_on_one_side_only_is_a_difference_of_request() {
    let before = moved_kernel(&unimported(), "/home/user/other/suspicious_kernel-gcc-O2.o");
    let diff = diff_of(&before, &failing());
    assert!(!has(&diff, "OpenQuestionNew"), "{:?}", kinds(&diff));
    assert!(
        diff.not_comparable.contains(&NotComparable {
            item: spawn_item(),
            cause: Cause::Request,
            checks: ids(&["binary.container"]),
            open_in: Side::Baseline,
        }),
        "{:?}",
        diff.not_comparable
    );
}

#[test]
fn an_open_question_of_another_rule_is_judged_by_the_absent_side_s_completeness() {
    // Example 7's loader question is the analysis's, not a policy's: the policies do not matter,
    // and a complete baseline without it would have recorded it.
    let after = open_question();
    let mut before = after.clone();
    before.open_questions.clear();
    settle(&mut before);
    assert_eq!(before.outcome.completeness, Completeness::Complete);
    let diff = diff_of(&before, &after);
    assert!(has(&diff, "OpenQuestionNew"), "{:?}", kinds(&diff));
    // An incomplete baseline leaves it not comparable, naming the checks it left open.
    let mut partial = before.clone();
    let scope = partial
        .coverage
        .iter()
        .find(|c| c.check.as_str() == "artifacts.discovery")
        .unwrap()
        .scope
        .clone();
    cut_short(
        &mut partial,
        "artifacts.discovery",
        &scope,
        "a directory not listed",
    );
    let diff = diff_of(&partial, &after);
    assert!(!has(&diff, "OpenQuestionNew"), "{:?}", kinds(&diff));
    assert!(
        diff.not_comparable
            .iter()
            .any(|n| matches!(n.item, Item::OpenQuestion { .. })
                && n.cause == Cause::Coverage
                && n.open_in == Side::Baseline),
        "{:?}",
        diff.not_comparable
    );
}
