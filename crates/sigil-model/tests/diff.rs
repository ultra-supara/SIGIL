//! `sigil_model::diff` (#16, PR-16a): what `sigil compare` reports between two sessions.

mod common;

use common::diff_cases::*;
use common::*;
use sigil_model::diff::*;
use sigil_model::*;

#[test]
fn identical_sessions_give_no_differences() {
    for (name, s) in [
        ("complete_pass", complete_pass()),
        ("store_and_runtime", store_and_runtime()),
        ("binary_inspect", binary_inspect()),
    ] {
        let diff = diff_of(&s, &s);
        assert!(diff.changes.is_empty(), "{name}: {:?}", diff.changes);
        assert!(
            diff.not_comparable.is_empty(),
            "{name}: {:?}",
            diff.not_comparable
        );
        assert_eq!(diff.schema, DiffSchema::V1);
        assert_eq!(diff.baseline, diff.current);
        assert_eq!(diff.baseline.sha256, session_sha256(&s));
    }
}

#[test]
fn a_side_names_its_session_mode_start_and_policy() {
    let s = store_and_runtime();
    let diff = diff_of(&complete_pass(), &s);
    assert_eq!(diff.current.mode, Mode::Observe);
    assert_eq!(diff.baseline.mode, Mode::Static);
    assert_eq!(diff.current.started_at, s.observation.started_at);
    assert_eq!(
        diff.current.policy.as_ref().map(|k| k.id.as_str()),
        Some("default")
    );
    assert_eq!(diff.current.tool, s.tool);
    assert_eq!(diff.tool, example_tool());
}

#[test]
fn canonical_json_orders_changes_by_kind_then_text() {
    let mut diff = diff_of(&complete_pass(), &complete_pass());
    diff.changes = vec![
        Change::ModelAdded {
            model: id("model:models/registry.ollama.ai/library/n/latest"),
            name: t("n:latest"),
        },
        Change::VerdictChanged {
            baseline: Verdict::Pass,
            current: Verdict::Warn,
        },
        Change::ModelAdded {
            model: id("model:models/registry.ollama.ai/library/a/latest"),
            name: t("a:latest"),
        },
    ];
    let json = diff.to_canonical_json().unwrap();
    assert!(json.ends_with("}\n"), "{json}");
    let back: Diff = serde_json::from_str(&json).unwrap();
    assert_eq!(kinds(&back), ["VerdictChanged", "ModelAdded", "ModelAdded"]);
    let Change::ModelAdded { name, .. } = &back.changes[1] else {
        unreachable!()
    };
    assert_eq!(name, &t("a:latest"));
    assert_eq!(back.to_canonical_json().unwrap(), json);
}
