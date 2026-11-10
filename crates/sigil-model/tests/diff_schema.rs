//! `schemas/diff-v1.schema.json` corresponds to `sigil_model::diff` (#16, PR-16a). The checks
//! are those `aibom_schema.rs` makes for the AI-BOM:
//!
//! - **Names:** the diff types' fields and variants equal the schema's (`support/schema_check`).
//! - **Shared definitions:** every definition that is not a diff type is a copy of the session
//!   schema's. `ReleaseBasisKind` is a copy of the AI-BOM schema's.
//! - **Types:** every variant of a diff type has a sample that validates (the fixture diffs,
//!   plus a gallery).
//! - **Rejections:** unknown fields and other schema versions are refused by serde and the
//!   schema.

mod common;
#[macro_use]
#[path = "support/schema_check.rs"]
mod schema_check;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Value};
use sigil_model::diff::*;
use sigil_model::render::aibom::ReleaseBasisKind;
use sigil_model::BindClass;

use common::diff_cases::{every_change, every_not_comparable};
use schema_check::{assert_valid_against, defs, validator_for, walk};

fn schema() -> Value {
    schema_check::load("diff-v1.schema.json")
}

/// The diff's own types; every other definition is shared.
fn registered() -> Vec<(&'static str, schema_check::Probe)> {
    registry![
        Diff => "Diff", DiffSchema => "DiffSchema", DiffSide => "DiffSide", Change => "Change",
        Placement => "Placement", SubjectKey => "SubjectKey", Item => "Item",
        NotComparable => "NotComparable", Cause => "Cause", Side => "Side", LicenseState => "LicenseState",
        ReleaseState => "ReleaseState", ComponentState => "ComponentState",
        CheckState => "CheckState", BindClass => "BindClass",
        ReleaseBasisKind => "ReleaseBasisKind",
    ]
}

fn own() -> BTreeSet<&'static str> {
    registered().into_iter().map(|(name, _)| name).collect()
}

fn examples() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/diff-v1");
    let mut out = vec![];
    for entry in fs::read_dir(dir).unwrap() {
        let case = entry.unwrap().path();
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        let raw = fs::read_to_string(case.join("diff.json")).unwrap();
        out.push((name, serde_json::from_str(&raw).unwrap()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn the_schema_compiles_against_draft_2020_12() {
    let _ = validator_for(&schema(), "Diff");
}

#[test]
fn every_fixture_diff_validates_against_the_schema() {
    let schema = schema();
    let validator = validator_for(&schema, "Diff");
    let all = examples();
    assert_eq!(all.len(), 10);
    for (name, value) in all {
        assert_valid_against(&validator, &value, &name);
    }
}

#[test]
fn rust_field_and_variant_names_equal_the_schema() {
    let problems = schema_check::name_problems(&schema(), registered(), &[]);
    assert!(
        problems.is_empty(),
        "schema drift:\n{}",
        problems.join("\n")
    );
}

#[test]
fn shared_definitions_are_copies() {
    let diff = schema();
    let session = schema_check::load("session-v1.schema.json");
    let aibom = schema_check::load("aibom-v2.schema.json");
    let own = own();
    for (name, def) in defs(&diff) {
        if name == "ReleaseBasisKind" {
            assert_eq!(
                def,
                &defs(&aibom)["ReleaseBasisKind"],
                "ReleaseBasisKind differs from aibom-v2.schema.json"
            );
            continue;
        }
        if own.contains(name.as_str()) {
            assert!(
                defs(&session).get(name).is_none(),
                "{name} is a diff type but the session schema defines it too"
            );
            continue;
        }
        let original = defs(&session)
            .get(name)
            .unwrap_or_else(|| panic!("{name} is neither a diff type nor a session definition"));
        assert_eq!(def, original, "{name} differs from session-v1.schema.json");
    }
    for name in own {
        assert!(
            defs(&diff).contains_key(name),
            "{name} is not in the schema"
        );
    }
}

fn sample<T: Serialize>(def: &'static str, value: T) -> (&'static str, Value) {
    (def, serde_json::to_value(value).unwrap())
}

fn gallery() -> Vec<(&'static str, Value)> {
    let mut out = vec![
        sample("Change", every_change()),
        sample(
            "BindClass",
            [
                BindClass::Loopback,
                BindClass::Private,
                BindClass::Global,
                BindClass::Wildcard,
            ],
        ),
        sample(
            "ReleaseBasisKind",
            [
                ReleaseBasisKind::ReferenceMatches,
                ReleaseBasisKind::SelfReportedCommit,
            ],
        ),
    ];
    out.push(sample(
        "Cause",
        [Cause::Coverage, Cause::Request, Cause::Policy],
    ));
    out.extend(
        every_not_comparable()
            .into_iter()
            .map(|n| sample("NotComparable", n)),
    );
    out
}

#[test]
fn every_variant_of_a_diff_type_has_a_sample_that_validates() {
    let schema = schema();
    let mut seen = BTreeSet::new();
    for (_, value) in examples() {
        walk(
            &schema,
            &json!({"$ref": "#/$defs/Diff"}),
            None,
            &value,
            &mut seen,
        );
    }
    schema_check::walk_gallery(&schema, gallery(), &mut seen);
    let own = own();
    let unsampled: Vec<String> = schema_check::unsampled(&schema, &seen)
        .into_iter()
        .filter(|v| own.contains(v.split("::").next().unwrap()))
        .collect();
    assert!(
        unsampled.is_empty(),
        "variants without a validated sample: {unsampled:?}"
    );
}

fn both_reject(value: Value, what: &str) {
    assert!(
        !validator_for(&schema(), "Diff").is_valid(&value),
        "schema accepted {what}"
    );
    assert!(
        serde_json::from_value::<Diff>(value).is_err(),
        "serde accepted {what}"
    );
}

#[test]
fn unknown_fields_and_other_versions_are_rejected_by_both() {
    let base = examples()
        .into_iter()
        .find(|(n, _)| n == "05-loopback-to-wildcard")
        .unwrap()
        .1;

    let mut v = base.clone();
    v["extra"] = json!(1);
    both_reject(v, "an unknown top-level field");

    let mut v = base.clone();
    v["changes"][0]["VerdictChanged"]["extra"] = json!(1);
    both_reject(v, "an unknown field in a struct variant");

    let mut v = base.clone();
    v["schema"] = json!("sigil-diff/2");
    both_reject(v, "another diff version");

    let mut v = base.clone();
    v["baseline"]["sha256"] = json!("d5aa7e58…");
    both_reject(v, "an elided session hash");
}
