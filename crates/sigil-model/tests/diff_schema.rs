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
        Placement => "Placement", MachOCpu => "MachOCpu", SubjectKey => "SubjectKey", Item => "Item",
        NotComparable => "NotComparable", Cause => "Cause", Side => "Side", LicenseState => "LicenseState",
        ReleaseState => "ReleaseState", ComponentState => "ComponentState",
        CheckState => "CheckState", BindClass => "BindClass",
        ReleaseBasisKind => "ReleaseBasisKind", Evaluation => "Evaluation",
        ChangeTreatment => "ChangeTreatment", NotComparableTreatment => "NotComparableTreatment",
        CompareAction => "CompareAction", DiffCompleteness => "DiffCompleteness",
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
    assert_eq!(all.len(), 11);
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
    out.push(sample(
        "CompareAction",
        [
            CompareAction::Fail,
            CompareAction::Warn,
            CompareAction::Ignore,
            CompareAction::Decided,
        ],
    ));
    out.push(sample(
        "DiffCompleteness",
        [
            DiffCompleteness::Complete,
            DiffCompleteness::Incomplete {
                inputs: Some(Side::Current),
                not_comparable: 0,
            },
            DiffCompleteness::Incomplete {
                inputs: None,
                not_comparable: 2,
            },
        ],
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

    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"]["extra"] = json!(1);
    both_reject(v, "an unknown field in a change treatment");

    let mut v = base.clone();
    let layer = v["evaluation"]["changes"]["LayerChanged"].clone();
    v["evaluation"]["changes"]["LayerChanges"] = layer;
    both_reject(v, "an unknown change kind in the evaluation");

    // Review P2b: a table without one of its kinds is refused by the schema and by serde.
    let mut v = base.clone();
    v["evaluation"]["changes"]
        .as_object_mut()
        .unwrap()
        .remove("BindNarrowed");
    both_reject(v, "an evaluation without BindNarrowed");

    let mut v = base.clone();
    v["evaluation"]["not_comparable"]
        .as_object_mut()
        .unwrap()
        .remove("Policy");
    both_reject(v, "an evaluation without the cause Policy");
}

fn example(name: &str) -> Value {
    examples()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no example {name}"))
        .1
}

#[test]
fn the_evaluation_names_every_change_kind_and_every_cause() {
    let schema = schema();
    let e = &defs(&schema)["Evaluation"]["properties"];
    let required = |v: &Value| -> BTreeSet<String> {
        v["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap().to_string())
            .collect()
    };
    let kinds: BTreeSet<String> = ChangeKind::ALL
        .iter()
        .map(|k| k.name().to_string())
        .collect();
    assert_eq!(required(&e["changes"]), kinds);
    assert_eq!(schema_check::object_keys(&e["changes"]), kinds);
    let variants: BTreeSet<String> = schema_check::variants(&defs(&schema)["Change"])
        .into_keys()
        .collect();
    assert_eq!(variants, kinds);
    let causes: BTreeSet<String> = Cause::ALL.iter().map(|c| c.name().to_string()).collect();
    assert_eq!(required(&e["not_comparable"]), causes);
    assert_eq!(schema_check::object_keys(&e["not_comparable"]), causes);
}

/// Review P2b: the schema checks a diff's shape; serde also checks that the recorded result is
/// what the recorded evaluation gives.
#[test]
fn a_recorded_result_that_its_evaluation_does_not_give_is_refused() {
    let base = example("05-loopback-to-wildcard");
    assert_eq!(base["evaluation"]["verdict"], json!("Fail"));
    let validator = validator_for(&schema(), "Diff");

    let mut v = base.clone();
    v["evaluation"]["verdict"] = json!("Pass");
    assert!(validator.is_valid(&v), "the schema cannot see the judgment");
    let err = serde_json::from_value::<Diff>(v).unwrap_err().to_string();
    assert!(err.contains("Pass") && err.contains("Fail"), "{err}");

    let mut v = base.clone();
    v["evaluation"]["completeness"] = json!({"Incomplete": {"inputs": null, "not_comparable": 1}});
    assert!(validator.is_valid(&v));
    let err = serde_json::from_value::<Diff>(v).unwrap_err().to_string();
    assert!(err.contains("not what its evaluation gives"), "{err}");

    // A side that turned incomplete while the evaluation still says complete.
    let mut v = base;
    v["current"]["completeness"] =
        json!({"Incomplete": {"missing_required": ["model_store.license"], "gaps": []}});
    assert!(validator.is_valid(&v));
    let err = serde_json::from_value::<Diff>(v).unwrap_err().to_string();
    assert!(err.contains("not what its evaluation gives"), "{err}");
}

/// Review P3 of PR #137: serde refuses a table that SIGIL would not write; the schema sees only
/// a policy's `Ignore` without a reason. The recorded result is what each table gives, so only
/// the table is wrong.
#[test]
fn a_table_that_sigil_would_not_write_is_refused() {
    let base = example("03-blob-digest-changed");
    assert_eq!(base["evaluation"]["verdict"], json!("Fail"));
    let validator = validator_for(&schema(), "Diff");
    let refused = |v: Value, shown: &str| {
        let err = serde_json::from_value::<Diff>(v).unwrap_err().to_string();
        assert!(err.contains(shown), "{err}");
    };

    // LayerChanged ignored under its default source, without a reason.
    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"]["action"] = json!("Ignore");
    v["evaluation"]["verdict"] = json!("Pass");
    assert!(validator.is_valid(&v), "the schema cannot see the default");
    refused(
        v.clone(),
        "LayerChanged has the default's source but is not the default",
    );
    // Under the policy's source, without a reason.
    v["evaluation"]["changes"]["LayerChanged"]["source"] =
        json!("policy:compare.changes.LayerChanged");
    assert!(
        !validator.is_valid(&v),
        "the schema accepted a policy's Ignore without a reason"
    );
    refused(v.clone(), "LayerChanged is ignored without a reason");
    // As a policy writes it, it loads.
    v["evaluation"]["changes"]["LayerChanged"]["reason"] = json!("The model is retrained nightly");
    assert!(validator.is_valid(&v));
    let diff: Diff = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(diff.evaluation.verdict(), sigil_model::Verdict::Pass);
    // A blank reason is none.
    v["evaluation"]["changes"]["LayerChanged"]["reason"] = json!("  ");
    assert!(!validator.is_valid(&v));
    refused(v, "LayerChanged is ignored without a reason");

    // The default's source with another action.
    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"]["action"] = json!("Warn");
    v["evaluation"]["verdict"] = json!("Warn");
    assert!(validator.is_valid(&v), "the schema cannot see sources");
    refused(
        v,
        "LayerChanged has the default's source but is not the default",
    );

    // The default's source with a reason.
    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"]["reason"] = json!("why");
    assert!(validator.is_valid(&v));
    refused(
        v,
        "LayerChanged has the default's source but is not the default",
    );

    // A policy's source that names another kind.
    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"]["source"] =
        json!("policy:compare.changes.ModelAdded");
    assert!(validator.is_valid(&v));
    refused(v, "the source of LayerChanged is neither");

    // A policy's entry with a blank reason, whatever its action.
    let mut v = base.clone();
    v["evaluation"]["changes"]["LayerChanged"] = json!({
        "action": "Fail",
        "source": "policy:compare.changes.LayerChanged",
        "reason": " "
    });
    refused(v, "LayerChanged has a blank reason");

    // A cause: the default's source with another treatment, and a source of another cause.
    let mut v = base.clone();
    v["evaluation"]["not_comparable"]["Coverage"]["treatment"] = json!("Warn");
    assert!(validator.is_valid(&v));
    refused(
        v,
        "Coverage has the default's source but is not the default",
    );
    let mut v = base.clone();
    v["evaluation"]["not_comparable"]["Policy"]["source"] =
        json!("policy:compare.not_comparable.Coverage");
    assert!(validator.is_valid(&v));
    refused(v, "the source of Policy is neither");

    // An ignored cause without a reason.
    let mut v = base;
    v["evaluation"]["not_comparable"]["Coverage"] = json!({
        "treatment": "Ignore",
        "source": "policy:compare.not_comparable.Coverage",
        "reason": null
    });
    assert!(
        !validator.is_valid(&v),
        "the schema accepted an Ignore without a reason"
    );
    refused(v, "Coverage is ignored without a reason");
}

/// Review P2a: `sigil-diff/1` was revised before its first release. A diff that main wrote
/// between #136 and PR-16b (no `evaluation`, no `completeness` per side, `FindingNew` without
/// `decisions`) neither validates nor loads. Nor does a diff whose table lacks the open
/// questions' kinds (#138).
#[test]
fn a_diff_written_before_the_revision_of_v1_is_refused() {
    let base = example("05-loopback-to-wildcard");

    let mut v = base.clone();
    v.as_object_mut().unwrap().remove("evaluation");
    both_reject(v, "a diff without evaluation");

    let mut v = base.clone();
    for side in ["baseline", "current"] {
        v[side].as_object_mut().unwrap().remove("completeness");
    }
    both_reject(v, "sides without completeness");

    let mut v = base.clone();
    let mut stripped = 0;
    for change in v["changes"].as_array_mut().unwrap() {
        if let Some(new) = change.get_mut("FindingNew") {
            new.as_object_mut().unwrap().remove("decisions");
            stripped += 1;
        }
    }
    assert_eq!(stripped, 1);
    both_reject(v, "a FindingNew without decisions");

    // #138: a table of #137's 24 kinds, without the open questions'.
    let mut v = base.clone();
    for kind in [
        "OpenQuestionNew",
        "OpenQuestionResolved",
        "OpenQuestionTreatmentChanged",
    ] {
        v["evaluation"]["changes"]
            .as_object_mut()
            .unwrap()
            .remove(kind)
            .unwrap();
    }
    both_reject(v, "a table of #137's kinds");

    let mut v = base;
    v.as_object_mut().unwrap().remove("evaluation");
    for side in ["baseline", "current"] {
        v[side].as_object_mut().unwrap().remove("completeness");
    }
    for change in v["changes"].as_array_mut().unwrap() {
        if let Some(new) = change.get_mut("FindingNew") {
            new.as_object_mut().unwrap().remove("decisions");
        }
    }
    both_reject(v, "a diff of PR-16a's shape");
}

/// The review of #141: a slice's key, and a component claim's, holds the slice's Mach-O CPU, null
/// for an ELF slice. A key written without it, as before the revision, is refused by both.
#[test]
fn a_slice_key_without_its_mach_o_cpu_is_refused() {
    // A question on a slice (fixture 11) and a component claim (fixture 07).
    for (name, kind, path) in [
        (
            "11-new-open-question",
            "OpenQuestionNew",
            &["subject", "Slice"][..],
        ),
        ("07-claim-conflicting", "ComponentChanged", &[][..]),
    ] {
        let mut v = example(name);
        let changes = v["changes"].as_array_mut().unwrap();
        let change = changes
            .iter_mut()
            .find_map(|c| c.get_mut(kind))
            .unwrap_or_else(|| panic!("no {kind} in {name}"));
        let key = path.iter().fold(change, |v, k| &mut v[*k]);
        assert_eq!(key.get("macho"), Some(&Value::Null), "{name}");
        key.as_object_mut().unwrap().remove("macho");
        both_reject(v, &format!("a {kind} key without macho"));
    }
    // An item not comparable: a component claim, and a violation on one.
    let validator = validator_for(&schema(), "NotComparable");
    let component = json!({
        "placement": {"Instance": "inst:install/bin/ollama"},
        "arch": "x86_64",
        "macho": null,
        "component": "ggml"
    });
    let items = [
        json!({"Component": component}),
        json!({"Violation": {
            "policy_rule": "policy:components.deny.ggml",
            "subject": {"Component": component}
        }}),
    ];
    for item in items {
        let with = |macho: Option<Value>| {
            let mut item = item.clone();
            let key = match item.get_mut("Component") {
                Some(key) => key,
                None => &mut item["Violation"]["subject"]["Component"],
            };
            match macho {
                Some(m) => key["macho"] = m,
                None => {
                    key.as_object_mut().unwrap().remove("macho");
                }
            }
            json!({
                "item": item,
                "cause": "Coverage",
                "checks": ["artifacts.identity"],
                "open_in": "Current"
            })
        };
        for macho in [
            Value::Null,
            json!({"cpu_type": 16777223, "cpu_subtype": 8}),
            json!({"cpu_type": -1, "cpu_subtype": 16777215}),
        ] {
            let v = with(Some(macho));
            assert_valid_against(&validator, &v, "a key with macho");
            serde_json::from_value::<NotComparable>(v).unwrap();
        }
        let v = with(None);
        assert!(!validator.is_valid(&v), "schema accepted {v}");
        assert!(
            serde_json::from_value::<NotComparable>(v.clone()).is_err(),
            "serde accepted {v}"
        );
        // The subtype without its capability bits: the top byte is clear.
        let v = with(Some(
            json!({"cpu_type": 16777223, "cpu_subtype": 2147483656_u64}),
        ));
        assert!(!validator.is_valid(&v), "schema accepted {v}");
        let v = with(Some(json!({"cpu_type": 16777223})));
        assert!(!validator.is_valid(&v), "schema accepted {v}");
        assert!(
            serde_json::from_value::<NotComparable>(v.clone()).is_err(),
            "serde accepted {v}"
        );
    }
}
