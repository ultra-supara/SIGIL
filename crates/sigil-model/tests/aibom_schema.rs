//! `schemas/aibom-v2.schema.json` corresponds to `sigil_model::render::aibom` (PR-3b-3a
//! design §6).
//!
//! - **Names:** the AI-BOM types' fields and variants equal the schema's (`support/schema_check`).
//! - **Shared definitions:** every definition that is not an AI-BOM type is a copy of the session
//!   schema's, equal to it. Their names and variants are checked by `schema.rs`.
//! - **Types:** every variant of an AI-BOM type has a sample that validates (the examples, plus a
//!   gallery).
//! - **Rejections:** unknown fields, an AI-BOM v1 document, and another schema version are refused
//!   by both serde and the schema.

mod common;
#[macro_use]
#[path = "support/schema_check.rs"]
mod schema_check;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Value};
use sigil_model::render::aibom::*;
use sigil_model::*;

use common::*;
use schema_check::{assert_valid_against, defs, validator_for, walk};

fn schema() -> Value {
    schema_check::load("aibom-v2.schema.json")
}

/// The AI-BOM's own types; every other definition is shared with the session schema.
fn registered() -> Vec<(&'static str, schema_check::Probe)> {
    registry![
        AiBom => "AiBom", AiBomSchema => "AiBomSchema", SessionLink => "SessionLink",
        BomRuntime => "BomRuntime", BomProcess => "BomProcess", BomRelease => "BomRelease",
        ReleaseBasisKind => "ReleaseBasisKind", BomModel => "BomModel", BomLayer => "BomLayer",
        BomBlob => "BomBlob", BomLicense => "BomLicense", BomArtifact => "BomArtifact",
        BomSlice => "BomSlice", BomComponent => "BomComponent", BomFinding => "BomFinding",
        BomViolation => "BomViolation", CheckSummary => "CheckSummary",
    ]
}

fn own() -> BTreeSet<&'static str> {
    registered().into_iter().map(|(name, _)| name).collect()
}

fn examples() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/aibom-v2");
    let mut out = vec![];
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        out.push((
            name,
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap(),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn the_schema_compiles_against_draft_2020_12() {
    let _ = validator_for(&schema(), "AiBom");
}

#[test]
fn every_example_validates_against_the_schema() {
    let schema = schema();
    let validator = validator_for(&schema, "AiBom");
    let all = examples();
    assert_eq!(all.len(), 14);
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
fn shared_definitions_are_copies_of_the_session_schema() {
    let aibom = schema();
    let session = schema_check::load("session-v1.schema.json");
    let own = own();
    for (name, def) in defs(&aibom) {
        if own.contains(name.as_str()) {
            assert!(
                defs(&session).get(name).is_none(),
                "{name} is an AI-BOM type but the session schema defines it too"
            );
            continue;
        }
        let original = defs(&session)
            .get(name)
            .unwrap_or_else(|| panic!("{name} is neither an AI-BOM type nor a session definition"));
        assert_eq!(def, original, "{name} differs from session-v1.schema.json");
    }
    // Every AI-BOM type is defined.
    for name in own {
        assert!(
            defs(&aibom).contains_key(name),
            "{name} is not in the schema"
        );
    }
}

fn sample<T: Serialize>(def: &'static str, value: T) -> (&'static str, Value) {
    (def, serde_json::to_value(value).unwrap())
}

fn gallery() -> Vec<(&'static str, Value)> {
    let artifact: ArtifactId = id(&format!("sha256:{}", hex(0x11)));
    vec![
        sample("BomBlob", BomBlob::NotLookedUp),
        sample("BomBlob", BomBlob::Absent),
        sample("BomBlob", BomBlob::Unresolved { why: t("a loop") }),
        sample(
            "BomBlob",
            BomBlob::Found {
                path: t("/models/blobs/sha256-11"),
                content: Some(artifact),
            },
        ),
        sample(
            "BomBlob",
            BomBlob::Found {
                path: UntrustedText::from_bytes(vec![0xff, b'/']),
                content: None,
            },
        ),
        sample("ReleaseBasisKind", ReleaseBasisKind::ReferenceMatches),
        sample("ReleaseBasisKind", ReleaseBasisKind::SelfReportedCommit),
        sample(
            "CheckSummary",
            CheckSummary {
                check: id("model_store.integrity"),
                required: true,
                closed: false,
                states: STATE_NAMES
                    .iter()
                    .map(|n| (n.to_string(), 1))
                    .collect::<BTreeMap<_, _>>(),
            },
        ),
    ]
}

#[test]
fn every_variant_of_an_aibom_type_has_a_sample_that_validates() {
    let schema = schema();
    let mut seen = BTreeSet::new();
    for (_, value) in examples() {
        walk(
            &schema,
            &json!({"$ref": "#/$defs/AiBom"}),
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
        !validator_for(&schema(), "AiBom").is_valid(&value),
        "schema accepted {what}"
    );
    assert!(
        serde_json::from_value::<AiBom>(value).is_err(),
        "serde accepted {what}"
    );
}

#[test]
fn unknown_fields_v1_documents_and_other_versions_are_rejected_by_both() {
    let base = examples()
        .into_iter()
        .find(|(n, _)| n == "14-store-and-runtime.json")
        .unwrap()
        .1;

    let mut v = base.clone();
    v["extra"] = json!(1);
    both_reject(v, "an unknown top-level field");

    let mut v = base.clone();
    v["models"][0]["layers"][0]["blob"]["Found"]["extra"] = json!(1);
    both_reject(v, "an unknown field in a struct variant");

    let mut v = base.clone();
    v["schema"] = json!("sigil-aibom/3");
    both_reject(v, "another AI-BOM version");

    let mut v = base.clone();
    v["session"]["sha256"] = json!("d5aa7e58…");
    both_reject(v, "an elided session hash");

    // An AI-BOM v1 document (SIGIL 0.1).
    let v1 = json!({
        "schema_version": "1.1",
        "tool": {"name": "sigil", "version": "0.1.0"},
        "runtime": {"name": "ollama"},
        "models": [],
        "findings": [],
        "verdict": "PASS"
    });
    both_reject(v1, "an AI-BOM v1 document");
}

#[test]
fn the_schema_is_stricter_than_serde_on_state_names() {
    // Rust keeps whatever names it is given; the schema accepts only coverage state names and
    // positive counts. The projection writes only those (`state_name`).
    let mut v = serde_json::to_value(&gallery()[7].1).unwrap();
    v["states"] = json!({"Bogus": 1});
    assert!(!validator_for(&schema(), "CheckSummary").is_valid(&v));
    assert!(serde_json::from_value::<CheckSummary>(v.clone()).is_ok());
    v["states"] = json!({"Complete": 0});
    assert!(!validator_for(&schema(), "CheckSummary").is_valid(&v));
}
