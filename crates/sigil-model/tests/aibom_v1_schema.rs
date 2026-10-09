//! The AI-BOM v1 schema (`schemas/aibom-v1.schema.json`): frozen history (ADR-006).
//!
//! SIGIL 0.1 wrote AI-BOM v1, and its generator is gone. The viewer names a v1 file and links to
//! this schema and to the 2026-H1 report, so the schema stays unchanged, and so do its tests:
//! - it accepts the five AI-BOMs SIGIL published (`reports/2026-h1/raw/`);
//! - it rejects what it rejected (v0.1's `sigil-core/tests/aibom_schema.rs`, now on plain JSON);
//! - its bytes are pinned.

use std::path::PathBuf;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// SHA-256 of `schemas/aibom-v1.schema.json`.
const V1_SCHEMA_SHA256: &str = "6a036c77f21bbfd8476e75c67c35473e1412623bcdfb3615e6fae6ccbda12c32";

/// The AI-BOMs published with the 2026-H1 report.
const PUBLISHED: [&str; 5] = [
    "gemma3_4b.aibom.json",
    "llama3.2_3b.aibom.json",
    "mistral_7b.aibom.json",
    "phi3_mini.aibom.json",
    "qwen2.5_7b.aibom.json",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema_path() -> PathBuf {
    root().join("schemas/aibom-v1.schema.json")
}

fn validator() -> jsonschema::Validator {
    let raw = std::fs::read_to_string(schema_path()).expect("read the v1 schema");
    let schema: Value = serde_json::from_str(&raw).expect("the v1 schema is JSON");
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .expect("the v1 schema compiles against draft 2020-12")
}

/// `reports/2026-h1/raw/*.aibom.json`, sorted by file name.
fn published() -> Vec<(String, Value)> {
    let dir = root().join("reports/2026-h1/raw");
    let mut out: Vec<(String, Value)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.to_string_lossy().ends_with(".aibom.json"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let value =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (name, value)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn errors(validator: &jsonschema::Validator, value: &Value) -> Vec<String> {
    validator
        .iter_errors(value)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect()
}

fn assert_valid(value: &Value) {
    let errors = errors(&validator(), value);
    assert!(
        errors.is_empty(),
        "the v1 schema must accept it: {errors:#?}"
    );
}

/// A published PASS AI-BOM: one model, no findings.
fn pass_bom() -> Value {
    published()
        .into_iter()
        .find(|(name, _)| name == "gemma3_4b.aibom.json")
        .expect("gemma3_4b.aibom.json is published")
        .1
}

/// `pass_bom()` as a WARN with one finding, built from the schema's `Finding` definition. The
/// published AI-BOMs have no findings.
fn warn_bom() -> Value {
    let mut bom = pass_bom();
    bom["verdict"] = json!("WARN");
    bom["findings"] = json!([{
        "id": "ollama.public_bind",
        "category": "runtime",
        "severity": "WARN",
        "message": "The Ollama API listens on every interface.",
        "evidence": "0.0.0.0:11434",
    }]);
    bom
}

/// `base` is accepted, and after `change` it is rejected with an error containing `expect`.
fn assert_rejected(base: Value, change: impl FnOnce(&mut Value), expect: &str) {
    let validator = validator();
    let before = errors(&validator, &base);
    assert!(before.is_empty(), "the base must be accepted: {before:#?}");
    let mut bom = base;
    change(&mut bom);
    let after = errors(&validator, &bom);
    assert!(
        after.iter().any(|e| e.contains(expect)),
        "expected an error containing {expect:?}, got {after:#?}"
    );
}

#[test]
fn schema_compiles_against_draft_2020_12() {
    validator();
}

#[test]
fn every_published_v1_aibom_validates() {
    let published = published();
    let names: Vec<&str> = published.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, PUBLISHED);
    let validator = validator();
    for (name, bom) in &published {
        let errors = errors(&validator, bom);
        assert!(errors.is_empty(), "{name}: {errors:#?}");
    }
}

#[test]
fn pass_verdict_aibom_validates() {
    let bom = pass_bom();
    assert_eq!(bom["verdict"], "PASS");
    assert_valid(&bom);
}

#[test]
fn warn_verdict_aibom_validates_with_finding() {
    let bom = warn_bom();
    assert_eq!(bom["findings"][0]["id"], "ollama.public_bind");
    assert_valid(&bom);
}

#[test]
fn aibom_with_no_models_validates() {
    let mut bom = pass_bom();
    bom["models"] = json!([]);
    assert_valid(&bom);
}

// jsonschema 0.46 reports a const failure as "<expected> was expected", an enum failure as "is
// not one of", and an unknown field as "Additional properties are not allowed".

#[test]
fn mutated_schema_version_fails() {
    assert_rejected(
        pass_bom(),
        |b| b["schema_version"] = json!("1.2"),
        "was expected",
    );
}

#[test]
fn mutated_verdict_fails() {
    assert_rejected(
        pass_bom(),
        |b| b["verdict"] = json!("MAYBE"),
        "is not one of",
    );
}

#[test]
fn mutated_severity_fails() {
    assert_rejected(
        warn_bom(),
        |b| b["findings"][0]["severity"] = json!("INFO"),
        "is not one of",
    );
}

#[test]
fn mutated_category_fails() {
    assert_rejected(
        warn_bom(),
        |b| b["findings"][0]["category"] = json!("network"),
        "is not one of",
    );
}

#[test]
fn mutated_api_exposure_fails() {
    assert_rejected(
        pass_bom(),
        |b| b["runtime"]["api_exposure"] = json!("intranet"),
        "is not one of",
    );
}

#[test]
fn mutated_status_fails() {
    assert_rejected(
        pass_bom(),
        |b| b["runtime"]["status"] = json!("flaky"),
        "is not one of",
    );
}

#[test]
fn mutated_exposure_class_fails() {
    assert_rejected(
        pass_bom(),
        |b| b["runtime"]["exposure"]["class"] = json!("vpn"),
        "is not one of",
    );
}

#[test]
fn unknown_top_level_field_fails() {
    assert_rejected(
        pass_bom(),
        |b| {
            b.as_object_mut().unwrap().insert("extra".into(), json!(1));
        },
        "Additional properties are not allowed",
    );
}

#[test]
fn unknown_runtime_field_fails() {
    assert_rejected(
        pass_bom(),
        |b| {
            b["runtime"]
                .as_object_mut()
                .unwrap()
                .insert("phantom".into(), json!(true));
        },
        "Additional properties are not allowed",
    );
}

#[test]
fn missing_required_field_fails() {
    assert_rejected(
        pass_bom(),
        |b| {
            b["runtime"].as_object_mut().unwrap().remove("host");
        },
        "host",
    );
}

#[test]
fn the_v1_schema_is_frozen() {
    let bytes = std::fs::read(schema_path()).expect("read the v1 schema");
    let actual = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        actual, V1_SCHEMA_SHA256,
        "schemas/aibom-v1.schema.json is frozen history (ADR-006): SIGIL no longer writes AI-BOM \
         v1, and the viewer links to this schema. Changing it needs an ADR."
    );
}
