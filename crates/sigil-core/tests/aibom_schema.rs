mod common;

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};

use common::bom_for;

const PASS_HOST: &str = "http://127.0.0.1:11434";
const WARN_HOST: &str = "0.0.0.0:11434";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn load_schema_value() -> Value {
    let path = workspace_root().join("schemas").join("aibom-v1.schema.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("schema is valid JSON")
}

// The jsonschema 0.46 API exposes top-level functions for one-shot use and
// a builder for cached compilation. We use the builder so the validator is
// compiled once per test.
fn load_validator() -> jsonschema::Validator {
    let raw = load_schema_value();
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&raw)
        .expect("schema compiles against draft 2020-12")
}

#[test]
fn schema_compiles_against_draft_2020_12() {
    let _ = load_validator();
}

fn validate_value(value: &Value) {
    let validator = load_validator();
    let errors: Vec<_> = validator.iter_errors(value).map(|e| e.to_string()).collect();
    assert!(
        validator.is_valid(value),
        "expected AiBom to validate against schema, errors: {errors:#?}"
    );
}

fn bom_value(host: &str) -> Value {
    serde_json::to_value(bom_for(host)).expect("AiBom serializes")
}

#[test]
fn pass_verdict_aibom_validates() {
    let v = bom_value(PASS_HOST);
    assert_eq!(v["verdict"], "PASS");
    validate_value(&v);
}

#[test]
fn warn_verdict_aibom_validates_with_finding() {
    let v = bom_value(WARN_HOST);
    assert_eq!(v["verdict"], "WARN");
    let findings = v["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["id"] == "ollama.public_bind"),
        "WARN baseline should contain ollama.public_bind finding"
    );
    validate_value(&v);
}

#[test]
fn aibom_with_no_models_validates() {
    let mut v = bom_value(PASS_HOST);
    v["models"] = json!([]);
    validate_value(&v);
}

fn assert_invalid<F>(host: &str, mutate: F, expect_keyword: &str)
where
    F: FnOnce(&mut Value),
{
    let validator = load_validator();
    let mut v = bom_value(host);
    mutate(&mut v);
    assert!(
        !validator.is_valid(&v),
        "expected validation to fail after mutation"
    );
    let errors: Vec<String> = validator.iter_errors(&v).map(|e| e.to_string()).collect();
    assert!(
        errors.iter().any(|e| e.contains(expect_keyword)),
        "expected error containing {expect_keyword:?}, got: {errors:#?}"
    );
}

#[test]
fn mutated_verdict_fails() {
    // Issue #17 acceptance criterion: verdict "MAYBE" must fail.
    // jsonschema 0.46 reports enum failures as "is not one of …"
    assert_invalid(
        PASS_HOST,
        |v| v["verdict"] = json!("MAYBE"),
        "is not one of",
    );
}

#[test]
fn mutated_severity_fails() {
    assert_invalid(
        WARN_HOST,
        |v| v["findings"][0]["severity"] = json!("INFO"),
        "is not one of",
    );
}

#[test]
fn mutated_category_fails() {
    assert_invalid(
        WARN_HOST,
        |v| v["findings"][0]["category"] = json!("network"),
        "is not one of",
    );
}

#[test]
fn mutated_api_exposure_fails() {
    assert_invalid(
        PASS_HOST,
        |v| v["runtime"]["api_exposure"] = json!("intranet"),
        "is not one of",
    );
}

#[test]
fn mutated_status_fails() {
    assert_invalid(
        PASS_HOST,
        |v| v["runtime"]["status"] = json!("flaky"),
        "is not one of",
    );
}

#[test]
fn mutated_exposure_class_fails() {
    assert_invalid(
        PASS_HOST,
        |v| v["runtime"]["exposure"]["class"] = json!("vpn"),
        "is not one of",
    );
}

#[test]
fn mutated_schema_version_fails() {
    // jsonschema 0.46 reports const failures as "<expected value> was expected"
    assert_invalid(
        PASS_HOST,
        |v| v["schema_version"] = json!("1.2"),
        "was expected",
    );
}

#[test]
fn unknown_top_level_field_fails() {
    // jsonschema 0.46 reports additionalProperties as "Additional properties are not allowed"
    assert_invalid(
        PASS_HOST,
        |v| {
            v.as_object_mut().unwrap().insert("extra".into(), json!(1));
        },
        "Additional properties are not allowed",
    );
}

#[test]
fn unknown_runtime_field_fails() {
    assert_invalid(
        PASS_HOST,
        |v| {
            v["runtime"]
                .as_object_mut()
                .unwrap()
                .insert("phantom".into(), json!(true));
        },
        "Additional properties are not allowed",
    );
}

#[test]
fn missing_required_field_fails() {
    assert_invalid(
        PASS_HOST,
        |v| {
            v["runtime"].as_object_mut().unwrap().remove("host");
        },
        "host",
    );
}

// Regression for PR #24 review comment: a manifest with a syntactically
// invalid layer digest must not leak the raw string into provenance, or
// the produced AI-BOM would fail the v1 schema's Sha256Digest pattern.
// The ollama.invalid_blob_digest WARN finding still carries the bad
// digest as evidence.
#[test]
fn aibom_with_invalid_layer_digest_still_validates() {
    use sigil_core::aibom::AiBom;
    use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
    use sigil_core::runtime::RuntimeListeners;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/badmodel");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();

    let bad_digest = "sha256:nothex";
    fs::write(
        manifest_dir.join("e1b"),
        format!(
            r#"{{"schemaVersion":2,"layers":[{{"digest":"{bad_digest}","mediaType":"application/vnd.ollama.image.model"}}]}}"#
        ),
    )
    .unwrap();

    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("badmodel:e1b".to_string()),
        models_dir: tmp.path().join("models"),
        host: PASS_HOST.to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .expect("inspect_ollama tolerates invalid digests");

    let bom = AiBom::from(&report);
    let value = serde_json::to_value(&bom).expect("AiBom serializes");

    let findings = value["findings"].as_array().expect("findings array");
    assert!(
        findings.iter().any(|f| f["id"] == "ollama.invalid_blob_digest"),
        "expected ollama.invalid_blob_digest finding, got: {findings:#?}"
    );

    let models = value["models"].as_array().expect("models array");
    if let Some(model) = models.first() {
        let layer_digests = model["provenance"]["layer_digests"]
            .as_array()
            .expect("layer_digests array");
        assert!(
            !layer_digests.iter().any(|d| d == bad_digest),
            "invalid digest must not appear in provenance.layer_digests, got: {layer_digests:#?}"
        );
    }

    validate_value(&value);
}
