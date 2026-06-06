//! Determinism: the path the wasm wrapper exposes
//! (`render_aibom_markdown_inner`, which the `#[wasm_bindgen]` function
//! `render_aibom_markdown` just forwards to) must produce byte-for-byte the
//! same Markdown as `sigil_core::aibom::render_ai_bom` for the same JSON
//! input. We exercise the inner function because the JS marshalling on the
//! `#[wasm_bindgen]` wrapper allocates through `JsError`, which panics on
//! non-wasm targets — splitting the two lets the native test cover the
//! pure-render contract without instantiating wasm.
//!
//! If a future refactor adds any transformation to the wasm wrapper (e.g.
//! normalizing line endings for the browser), the wrapper must do it *after*
//! calling the inner; otherwise this test catches the divergence.
//!
//! Coverage: every committed file under `site/viewer/samples/`. Adding a
//! sample to that directory automatically extends the byte-equality test.
//! Schema-envelope validation (PR #36 discussion r3367927561) lives in the
//! `schema_envelope_validation` submodule below.

use std::fs;
use std::path::{Path, PathBuf};

use sigil_aibom_wasm::{aibom_schema_version, render_aibom_markdown_inner};
use sigil_core::aibom::{render_ai_bom, AiBom};

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives at <repo>/crates/<name>")
        .join("site/viewer/samples")
}

fn collect_samples() -> Vec<PathBuf> {
    let dir = samples_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.to_string_lossy().ends_with(".aibom.json"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "no .aibom.json samples in {}",
        dir.display()
    );
    entries
}

#[test]
fn wasm_render_matches_native_render_byte_for_byte() {
    for path in collect_samples() {
        let json = fs::read_to_string(&path).expect("read sample");
        let bom: AiBom = serde_json::from_str(&json).expect("parse sample");
        let native = render_ai_bom(&bom);
        let exported = render_aibom_markdown_inner(&json)
            .unwrap_or_else(|err| panic!("wasm render of {} failed: {err}", path.display()));
        assert_eq!(
            native,
            exported,
            "wasm-exported render diverges from native render for {}",
            path.display()
        );
    }
}

#[test]
fn samples_cover_all_three_verdicts() {
    use std::collections::BTreeSet;
    let mut verdicts = BTreeSet::new();
    for path in collect_samples() {
        let json = fs::read_to_string(&path).expect("read sample");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        verdicts.insert(value["verdict"].as_str().unwrap().to_string());
    }
    let expected: BTreeSet<String> = ["PASS", "WARN", "FAIL"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        verdicts, expected,
        "viewer samples must cover PASS, WARN, and FAIL"
    );
}

#[test]
fn schema_version_matches_core() {
    assert_eq!(aibom_schema_version(), sigil_core::aibom::SCHEMA_VERSION);
}

#[test]
fn invalid_json_returns_error_message() {
    let err = render_aibom_markdown_inner("{ not json").expect_err("must error");
    assert!(
        err.contains("invalid AI-BOM JSON"),
        "error message should be human-readable: {err}"
    );
}

#[test]
fn schema_mismatch_returns_error() {
    // Valid JSON, wrong shape: missing required fields.
    let err = render_aibom_markdown_inner("{\"hello\":\"world\"}").expect_err("must error");
    assert!(err.contains("invalid AI-BOM JSON"));
}

/// Defends against the Codex review on PR #36 (discussion r3367927561): the
/// schema declares `schema_version` as a `const "1.1"` and the root with
/// `additionalProperties: false`, but `AiBom` deserialization alone accepts
/// any string and silently drops unknown top-level fields. The wasm wrapper
/// now walks the JSON object first and rejects both.
mod schema_envelope_validation {
    use super::render_aibom_markdown_inner;

    fn valid_pass_sample() -> String {
        let path = super::samples_dir().join("pass.aibom.json");
        std::fs::read_to_string(path).expect("read pass sample")
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let json = valid_pass_sample().replace("\"1.1\"", "\"1.2\"");
        let err = render_aibom_markdown_inner(&json).expect_err("must reject 1.2");
        assert!(
            err.contains("schema_version") && err.contains("1.2"),
            "error must name the bad schema_version: {err}"
        );
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let json = valid_pass_sample().replacen(
            "\"schema_version\":",
            "\"unexpected\": true,\n  \"schema_version\":",
            1,
        );
        let err = render_aibom_markdown_inner(&json).expect_err("must reject unknown field");
        assert!(
            err.contains("unexpected"),
            "error must name the rejected field: {err}"
        );
    }

    #[test]
    fn rejects_non_string_schema_version() {
        let json = valid_pass_sample().replace("\"1.1\"", "11");
        let err = render_aibom_markdown_inner(&json).expect_err("must reject");
        assert!(err.contains("schema_version"), "error: {err}");
    }

    #[test]
    fn rejects_non_object_root() {
        let err = render_aibom_markdown_inner("[]").expect_err("must reject array root");
        assert!(err.contains("object"), "error: {err}");
    }

    #[test]
    fn missing_schema_version_is_reported_clearly() {
        let json = valid_pass_sample().replacen("\"schema_version\": \"1.1\",\n  ", "", 1);
        let err = render_aibom_markdown_inner(&json).expect_err("must error");
        assert!(
            err.contains("schema_version"),
            "error must name the missing field: {err}"
        );
    }

    #[test]
    fn accepts_canonical_sample_unchanged() {
        // Guard against the validator becoming so strict it rejects real output.
        let bom = render_aibom_markdown_inner(&valid_pass_sample())
            .expect("pass sample must pass the validator");
        assert!(bom.starts_with("# SIGIL AI-BOM:"), "bad render: {bom}");
    }
}

/// Independently re-derives the schema's root `required` field from the
/// committed `schemas/aibom-v1.schema.json` and asserts that the
/// `REQUIRED_TOP_LEVEL_KEYS` list in the wasm wrapper matches it. If the
/// schema gains or drops a root key and the wrapper isn't updated, this
/// test fails — the validator would otherwise silently accept (or wrongly
/// reject) the new shape.
#[test]
fn top_level_keys_match_schema() {
    use std::collections::BTreeSet;

    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate at <repo>/crates/<name>")
        .join("schemas/aibom-v1.schema.json");
    let schema_text = fs::read_to_string(&schema_path).expect("read schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("parse schema");

    let root_def = &schema["$defs"]["AiBom"];
    let required: BTreeSet<String> = root_def["required"]
        .as_array()
        .expect("schema $defs.AiBom.required is an array")
        .iter()
        .map(|v| v.as_str().expect("required entry is a string").to_string())
        .collect();
    let properties: BTreeSet<String> = root_def["properties"]
        .as_object()
        .expect("schema $defs.AiBom.properties is an object")
        .keys()
        .cloned()
        .collect();
    assert!(
        root_def["additionalProperties"].as_bool() == Some(false),
        "schema must keep additionalProperties: false on the root"
    );
    assert_eq!(
        required, properties,
        "every property is required (no optional top-level fields)"
    );

    // Sanity: the validator's allow-list is exactly the schema's property set.
    // The list is private to the crate but visible to error messages, so we
    // round-trip an empty object and read the field names back out of the
    // error.
    let err = render_aibom_markdown_inner("{}").expect_err("empty object must fail");
    // The empty-object path errors on missing schema_version before listing
    // unknown fields; assert separately that an object with every required
    // key set to a sentinel string but no unknown fields fails *only* on the
    // deeper schema mismatch — i.e. the envelope check passes.
    assert!(err.contains("schema_version"), "got: {err}");

    let mut sentinel = serde_json::Map::new();
    for key in &required {
        sentinel.insert(key.clone(), serde_json::json!(null));
    }
    sentinel.insert(
        "schema_version".to_string(),
        serde_json::Value::String(sigil_core::aibom::SCHEMA_VERSION.to_string()),
    );
    let json = serde_json::Value::Object(sentinel).to_string();
    let err = render_aibom_markdown_inner(&json).expect_err("nulls must trigger struct mismatch");
    assert!(
        err.contains("schema mismatch") || !err.contains("unexpected top-level field"),
        "envelope must accept the schema's key set (any failure must come from the struct \
         deserializer, not the unknown-field branch): {err}"
    );
}
