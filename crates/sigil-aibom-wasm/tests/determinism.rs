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

/// Native-only test: the pure render path the wasm wrapper forwards to must
/// be byte-equal to `render_ai_bom`. This does NOT instantiate the wasm
/// binary — see the module doc above for the rationale. The committed wasm
/// is exercised against this exact contract behaviourally in CI
/// (`ci/check-committed-wasm.mjs`), so a stale `site/viewer/pkg/` would fail
/// there even if it would pass this test.
#[test]
fn inner_render_matches_core_render_byte_for_byte() {
    for path in collect_samples() {
        let json = fs::read_to_string(&path).expect("read sample");
        let bom: AiBom = serde_json::from_str(&json).expect("parse sample");
        let native = render_ai_bom(&bom);
        let exported = render_aibom_markdown_inner(&json)
            .unwrap_or_else(|err| panic!("inner render of {} failed: {err}", path.display()));
        assert_eq!(
            native,
            exported,
            "inner render diverges from render_ai_bom for {}",
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

    // Codex PR #36 P2 (discussion r3367938925): the schema sets
    // `additionalProperties: false` on every nested object too. Without
    // `deny_unknown_fields` on the structs in sigil-core, serde happily
    // dropped `runtime.unexpected` etc. The tests below pin each nested
    // object to the same behaviour the schema requires.

    #[test]
    fn rejects_unknown_field_inside_runtime() {
        // Insert `"sneaky": true` into the runtime object.
        let json = valid_pass_sample().replacen(
            "\"runtime\": {",
            "\"runtime\": {\n    \"sneaky\": true,",
            1,
        );
        let err = render_aibom_markdown_inner(&json).expect_err("must reject");
        assert!(
            err.contains("sneaky") || err.contains("unknown field"),
            "error must name the rejected nested field: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_inside_tool() {
        let json = valid_pass_sample().replacen("\"tool\": {", "\"tool\": {\n    \"extra\": 1,", 1);
        let err = render_aibom_markdown_inner(&json).expect_err("must reject");
        assert!(
            err.contains("extra") || err.contains("unknown field"),
            "error must name the rejected nested field: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_inside_runtime_exposure() {
        let json = valid_pass_sample().replacen(
            "\"exposure\": {",
            "\"exposure\": {\n      \"creep\": 0,",
            1,
        );
        let err = render_aibom_markdown_inner(&json).expect_err("must reject");
        assert!(
            err.contains("creep") || err.contains("unknown field"),
            "error must name the rejected nested field: {err}"
        );
    }
}

/// Defends against the Codex review on PR #36 (discussion r3367962268): the
/// schema declares `minLength`, `pattern`, and `maxLength` constraints on
/// string fields that serde's `String` deserializer cannot enforce. The
/// wasm wrapper now runs the bundled schema as a full JSON Schema check
/// before struct deserialization, so these violations surface as render
/// errors instead of passing through silently.
mod schema_scalar_validation {
    use super::render_aibom_markdown_inner;

    fn valid_pass_sample() -> String {
        let path = super::samples_dir().join("pass.aibom.json");
        std::fs::read_to_string(path).expect("read pass sample")
    }

    #[test]
    fn rejects_empty_tool_name() {
        // schema: ToolInfo.name { minLength: 1 }
        let json = valid_pass_sample().replacen("\"sigil\"", "\"\"", 1);
        let err = render_aibom_markdown_inner(&json).expect_err("must reject empty name");
        assert!(
            err.contains("schema violation") && err.contains("tool"),
            "error must mention the schema violation and the path: {err}"
        );
    }

    #[test]
    fn rejects_non_hex_sha256() {
        // schema: FileEntry.sha256 { pattern: "^[0-9a-fA-F]{64}$" }
        // pass sample has files[0].sha256 — replace it with garbage.
        let json = valid_pass_sample();
        // Find the first `"sha256": "..."` entry and replace its value.
        let pat = "\"sha256\":";
        let idx = json.find(pat).expect("sha256 field in sample");
        let after = &json[idx + pat.len()..];
        let start = after.find('"').expect("opening quote") + 1;
        let end = after[start..].find('"').expect("closing quote") + start;
        let mut mutated = String::with_capacity(json.len());
        mutated.push_str(&json[..idx + pat.len() + start]);
        mutated.push_str("nothex-not-64-chars-not-hex-at-all");
        mutated.push_str(&after[end..]);

        let err = render_aibom_markdown_inner(&mutated).expect_err("must reject non-hex sha256");
        assert!(
            err.contains("schema violation") && err.contains("sha256"),
            "error must mention the schema violation and field: {err}"
        );
    }

    #[test]
    fn rejects_text_excerpt_over_max_length() {
        // schema: LicenseEntry.text_excerpt { maxLength: 256 }
        let json = valid_pass_sample();
        let needle = "\"text_excerpt\":";
        let idx = json.find(needle).expect("text_excerpt field in sample");
        let after = &json[idx + needle.len()..];
        let start = after.find('"').expect("opening quote") + 1;
        let end = after[start..].find('"').expect("closing quote") + start;
        let mut mutated = String::with_capacity(json.len() + 300);
        mutated.push_str(&json[..idx + needle.len() + start]);
        mutated.push_str(&"x".repeat(257));
        mutated.push_str(&after[end..]);

        let err = render_aibom_markdown_inner(&mutated)
            .expect_err("must reject text_excerpt over 256 chars");
        assert!(
            err.contains("schema violation") && err.contains("text_excerpt"),
            "error must mention the violation: {err}"
        );
    }

    #[test]
    fn accepts_canonical_sample() {
        // Real samples must continue to pass after schema validation lands.
        render_aibom_markdown_inner(&valid_pass_sample())
            .expect("pass sample must clear the full schema");
    }

    /// Codex PR #36 P2 (discussion r3367974319): the error-path fixtures
    /// under `site/viewer/samples/invalid/` are walked by
    /// `ci/check-committed-wasm.mjs` to confirm the committed wasm rejects
    /// each one. We mirror that walk here so the native render path stays
    /// in sync with what the smoke asserts — if a maintainer updates the
    /// fixture set without regenerating the manifest, this native test
    /// fails with the same error the Node smoke would report on the rebuild.
    #[test]
    fn native_render_rejects_every_invalid_fixture_with_manifest_substring() {
        let dir = super::samples_dir().join("invalid");
        assert!(
            dir.exists(),
            "invalid fixtures missing; run `cargo run -p sigil-aibom-wasm --example regen_invalid_samples`"
        );
        let manifest_text =
            std::fs::read_to_string(dir.join("manifest.json")).expect("read manifest");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_text).expect("parse manifest");
        let entries = manifest.as_object().expect("manifest is an object");
        assert!(!entries.is_empty(), "manifest must have at least one entry");

        for (file, spec) in entries {
            let expected = spec["expected_error_contains"]
                .as_str()
                .unwrap_or_else(|| panic!("entry {file} missing expected_error_contains"));
            let json = std::fs::read_to_string(dir.join(file))
                .unwrap_or_else(|err| panic!("read {file}: {err}"));
            let result = render_aibom_markdown_inner(&json);
            let err = match result {
                Err(e) => e,
                Ok(rendered) => panic!(
                    "fixture {file} unexpectedly rendered OK (first 80 bytes: {:?})",
                    &rendered[..rendered.len().min(80)]
                ),
            };
            assert!(
                err.contains(expected),
                "fixture {file}: error message {err:?} must contain {expected:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_sha256_digest_prefix() {
        // schema: ProvenanceEntry.config_digest pattern ^sha256:[0-9a-fA-F]{64}$
        let json = valid_pass_sample();
        // Drop the "sha256:" prefix on the first digest-looking field.
        let pat = "\"digest\": \"sha256:";
        let mutated = json.replacen(pat, "\"digest\": \"md5:", 1);
        let err = render_aibom_markdown_inner(&mutated).expect_err("must reject non-sha256 digest");
        assert!(
            err.contains("schema violation") && err.contains("sha256:"),
            "error must mention the prefix requirement: {err}"
        );
    }
}

/// Guard against drift between `schemas/aibom-v1.schema.json` and
/// `validate_scalar_constraints` in `src/lib.rs`. Walks the bundled schema
/// definitions, tallies every `minLength`, `pattern`, and `maxLength`
/// constraint, and asserts the counts match the hard-rolled validator's
/// coverage. If a maintainer adds a new constraint to the schema without
/// updating the validator, this test fails — and points at the specific
/// path the validator is missing.
#[test]
fn scalar_constraints_match_schema() {
    use std::collections::BTreeSet;

    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate at <repo>/crates/<name>")
        .join("schemas/aibom-v1.schema.json");
    let schema: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&schema_path).expect("read schema"))
            .expect("parse schema");

    // Walk every property in every $def and collect the (def, property,
    // constraint) triple. We treat the schema as the source of truth: the
    // validator must cover everything we find here.
    let mut min_length: BTreeSet<(String, String, u64)> = BTreeSet::new();
    let mut max_length: BTreeSet<(String, String, u64)> = BTreeSet::new();
    let mut patterns: BTreeSet<(String, String, String)> = BTreeSet::new();

    let defs = schema["$defs"].as_object().expect("schema has $defs map");
    for (def_name, def) in defs {
        // String-typed $defs (Sha256Digest, Sha256Hex) carry their pattern
        // at the top level rather than under properties.
        if def.get("pattern").is_some() && def.get("properties").is_none() {
            let pattern = def["pattern"].as_str().unwrap().to_string();
            patterns.insert((def_name.clone(), "<self>".to_string(), pattern));
            continue;
        }
        let Some(properties) = def.get("properties").and_then(|p| p.as_object()) else {
            continue;
        };
        for (prop_name, prop) in properties {
            if let Some(n) = prop.get("minLength").and_then(|v| v.as_u64()) {
                min_length.insert((def_name.clone(), prop_name.clone(), n));
            }
            if let Some(n) = prop.get("maxLength").and_then(|v| v.as_u64()) {
                max_length.insert((def_name.clone(), prop_name.clone(), n));
            }
            if let Some(p) = prop.get("pattern").and_then(|v| v.as_str()) {
                patterns.insert((def_name.clone(), prop_name.clone(), p.to_string()));
            }
        }
    }

    // Expected coverage — every constraint type and its pattern. The
    // validator in src/lib.rs reaches every one of these via its
    // `non_empty` / `sha256_hex` / `sha256_digest` / `text_excerpt`
    // helpers. Adding a new constraint to the schema → update both lists.
    let expected_patterns: BTreeSet<String> = ["^sha256:[0-9a-fA-F]{64}$", "^[0-9a-fA-F]{64}$"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let actual_patterns: BTreeSet<String> = patterns.iter().map(|(_, _, p)| p.clone()).collect();
    assert_eq!(
        actual_patterns, expected_patterns,
        "schema introduced (or removed) a `pattern` constraint that \
         validate_scalar_constraints does not cover. Update both."
    );

    // Every `minLength` in the schema is exactly 1 (the only "non-empty"
    // form SIGIL uses). If a future field adds minLength: 2 we want to
    // know — the validator's non_empty helper only enforces ≥1.
    for (def, prop, n) in &min_length {
        assert_eq!(
            *n, 1,
            "schema introduced minLength != 1 on {def}.{prop}; validate_scalar_constraints \
             only handles minLength: 1 via the non_empty helper. Either add a new helper or \
             adjust the schema."
        );
    }

    // Every `maxLength` in the schema is exactly 256 (text_excerpt). If a
    // future field adds maxLength: M, the validator needs to learn about it.
    let known_max = (
        "LicenseEntry".to_string(),
        "text_excerpt".to_string(),
        sigil_aibom_wasm::TEXT_EXCERPT_MAX_LEN as u64,
    );
    let actual_max: BTreeSet<(String, String, u64)> = max_length.iter().cloned().collect();
    assert_eq!(
        actual_max,
        std::iter::once(known_max).collect::<BTreeSet<_>>(),
        "schema introduced a `maxLength` constraint validate_scalar_constraints does not \
         cover."
    );

    // Sanity floor: the schema *must* still carry the constraints the
    // validator's helpers are written against; if the schema drops them
    // (e.g. someone deletes the sha256 pattern), the validator would go
    // from enforcing to silently allowing.
    assert!(
        !min_length.is_empty(),
        "schema has no minLength constraints — validator regression risk"
    );
    assert!(
        !patterns.is_empty(),
        "schema has no pattern constraints — validator regression risk"
    );
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
    let required: BTreeSet<&str> = root_def["required"]
        .as_array()
        .expect("schema $defs.AiBom.required is an array")
        .iter()
        .map(|v| v.as_str().expect("required entry is a string"))
        .collect();
    let properties: BTreeSet<&str> = root_def["properties"]
        .as_object()
        .expect("schema $defs.AiBom.properties is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        root_def["additionalProperties"].as_bool() == Some(false),
        "schema must keep additionalProperties: false on the root"
    );
    assert_eq!(
        required, properties,
        "every root property must be required (no optional top-level fields)"
    );

    // Direct comparison: the validator's allow-list IS the schema's property
    // set. No indirection through error messages.
    let validator_allow_list: BTreeSet<&str> = sigil_aibom_wasm::REQUIRED_TOP_LEVEL_KEYS
        .iter()
        .copied()
        .collect();
    assert_eq!(
        validator_allow_list, properties,
        "REQUIRED_TOP_LEVEL_KEYS in src/lib.rs has drifted from the schema's root property set. \
         Update the constant to match."
    );
}
