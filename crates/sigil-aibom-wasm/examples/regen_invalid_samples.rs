//! Regenerate the invalid-fixtures the behavioural CI smoke uses to exercise
//! the wasm wrapper's error paths. Each fixture mutates the canonical
//! `pass.aibom.json` in exactly one way that triggers a specific layer of
//! validation (envelope, serde `deny_unknown_fields`, scalar constraints).
//!
//! Output:
//!   - site/viewer/samples/invalid/<case>.aibom.json
//!   - site/viewer/samples/invalid/manifest.json
//!     maps each filename to a substring the produced error MUST contain,
//!     so `ci/check-committed-wasm.mjs` can assert the committed wasm
//!     rejects the input AND the error message names the problem.
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run -q -p sigil-aibom-wasm --example regen_invalid_samples
//! ```

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let pass = fs::read_to_string(root.join("site/viewer/samples/pass.aibom.json"))?;
    let base: Value = serde_json::from_str(&pass)?;

    let out_dir = root.join("site/viewer/samples/invalid");
    fs::create_dir_all(&out_dir)?;

    let cases = vec![
        Case {
            file: "wrong-schema-version.aibom.json",
            expected_error_contains: "1.2",
            description: "envelope: schema_version != \"1.1\"",
            mutate: |mut v| {
                v["schema_version"] = json!("1.2");
                v
            },
        },
        Case {
            file: "unknown-top-level-field.aibom.json",
            expected_error_contains: "smuggled",
            description: "envelope: additionalProperties: false at root",
            mutate: |mut v| {
                v.as_object_mut()
                    .unwrap()
                    .insert("smuggled".into(), json!(true));
                v
            },
        },
        Case {
            file: "unknown-nested-runtime.aibom.json",
            expected_error_contains: "unknown field",
            description: "serde deny_unknown_fields on RuntimeInfo",
            mutate: |mut v| {
                v["runtime"]
                    .as_object_mut()
                    .unwrap()
                    .insert("sneaky".into(), json!(true));
                v
            },
        },
        Case {
            file: "empty-tool-name.aibom.json",
            expected_error_contains: "tool.name",
            description: "scalar: minLength on tool.name",
            mutate: |mut v| {
                v["tool"]["name"] = json!("");
                v
            },
        },
        Case {
            file: "non-hex-sha256.aibom.json",
            expected_error_contains: "sha256",
            description: "scalar: pattern on files[*].sha256",
            mutate: |mut v| {
                v["models"][0]["files"][0]["sha256"] = json!("not-64-hex-chars");
                v
            },
        },
        Case {
            file: "bad-digest-prefix.aibom.json",
            expected_error_contains: "sha256:",
            description: "scalar: pattern on files[*].digest",
            mutate: |mut v| {
                v["models"][0]["files"][0]["digest"] =
                    json!("md5:2af71558e438db0b73a20beab92dc278a94e1bbe974c00c1a33e3ab62d53a608");
                v
            },
        },
        Case {
            file: "text-excerpt-too-long.aibom.json",
            expected_error_contains: "text_excerpt",
            description: "scalar: maxLength on license.text_excerpt",
            mutate: |mut v| {
                v["models"][0]["license"]["text_excerpt"] = json!("x".repeat(257));
                v
            },
        },
        Case {
            file: "wrong-enum-verdict.aibom.json",
            expected_error_contains: "unknown variant",
            description: "serde enum: verdict must be PASS/WARN/FAIL",
            mutate: |mut v| {
                v["verdict"] = json!("MAYBE");
                v
            },
        },
    ];

    let mut manifest = Map::new();
    for case in &cases {
        let mutated = (case.mutate)(base.clone());
        let mut content = serde_json::to_string_pretty(&mutated)?;
        content.push('\n');
        fs::write(out_dir.join(case.file), content)?;
        manifest.insert(
            case.file.to_string(),
            json!({
                "expected_error_contains": case.expected_error_contains,
                "description": case.description,
            }),
        );
    }
    let mut manifest_text = serde_json::to_string_pretty(&Value::Object(manifest))?;
    manifest_text.push('\n');
    fs::write(out_dir.join("manifest.json"), manifest_text)?;

    println!(
        "wrote {} invalid fixtures to {}",
        cases.len(),
        out_dir.display()
    );
    Ok(())
}

struct Case {
    file: &'static str,
    expected_error_contains: &'static str,
    description: &'static str,
    mutate: fn(Value) -> Value,
}

fn repo_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .expect("crate is nested under <root>/crates/<crate>")
}
