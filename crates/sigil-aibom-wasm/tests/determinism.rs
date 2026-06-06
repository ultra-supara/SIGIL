//! Determinism: the public wasm entrypoint (`render_aibom_markdown`) must
//! produce byte-for-byte the same Markdown as `sigil_core::aibom::render_ai_bom`
//! does for the same JSON input.
//!
//! `#[wasm_bindgen]` functions compile to plain Rust on the host, so running
//! this suite natively exercises the same render path the wasm module exposes
//! — minus the JS marshalling. If a future refactor adds any transformation
//! (e.g. normalizing line endings for the browser), that change will make this
//! test fail until the snapshot is reconciled.
//!
//! Coverage: every committed file under `site/viewer/samples/`. Adding a
//! sample to that directory automatically extends this test.

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
