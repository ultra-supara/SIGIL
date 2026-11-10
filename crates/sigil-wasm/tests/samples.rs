//! The viewer's samples (`site/viewer/samples/`): each is a copy of a golden example and renders;
//! each invalid sample is refused with the error its `manifest.json` names. CI runs the same
//! samples through the committed wasm (`ci/check-committed-wasm.mjs`).

use std::fs;
use std::path::PathBuf;

use sigil_wasm::render_markdown_inner;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The golden file a sample copies: `session-<n>.json` from `schemas/examples/session-v1/<n>.json`,
/// `aibom-<n>.json` from `schemas/examples/aibom-v2/<n>.json`.
fn source(sample: &str) -> PathBuf {
    let (dir, name) = if let Some(n) = sample.strip_prefix("session-") {
        ("session-v1", n)
    } else if let Some(n) = sample.strip_prefix("aibom-") {
        ("aibom-v2", n)
    } else {
        panic!("{sample}: a sample is session-<example>.json or aibom-<example>.json");
    };
    root().join("schemas/examples").join(dir).join(name)
}

fn samples() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root().join("site/viewer/samples"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_sample_is_a_golden_example_and_renders() {
    let names = samples();
    assert_eq!(names.len(), 20, "{names:?}");
    for name in names {
        let sample = fs::read(root().join("site/viewer/samples").join(&name)).unwrap();
        let golden = fs::read(source(&name)).unwrap();
        assert!(
            sample == golden,
            "{name} differs from {}",
            source(&name).display()
        );
        let json = String::from_utf8(sample).unwrap();
        render_markdown_inner(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn every_invalid_sample_gives_its_error() {
    let dir = root().join("site/viewer/samples/invalid");
    let manifest: Vec<serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
    let mut listed: Vec<String> = vec![];
    for entry in &manifest {
        let file = entry["file"].as_str().unwrap();
        let expect = entry["expect"].as_str().unwrap();
        let json = fs::read_to_string(dir.join(file)).unwrap();
        let err = render_markdown_inner(&json).expect_err(file);
        assert!(
            err.contains(expect),
            "{file}: {err:?} does not contain {expect:?}"
        );
        listed.push(file.to_string());
    }
    // Every invalid sample is in the manifest.
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "manifest.json")
        .collect();
    files.sort();
    listed.sort();
    assert_eq!(files, listed);
}

#[test]
fn macho_samples_preserve_library_and_slice_uncertainty() {
    use sigil_model::{CoverageState, EvidenceRef, Loc, Session};
    let read = |name: &str| -> Session {
        serde_json::from_slice(&fs::read(root().join("site/viewer/samples").join(name)).unwrap())
            .unwrap()
    };
    let same = read("session-23-macho-same-name.json");
    assert_eq!(same.code[0].call_sites.len(), 3);
    assert_eq!(same.policy_violations[0].evidence.len(), 2);
    let mixed = read("session-25-macho-mixed.json");
    assert!(mixed
        .coverage
        .iter()
        .any(|c| matches!(c.state, CoverageState::Unsupported { .. })));
    let install = read("session-26-macho-install.json");
    assert!(install.policy_violations.is_empty());
    assert!(install
        .open_questions
        .iter()
        .flat_map(|q| &q.evidence)
        .any(|e| matches!(
            e,
            EvidenceRef::Code {
                loc: Loc::CallSite(_),
                ..
            }
        )));
    let chain = read("session-27-macho-unsupported-chain.json");
    assert!(chain.code.is_empty());
    let archived = read("session-28-macho-archived-library.json");
    assert!(archived.policy_violations.is_empty());
    let md = render_markdown_inner(&archived.to_canonical_json().unwrap()).unwrap();
    let row = md
        .lines()
        .find(|line| line.starts_with("| cxx\\.file\\_write |"))
        .unwrap();
    assert!(row.contains("none found"), "{row}");
}
