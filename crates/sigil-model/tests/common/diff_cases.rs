//! Builders for `sigil compare` (#16, PR-16a): sessions that differ in one way each, the fixture
//! pairs under `schemas/examples/diff-v1/` (`tests/diff_examples.rs`), and samples of every
//! variant of the diff's types (`tests/diff_schema.rs`).

use sigil_model::diff::*;
use sigil_model::*;

use super::*;

/// The SIGIL that compares the examples.
pub fn example_tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: EXAMPLE_VERSION.to_string(),
        git_rev: None,
    }
}

/// The SHA-256 of `s`'s canonical JSON: what a diff names it by.
pub fn session_sha256(s: &Session) -> Sha256Hex {
    id(&sha256_hex(s.to_canonical_json().unwrap()))
}

/// The diff of two valid sessions, as `sigil compare` makes it.
pub fn diff_of(baseline: &Session, current: &Session) -> Diff {
    let b = ValidatedSession::new(baseline.clone())
        .unwrap_or_else(|e| panic!("baseline is not valid: {}", render(&e)));
    let c = ValidatedSession::new(current.clone())
        .unwrap_or_else(|e| panic!("current is not valid: {}", render(&e)));
    compare(
        &b,
        session_sha256(baseline),
        &c,
        session_sha256(current),
        example_tool(),
    )
}

/// The kind (variant name) of each change, in order.
pub fn kinds(d: &Diff) -> Vec<String> {
    d.changes
        .iter()
        .map(|c| match serde_json::to_value(c).unwrap() {
            serde_json::Value::Object(m) => m.keys().next().unwrap().clone(),
            other => panic!("a change is a struct variant: {other}"),
        })
        .collect()
}

/// Whether `d` has a change of `kind`.
pub fn has(d: &Diff, kind: &str) -> bool {
    kinds(d).iter().any(|k| k == kind)
}
