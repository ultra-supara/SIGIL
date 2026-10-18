//! Every golden session example carries exactly the feature hints the engine derives from its
//! binary facts (PR-5a-2 plan P-g): an example shows what a run writes.

use std::path::Path;

use sigil_model::Session;

#[test]
fn every_session_example_carries_the_hints_the_engine_derives() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/session-v1");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    assert_eq!(names.len(), 16, "{names:?}");
    for path in names {
        let session: Session =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let key = |h: &sigil_model::FeatureHint| serde_json::to_string(h).unwrap();
        let mut derived = sigil_engine::analyze::hints::derive(&session.binaries).unwrap();
        derived.sort_by_key(key);
        let mut recorded = session.hints.clone();
        recorded.sort_by_key(key);
        assert_eq!(recorded, derived, "{}", path.display());
    }
}
