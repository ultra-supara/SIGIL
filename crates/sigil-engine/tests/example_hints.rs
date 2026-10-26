//! Every golden session example carries exactly the feature hints the engine derives from its
//! binary facts (PR-5a-2 plan P-g), and one with binary facts records the capability table they
//! were made with (#51): an example shows what a run writes.

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
    assert_eq!(names.len(), 18, "{names:?}");
    for path in names {
        let session: Session =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let key = |h: &sigil_model::FeatureHint| serde_json::to_string(h).unwrap();
        let mut derived = sigil_engine::analyze::hints::derive(&session.binaries).unwrap();
        derived.sort_by_cached_key(key);
        let mut recorded = session.hints.clone();
        recorded.sort_by_cached_key(key);
        assert_eq!(recorded, derived, "{}", path.display());
        // The table's kind, ID, and SHA-256: its version only says which build wrote it.
        let table = sigil_engine::code::data::signatures().unwrap().knowledge();
        let pin = |k: &sigil_model::KnowledgeRef| (k.kind, k.id.clone(), k.sha256.clone());
        let tables: Vec<_> = session
            .knowledge
            .iter()
            .filter(|k| {
                k.kind == sigil_model::KnowledgeKind::SignatureDb
                    && k.id == sigil_model::CAPABILITY_TABLE_ID
            })
            .map(pin)
            .collect();
        if session.binaries.is_empty() {
            assert!(tables.is_empty(), "{}", path.display());
        } else {
            assert_eq!(
                tables,
                [pin(table)],
                "{}: not this build's capability table. After a change to \
                 signatures/capabilities.toml, set CAPABILITY_TABLE_HEX in \
                 crates/sigil-model/tests/common/mod.rs to its SHA-256 ({}), then run \
                 SIGIL_BLESS=1 cargo test -p sigil-model --test examples, then --test aibom, and \
                 copy 16-binary-code.json to site/viewer/samples/session-16-binary-code.json",
                path.display(),
                table.sha256
            );
        }
    }
}
