//! Sessions with code facts, `binary.code`, hints, and the code scope (PR-5a).

mod common;

use std::path::PathBuf;

use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    binary_session, store_session, ActiveInput, BinaryRequest, InstallRequest, StoreRequest,
};
use sigil_engine::policy::Policy;
use sigil_model::Session;
use tempfile::TempDir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/code")
        .join(name)
}

/// The session's hints as (feature, value).
fn hint_pairs(s: &Session) -> Vec<(String, String)> {
    s.hints
        .iter()
        .map(|h| (h.feature.to_string(), h.value.as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn a_binary_session_has_the_import_hints() {
    let req = BinaryRequest {
        paths: vec![fixture("net-plt-gcc.so")],
        budgets: Default::default(),
    };
    let s = binary_session(
        &req,
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_eq!(
        hint_pairs(&s),
        [("posix.network".to_string(), "connect".to_string())]
    );
    assert!(s.validate().is_ok());
}

#[test]
fn an_install_session_has_the_import_hints() {
    // A synthetic tree: the fixture stands in for `bin/ollama`.
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::copy(fixture("net-plt-gcc.so"), tree.path().join("bin/ollama")).unwrap();
    let models = TempDir::new().unwrap();
    let req = StoreRequest {
        models_dir: models.path().to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest {
            dir: tree.path().to_path_buf(),
            budgets: InstallBudgets::default(),
        }),
    };
    let s = store_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        common::tool(),
        common::observation(),
        common::policy_time(),
    )
    .unwrap();
    assert_eq!(
        hint_pairs(&s),
        [("posix.network".to_string(), "connect".to_string())]
    );
    assert_eq!(s.hints[0].subject, s.binaries[0].slice);
    assert!(s.validate().is_ok());
}
