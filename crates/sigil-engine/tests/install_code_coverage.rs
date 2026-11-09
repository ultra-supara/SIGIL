use std::path::PathBuf;

use sigil_engine::analyze::install_code;
use sigil_engine::code::CodeBudgets;
use sigil_engine::collect::install::{collect_with_code, InstallBudgets};
use sigil_model::{CoverageState, Ref};
use tempfile::TempDir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code/spawn.so")
}

#[test]
fn duplicate_contents_have_one_entry_and_a_small_budget_remains_a_gap() {
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    std::fs::copy(fixture(), tree.path().join("bin/ollama")).unwrap();
    std::fs::copy(fixture(), tree.path().join("lib/ollama/copy.so")).unwrap();
    let mut budgets = InstallBudgets::default();
    budgets.binary.code = Some(CodeBudgets {
        bytes: 0,
        ..CodeBudgets::default()
    });
    let facts = collect_with_code(tree.path(), budgets).unwrap();
    let coverage = install_code::coverage(&facts, 0).unwrap();
    assert_eq!(coverage.len(), 2);
    assert!(matches!(coverage[0].scope, Ref::Root(_)));
    assert!(matches!(coverage[0].state, CoverageState::Partial { .. }));
    assert!(matches!(coverage[1].scope, Ref::Artifact(_)));
    assert!(matches!(coverage[1].state, CoverageState::Partial { .. }));
    assert_eq!(coverage[1].budget.as_ref().unwrap().limit, 0);
}

#[test]
fn incomplete_discovery_cannot_report_complete_even_with_no_binaries() {
    let tree = TempDir::new().unwrap();
    let mut facts = collect_with_code(tree.path(), InstallBudgets::default()).unwrap();
    facts.discovery.state = CoverageState::Partial {
        missing: vec!["unread directory".into()],
    };
    let coverage = install_code::coverage(&facts, 10).unwrap();
    assert_eq!(coverage.len(), 1);
    assert!(
        matches!(&coverage[0].state, CoverageState::Partial { missing } if missing.contains(&"discovery incomplete".to_string()))
    );
}

#[test]
fn other_architectures_are_explicitly_unsupported() {
    let tree = TempDir::new().unwrap();
    std::fs::create_dir_all(tree.path().join("bin")).unwrap();
    std::fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    let mut bytes = std::fs::read(fixture()).unwrap();
    bytes[18..20].copy_from_slice(&40u16.to_le_bytes());
    std::fs::write(tree.path().join("bin/ollama"), bytes).unwrap();
    let mut budgets = InstallBudgets::default();
    budgets.binary.code = Some(CodeBudgets::default());
    let facts = collect_with_code(tree.path(), budgets).unwrap();
    let coverage = install_code::coverage(&facts, CodeBudgets::default().bytes).unwrap();
    assert!(matches!(coverage[0].state, CoverageState::Partial { .. }));
    assert!(matches!(
        coverage[1].state,
        CoverageState::Unsupported { .. }
    ));
}
