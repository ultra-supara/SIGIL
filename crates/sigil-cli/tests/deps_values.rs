#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

fn run(args: &[&str]) -> std::process::Output {
    Command::cargo_bin("sigil")
        .unwrap()
        .env_remove("OLLAMA_MODELS")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn observe_env_requires_observe_and_does_not_open_a_unit_before_usage_validation() {
    let out = run(&[
        "inspect",
        "ollama",
        "--mode",
        "static",
        "--observe-env",
        "--service-unit",
        "/no/such/unit",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--observe-env requires --mode observe"));
}

#[test]
fn each_new_budget_rejects_irrelevant_scope_before_collection() {
    for (args, needle) in [
        (
            vec!["inspect", "ollama", "--budget", "proc_status_bytes=1"],
            "--mode observe",
        ),
        (
            vec!["inspect", "ollama", "--budget", "process_values=1"],
            "--mode observe",
        ),
        (
            vec![
                "inspect",
                "ollama",
                "--mode",
                "observe",
                "--budget",
                "proc_environ_bytes=1",
            ],
            "--observe-env",
        ),
        (
            vec![
                "inspect",
                "ollama",
                "--mode",
                "observe",
                "--budget",
                "proc_environ_total_bytes=1",
            ],
            "--observe-env",
        ),
        (
            vec!["inspect", "ollama", "--budget", "dependency_contexts=1"],
            "--install-dir or --service-unit",
        ),
        (
            vec!["inspect", "ollama", "--budget", "dependency_candidates=1"],
            "--install-dir or --service-unit",
        ),
        (
            vec!["inspect", "ollama", "--budget", "dependency_search_paths=1"],
            "--install-dir or --service-unit",
        ),
        (
            vec!["inspect", "ollama", "--budget", "service_unit_values=1"],
            "fixed",
        ),
        (
            vec![
                "binary",
                "inspect",
                "/no/such/file",
                "--budget",
                "proc_environ_bytes=1",
            ],
            "unknown budget",
        ),
    ] {
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(needle),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn binary_dependency_budgets_are_recorded_and_zero_does_not_mean_no_dependencies() {
    let d = TempDir::new().unwrap();
    let file = d.path().join("file");
    // A clean minimal ELF64 header is enough for budget/relevance coverage; parsing gaps remain.
    let mut bytes = vec![0u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    std::fs::write(&file, bytes).unwrap();
    let out = run(&[
        "binary",
        "inspect",
        file.to_str().unwrap(),
        "--budget",
        "dependency_contexts=0",
        "--budget",
        "dependency_candidates=7",
        "--budget",
        "dependency_search_paths=8",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["request"]["budgets"]["dependency_contexts"], 0);
    assert_eq!(value["request"]["budgets"]["dependency_candidates"], 7);
    assert_eq!(value["request"]["budgets"]["dependency_search_paths"], 8);
    assert!(value["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["check"] == "binary.dependencies"));
    assert!(!value["request"]["observe_env"].as_bool().unwrap());
}
