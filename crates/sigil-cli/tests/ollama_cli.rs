use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(digest.replace(':', "-")),
        b"hello",
    )
    .unwrap();
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{digest}"}},"layers":[{{"digest":"{digest}"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}

#[test]
fn runtime_inspect_ollama_writes_evidence_json() {
    let tmp = fake_store();
    let out = tmp.path().join("nested").join("ollama.evidence.json");

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "runtime",
        "inspect",
        "ollama",
        "--model",
        "gemma4:e2b",
        "--models-dir",
        tmp.path().join("models").to_str().unwrap(),
        "--host",
        "http://127.0.0.1:11434",
        "--no-probe-api",
        "--no-inspect-runtime",
        "--out",
        out.to_str().unwrap(),
    ])
    .current_dir(workspace_root())
    .assert()
    .success()
    .stdout(contains("SIGIL Runtime Verdict: PASS"));

    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"model\": \"gemma4:e2b\""));
    assert!(json.contains("\"api\": \"not_probed\""));
    assert!(json.contains("\"runtime_exposure\""));
    assert!(json.contains("\"class\": \"unknown\""));
}

#[test]
fn aibom_generate_ollama_writes_markdown() {
    let tmp = fake_store();
    let out = tmp.path().join("reports").join("aibom.md");

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "aibom",
        "generate",
        "--runtime",
        "ollama",
        "--model",
        "gemma4:e2b",
        "--models-dir",
        tmp.path().join("models").to_str().unwrap(),
        "--no-probe-api",
        "--no-inspect-runtime",
        "--out",
        out.to_str().unwrap(),
    ])
    .current_dir(workspace_root())
    .assert()
    .success()
    .stdout(contains("SIGIL AI-BOM:"));

    let markdown = fs::read_to_string(out).unwrap();
    assert!(markdown.contains("# SIGIL AI-BOM"));
    assert!(markdown.contains("gemma4:e2b"));
    assert!(markdown.contains("- API exposure: `not_probed`"));
    assert!(markdown.contains("- Runtime exposure: `unknown`"));
}
