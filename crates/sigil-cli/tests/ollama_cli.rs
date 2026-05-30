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
    let model_digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    // sha256("MIT")
    let license_digest = "sha256:e5dcffe836b6ec8a58e492419b550e65fb8cbdc308503979e5dacb33ac7ea3b7";
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(model_digest.replace(':', "-")),
        b"hello",
    )
    .unwrap();
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(license_digest.replace(':', "-")),
        b"MIT",
    )
    .unwrap();
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{model_digest}"}},"layers":[{{"digest":"{model_digest}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{license_digest}","mediaType":"application/vnd.ollama.image.license"}}]}}"#
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
    assert!(json.contains("\"schema_version\": \"1.1\""));
    assert!(json.contains("\"name\": \"ollama\""));
    assert!(json.contains("\"api_exposure\": \"not_probed\""));
    assert!(json.contains("\"class\": \"unknown\""));
    assert!(json.contains("gemma4:e2b"));
    assert!(json.contains("\"verdict\": \"PASS\""));
    assert!(json.contains("\"registry\": \"registry.ollama.ai\""));
    assert!(json.contains("\"namespace\": \"library\""));
    assert!(json.contains("\"tag\": \"e2b\""));
    assert!(json.contains("\"spdx_id\": \"MIT\""));
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
        "--format",
        "md",
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
    .env_remove("OLLAMA_HOST")
    .assert()
    .success()
    .stdout(contains("SIGIL AI-BOM:"));

    let markdown = fs::read_to_string(out).unwrap();
    assert!(markdown.contains("# SIGIL AI-BOM"));
    assert!(markdown.contains("gemma4:e2b"));
    assert!(markdown.contains("- API exposure: `not_probed`"));
    assert!(markdown.contains("- Runtime exposure: `unknown`"));
    assert!(markdown.contains("- Provenance:"));
    assert!(markdown.contains("registry=`registry.ollama.ai`"));
    assert!(markdown.contains("tag=`e2b`"));
    assert!(markdown.contains("- License: `MIT`"));
}

#[test]
fn runtime_inspect_ollama_honors_ollama_host_env_when_host_flag_omitted() {
    let tmp = fake_store();
    let out = tmp.path().join("ollama.evidence.json");

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "runtime",
        "inspect",
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
    .env("OLLAMA_HOST", "0.0.0.0:11434")
    .assert()
    .success()
    .stdout(contains("SIGIL Runtime Verdict: WARN"));

    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"api_exposure\": \"public_bind\""));
    assert!(json.contains("\"ollama.public_bind\""));
}

#[test]
fn aibom_generate_ollama_writes_json_by_default() {
    let tmp = fake_store();
    let out = tmp.path().join("reports").join("aibom.json");

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
    .env_remove("OLLAMA_HOST")
    .assert()
    .success()
    .stdout(contains("SIGIL AI-BOM:"));

    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"schema_version\": \"1.1\""));
    assert!(json.contains("\"api_exposure\": \"not_probed\""));
    assert!(json.contains("gemma4:e2b"));
}
