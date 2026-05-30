use std::fs;
use std::path::Path;

use sigil_core::aibom::AiBom;
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
use sigil_core::runtime::RuntimeListeners;
use tempfile::TempDir;

const CONFIG_DIGEST: &str =
    "sha256:e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0";
const MODEL_DIGEST: &str =
    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    // Distinct blobs for the config descriptor and the model layer, mirroring a
    // real Ollama store where every blob has its own sha256.
    write_blob(tmp.path(), CONFIG_DIGEST, b"cfg");
    write_blob(tmp.path(), MODEL_DIGEST, b"hello");
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{CONFIG_DIGEST}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{{"digest":"{MODEL_DIGEST}","mediaType":"application/vnd.ollama.image.model"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}

fn write_blob(root: &Path, digest: &str, content: &[u8]) {
    let blob_path = root.join("models/blobs").join(digest.replace(':', "-"));
    fs::write(&blob_path, content).unwrap();
}

fn bom_for(host: &str) -> AiBom {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: host.to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();
    AiBom::from(&report)
}

#[test]
fn aibom_has_stable_top_level_shape() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    let object = value.as_object().unwrap();

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "findings",
            "models",
            "runtime",
            "schema_version",
            "tool",
            "verdict"
        ]
    );

    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["tool"]["name"], "sigil");
    assert!(value["tool"]["version"].is_string());
    assert_eq!(value["runtime"]["name"], "ollama");
    assert_eq!(value["runtime"]["api_exposure"], "not_probed");
    assert_eq!(value["runtime"]["status"], "not_probed");
    assert_eq!(value["runtime"]["exposure"]["class"], "unknown");
    assert_eq!(value["runtime"]["exposure"]["source"], "disabled");
    assert_eq!(value["verdict"], "PASS");
    assert_eq!(value["models"][0]["name"], "gemma4:e2b");
    // models_dir / manifest_path are Option in the schema but always present for Ollama.
    assert!(value["runtime"]["models_dir"].is_string());
    assert!(value["models"][0]["manifest_path"].is_string());

    let files = value["models"][0]["files"].as_array().unwrap();
    let model_file = files
        .iter()
        .find(|file| file["kind"] == "model")
        .expect("a model-kind file is present");
    assert_eq!(model_file["digest"], MODEL_DIGEST);
    assert!(model_file["sha256"].is_string());
}

#[test]
fn aibom_omits_absent_optional_fields() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    // probe_api = false -> no runtime version is recorded.
    assert!(value["runtime"]
        .as_object()
        .unwrap()
        .get("version")
        .is_none());
}

#[test]
fn aibom_maps_public_bind_finding_with_runtime_category_and_warn() {
    let bom = bom_for("0.0.0.0:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    assert_eq!(value["verdict"], "WARN");
    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "ollama.public_bind")
        .expect("public_bind finding present");
    assert_eq!(finding["category"], "runtime");
    assert_eq!(finding["severity"], "WARN");
}
