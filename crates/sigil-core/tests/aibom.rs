mod common;

use common::{bom_for, CONFIG_DIGEST, LICENSE_DIGEST, MODEL_DIGEST};

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

    assert_eq!(value["schema_version"], "1.1");
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
fn aibom_exposes_license_and_provenance_in_models() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    let model = &value["models"][0];
    let provenance = &model["provenance"];
    assert_eq!(provenance["registry"], "registry.ollama.ai");
    assert_eq!(provenance["namespace"], "library");
    assert_eq!(provenance["model"], "gemma4");
    assert_eq!(provenance["tag"], "e2b");
    assert_eq!(provenance["config_digest"], CONFIG_DIGEST);
    let layer_digests = provenance["layer_digests"].as_array().unwrap();
    assert!(layer_digests.iter().any(|digest| digest == MODEL_DIGEST));
    assert!(layer_digests.iter().any(|digest| digest == LICENSE_DIGEST));

    let license = &model["license"];
    assert_eq!(license["digest"], LICENSE_DIGEST);
    assert_eq!(license["spdx_id"], "Apache-2.0");
    assert_eq!(license["text_excerpt"], "Apache-2.0");
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
