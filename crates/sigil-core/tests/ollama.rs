use std::collections::HashMap;
use std::fs;
use std::path::Path;

use sigil_core::ollama::{
    inspect_ollama, render_ai_bom, ApiExposure, ModelFile, OllamaInspectOptions, RuntimeStatus,
};
use sigil_core::runtime::{
    BindEvidence, Listener, ListenerSnapshot, RuntimeExposure, RuntimeListeners,
};
use tempfile::TempDir;

fn write_blob(root: &Path, digest: &str, content: &[u8]) -> ModelFile {
    let blob_path = root.join("models/blobs").join(digest.replace(':', "-"));
    fs::write(&blob_path, content).unwrap();
    ModelFile {
        digest: digest.to_string(),
        path: blob_path,
        size: content.len() as u64,
        sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
        kind: "blob".to_string(),
    }
}

fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    write_blob(tmp.path(), digest, b"hello");
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {{"digest": "{digest}", "mediaType": "application/vnd.ollama.image.config"}},
  "layers": [
    {{"digest": "{digest}", "mediaType": "application/vnd.ollama.image.model"}}
  ]
}}"#
        ),
    )
    .unwrap();
    tmp
}

fn fixed_listener(addr: &str, port: u16) -> RuntimeListeners {
    RuntimeListeners::Fixed(ListenerSnapshot {
        listeners: vec![Listener {
            addr: addr.parse().unwrap(),
            port,
            inode: 1,
        }],
        processes: HashMap::new(),
        available: true,
        source: "proc".to_string(),
    })
}

#[test]
fn inventories_ollama_model_store_manifest_and_blobs() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.model.as_deref(), Some("gemma4:e2b"));
    assert_eq!(report.models.len(), 1);
    assert_eq!(report.models[0].name, "gemma4:e2b");
    assert_eq!(report.models[0].files.len(), 1);
    assert_eq!(report.models[0].files[0].size, 5);
    assert_eq!(
        report.models[0].files[0].sha256,
        report.models[0].files[0].digest["sha256:".len()..]
    );
    assert_eq!(report.api, ApiExposure::NotProbed);
    assert_eq!(report.runtime_status, RuntimeStatus::NotProbed);
    assert_eq!(report.verdict, "PASS");
    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Unknown);
    assert_eq!(report.runtime_exposure.source, "disabled");
}

#[test]
fn flags_public_bind_host_as_warn_without_network_probe() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "0.0.0.0:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.public_bind"));
}

#[test]
fn treats_scheme_less_loopback_host_as_local() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.api, ApiExposure::NotProbed);
    assert_eq!(report.verdict, "PASS");
}

#[test]
fn flags_non_local_network_host_as_warn_without_probe() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://192.0.2.10:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.api, ApiExposure::Network);
    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.network_endpoint"));
}

#[test]
fn flags_manifest_blob_digest_mismatch_as_fail() {
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
        b"tampered",
    )
    .unwrap();
    fs::write(
        manifest_dir.join("e2b"),
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{digest}"}},"layers":[]}}"#),
    )
    .unwrap();

    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "FAIL");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.blob_digest_mismatch"));
}

#[test]
fn rejects_manifest_digest_with_path_separators_before_blob_lookup() {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let digest = "sha256:foo/../../secret";
    fs::write(
        manifest_dir.join("e2b"),
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{digest}"}},"layers":[]}}"#),
    )
    .unwrap();

    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "WARN");
    assert!(report.models[0].files.is_empty());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.invalid_blob_digest"));
}

#[test]
fn renders_ai_bom_with_model_runtime_and_files() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    let bom = render_ai_bom(&report);
    assert!(bom.contains("# SIGIL AI-BOM"));
    assert!(bom.contains("gemma4:e2b"));
    assert!(bom.contains("- API exposure: `not_probed`"));
    assert!(bom.contains("- Runtime status: `not_probed`"));
    assert!(bom.contains("sha256:2cf24"));
}

#[test]
fn runtime_public_bind_listener_warns() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("0.0.0.0", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::PublicBind);
    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.runtime_public_bind"));
    assert_eq!(
        report.runtime_exposure.observed,
        vec![BindEvidence {
            addr: "0.0.0.0".to_string(),
            port: 11434,
            process: None,
        }]
    );
}

#[test]
fn runtime_localhost_listener_keeps_pass() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("127.0.0.1", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Localhost);
    assert_eq!(report.verdict, "PASS");
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.id.starts_with("ollama.runtime_")));
}

#[test]
fn runtime_lan_listener_warns() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("10.0.0.5", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Lan);
    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.runtime_lan_exposure"));
}

#[test]
fn ai_bom_includes_runtime_exposure_and_binds() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("0.0.0.0", 11434),
    })
    .unwrap();

    let bom = render_ai_bom(&report);
    assert!(bom.contains("- Runtime exposure: `public_bind`"));
    assert!(bom.contains("0.0.0.0:11434"));
}

#[test]
fn ai_bom_runtime_exposure_unknown_when_disabled() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    let bom = render_ai_bom(&report);
    assert!(bom.contains("- Runtime exposure: `unknown`"));
}
