use std::fs;
use std::path::Path;

use sigil_core::aibom::AiBom;
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
use sigil_core::runtime::RuntimeListeners;
use tempfile::TempDir;

pub const CONFIG_DIGEST: &str =
    "sha256:e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0";
pub const MODEL_DIGEST: &str =
    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
// sha256("Apache-2.0") — keep aligned with the license blob content below.
pub const LICENSE_DIGEST: &str =
    "sha256:2af71558e438db0b73a20beab92dc278a94e1bbe974c00c1a33e3ab62d53a608";

pub fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    write_blob(tmp.path(), CONFIG_DIGEST, b"cfg");
    write_blob(tmp.path(), MODEL_DIGEST, b"hello");
    write_blob(tmp.path(), LICENSE_DIGEST, b"Apache-2.0");
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{CONFIG_DIGEST}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{{"digest":"{MODEL_DIGEST}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{LICENSE_DIGEST}","mediaType":"application/vnd.ollama.image.license"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}

fn write_blob(root: &Path, digest: &str, content: &[u8]) {
    let blob_path = root.join("models/blobs").join(digest.replace(':', "-"));
    fs::write(&blob_path, content).unwrap();
}

pub fn bom_for(host: &str) -> AiBom {
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
