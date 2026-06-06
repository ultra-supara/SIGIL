//! Regenerate the three browser-viewer sample AI-BOMs from synthetic Ollama
//! model stores. Each output is produced by the same `inspect_ollama` →
//! `AiBom::from` path the CLI's `aibom generate` uses, so the viewer is fed
//! real tool output, not hand-rolled JSON.
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run -p sigil-aibom-wasm --example regen_viewer_samples
//! ```
//!
//! Writes:
//!   - site/viewer/samples/pass.aibom.json
//!   - site/viewer/samples/warn.aibom.json
//!   - site/viewer/samples/fail.aibom.json
//!
//! Every field that holds a tempdir path is rewritten to a stable, fictional
//! one — otherwise the committed sample would churn on every developer's
//! machine. Specifically `stabilize_paths` substitutes the tempdir root in:
//!   - `runtime.models_dir`
//!   - `models[*].manifest_path`
//!   - `models[*].files[*].path`
//!   - `findings[*].evidence`
//!
//! All other fields (digests, sizes, provenance tuples, license text,
//! verdict, findings shape) come straight from the inspector.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sigil_core::aibom::AiBom;
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
use sigil_core::runtime::RuntimeListeners;
use tempfile::TempDir;

const STABLE_MODELS_DIR: &str = "/var/lib/ollama/.ollama/models";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = repo_root().join("site/viewer/samples");
    fs::create_dir_all(&out)?;

    let pass = generate_pass()?;
    let warn = generate_warn()?;
    let fail = generate_fail()?;

    fs::write(out.join("pass.aibom.json"), pass)?;
    fs::write(out.join("warn.aibom.json"), warn)?;
    fs::write(out.join("fail.aibom.json"), fail)?;

    println!("wrote 3 samples to {}", out.display());
    Ok(())
}

fn generate_pass() -> Result<String, Box<dyn std::error::Error>> {
    // Clean store, localhost host, no probe → no findings, verdict = PASS.
    let store = StoreBuilder::new("gemma4", "e2b")
        .with_license_layer(true)
        .with_blob_tamper(false)
        .build()?;
    bom_json(store, "127.0.0.1:11434", "gemma4:e2b")
}

fn generate_warn() -> Result<String, Box<dyn std::error::Error>> {
    // Same clean store, but host is configured as a public bind → public_bind
    // finding (WARN), verdict = WARN.
    let store = StoreBuilder::new("llama3", "8b")
        .with_license_layer(true)
        .with_blob_tamper(false)
        .build()?;
    bom_json(store, "0.0.0.0:11434", "llama3:8b")
}

fn generate_fail() -> Result<String, Box<dyn std::error::Error>> {
    // Tampered model blob: sha256(content) != declared digest → FAIL.
    let store = StoreBuilder::new("mistral", "7b")
        .with_license_layer(true)
        .with_blob_tamper(true)
        .build()?;
    bom_json(store, "127.0.0.1:11434", "mistral:7b")
}

fn bom_json(
    store: BuiltStore,
    host: &str,
    model: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some(model.to_string()),
        models_dir: store.models_dir(),
        host: host.to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })?;
    let mut bom = AiBom::from(&report);
    stabilize_paths(&mut bom, &store);
    Ok(bom.to_json()? + "\n")
}

/// Replace tempdir paths with stable, fictional paths so the committed sample
/// is byte-stable across machines.
fn stabilize_paths(bom: &mut AiBom, store: &BuiltStore) {
    let tmp = store.tempdir.path().display().to_string();
    let replace =
        |s: &str| -> String { s.replace(&tmp, STABLE_MODELS_DIR.trim_end_matches("/models")) };

    if let Some(dir) = &bom.runtime.models_dir {
        bom.runtime.models_dir = Some(replace(dir));
    }
    for model in &mut bom.models {
        if let Some(mp) = &model.manifest_path {
            model.manifest_path = Some(replace(mp));
        }
        for file in &mut model.files {
            file.path = replace(&file.path);
        }
    }
    for finding in &mut bom.findings {
        finding.evidence = replace(&finding.evidence);
    }
}

struct StoreBuilder {
    model: String,
    tag: String,
    has_license: bool,
    tamper_blob: bool,
}

impl StoreBuilder {
    fn new(model: &str, tag: &str) -> Self {
        Self {
            model: model.to_string(),
            tag: tag.to_string(),
            has_license: true,
            tamper_blob: false,
        }
    }
    fn with_license_layer(mut self, has: bool) -> Self {
        self.has_license = has;
        self
    }
    fn with_blob_tamper(mut self, tamper: bool) -> Self {
        self.tamper_blob = tamper;
        self
    }

    fn build(self) -> Result<BuiltStore, Box<dyn std::error::Error>> {
        let tempdir = TempDir::new()?;
        let root = tempdir.path();
        let manifest_dir = root.join(format!(
            "models/manifests/registry.ollama.ai/library/{}",
            self.model
        ));
        fs::create_dir_all(&manifest_dir)?;
        fs::create_dir_all(root.join("models/blobs"))?;

        let config_bytes = b"{\"architecture\":\"transformer\"}";
        let model_bytes = b"...weights bytes...";
        let license_bytes = b"Apache-2.0";

        let config_digest = write_blob(root, config_bytes)?;
        // For the FAIL case we want declared digest != actual content's sha256.
        // We write *different* bytes than what the manifest will reference.
        let declared_model_digest = sha256_digest(model_bytes);
        let actual_model_bytes: &[u8] = if self.tamper_blob {
            b"...tampered bytes..."
        } else {
            model_bytes
        };
        write_blob_exact(root, &declared_model_digest, actual_model_bytes)?;

        let mut layers = vec![format!(
            r#"{{"digest":"{declared_model_digest}","mediaType":"application/vnd.ollama.image.model"}}"#
        )];
        if self.has_license {
            let license_digest = write_blob(root, license_bytes)?;
            layers.push(format!(
                r#"{{"digest":"{license_digest}","mediaType":"application/vnd.ollama.image.license"}}"#
            ));
        }
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{config_digest}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{}]}}"#,
            layers.join(",")
        );
        fs::write(manifest_dir.join(&self.tag), manifest)?;

        Ok(BuiltStore { tempdir })
    }
}

struct BuiltStore {
    tempdir: TempDir,
}

impl BuiltStore {
    fn models_dir(&self) -> PathBuf {
        self.tempdir.path().join("models")
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn write_blob(root: &Path, bytes: &[u8]) -> Result<String, std::io::Error> {
    let digest = sha256_digest(bytes);
    write_blob_exact(root, &digest, bytes)?;
    Ok(digest)
}

fn write_blob_exact(root: &Path, digest: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
    let path = root.join("models/blobs").join(digest.replace(':', "-"));
    fs::write(path, bytes)
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the crate's Cargo.toml directory.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("crate is nested under <root>/crates/<crate>")
}
