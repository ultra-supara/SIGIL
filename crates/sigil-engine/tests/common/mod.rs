//! Helpers shared by the model-store tests: writing blobs and manifests into a temporary store.
#![allow(dead_code)]

pub mod elf;
pub mod proc;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};
use sigil_model::{InstanceId, RootId};

pub const MODEL_MEDIA: &str = "application/vnd.ollama.image.model";
pub const LIB: &str = "registry.ollama.ai/library/m/latest";

pub fn root() -> RootId {
    RootId::new("models").unwrap()
}

pub fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Writes a blob under `blobs/` and returns its digest.
pub fn blob(dir: &Path, bytes: &[u8]) -> String {
    fs::create_dir_all(dir.join("blobs")).unwrap();
    fs::write(
        dir.join("blobs").join(format!("sha256-{}", hex(bytes))),
        bytes,
    )
    .unwrap();
    format!("sha256:{}", hex(bytes))
}

/// Writes `manifests/<path>` with an optional config and `(mediaType, digest)` layers.
pub fn manifest(dir: &Path, path: &str, config: Option<&str>, layers: &[(&str, &str)]) {
    let layers: Vec<serde_json::Value> = layers
        .iter()
        .map(|(m, d)| serde_json::json!({"mediaType": m, "digest": d, "size": 1}))
        .collect();
    let mut doc = serde_json::json!({"schemaVersion": 2, "layers": layers});
    if let Some(c) = config {
        doc["config"] = serde_json::json!({"mediaType": "application/vnd.docker.container.image.v1+json", "digest": c});
    }
    let file = dir.join("manifests").join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, serde_json::to_vec(&doc).unwrap()).unwrap();
}

pub fn inst(rel: &str) -> InstanceId {
    InstanceId::new(format!("inst:models/{rel}")).unwrap()
}

pub fn privileged(dir: &Path) -> bool {
    let probe = dir.join(".probe");
    fs::write(&probe, b"x").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read(&probe).is_ok();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&probe).unwrap();
    readable
}
