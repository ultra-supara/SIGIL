//! The model-store collector on real temporary trees (plan §4.6.7). Adversarial cases: a symlink
//! loop and a FIFO under `manifests/`, a manifest over the limit, a malformed manifest next to a
//! good one, symlinked blobs inside and outside the root, an unreadable blob, malformed digests.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use sigil_engine::collect::fs::{FsBudgets, SafeFs};
use sigil_engine::collect::ollama_store::{collect, StoreFacts, DEFAULT_MANIFEST_LIMIT};
use sigil_model::*;
use tempfile::TempDir;

const MODEL_MEDIA: &str = "application/vnd.ollama.image.model";
const LIB: &str = "registry.ollama.ai/library/m/latest";

fn root() -> RootId {
    RootId::new("models").unwrap()
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Writes a blob under `blobs/` and returns its digest.
fn blob(dir: &Path, bytes: &[u8]) -> String {
    fs::create_dir_all(dir.join("blobs")).unwrap();
    fs::write(
        dir.join("blobs").join(format!("sha256-{}", hex(bytes))),
        bytes,
    )
    .unwrap();
    format!("sha256:{}", hex(bytes))
}

/// Writes `manifests/<path>` with an optional config and `(mediaType, digest)` layers.
fn manifest(dir: &Path, path: &str, config: Option<&str>, layers: &[(&str, &str)]) {
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

fn run_with(dir: &Path, filter: Option<&str>, manifest_limit: u64) -> StoreFacts {
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_root(root(), dir).unwrap();
    collect(&fs, &root(), filter, manifest_limit)
}

fn run(dir: &Path, filter: Option<&str>) -> StoreFacts {
    run_with(dir, filter, DEFAULT_MANIFEST_LIMIT)
}

fn inventory(f: &StoreFacts) -> Vec<(Ref, CoverageState)> {
    f.coverage
        .iter()
        .filter(|c| c.check.as_str() == "model_store.inventory")
        .map(|c| (c.scope.clone(), c.state.clone()))
        .collect()
}

fn complete() -> Vec<(Ref, CoverageState)> {
    vec![(Ref::Root(root()), CoverageState::Complete)]
}

fn placed<'a>(f: &'a StoreFacts, id: &InstanceId) -> &'a FileInstance {
    f.instances.iter().find(|i| i.id == *id).unwrap()
}

fn inst(rel: &str) -> InstanceId {
    InstanceId::new(format!("inst:models/{rel}")).unwrap()
}

fn privileged(dir: &Path) -> bool {
    let probe = dir.join(".probe");
    fs::write(&probe, b"x").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read(&probe).is_ok();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&probe).unwrap();
    readable
}

#[test]
fn one_model_is_inventoried_with_its_blobs_read() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let config = blob(d, b"{}");
    let weights = blob(d, b"hello");
    manifest(d, LIB, Some(&config), &[(MODEL_MEDIA, &weights)]);

    let f = run(d, None);
    assert_eq!(f.models.len(), 1);
    let m = &f.models[0];
    assert_eq!(
        m.id.as_str(),
        "model:models/registry.ollama.ai/library/m/latest"
    );
    assert_eq!(m.name.as_str(), Some("m:latest"));
    let manifest_inst = inst(&format!("manifests/{LIB}"));
    assert_eq!(m.manifest, manifest_inst);
    assert_eq!(
        m.layers.iter().map(|l| l.role).collect::<Vec<_>>(),
        [LayerRole::Config, LayerRole::Layer]
    );
    for (layer, digest) in m.layers.iter().zip([&config, &weights]) {
        assert_eq!(layer.digest.as_str(), Some(digest.as_str()));
        let blob = placed(&f, layer.blob.as_ref().unwrap());
        assert_eq!(
            blob.content,
            InstanceContent::Read {
                artifact: ArtifactId::new(digest.clone()).unwrap()
            }
        );
        assert_eq!(
            blob.discovered_by,
            [DiscoverySource::Manifest {
                manifest: manifest_inst.clone()
            }]
        );
    }
    let weights_art = f
        .artifacts
        .iter()
        .find(|a| a.id.as_str() == weights)
        .unwrap();
    assert_eq!(weights_art.size, 5);
    assert_eq!(m.license, None);
    assert!(f.shallow.is_empty() && f.unparseable.is_empty());
    assert_eq!(inventory(&f), complete());
}

#[test]
fn models_that_share_a_blob_share_its_instance() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"shared weights");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    manifest(
        d,
        "registry.ollama.ai/library/n/latest",
        None,
        &[(MODEL_MEDIA, &weights)],
    );

    let f = run(d, None);
    assert_eq!(f.models.len(), 2);
    let blob_inst = inst(&format!("blobs/sha256-{}", hex(b"shared weights")));
    assert_eq!(f.instances.iter().filter(|i| i.id == blob_inst).count(), 1);
    assert_eq!(
        f.artifacts
            .iter()
            .filter(|a| a.id.as_str() == weights)
            .count(),
        1
    );
    assert_eq!(placed(&f, &blob_inst).discovered_by.len(), 2);
}

#[test]
fn a_missing_manifests_directory_is_unavailable() {
    let dir = TempDir::new().unwrap();
    let f = run(dir.path(), None);
    assert!(f.models.is_empty() && f.instances.is_empty());
    assert_eq!(
        inventory(&f),
        [(
            Ref::Root(root()),
            CoverageState::Unavailable {
                why: Unavailability::NotFound
            }
        )]
    );
}

#[test]
fn a_symlinked_blob_is_read_inside_the_root_and_not_outside() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let d = dir.path();
    fs::create_dir_all(d.join("blobs")).unwrap();
    fs::create_dir_all(d.join("store")).unwrap();
    fs::write(d.join("store/w"), b"inside").unwrap();
    symlink(
        "../store/w",
        d.join(format!("blobs/sha256-{}", hex(b"inside"))),
    )
    .unwrap();
    fs::write(outside.path().join("w"), b"outside").unwrap();
    symlink(
        outside.path().join("w"),
        d.join(format!("blobs/sha256-{}", hex(b"outside"))),
    )
    .unwrap();
    let inside = format!("sha256:{}", hex(b"inside"));
    let away = format!("sha256:{}", hex(b"outside"));
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &inside), (MODEL_MEDIA, &away)],
    );

    let f = run(d, None);
    let layers = &f.models[0].layers;
    let read = placed(&f, layers[0].blob.as_ref().unwrap());
    assert!(matches!(read.content, InstanceContent::Read { .. }));
    assert_eq!(read.link_chain.len(), 1);
    // I-07: a blob outside the store is recorded and never read.
    let away = placed(&f, layers[1].blob.as_ref().unwrap());
    assert_eq!(
        away.content,
        InstanceContent::NotRead {
            why: NotReadReason::OutsideScanRoots
        }
    );
}

#[test]
fn a_symlink_loop_and_a_fifo_under_manifests_do_not_stop_the_run() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    symlink(".", d.join("manifests/registry.ollama.ai/loop")).unwrap();
    fs::create_dir_all(d.join("manifests/registry.ollama.ai/library/pipe")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        d.join("manifests/registry.ollama.ai/library/pipe/latest"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();

    let f = run(d, None);
    assert_eq!(f.models.len(), 1);
    assert_eq!(inventory(&f), complete());
}

#[test]
fn a_manifest_over_the_limit_is_not_read() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    let size = fs::metadata(d.join("manifests").join(LIB)).unwrap().len();

    let f = run_with(d, None, 64);
    assert!(f.models.is_empty());
    let manifest_inst = inst(&format!("manifests/{LIB}"));
    assert_eq!(
        placed(&f, &manifest_inst).content,
        InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded
        }
    );
    assert_eq!(
        inventory(&f),
        [
            (
                Ref::Instance(manifest_inst),
                CoverageState::BudgetExceeded {
                    budget: "manifest_bytes".to_string(),
                    used: size,
                    limit: 64
                }
            ),
            (Ref::Root(root()), CoverageState::Complete),
        ]
    );
}

#[test]
fn an_unparseable_manifest_stays_with_itself() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    let broken = "registry.ollama.ai/library/broken/latest";
    fs::create_dir_all(d.join("manifests/registry.ollama.ai/library/broken")).unwrap();
    fs::write(d.join("manifests").join(broken), b"not json").unwrap();

    let f = run(d, None);
    assert_eq!(
        f.models.len(),
        1,
        "the good manifest is still a model (I-04)"
    );
    let broken_inst = inst(&format!("manifests/{broken}"));
    assert_eq!(f.unparseable.len(), 1);
    assert_eq!(f.unparseable[0].0, broken_inst);
    let states = inventory(&f);
    assert!(states.contains(&(Ref::Root(root()), CoverageState::Complete)));
    assert!(states.iter().any(
        |(scope, state)| *scope == Ref::Instance(broken_inst.clone())
            && matches!(state, CoverageState::Error { .. })
    ));
}

#[test]
fn an_unreadable_blob_is_recorded_and_not_read() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    if privileged(d) {
        eprintln!("SKIPPED: an unreadable blob needs an unprivileged user");
        return;
    }
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    let path = d.join(format!("blobs/sha256-{}", hex(b"w")));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let f = run(d, None);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        placed(&f, f.models[0].layers[0].blob.as_ref().unwrap()).content,
        InstanceContent::NotRead {
            why: NotReadReason::PermissionDenied
        }
    );
}

#[test]
fn the_filter_applies_before_anything_is_read() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    manifest(d, "registry.ollama.ai/library/other/latest", None, &[]);
    fs::create_dir_all(d.join("manifests/orphaned")).unwrap();
    fs::write(d.join("manifests/orphaned/loose"), b"{}").unwrap();

    let f = run(d, Some("m:latest"));
    assert!(f.matched_filter);
    assert_eq!(f.models.len(), 1);
    let read: Vec<&str> = f.instances.iter().map(|i| i.id.as_str()).collect();
    assert!(
        !read
            .iter()
            .any(|id| id.contains("/other/") || id.contains("/orphaned/")),
        "{read:?}"
    );
    // I-05: a shallow path cannot match a filter, so it is not reported with one.
    assert!(f.shallow.is_empty());

    let f = run(d, Some("absent:latest"));
    assert!(!f.matched_filter);
    assert!(f.models.is_empty() && f.instances.is_empty());

    let f = run(d, None);
    assert!(!f.matched_filter);
    assert_eq!(f.models.len(), 2);
    assert_eq!(f.shallow, [inst("manifests/orphaned/loose")]);
}

#[test]
fn the_license_text_is_read_from_the_license_layer() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
    );
    let f = run(d, None);
    assert_eq!(
        f.models[0].license,
        Some(LicenseText {
            artifact: ArtifactId::new(license).unwrap(),
            spdx: Some("MIT".to_string()),
            excerpt: UntrustedText::new("MIT"),
        })
    );
}

#[test]
fn malformed_and_missing_digests_have_no_blob() {
    let dir = TempDir::new().unwrap();
    let d = dir.path();
    let upper = format!("sha256:{}", hex(b"w").to_uppercase());
    blob(d, b"w");
    // The uppercase file exists too: it must still not be looked up (I-06).
    fs::write(
        d.join(format!("blobs/sha256-{}", hex(b"w").to_uppercase())),
        b"w",
    )
    .unwrap();
    let absent = format!("sha256:{}", hex(b"absent"));
    manifest(
        d,
        LIB,
        None,
        &[
            (MODEL_MEDIA, &upper),
            (MODEL_MEDIA, "sha256:foo/../../secret"),
            (MODEL_MEDIA, &absent),
        ],
    );
    let f = run(d, None);
    assert!(f.models[0].layers.iter().all(|l| l.blob.is_none()));
    assert!(f
        .instances
        .iter()
        .all(|i| i.id.as_str().starts_with("inst:models/manifests/")));
}

#[test]
fn a_manifest_link_out_of_the_root_makes_the_inventory_partial() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let d = dir.path();
    let weights = blob(d, b"w");
    manifest(d, LIB, None, &[(MODEL_MEDIA, &weights)]);
    fs::write(outside.path().join("m"), b"{}").unwrap();
    symlink(
        outside.path().join("m"),
        d.join("manifests/registry.ollama.ai/library/m/away"),
    )
    .unwrap();
    let f = run(d, None);
    assert_eq!(f.models.len(), 1);
    assert_eq!(
        inventory(&f),
        [(
            Ref::Root(root()),
            CoverageState::Partial {
                missing: vec!["manifests/registry.ollama.ai/library/m/away".to_string()]
            }
        )]
    );
}
