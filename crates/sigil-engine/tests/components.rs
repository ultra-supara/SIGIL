//! The component database against the embedded reference manifests (PR-4c-1 spec §3): every
//! regular member of every release is named by exactly one entry, the v0.30.6 bundle maps as the
//! spec lists, and a symlink member names the component of the file it leads to.

use sigil_engine::analyze::components::components;
use sigil_engine::reference::{official, RefMember};

/// The last component of a member path.
fn name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[test]
fn every_regular_member_of_every_release_is_one_component() {
    let db = components().unwrap();
    let set = official().unwrap();
    assert_eq!(set.releases.len(), 3);
    for release in &set.releases {
        let files: Vec<&String> = release
            .members
            .iter()
            .filter(|(_, m)| matches!(m, RefMember::File { .. }))
            .map(|(path, _)| path)
            .collect();
        assert_eq!(files.len(), 34, "{}", release.tag);
        for path in files {
            let found = db.matching(name(path).as_bytes());
            assert_eq!(found.len(), 1, "{} {path}: {found:?}", release.tag);
        }
    }
}

#[test]
fn the_v0_30_6_bundle_maps_as_the_spec_lists() {
    const EXPECTED: [(&str, &str); 34] = [
        ("bin/ollama", "ollama"),
        ("lib/ollama/cuda_v12/libcublas.so.12.8.5.5", "cuda/cublas"),
        (
            "lib/ollama/cuda_v12/libcublasLt.so.12.8.5.5",
            "cuda/cublasLt",
        ),
        ("lib/ollama/cuda_v12/libcudart.so.12.8.90", "cuda-runtime"),
        ("lib/ollama/cuda_v12/libggml-cuda.so", "ggml-backend/cuda"),
        ("lib/ollama/cuda_v13/libcublas.so.13.1.1.3", "cuda/cublas"),
        (
            "lib/ollama/cuda_v13/libcublasLt.so.13.1.1.3",
            "cuda/cublasLt",
        ),
        ("lib/ollama/cuda_v13/libcudart.so.13.0.96", "cuda-runtime"),
        ("lib/ollama/cuda_v13/libggml-cuda.so", "ggml-backend/cuda"),
        ("lib/ollama/libggml-base.so.0.13.1", "ggml-base"),
        ("lib/ollama/libggml-cpu-alderlake.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-cannonlake.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-cascadelake.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-cooperlake.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-haswell.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-icelake.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-ivybridge.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-piledriver.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-sandybridge.so", "ggml-backend/cpu"),
        (
            "lib/ollama/libggml-cpu-sapphirerapids.so",
            "ggml-backend/cpu",
        ),
        ("lib/ollama/libggml-cpu-skylakex.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-sse42.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-x64.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml-cpu-zen4.so", "ggml-backend/cpu"),
        ("lib/ollama/libggml.so.0.13.1", "ggml"),
        ("lib/ollama/libgomp.so.1.0.0", "gcc/libgomp"),
        ("lib/ollama/libllama-common.so.0.0.1", "llama.cpp/common"),
        ("lib/ollama/libllama-quantize-impl.so", "llama.cpp/quantize"),
        ("lib/ollama/libllama-server-impl.so", "llama.cpp/server"),
        ("lib/ollama/libllama.so.0.0.1", "llama.cpp"),
        ("lib/ollama/libmtmd.so.0.0.1", "llama.cpp/mtmd"),
        ("lib/ollama/llama-quantize", "llama.cpp/quantize"),
        ("lib/ollama/llama-server", "llama.cpp/server"),
        ("lib/ollama/vulkan/libggml-vulkan.so", "ggml-backend/vulkan"),
    ];
    let db = components().unwrap();
    let set = official().unwrap();
    let release = set.releases.iter().find(|r| r.tag == "v0.30.6").unwrap();
    let got: Vec<(&str, &str)> = release
        .members
        .iter()
        .filter(|(_, m)| matches!(m, RefMember::File { .. }))
        .map(|(path, _)| {
            let key = db.component(name(path).as_bytes());
            (path.as_str(), key.map_or("-", |k| k.as_str()))
        })
        .collect();
    assert_eq!(got, EXPECTED);
}

/// `libggml-base.so` → `libggml-base.so.0` → `libggml-base.so.0.13.1`: each name of the chain
/// names the file's component.
#[test]
fn a_symlink_member_names_the_component_of_its_file() {
    let db = components().unwrap();
    for release in &official().unwrap().releases {
        let mut links = 0;
        for (path, member) in &release.members {
            let RefMember::Symlink { .. } = member else {
                continue;
            };
            links += 1;
            let mut at = path.clone();
            for _ in 0..8 {
                let Some(RefMember::Symlink { target }) = release.members.get(&at) else {
                    break;
                };
                let (dir, _) = at.rsplit_once('/').unwrap();
                at = format!("{dir}/{target}");
            }
            assert!(
                matches!(release.members.get(&at), Some(RefMember::File { .. })),
                "{} {path} leads to {at}",
                release.tag
            );
            assert_eq!(
                db.component(name(path).as_bytes()),
                db.component(name(&at).as_bytes()),
                "{} {path} -> {at}",
                release.tag
            );
            assert!(db.component(name(path).as_bytes()).is_some(), "{path}");
        }
        assert_eq!(links, 17, "{}", release.tag);
    }
}

/// PR-4c-2a: the components whose files are never scanned (`scan = false`) are the model's
/// `NAME_AND_HASH_ONLY`, for which `Session::validate` admits `binary.identity` `OutOfScope`.
#[test]
fn the_unscanned_components_are_the_model_s_name_and_hash_only() {
    let db = components().unwrap();
    let unscanned: Vec<&str> = db.unscanned().iter().map(|k| k.as_str()).collect();
    assert_eq!(unscanned, sigil_model::NAME_AND_HASH_ONLY);
}
