//! Fixtures, built by the harness before a traced run starts (their creation is not traced).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn compiler() -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for name in ["cc", "clang", "gcc"] {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err("no C compiler (cc, clang or gcc) in PATH; fixtures are compiled from examples/src".into())
}

fn compile(args: &[&str], source: &Path, output: &Path) -> Result<PathBuf, String> {
    let cc = compiler()?;
    let out = Command::new(&cc)
        .args(args)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .map_err(|e| format!("{} failed to start: {e}", cc.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} failed: {}",
            cc.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(output.to_path_buf())
}

/// `examples/src/clean_kernel.c` compiled to an x86-64 relocatable object in `dir`.
pub fn kernel_object(dir: &Path) -> Result<PathBuf, String> {
    compile(
        &["-O0", "-c"],
        &workspace_root().join("examples/src/clean_kernel.c"),
        &dir.join("kernel.o"),
    )
}

/// A small shared object for the dlopen negative control.
pub fn shared_object(dir: &Path) -> Result<PathBuf, String> {
    let src = dir.join("plugin.c");
    fs::write(&src, "int ggml_backend_score(void) { return 0; }\n").map_err(|e| e.to_string())?;
    compile(
        &["-shared", "-fPIC"],
        &src,
        &dir.join("libggml-cpu-control.so"),
    )
}

/// Malformed inputs: random bytes and a truncated ELF header.
pub fn malformed_inputs(dir: &Path, object: &Path) -> (PathBuf, PathBuf) {
    let garbage = dir.join("garbage.o");
    fs::write(
        &garbage,
        (0u32..4096)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let truncated = dir.join("truncated.o");
    let bytes = fs::read(object).unwrap();
    fs::write(&truncated, &bytes[..bytes.len().min(80)]).unwrap();
    (garbage, truncated)
}

pub const CONFIG_DIGEST: &str =
    "sha256:e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0";
pub const MODEL_DIGEST: &str =
    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
pub const LICENSE_DIGEST: &str =
    "sha256:2af71558e438db0b73a20beab92dc278a94e1bbe974c00c1a33e3ab62d53a608";

/// A minimal Ollama model store (same layout as sigil-core's `tests/common`). Returns `models/`.
pub fn ollama_store(root: &Path) -> PathBuf {
    let models = root.join("models");
    let manifest_dir = models.join("manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(models.join("blobs")).unwrap();
    for (digest, content) in [
        (CONFIG_DIGEST, &b"cfg"[..]),
        (MODEL_DIGEST, b"hello"),
        (LICENSE_DIGEST, b"Apache-2.0"),
    ] {
        fs::write(models.join("blobs").join(digest.replace(':', "-")), content).unwrap();
    }
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{CONFIG_DIGEST}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{{"digest":"{MODEL_DIGEST}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{LICENSE_DIGEST}","mediaType":"application/vnd.ollama.image.license"}}]}}"#
        ),
    )
    .unwrap();
    models
}

/// A store whose only manifest is not JSON (an untrusted, malformed input).
pub fn malformed_store(root: &Path) -> PathBuf {
    let models = root.join("models");
    let manifest_dir = models.join("manifests/registry.ollama.ai/library/broken");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(models.join("blobs")).unwrap();
    fs::write(
        manifest_dir.join("latest"),
        "{\"schemaVersion\":2,\"layers\":[{\"digest\":",
    )
    .unwrap();
    models
}

/// Like `trace::require_tracer`: `Some` when the fixture is available; otherwise skip with a
/// printed reason, or fail when `SIGIL_SAFETY_REQUIRED=1`.
pub fn require<T>(test: &str, r: Result<T, String>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(reason) => {
            if std::env::var("SIGIL_SAFETY_REQUIRED").as_deref() == Ok("1") {
                panic!("SIGIL_SAFETY_REQUIRED=1, but a fixture is unavailable: {reason}");
            }
            eprintln!(
                "SKIPPED {test}: {reason} (set SIGIL_SAFETY_REQUIRED=1 to make this a failure)"
            );
            None
        }
    }
}
