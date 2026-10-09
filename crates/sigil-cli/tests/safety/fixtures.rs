//! Fixtures, built by the harness before a traced run starts (their creation is not traced).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    Err(
        "no C compiler (cc, clang or gcc) in PATH; the dlopen control compiles a shared object"
            .into(),
    )
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
pub const CONFIG_DIGEST: &str =
    "sha256:e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0";
pub const MODEL_DIGEST: &str =
    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
pub const LICENSE_DIGEST: &str =
    "sha256:2af71558e438db0b73a20beab92dc278a94e1bbe974c00c1a33e3ab62d53a608";

/// A minimal Ollama model store: one model with a config, a model layer, and a license. Returns
/// `models/`.
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

/// An Ollama installation (`install/`): `bin/ollama` and `lib/ollama/` hold copies of the real
/// shared object `so` (which must never be loaded), a symlink to it, a subdirectory, a dangling
/// link, and a link out of the install into `root/models`. No link is followed. Returns
/// `install/`.
pub fn ollama_install(root: &Path, so: &Path) -> PathBuf {
    let install = root.join("install");
    let lib = install.join("lib/ollama");
    fs::create_dir_all(install.join("bin")).unwrap();
    fs::create_dir_all(lib.join("cuda_v12")).unwrap();
    fs::copy(so, install.join("bin/ollama")).unwrap();
    fs::copy(so, lib.join("libggml-cpu.so")).unwrap();
    fs::copy(so, lib.join("cuda_v12/libggml-cuda.so")).unwrap();
    std::os::unix::fs::symlink("libggml-cpu.so", lib.join("libggml-cpu.so.0")).unwrap();
    std::os::unix::fs::symlink("missing.so", lib.join("libdangling.so")).unwrap();
    std::os::unix::fs::symlink("../../../models", lib.join("models")).unwrap();
    install
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
