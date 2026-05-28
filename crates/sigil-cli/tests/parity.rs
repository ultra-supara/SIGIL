use assert_cmd::Command;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn legacy_python_path() -> PathBuf {
    workspace_root().join("legacy/python")
}

fn python_available() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|binary| {
        StdCommand::new(binary)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}

fn run_python(args: &[&str]) -> Option<String> {
    let python = python_available()?;
    assert!(
        legacy_python_path().join("sigil/cli.py").is_file(),
        "legacy Python CLI must exist before parity can be checked"
    );
    let output = StdCommand::new(python)
        .current_dir(workspace_root())
        .env("PYTHONPATH", legacy_python_path())
        .args(["-m", "sigil.cli"])
        .args(args)
        .output()
        .expect("python should run");
    assert!(
        output.status.success(),
        "python failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).unwrap())
}

fn run_rust(args: &[&str]) -> String {
    let output = Command::cargo_bin("sigil")
        .unwrap()
        .current_dir(workspace_root())
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rust failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn which(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|dir| PathBuf::from(dir).join(binary))
        .find(|path| path.is_file())
}

fn compile_fixture(source: &str, output: &Path) -> bool {
    let Some(clang) = which("clang") else {
        return false;
    };
    let status = StdCommand::new(clang)
        .current_dir(workspace_root())
        .args(["-O0", "-c", source, "-o"])
        .arg(output)
        .status()
        .expect("clang should run");
    status.success()
}

fn python_has_binary_deps() -> bool {
    let Some(python) = python_available() else {
        return false;
    };
    StdCommand::new(python)
        .args(["-c", "import capstone, elftools"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn rust_matches_legacy_python_external_call_verdict() {
    let args = [
        "assess",
        "examples/binaries/clean_kernel.o",
        "--entry",
        "kernel",
        "--policy",
        "examples/policies/numeric_kernel.yml",
        "--external-call",
        "connect",
    ];
    let Some(python_stdout) = run_python(&args) else {
        return;
    };
    let rust_stdout = run_rust(&args);
    assert_eq!(rust_stdout, python_stdout);
}

#[test]
fn rust_matches_legacy_python_binary_backed_suspicious_verdict_when_deps_exist() {
    if !python_has_binary_deps() {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let object = tmp.path().join("suspicious.o");
    if !compile_fixture("examples/src/suspicious_kernel.c", &object) {
        return;
    }
    let object = object.to_str().unwrap();
    let args = [
        "assess",
        object,
        "--entry",
        "kernel",
        "--policy",
        "examples/policies/numeric_kernel.yml",
    ];
    let Some(python_stdout) = run_python(&args) else {
        return;
    };
    let rust_stdout = run_rust(&args);
    assert_eq!(rust_stdout, python_stdout);
}
