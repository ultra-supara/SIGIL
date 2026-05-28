use assert_cmd::Command;
use predicates::str::contains;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn which(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|dir| PathBuf::from(dir).join(binary))
        .find(|path| path.is_file())
}

fn compile_fixture(source: &str, output: &std::path::Path) -> bool {
    let Some(clang) = which("clang") else {
        return false;
    };
    let status = StdCommand::new(clang)
        .current_dir(workspace_root())
        .args(["-target", x86_64_target(), "-O0", "-c", source, "-o"])
        .arg(output)
        .status()
        .expect("clang should run");
    status.success()
}

fn x86_64_target() -> &'static str {
    if cfg!(target_os = "macos") {
        "x86_64-apple-macos"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

#[test]
fn cli_help_lists_assess() {
    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("assess"));
}

#[test]
fn cli_external_call_drives_fail_verdict() {
    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "assess",
        "examples/binaries/clean_kernel.o",
        "--entry",
        "kernel",
        "--policy",
        "examples/policies/numeric_kernel.yml",
        "--external-call",
        "connect",
    ])
    .current_dir(workspace_root())
    .assert()
    .success()
    .stdout(contains("SIGIL Verdict: FAIL"));
}

#[test]
fn cli_lift_writes_ir_and_safeisa() {
    let tmp = TempDir::new().unwrap();
    let object = tmp.path().join("clean.o");
    if !compile_fixture("examples/src/clean_kernel.c", &object) {
        return;
    }
    let ir = tmp.path().join("out.ir");
    let safeisa = tmp.path().join("out.safeisa");

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "lift",
        object.to_str().unwrap(),
        "--entry",
        "kernel",
        "--emit-ir",
        ir.to_str().unwrap(),
        "--emit-safeisa",
        safeisa.to_str().unwrap(),
    ])
    .current_dir(workspace_root())
    .assert()
    .success();

    assert!(std::fs::read_to_string(ir)
        .unwrap()
        .contains("func kernel:"));
    assert!(std::fs::read_to_string(safeisa)
        .unwrap()
        .contains("FUNC kernel"));
}

#[test]
fn cli_binary_assess_detects_suspicious_external_call() {
    let tmp = TempDir::new().unwrap();
    let object = tmp.path().join("suspicious.o");
    if !compile_fixture("examples/src/suspicious_kernel.c", &object) {
        return;
    }

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "assess",
        object.to_str().unwrap(),
        "--entry",
        "kernel",
        "--policy",
        "examples/policies/numeric_kernel.yml",
    ])
    .current_dir(workspace_root())
    .assert()
    .success()
    .stdout(contains("SIGIL Verdict: FAIL"));
}
