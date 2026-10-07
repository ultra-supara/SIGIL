//! The exercised CLI paths. Each runs the real `sigil` binary under strace and asserts that the
//! contracts hold for that run, and that the run really read its inspected input (so a broken
//! fixture cannot pass vacuously). Only these paths are checked; see ADR-002.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::contracts::{assert_clean, check, report, Contract, Policy};
use crate::fixtures::{self, require};
use crate::trace::{fd_path, require_tracer, run_traced, TracedRun};

fn sigil() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sigil"))
}

/// `target/` is the inspected root (read only); `out/` receives the outputs a test names.
struct Fixture {
    tmp: TempDir,
    target: PathBuf,
    out: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join("target");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    Fixture { tmp, target, out }
}

fn run(case: &str, fx: &Fixture, args: &[&OsStr]) -> TracedRun {
    run_traced(case, &sigil(), args, fx.tmp.path(), &[])
}

fn policy(fx: &Fixture, outputs: &[&Path], scopes: &[&'static str]) -> Policy {
    Policy {
        binary: sigil(),
        targets: vec![fx.target.clone()],
        allowed_writes: outputs.iter().map(|p| p.to_path_buf()).collect(),
        proc_scopes: scopes.to_vec(),
        cwd: fx.tmp.path().to_path_buf(),
    }
}

/// The run opened something under `root` (evidence that the inspection path was exercised).
fn assert_read_under(run: &TracedRun, root: &Path) {
    let root = std::fs::canonicalize(root).unwrap();
    let read = run
        .events
        .iter()
        .any(|e| matches!(e.name.as_str(), "openat" | "open" | "openat2") && fd_path(&e.ret).map(|p| p.starts_with(&root)).unwrap_or(false));
    assert!(read, "case `{}` never opened anything under {}; the fixture did not exercise the path.\nstdout: {}\nstderr: {}", run.case, root.display(), run.stdout, run.stderr);
}

fn os(args: &[&dyn AsRef<OsStr>]) -> Vec<std::ffi::OsString> {
    args.iter().map(|a| a.as_ref().to_os_string()).collect()
}

fn refs(v: &[std::ffi::OsString]) -> Vec<&OsStr> {
    v.iter().map(|s| s.as_os_str()).collect()
}

fn policy_file() -> PathBuf {
    fixtures::workspace_root().join("examples/policies/numeric_kernel.yml")
}

#[test]
fn static_assess_on_a_compiled_object() {
    if !require_tracer("static_assess_on_a_compiled_object") {
        return;
    }
    let fx = fixture();
    let Some(obj) = require("static_assess_on_a_compiled_object", fixtures::kernel_object(&fx.target)) else { return };
    let args = os(&[&"assess", &obj, &"--entry", &"kernel", &"--policy", &policy_file()]);
    let r = run("assess-object", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &fx.target);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn static_assess_on_malformed_inputs() {
    if !require_tracer("static_assess_on_malformed_inputs") {
        return;
    }
    let fx = fixture();
    let Some(obj) = require("static_assess_on_malformed_inputs", fixtures::kernel_object(&fx.out)) else { return };
    let (garbage, truncated) = fixtures::malformed_inputs(&fx.target, &obj);
    for (case, input) in [("assess-garbage", garbage), ("assess-truncated-elf", truncated)] {
        let args = os(&[&"assess", &input, &"--entry", &"kernel", &"--policy", &policy_file()]);
        let r = run(case, &fx, &refs(&args));
        assert!(!r.status.unwrap().success(), "malformed input should be rejected: {}", r.stdout);
        assert_read_under(&r, &fx.target);
        assert_clean(&r, &policy(&fx, &[], &["runtime"]));
    }
}

#[test]
fn static_assess_writes_only_the_named_outputs() {
    if !require_tracer("static_assess_writes_only_the_named_outputs") {
        return;
    }
    let fx = fixture();
    let Some(obj) = require("static_assess_writes_only_the_named_outputs", fixtures::kernel_object(&fx.target)) else { return };
    let (report_md, evidence) = (fx.out.join("report.md"), fx.out.join("evidence.json"));
    let args = os(&[&"assess", &obj, &"--entry", &"kernel", &"--policy", &policy_file(), &"--out", &report_md, &"--emit-evidence", &evidence]);
    let r = run("assess-with-outputs", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(report_md.is_file() && evidence.is_file());
    assert_read_under(&r, &fx.target);
    assert_clean(&r, &policy(&fx, &[&report_md, &evidence], &["runtime"]));
}

#[test]
fn static_lift_writes_only_the_named_outputs() {
    if !require_tracer("static_lift_writes_only_the_named_outputs") {
        return;
    }
    let fx = fixture();
    let Some(obj) = require("static_lift_writes_only_the_named_outputs", fixtures::kernel_object(&fx.target)) else { return };
    let (ir, safeisa) = (fx.out.join("kernel.ir"), fx.out.join("kernel.safeisa"));
    let args = os(&[&"lift", &obj, &"--entry", &"kernel", &"--emit-ir", &ir, &"--emit-safeisa", &safeisa]);
    let r = run("lift-with-outputs", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &fx.target);
    assert_clean(&r, &policy(&fx, &[&ir, &safeisa], &["runtime"]));
}

#[test]
fn ollama_store_inspection_without_probe_or_runtime() {
    if !require_tracer("ollama_store_inspection_without_probe_or_runtime") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let bom = fx.out.join("aibom.json");
    let args = os(&[&"runtime", &"inspect", &"ollama", &"--models-dir", &models, &"--no-probe-api", &"--no-inspect-runtime", &"--out", &bom]);
    let r = run("ollama-static", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(bom.is_file());
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[&bom], &["runtime"]));
}

#[test]
fn ollama_runtime_inspection_reads_only_allowlisted_proc() {
    if !require_tracer("ollama_runtime_inspection_reads_only_allowlisted_proc") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let bom = fx.out.join("aibom.json");
    // Probe off, runtime (listener) inspection on: today's observe-like path (PR-3b: --mode observe).
    let args = os(&[&"runtime", &"inspect", &"ollama", &"--models-dir", &models, &"--no-probe-api", &"--out", &bom]);
    let r = run("ollama-observe-current", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    let proc_reads = r.events.iter().filter(|e| e.raw.contains("/proc") || e.args.iter().any(|a| crate::trace::str_arg(a).map(|p| p.starts_with("/proc")).unwrap_or(false))).count();
    assert!(proc_reads > 0, "runtime inspection did not touch /proc; the observe allowlist was not exercised");
    assert_clean(&r, &policy(&fx, &[&bom], &["runtime", "observe"]));
    // The same trace under the static scope must fail C-6: the observe entries do real work.
    let v = check(&r, &policy(&fx, &[&bom], &["runtime"]));
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        assert!(
            v.iter().any(|x| x.contract == Contract::C6ProcScope && x.detail.contains(path)),
            "{path} was not flagged under the static scope:\n{}",
            report(&r, &v)
        );
    }
}

#[test]
fn aibom_generate_markdown() {
    if !require_tracer("aibom_generate_markdown") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let md = fx.out.join("nested/aibom.md");
    let args = os(&[&"aibom", &"generate", &"--runtime", &"ollama", &"--models-dir", &models, &"--no-probe-api", &"--no-inspect-runtime", &"--format", &"md", &"--out", &md]);
    let r = run("aibom-generate-md", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

#[test]
fn ollama_store_with_a_malformed_manifest() {
    if !require_tracer("ollama_store_with_a_malformed_manifest") {
        return;
    }
    let fx = fixture();
    let models = fixtures::malformed_store(&fx.target);
    let args = os(&[&"runtime", &"inspect", &"ollama", &"--models-dir", &models, &"--no-probe-api", &"--no-inspect-runtime"]);
    let r = run("ollama-malformed-manifest", &fx, &refs(&args));
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

/// The legacy API probe (on by default until PR-3b) connects to the configured host. This test
/// exercises it on purpose and asserts that C-4 catches it: a known, documented violation.
#[test]
fn legacy_api_probe_is_detected_as_a_network_violation() {
    if !require_tracer("legacy_api_probe_is_detected_as_a_network_violation") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let args = os(&[&"runtime", &"inspect", &"ollama", &"--models-dir", &models, &"--no-inspect-runtime", &"--host", &"http://127.0.0.1:9"]);
    let r = run("ollama-legacy-probe", &fx, &refs(&args));
    let v = check(&r, &policy(&fx, &[], &["runtime"]));
    for syscall in ["socket", "connect"] {
        assert!(
            v.iter().any(|x| x.contract == Contract::C4NoNetwork && x.syscall == syscall),
            "the legacy probe's {syscall} was not detected as C-4:\n{}",
            report(&r, &v)
        );
    }
    assert!(v.iter().all(|x| x.contract == Contract::C4NoNetwork), "only C-4 was expected:\n{}", report(&r, &v));
}
