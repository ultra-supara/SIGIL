//! The exercised CLI paths. Each runs the real `sigil` binary under strace and asserts that the
//! contracts hold for that run, and that the run really read its inspected input (so a broken
//! fixture cannot pass vacuously). Only these paths are checked; see ADR-002.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::contracts::{assert_clean, check, report, Contract, Policy};
use crate::fixtures;
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
        network: None,
    }
}

/// The run opened something under `root` (evidence that the inspection path was exercised).
fn assert_read_under(run: &TracedRun, root: &Path) {
    let root = std::fs::canonicalize(root).unwrap();
    let read = run.events.iter().any(|e| {
        matches!(e.name.as_str(), "openat" | "open" | "openat2")
            && fd_path(&e.ret)
                .map(|p| p.starts_with(&root))
                .unwrap_or(false)
    });
    assert!(read, "case `{}` never opened anything under {}; the fixture did not exercise the path.\nstdout: {}\nstderr: {}", run.case, root.display(), run.stdout, run.stderr);
}

fn os(args: &[&dyn AsRef<OsStr>]) -> Vec<std::ffi::OsString> {
    args.iter().map(|a| a.as_ref().to_os_string()).collect()
}

fn refs(v: &[std::ffi::OsString]) -> Vec<&OsStr> {
    v.iter().map(|s| s.as_os_str()).collect()
}

/// A saved session under `target/`, written by an untraced run: the input of the commands that
/// read a session.
fn saved_session(fx: &Fixture) -> PathBuf {
    let models = fixtures::ollama_store(&fx.target);
    let session = fx.target.join("session.json");
    let status = std::process::Command::new(sigil())
        .args(["inspect", "ollama", "--models-dir"])
        .arg(&models)
        .arg("--out")
        .arg(&session)
        .status()
        .unwrap();
    assert!(status.success());
    session
}

#[test]
fn static_inspection_to_stdout() {
    if !require_tracer("static_inspection_to_stdout") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let args = os(&[&"inspect", &"ollama", &"--models-dir", &models]);
    let r = run("inspect-static", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stdout.contains("sigil-session/1"), "{}", r.stdout);
    assert_read_under(&r, &models);
    // Static mode: no /proc entry beyond SIGIL's own runtime.
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn static_markdown_writes_only_its_out() {
    if !require_tracer("static_markdown_writes_only_its_out") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let md = fx.out.join("nested/report.md");
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--models-dir",
        &models,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    let r = run("inspect-static-md-out", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

#[test]
fn static_inspection_of_a_malformed_manifest() {
    if !require_tracer("static_inspection_of_a_malformed_manifest") {
        return;
    }
    let fx = fixture();
    let models = fixtures::malformed_store(&fx.target);
    let args = os(&[&"inspect", &"ollama", &"--models-dir", &models]);
    let r = run("inspect-malformed-manifest", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &models);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn observe_mode_reads_only_allowlisted_proc() {
    if !require_tracer("observe_mode_reads_only_allowlisted_proc") {
        return;
    }
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let session = fx.out.join("session.json");
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--mode",
        &"observe",
        &"--models-dir",
        &models,
        &"--out",
        &session,
    ]);
    let r = run("inspect-observe", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(session.is_file());
    let proc_reads = r
        .events
        .iter()
        .filter(|e| {
            e.raw.contains("/proc")
                || e.args.iter().any(|a| {
                    crate::trace::str_arg(a)
                        .map(|p| p.starts_with("/proc"))
                        .unwrap_or(false)
                })
        })
        .count();
    assert!(
        proc_reads > 0,
        "observe mode did not touch /proc; the observe allowlist was not exercised"
    );
    assert_clean(&r, &policy(&fx, &[&session], &["runtime", "observe"]));
    // The same trace under the static scope must fail C-6: the observe entries do real work.
    let v = check(&r, &policy(&fx, &[&session], &["runtime"]));
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        assert!(
            v.iter()
                .any(|x| x.contract == Contract::C6ProcScope && x.detail.contains(path)),
            "{path} was not flagged under the static scope:\n{}",
            report(&r, &v)
        );
    }
}

#[test]
fn session_render_writes_only_its_out() {
    if !require_tracer("session_render_writes_only_its_out") {
        return;
    }
    let fx = fixture();
    let session = saved_session(&fx);
    let md = fx.out.join("render/session.md");
    let args = os(&[&"session", &"render", &session, &"--out", &md]);
    let r = run("session-render", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(md.is_file());
    assert_read_under(&r, &session);
    assert_clean(&r, &policy(&fx, &[&md], &["runtime"]));
}

#[test]
fn explain_the_verdict() {
    if !require_tracer("explain_the_verdict") {
        return;
    }
    let fx = fixture();
    let session = saved_session(&fx);
    let args = os(&[&"explain", &session, &"--verdict"]);
    let r = run("explain-verdict", &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert_read_under(&r, &session);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

#[test]
fn rules_reads_nothing() {
    if !require_tracer("rules_reads_nothing") {
        return;
    }
    let fx = fixture();
    let r = run("rules", &fx, &[OsStr::new("rules")]);
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stdout.contains("exposure.bind_public"), "{}", r.stdout);
    assert_clean(&r, &policy(&fx, &[], &["runtime"]));
}

// --- the active API probe (ADR-002 active C-4) ------------------------------------------------

/// A server in this test process (not traced) that answers one `/api/version` request.
fn api_server() -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut request = vec![];
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => break,
            }
        }
        let body = "{\"version\":\"0.12.3\"}";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
    });
    addr
}

/// Runs `inspect ollama --active api-probe --api-addr <dest>` under strace and checks it with the
/// probe's destination allowed. Without it, the same trace must break C-4: the case really
/// exercised the network.
fn probe_case(case: &str, dest: std::net::SocketAddr, expect: &str) {
    let fx = fixture();
    let models = fixtures::ollama_store(&fx.target);
    let addr = dest.to_string();
    let args = os(&[
        &"inspect",
        &"ollama",
        &"--models-dir",
        &models,
        &"--active",
        &"api-probe",
        &"--api-addr",
        &addr,
    ]);
    let r = run(case, &fx, &refs(&args));
    assert!(r.status.unwrap().success(), "{}", r.stderr);
    assert!(r.stderr.contains(expect), "{}", r.stderr);
    assert_read_under(&r, &models);
    let allowed = Policy {
        network: Some(dest),
        ..policy(&fx, &[], &["runtime"])
    };
    assert_clean(&r, &allowed);
    let v = check(&r, &policy(&fx, &[], &["runtime"]));
    assert!(
        v.iter()
            .any(|x| x.contract == Contract::C4NoNetwork && x.syscall == "connect"),
        "the probe's connect is missing from the trace:\n{}",
        report(&r, &v)
    );
}

#[test]
fn active_api_probe_connects_only_to_its_destination() {
    if !require_tracer("active_api_probe_connects_only_to_its_destination") {
        return;
    }
    probe_case(
        "inspect-active-api-probe",
        api_server(),
        "answered (HTTP 200), version 0.12.3",
    );
}

#[test]
fn active_api_probe_refused() {
    if !require_tracer("active_api_probe_refused") {
        return;
    }
    let dest = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    probe_case("inspect-active-api-probe-refused", dest, "→ refused");
}
