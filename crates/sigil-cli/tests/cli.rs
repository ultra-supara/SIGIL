//! The v2 command line, end to end (plan §4.8, §4.9): `inspect ollama`, `session render`,
//! `explain` (#21), and `rules`, with their outputs and exit codes.

// Runs the CLI binary (assert_cmd), and serves the API probe on loopback from this process.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use sha2::{Digest, Sha256};
use sigil_model::render::markdown::render_session;
use sigil_model::{Completeness, CoverageState, Mode, ProbeResult, Session, Verdict};
use tempfile::TempDir;

const MODEL_MEDIA: &str = "application/vnd.ollama.image.model";
const LICENSE_MEDIA: &str = "application/vnd.ollama.image.license";
const LIB: &str = "registry.ollama.ai/library/m/latest";
const LICENSE_MISSING: &str =
    "finding:model.license_missing@model:models/registry.ollama.ai/library/m/latest";

fn blob(dir: &Path, bytes: &[u8]) -> String {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    fs::create_dir_all(dir.join("blobs")).unwrap();
    fs::write(dir.join("blobs").join(format!("sha256-{hex}")), bytes).unwrap();
    format!("sha256:{hex}")
}

fn manifest(dir: &Path, path: &str, layers: &[(&str, &str)]) {
    let layers: Vec<serde_json::Value> = layers
        .iter()
        .map(|(m, d)| serde_json::json!({"mediaType": m, "digest": d, "size": 1}))
        .collect();
    let file = dir.join("manifests").join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(
        file,
        serde_json::to_vec(&serde_json::json!({"schemaVersion": 2, "layers": layers})).unwrap(),
    )
    .unwrap();
}

/// A store with one model in `d`; with a license layer, or without one (a WARN).
fn fill_store(d: &Path, licensed: bool) {
    let weights = blob(d, b"weights");
    let license;
    let mut layers = vec![(MODEL_MEDIA, weights.as_str())];
    if licensed {
        license = blob(d, b"MIT");
        layers.push((LICENSE_MEDIA, license.as_str()));
    }
    manifest(d, LIB, &layers);
}

fn store(licensed: bool) -> TempDir {
    let d = TempDir::new().unwrap();
    fill_store(d.path(), licensed);
    d
}

fn sigil() -> Command {
    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.env_remove("OLLAMA_MODELS");
    cmd
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Run {
    let out = sigil().args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn inspect(models: &Path, extra: &[&dyn AsRef<std::ffi::OsStr>]) -> Run {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> =
        vec![&"inspect", &"ollama", &"--models-dir", &models];
    args.extend_from_slice(extra);
    run(&args)
}

fn session_of(r: &Run) -> Session {
    let s: Session = serde_json::from_str(&r.stdout)
        .unwrap_or_else(|e| panic!("stdout is not a session ({e}):\n{}\n{}", r.stdout, r.stderr));
    if let Err(errors) = s.validate() {
        panic!("invalid session: {errors:?}");
    }
    s
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).unwrap();
    path
}

// --- inspect ollama ---------------------------------------------------------------------------

#[test]
fn a_static_pass_writes_the_session_to_stdout_and_a_summary_to_stderr() {
    let d = store(true);
    let r = inspect(d.path(), &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.mode, Mode::Static);
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Pass, Completeness::Complete)
    );
    // Static mode reads nothing under /proc.
    assert_eq!(s.observation.boot_id, "");
    // The document is the canonical JSON.
    assert_eq!(r.stdout, s.to_canonical_json().unwrap());
    for expected in [
        "mode=static",
        "audit=model_store",
        "verdict: PASS",
        "completeness: COMPLETE",
        "note: model blob hashing is unbounded",
    ] {
        assert!(
            r.stderr.contains(expected),
            "{expected:?} missing:\n{}",
            r.stderr
        );
    }
}

#[test]
fn fail_on_compares_the_verdict() {
    let d = store(false);
    let r = inspect(d.path(), &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).outcome.verdict, Verdict::Warn);
    assert!(r.stderr.contains("verdict: WARN"), "{}", r.stderr);
    assert_eq!(inspect(d.path(), &[&"--fail-on", &"warn"]).code, 3);
    assert_eq!(inspect(d.path(), &[&"--fail-on", &"fail"]).code, 0);
}

#[test]
fn fail_on_incomplete_is_separate_and_second() {
    let missing = TempDir::new().unwrap();
    let gone = missing.path().join("nothing-here");
    let r = inspect(&gone, &[]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.outcome.verdict, Verdict::Pass);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    assert!(
        r.stderr.contains("completeness: INCOMPLETE"),
        "{}",
        r.stderr
    );
    assert_eq!(inspect(&gone, &[&"--fail-on-incomplete"]).code, 4);
    assert_eq!(
        inspect(&gone, &[&"--fail-on", &"warn", &"--fail-on-incomplete"]).code,
        4
    );

    // WARN and INCOMPLETE: the verdict's code wins.
    let d = store(false);
    let p = TempDir::new().unwrap();
    let policy = write(
        p.path(),
        "p.toml",
        "schema = \"sigil-policy/1\"\nname = \"strict\"\n[scope]\naudit = [\"model_store\"]\nextra_required = [\"exposure.binds\"]\n",
    );
    let both: [&dyn AsRef<std::ffi::OsStr>; 5] = [
        &"--policy",
        &policy,
        &"--fail-on",
        &"warn",
        &"--fail-on-incomplete",
    ];
    assert_eq!(inspect(d.path(), &both).code, 3);
}

#[test]
fn markdown_goes_to_out_and_creates_its_directories() {
    let d = store(false);
    let o = TempDir::new().unwrap();
    let out = o.path().join("nested/deeper/report.md");
    let r = inspect(d.path(), &[&"--format", &"md", &"--out", &out]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    let md = fs::read_to_string(&out).unwrap();
    assert!(md.starts_with("# SIGIL session\n"), "{md}");
    assert!(md.contains("**Verdict:** WARN"), "{md}");
    assert!(r.stderr.contains("wrote "), "{}", r.stderr);
}

#[test]
fn out_inside_the_models_directory_is_a_usage_error() {
    let d = store(true);
    let out = d.path().join("report.json");
    let r = inspect(d.path(), &[&"--out", &out]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!out.exists());
}

#[test]
fn out_reaching_the_models_directory_through_a_new_directory_and_dot_dot_is_refused() {
    // Review of #75: `fresh` does not exist, so `fresh/..` cannot be resolved before SIGIL
    // creates `fresh`; it then leads back into the store.
    let base = TempDir::new().unwrap();
    let models = base.path().join("models");
    fill_store(&models, true);
    let out = base.path().join("fresh/../models/report.json");
    let r = inspect(&models, &[&"--out", &out]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!models.join("report.json").exists());
    assert!(!base.path().join("fresh").exists(), "nothing is created");
}

#[test]
fn out_through_a_symlink_into_the_models_directory_is_refused() {
    use std::os::unix::fs::symlink;
    let base = TempDir::new().unwrap();
    let models = base.path().join("models");
    fill_store(&models, true);
    // A symlink to the store.
    symlink(&models, base.path().join("link")).unwrap();
    let r = inspect(&models, &[&"--out", &base.path().join("link/report.json")]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!models.join("report.json").exists());
    // A symlink whose target, in the store, does not exist yet.
    symlink(models.join("new.json"), base.path().join("dangling")).unwrap();
    let r = inspect(&models, &[&"--out", &base.path().join("dangling")]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!models.join("new.json").exists());
}

#[test]
fn new_nested_directories_and_dot_dot_outside_the_store_are_allowed() {
    let d = store(true);
    let o = TempDir::new().unwrap();
    let out = o.path().join("a/b/../c/report.json");
    let r = inspect(d.path(), &[&"--out", &out]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(o.path().join("a/c/report.json").is_file());
}

#[test]
fn budgets_use_the_names_the_session_records() {
    let d = store(true);
    let r = inspect(d.path(), &[&"--budget", &"manifest_bytes=8"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["manifest_bytes"], 8);
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));

    for bad in [
        "nope=1",
        "manifest_bytes=x",
        "manifest_bytes",
        "processes_listed=5",
    ] {
        let r = inspect(d.path(), &[&"--budget", &bad]);
        assert_eq!(r.code, 2, "{bad}: {}", r.stderr);
        assert!(r.stdout.is_empty());
    }
    // Observe-mode budgets are accepted in observe mode.
    let r = inspect(
        d.path(),
        &[
            &"--mode",
            &"observe",
            &"--budget",
            &"processes_listed=100000",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).request.budgets["processes_listed"], 100000);
}

#[test]
fn a_policy_file_is_loaded_or_the_run_fails() {
    let d = store(false);
    let p = TempDir::new().unwrap();
    let policy = write(
        p.path(),
        "p.toml",
        "schema = \"sigil-policy/1\"\nname = \"internal\"\n[scope]\naudit = [\"model_store\"]\n[rules.\"model.license_missing\"]\naction = \"ignore\"\nreason = \"internal models\"\n",
    );
    let r = inspect(d.path(), &[&"--policy", &policy]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).outcome.verdict, Verdict::Pass);

    let r = inspect(d.path(), &[&"--policy", &p.path().join("absent.toml")]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stdout.is_empty());
    let bad = write(p.path(), "bad.toml", "schema = \"sigil-policy/9\"\n");
    let r = inspect(d.path(), &[&"--policy", &bad]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stdout.is_empty());
}

#[test]
fn policy_time_is_now_or_a_given_instant() {
    let d = store(true);
    let r = inspect(d.path(), &[&"--policy-time", &"2027-01-02T03:04:05Z"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        session_of(&r).outcome.policy_time.as_str(),
        "2027-01-02T03:04:05Z"
    );
    let s = session_of(&inspect(d.path(), &[]));
    assert_eq!(s.outcome.policy_time, s.observation.started_at);
    assert_eq!(inspect(d.path(), &[&"--policy-time", &"yesterday"]).code, 2);
}

#[test]
fn a_model_filter_is_recorded() {
    let d = store(true);
    let r = inspect(d.path(), &[&"--model", &"m:latest"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.model_filter.as_deref(), Some("m:latest"));
    assert_eq!(s.models.len(), 1);
}

#[test]
fn observe_mode_reads_this_system() {
    let d = store(true);
    let r = inspect(d.path(), &[&"--mode", &"observe"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.mode, Mode::Observe);
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == "exposure.binds"));
    assert!(s.observation.net_ns.is_some());
    if Path::new("/proc/sys/kernel/random/boot_id").exists() {
        assert_eq!(
            s.observation.boot_id.len(),
            36,
            "{:?}",
            s.observation.boot_id
        );
    }
    assert!(r.stderr.contains("mode=observe"), "{}", r.stderr);
}

// --- session render, explain, rules -----------------------------------------------------------

/// A saved session with a WARN finding (no license layer).
fn saved_warn() -> (TempDir, PathBuf) {
    let d = store(false);
    let r = inspect(d.path(), &[]);
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "s.json", &r.stdout);
    (dir, path)
}

#[test]
fn session_render_gives_the_markdown_of_the_saved_session() {
    let (_dir, path) = saved_warn();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s: Session = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(r.stdout, render_session(&s));
}

/// Real sessions of the PR #75 CLI, without `request.active` and `probes` (see their README).
#[test]
fn sessions_written_before_pr76_are_rendered_and_explained() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../sigil-model/tests/fixtures/pre-pr76");
    for name in ["pass-complete.json", "warn.json", "incomplete.json"] {
        let path = dir.join(name);
        let r = run(&[&"session", &"render", &path]);
        assert_eq!(r.code, 0, "{name}: {}", r.stderr);
        let s: Session = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(r.stdout, render_session(&s), "{name}");
        assert!(!r.stdout.contains("Runtime API"), "{name}");
        for question in ["--verdict", "--coverage"] {
            let r = run(&[&"explain", &path, &question]);
            assert_eq!(r.code, 0, "{name} {question}: {}", r.stderr);
        }
    }
}

#[test]
fn a_broken_session_file_is_an_execution_error() {
    let dir = TempDir::new().unwrap();
    for (name, text, says) in [
        ("garbage.json", "{not json", "not valid JSON"),
        (
            "future.json",
            "{\"schema\": \"sigil-session/2\"}",
            "sigil-session/2",
        ),
        (
            "aibom.json",
            "{\"schema_version\": \"1.1\", \"verdict\": \"PASS\"}",
            "not a SIGIL session",
        ),
    ] {
        let path = write(dir.path(), name, text);
        for args in [vec!["session", "render"], vec!["explain", "--verdict"]] {
            let mut all: Vec<&dyn AsRef<std::ffi::OsStr>> = args
                .iter()
                .map(|a| a as &dyn AsRef<std::ffi::OsStr>)
                .collect();
            all.push(&path);
            let r = run(&all);
            assert_eq!(r.code, 1, "{name} {args:?}: {}", r.stderr);
            assert!(r.stderr.contains(says), "{name}: {}", r.stderr);
        }
    }
    let r = run(&[&"session", &"render", &dir.path().join("absent.json")]);
    assert_eq!(r.code, 1, "{}", r.stderr);
}

#[test]
fn a_session_that_fails_validation_is_refused() {
    // Well-formed JSON of the right schema, but its outcome no longer matches its findings.
    let (dir, path) = saved_warn();
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"confirmed_warnings\": 1"), "{text}");
    let edited = write(
        dir.path(),
        "edited.json",
        &text.replace("\"confirmed_warnings\": 1", "\"confirmed_warnings\": 7"),
    );
    for command in [&["session", "render"][..], &["explain", "--verdict"][..]] {
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = command
            .iter()
            .map(|a| a as &dyn AsRef<std::ffi::OsStr>)
            .collect();
        args.push(&edited);
        let r = run(&args);
        assert_eq!(r.code, 1, "{command:?}: {}", r.stderr);
        assert!(r.stderr.contains("is not a valid session"), "{}", r.stderr);
        assert!(r.stdout.is_empty());
    }
}

#[test]
fn explain_a_known_finding() {
    // #21: the finding, its evidence, the rule that fired, and the remediation.
    let (_dir, path) = saved_warn();
    let r = run(&[&"explain", &path, &"--finding", &LICENSE_MISSING]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for expected in [
        LICENSE_MISSING,
        "model.license_missing",
        "default:model.license_missing",
        "Remediation",
        "m:latest",
    ] {
        assert!(
            r.stdout.contains(expected),
            "{expected:?} missing:\n{}",
            r.stdout
        );
    }
    let md = run(&[
        &"explain",
        &path,
        &"--finding",
        &LICENSE_MISSING,
        &"--format",
        &"md",
    ]);
    assert_eq!(md.code, 0, "{}", md.stderr);
    assert!(md.stdout.starts_with("# "), "{}", md.stdout);
}

#[test]
fn explain_an_unknown_finding_is_a_clean_error() {
    let (_dir, path) = saved_warn();
    let r = run(&[&"explain", &path, &"--finding", &"finding:nope"]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.contains(LICENSE_MISSING), "{}", r.stderr);
}

#[test]
fn explain_the_verdict_with_and_without_findings() {
    let (_dir, path) = saved_warn();
    let r = run(&[&"explain", &path, &"--verdict"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("WARN"), "{}", r.stdout);
    assert!(r.stdout.contains(LICENSE_MISSING), "{}", r.stdout);

    let d = store(true);
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "s.json", &inspect(d.path(), &[]).stdout);
    let r = run(&[&"explain", &path, &"--verdict"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("Nothing raises the verdict"),
        "{}",
        r.stdout
    );
    let r = run(&[&"explain", &path, &"--coverage"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("model_store.integrity"), "{}", r.stdout);
}

#[test]
fn explain_takes_exactly_one_question_and_shows_real_flags() {
    let (_dir, path) = saved_warn();
    assert_eq!(run(&[&"explain", &path]).code, 2);
    assert_eq!(
        run(&[&"explain", &path, &"--verdict", &"--coverage"]).code,
        2
    );
    let help = run(&[&"explain", &"--help"]);
    assert_eq!(help.code, 0);
    for flag in ["--finding", "--verdict", "--coverage", "--format", "--out"] {
        assert!(help.stdout.contains(flag), "{flag}:\n{}", help.stdout);
    }
}

#[test]
fn rules_lists_the_catalog() {
    let r = run(&[&"rules"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for id in [
        "model.blob_missing",
        "model.blob_digest_mismatch",
        "model.manifest_digest_malformed",
        "model.manifest_unparseable",
        "model.license_missing",
        "model.provenance_unknown",
        "model.not_found",
        "exposure.bind_public",
        "exposure.bind_lan",
    ] {
        assert!(r.stdout.contains(id), "{id}:\n{}", r.stdout);
    }
}

#[test]
fn the_v0_1_commands_are_gone() {
    for command in [
        "lift",
        "assess",
        "trace",
        "policy-from-source",
        "runtime",
        "aibom",
    ] {
        assert_eq!(run(&[&command]).code, 2, "{command}");
    }
}

// --- the active API probe (PR-3b-2) -----------------------------------------------------------

/// A server on 127.0.0.1 that reads one request and answers `response`, or holds the connection
/// open for 3 s without answering when `response` is `None`.
fn api_server(response: Option<&'static str>) -> String {
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
        match response {
            Some(body) => {
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
            }
            None => std::thread::sleep(std::time::Duration::from_secs(3)),
        }
    });
    addr.to_string()
}

/// A server on 127.0.0.1 that sends 404 headers announcing a long body, and never sends it.
fn not_found_server() -> String {
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
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 1000000\r\n\r\n");
        std::thread::sleep(std::time::Duration::from_secs(5));
    });
    addr.to_string()
}

/// A loopback address where nothing listens.
fn refused_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn version_coverage(s: &Session) -> &CoverageState {
    &s.coverage
        .iter()
        .find(|c| c.check.as_str() == "runtime_api.version")
        .expect("runtime_api.version coverage")
        .state
}

#[test]
fn the_api_probe_records_the_version() {
    let d = store(true);
    let addr = api_server(Some("{\"version\":\"0.12.3\"}"));
    let r = inspect(d.path(), &[&"--active", &"api-probe", &"--api-addr", &addr]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.active.len(), 1);
    assert!(s.request.audit.iter().any(|a| a.as_str() == "runtime_api"));
    assert!(matches!(
        &s.probes[0].result,
        ProbeResult::Answered { status: 200, version: Some(v) } if v.as_str() == Some("0.12.3")
    ));
    assert_eq!(version_coverage(&s), &CoverageState::Complete);
    for key in ["api_connect_ms", "api_io_ms", "api_response_bytes"] {
        assert!(s.request.budgets.contains_key(key), "{key}");
    }
    for expected in [
        "active=api-probe".to_string(),
        format!("api probe: {addr} → answered (HTTP 200), version 0.12.3"),
    ] {
        assert!(
            r.stderr.contains(&expected),
            "{expected:?} missing:\n{}",
            r.stderr
        );
    }
}

#[test]
fn a_refused_probe_closes_the_check() {
    let d = store(true);
    let addr = refused_addr();
    let r = inspect(
        d.path(),
        &[
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
            &"--fail-on-incomplete",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    assert_eq!(s.probes[0].result, ProbeResult::Refused);
    assert!(
        r.stderr.contains(&format!("api probe: {addr} → refused")),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(sigil_model::render::PROBE_SCOPE_NOTE),
        "the probe's limits are not stated:\n{}",
        r.stderr
    );
}

#[test]
fn a_probe_that_times_out_leaves_the_result_incomplete() {
    let d = store(true);
    let addr = api_server(None);
    let r = inspect(
        d.path(),
        &[
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
            &"--budget",
            &"api_io_ms=200",
            &"--fail-on-incomplete",
        ],
    );
    assert_eq!(r.code, 4, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["api_io_ms"], 200);
    assert!(matches!(version_coverage(&s), CoverageState::Error { .. }));
    assert!(r.stderr.contains("timed out (read)"), "{}", r.stderr);
}

#[test]
fn a_non_200_answer_is_unsupported_without_waiting_for_its_body() {
    let d = store(true);
    let addr = not_found_server();
    let started = std::time::Instant::now();
    let r = inspect(
        d.path(),
        &[
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
            &"--budget",
            &"api_io_ms=4000",
        ],
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "waited {:?}",
        started.elapsed()
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(
        s.probes[0].result,
        ProbeResult::Answered {
            status: 404,
            version: None
        }
    );
    assert!(
        matches!(version_coverage(&s), CoverageState::Unsupported { what } if what.contains("HTTP 404")),
        "{:?}",
        version_coverage(&s)
    );
    assert!(
        r.stderr.contains("answered (HTTP 404), no version"),
        "{}",
        r.stderr
    );
}

#[test]
fn the_probe_is_shown_in_markdown_and_with_observe_mode() {
    let d = store(true);
    let addr = refused_addr();
    let r = inspect(
        d.path(),
        &[
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
            &"--format",
            &"md",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("\n## Runtime API\n"), "{}", r.stdout);

    let r = inspect(
        d.path(),
        &[
            &"--mode",
            &"observe",
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.mode, Mode::Observe);
    assert_eq!(s.probes.len(), 1);
    for check in ["exposure.binds", "runtime_api.version"] {
        assert!(
            s.request
                .required_checks
                .iter()
                .any(|c| c.as_str() == check),
            "{check}"
        );
    }
}

#[test]
fn probe_budgets_at_their_maximum_are_accepted() {
    let d = store(true);
    let addr = refused_addr();
    let r = inspect(
        d.path(),
        &[
            &"--active",
            &"api-probe",
            &"--api-addr",
            &addr,
            &"--budget",
            &"api_connect_ms=30000",
            &"--budget",
            &"api_io_ms=60000",
            &"--budget",
            &"api_response_bytes=1048576",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["api_response_bytes"], 1 << 20);
}

#[test]
fn the_probe_target_is_checked_before_anything_runs() {
    let d = store(true);
    let cases: &[(&[&str], &str)] = &[
        (&["--api-addr", "127.0.0.1:11434"], "--active"),
        (&["--allow-remote"], "--active"),
        (
            &["--active", "api-probe", "--api-addr", "192.0.2.1"],
            "--allow-remote",
        ),
        (
            &["--active", "api-probe", "--api-addr", "[2001:db8::1]:80"],
            "--allow-remote",
        ),
        (
            &["--active", "api-probe", "--api-addr", "https://127.0.0.1"],
            "scheme",
        ),
        (
            &["--active", "api-probe", "--api-addr", "example.com"],
            "not an IP address",
        ),
        (
            &["--active", "api-probe", "--api-addr", "0.0.0.0"],
            "unspecified",
        ),
        (
            &["--active", "api-probe", "--api-addr", "127.0.0.1:0"],
            "port 0",
        ),
        (
            &["--active", "api-probe", "--api-addr", "127.0.0.1:"],
            "port",
        ),
        (
            &["--active", "api-probe", "--api-addr", "127.0.0.1/api"],
            "path",
        ),
        (
            &[
                "--active",
                "api-probe",
                "--api-addr",
                "[fe80::1%eth0]:11434",
            ],
            "zone",
        ),
        (
            &["--active", "api-probe", "--api-addr", "[127.0.0.1]:11434"],
            "IPv6",
        ),
        (
            &["--active", "api-probe", "--budget", "api_io_ms=0"],
            "greater than 0",
        ),
        (
            &["--active", "api-probe", "--budget", "api_connect_ms=30001"],
            "at most 30000",
        ),
        (
            &["--active", "api-probe", "--budget", "api_io_ms=60001"],
            "at most 60000",
        ),
        (
            &[
                "--active",
                "api-probe",
                "--budget",
                "api_response_bytes=1048577",
            ],
            "at most 1048576",
        ),
        (&["--budget", "api_io_ms=200"], "--active api-probe"),
    ];
    for (given, expected) in cases {
        let extra: Vec<&dyn AsRef<std::ffi::OsStr>> = given
            .iter()
            .map(|a| a as &dyn AsRef<std::ffi::OsStr>)
            .collect();
        let r = inspect(d.path(), &extra);
        assert_eq!(r.code, 2, "{given:?}: {}", r.stderr);
        assert!(
            r.stderr.contains(expected),
            "{expected:?} for {given:?}:\n{}",
            r.stderr
        );
        assert!(r.stdout.is_empty(), "{}", r.stdout);
    }
}

// --- AI-BOM v2 (PR-3b-3a) ---------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn aibom_of(text: &str) -> sigil_model::AiBom {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("not an AI-BOM v2 ({e}):\n{text}"))
}

#[test]
fn inspect_writes_an_aibom_linked_to_its_session() {
    let d = store(false);
    let r = inspect(d.path(), &[&"--format", &"aibom"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let bom = aibom_of(&r.stdout);
    assert_eq!(bom.schema, sigil_model::render::aibom::AiBomSchema::V2);
    assert_eq!(bom.outcome.verdict, Verdict::Warn);
    assert_eq!(bom.models.len(), 1);
    // The summary names the session's hash, and says the session itself was not saved.
    let line = r
        .stderr
        .lines()
        .find(|l| l.starts_with("session sha256: "))
        .unwrap_or_else(|| panic!("no session hash line:\n{}", r.stderr));
    assert!(line.contains(bom.session.sha256.as_str()), "{line}");
    assert!(line.contains("--format session"), "{line}");
    // The document is pretty JSON with a trailing newline.
    assert!(r.stdout.ends_with("}\n"));

    let out = TempDir::new().unwrap();
    let path = out.path().join("bom.json");
    let r = inspect(d.path(), &[&"--format", &"aibom", &"--out", &path]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    aibom_of(&fs::read_to_string(&path).unwrap());
}

#[test]
fn session_render_gives_the_aibom_of_a_saved_session() {
    let (_dir, path) = saved_warn();
    let r = run(&[&"session", &"render", &path, &"--format", &"aibom"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let bom = aibom_of(&r.stdout);
    // A session SIGIL saved hashes to its file.
    assert_eq!(
        bom.session.sha256.as_str(),
        sha256_hex(&fs::read(&path).unwrap())
    );
    assert_eq!(bom.findings.len(), 1);
    // Markdown is still the session's report.
    let r = run(&[&"session", &"render", &path, &"--format", &"md"]);
    assert!(r.stdout.starts_with("# SIGIL session\n"), "{}", r.stdout);
}

#[test]
fn an_aibom_of_a_session_written_before_pr76_hashes_its_upgraded_form() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sigil-model/tests/fixtures/pre-pr76/warn.json");
    let r = run(&[&"session", &"render", &path, &"--format", &"aibom"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let bom = aibom_of(&r.stdout);
    let file = fs::read(&path).unwrap();
    let session: Session = serde_json::from_slice(&file).unwrap();
    let upgraded = session.to_canonical_json().unwrap();
    assert_eq!(bom.session.sha256.as_str(), sha256_hex(upgraded.as_bytes()));
    assert_ne!(bom.session.sha256.as_str(), sha256_hex(&file));
}

#[test]
fn help_lists_the_aibom_format() {
    let r = run(&[&"inspect", &"ollama", &"--help"]);
    assert!(r.stdout.contains("aibom"), "{}", r.stdout);
    let r = run(&[&"session", &"render", &"--help"]);
    assert!(r.stdout.contains("aibom"), "{}", r.stdout);
}

// --- the documented commands (README, docs/ollama-inspection.md) ------------------------------

/// The `cargo run … -p sigil-cli -- ARGS` commands of the fenced `bash` blocks of `markdown`, in
/// order, as argument lists. A trailing `\` joins lines, and a token starting with `#` starts a
/// comment.
fn documented_commands(markdown: &str) -> Vec<Vec<String>> {
    let mut commands = vec![];
    let mut in_bash = false;
    let mut pending = String::new();
    for line in markdown.lines() {
        let trimmed = line.trim();
        if !in_bash {
            in_bash = trimmed == "```bash";
            continue;
        }
        if trimmed == "```" {
            in_bash = false;
            continue;
        }
        if let Some(head) = trimmed.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(trimmed);
        let joined = std::mem::take(&mut pending);
        let tokens: Vec<&str> = joined
            .split_whitespace()
            .take_while(|t| !t.starts_with('#'))
            .collect();
        if tokens.len() < 2 || tokens[0] != "cargo" || tokens[1] != "run" {
            continue;
        }
        let Some(dash) = tokens.iter().position(|t| *t == "--") else {
            continue;
        };
        if !tokens[2..dash].windows(2).any(|w| w == ["-p", "sigil-cli"]) {
            continue;
        }
        commands.push(tokens[dash + 1..].iter().map(|t| t.to_string()).collect());
    }
    commands
}

/// Runs the commands of `doc` (relative to the workspace) in order, in one temporary directory,
/// with `OLLAMA_MODELS` set to a store whose model has no license (one WARN finding). Each must
/// exit 0, 3, or 4: never an execution error (1) or a usage error (2).
fn run_documented(doc: &str) -> usize {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(doc);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {doc}: {e}"));
    let models = store(false);
    let cwd = TempDir::new().unwrap();
    let commands = documented_commands(&text);
    for documented in &commands {
        let mut args: Vec<String> = documented
            .iter()
            .map(|a| a.replace("<FINDING-ID>", LICENSE_MISSING))
            .collect();
        assert!(
            !args.iter().any(|a| a.contains('<') || a.contains('>')),
            "{doc}: a placeholder is left in `sigil {}`",
            args.join(" ")
        );
        // Never reach a local Ollama from a test.
        if args.iter().any(|a| a == "--active") && !args.iter().any(|a| a == "--api-addr") {
            args.extend(["--api-addr".to_string(), "127.0.0.1:9".to_string()]);
        }
        let out = sigil()
            .current_dir(cwd.path())
            .env("OLLAMA_MODELS", models.path())
            .args(&args)
            .output()
            .unwrap();
        let code = out.status.code().unwrap();
        assert!(
            matches!(code, 0 | 3 | 4),
            "{doc}: `sigil {}` exited {code}:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    commands.len()
}

#[test]
fn every_documented_command_runs() {
    let n = run_documented("README.md") + run_documented("docs/ollama-inspection.md");
    assert!(n >= 10, "only {n} documented commands were found");
}
