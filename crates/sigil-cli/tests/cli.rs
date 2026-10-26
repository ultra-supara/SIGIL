//! The v2 command line, end to end (plan §4.8, §4.9): `inspect ollama`, `session render`,
//! `explain` (#21), and `rules`, with their outputs and exit codes.

// Runs the CLI binary (assert_cmd), and serves the API probe on loopback from this process.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use sha2::{Digest, Sha256};
use sigil_model::render::code::{no_capability_imports_kept, NOT_ANALYZED, NO_CAPABILITY_IMPORTS};
use sigil_model::render::markdown::{render_session, CODE_CAVEAT, NOT_SCANNED, NO_SIGNATURES};
use sigil_model::{
    CallTarget, Completeness, ContainerFacts, CoverageState, Mode, ProbeResult, Session,
    UntrustedText, Verdict, BINARY_UNSUPPORTED, NAME_AND_HASH_ONLY_WHY,
};
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

/// PR-4b-2a spec §3.1 (review P1-1): an `--out` that is a hard link of a model blob is replaced,
/// never written through, so the blob keeps its content.
#[test]
fn an_out_that_is_a_hard_link_of_a_blob_leaves_the_blob_intact() {
    let d = store(true);
    let blob = fs::read_dir(d.path().join("blobs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before = fs::read(&blob).unwrap();
    let o = TempDir::new().unwrap();
    let out = o.path().join("report.json");
    fs::hard_link(&blob, &out).unwrap();
    let r = inspect(d.path(), &[&"--out", &out]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        fs::read(&blob).unwrap(),
        before,
        "the blob was written through its hard link"
    );
    assert!(fs::read_to_string(&out)
        .unwrap()
        .contains("sigil-session/1"));
}

/// PR-4b-2a spec §3.1 (plan review P2): an existing symlink at `--out` is resolved when `--out`
/// is checked, as before: the file it leads to is replaced, and the link stays.
#[test]
fn an_out_that_is_a_symlink_replaces_the_file_it_leads_to() {
    use std::os::unix::fs::symlink;
    let d = store(true);
    let o = TempDir::new().unwrap();
    let actual = o.path().join("actual.json");
    fs::write(&actual, b"old").unwrap();
    let link = o.path().join("report.json");
    symlink(&actual, &link).unwrap();
    let r = inspect(d.path(), &[&"--out", &link]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(fs::read_to_string(&actual)
        .unwrap()
        .contains("sigil-session/1"));
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
    // #51: and the capabilities a policy can deny.
    assert!(
        r.stdout.contains(
            "\nCapabilities a policy can deny ([[capabilities.deny]]):\n  cxx.file_read\n  \
             cxx.file_write\n  posix.anti_debug\n  posix.dynamic_loading\n  \
             posix.environment_access\n  posix.file_read\n  posix.file_write\n  posix.network\n  \
             posix.process_spawn\nIts open questions: binary.capability_call (A slice imports a \
             capability that the policy denies, with no direct call site of it)\n"
        ),
        "{}",
        r.stdout
    );
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

/// `args` with the API probe pointed at `addr`: for a command with `--active`, any `--api-addr`
/// the docs give (`--api-addr X` or `--api-addr=X`) is replaced. Other commands are unchanged.
fn isolate_probe(args: &[String], addr: &str) -> Vec<String> {
    if !args
        .iter()
        .any(|a| a == "--active" || a.starts_with("--active="))
    {
        return args.to_vec();
    }
    let mut out = vec![];
    let mut value_follows = false;
    for a in args {
        if value_follows {
            value_follows = false;
        } else if a == "--api-addr" {
            value_follows = true;
        } else if !a.starts_with("--api-addr=") {
            out.push(a.clone());
        }
    }
    out.extend(["--api-addr".to_string(), addr.to_string()]);
    out
}

/// `args` with any `--install-dir` (`--install-dir X` or `--install-dir=X`) pointed at `dir`, so
/// that no test reads a real installation.
fn isolate_install(args: &[String], dir: &str) -> Vec<String> {
    let mut out = vec![];
    let mut value_follows = false;
    for a in args {
        if value_follows {
            value_follows = false;
            out.push(dir.to_string());
        } else if a == "--install-dir" {
            value_follows = true;
            out.push(a.clone());
        } else if a.starts_with("--install-dir=") {
            out.push(format!("--install-dir={dir}"));
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// `args` with every `<PATH>` of a `binary inspect` command replaced by `fixture`, so that no
/// test reads a file outside the workspace. Flags and their values are kept.
fn isolate_binary(args: &[String], fixture: &str) -> Vec<String> {
    if args.first().map(String::as_str) != Some("binary") {
        return args.to_vec();
    }
    const VALUED: &[&str] = &[
        "--policy",
        "--budget",
        "--policy-time",
        "--format",
        "--out",
        "--fail-on",
    ];
    let mut out = vec![];
    let mut value_follows = false;
    for (i, a) in args.iter().enumerate() {
        if i < 2 || value_follows {
            value_follows = false;
            out.push(a.clone());
        } else if a.starts_with("--") {
            value_follows = VALUED.contains(&a.as_str());
            out.push(a.clone());
        } else {
            out.push(fixture.to_string());
        }
    }
    out
}

/// A server on 127.0.0.1 that answers every request with an Ollama version, and counts them.
fn counting_api_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let mut request = vec![];
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => break,
                }
            }
            // Counted before the reply, so the count is final when the CLI exits.
            counted.fetch_add(1, Ordering::SeqCst);
            let body = "{\"version\":\"0.0.0-docs\"}";
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (addr, requests)
}

/// Runs the commands of `doc` (relative to the workspace) in order, in one temporary directory,
/// with `OLLAMA_MODELS` set to a store whose model has no license (one WARN finding). Each must
/// exit 0, 3, or 4: never an execution error (1) or a usage error (2). Every API probe goes to a
/// server of this test, which must see exactly one request per active command, and every
/// `--install-dir` to a synthetic tree. Returns the number of commands and of active commands.
fn run_documented(doc: &str) -> (usize, usize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(doc);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {doc}: {e}"));
    let models = store(false);
    let install = install_tree();
    let cwd = TempDir::new().unwrap();
    let (server, requests) = counting_api_server();
    let commands = documented_commands(&text);
    let mut active = 0;
    for documented in &commands {
        let args: Vec<String> = documented
            .iter()
            .map(|a| a.replace("<FINDING-ID>", LICENSE_MISSING))
            .collect();
        assert!(
            !args.iter().any(|a| a.contains('<') || a.contains('>')),
            "{doc}: a placeholder is left in `sigil {}`",
            args.join(" ")
        );
        // Counted from the docs, so a probe that escapes the server is a missing request.
        active += usize::from(
            args.iter()
                .any(|a| a == "--active" || a.starts_with("--active=")),
        );
        // Never reach a real Ollama from a test, whatever address the docs give.
        let args = isolate_probe(&args, &server);
        // Nor a real installation.
        let args = isolate_install(&args, install.path().to_str().unwrap());
        // Nor a file outside the workspace.
        let fixture = elf_fixture("libdata.so");
        let args = isolate_binary(&args, fixture.to_str().unwrap());
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
    assert_eq!(
        requests.load(std::sync::atomic::Ordering::SeqCst),
        active,
        "{doc}: the probe server must see one request per active command"
    );
    (commands.len(), active)
}

#[test]
fn every_documented_command_runs() {
    let (readme, readme_active) = run_documented("README.md");
    let (guide, guide_active) = run_documented("docs/ollama-inspection.md");
    let n = readme + guide;
    assert!(n >= 10, "only {n} documented commands were found");
    assert!(
        readme_active + guide_active >= 2,
        "the docs' active commands were not found"
    );
}

#[test]
fn the_binary_inspect_guide_s_commands_run() {
    let (n, _) = run_documented("docs/binary-inspect.md");
    assert!(n >= 3, "only {n} documented commands were found");
}

#[test]
fn documented_probes_are_pointed_at_the_test_server() {
    let v = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    let to = "127.0.0.1:5";
    // An address the docs give is replaced, in either form.
    assert_eq!(
        isolate_probe(
            &v(&[
                "inspect",
                "ollama",
                "--active",
                "api-probe",
                "--api-addr",
                "127.0.0.1:11434"
            ]),
            to
        ),
        v(&[
            "inspect",
            "ollama",
            "--active",
            "api-probe",
            "--api-addr",
            to
        ])
    );
    assert_eq!(
        isolate_probe(
            &v(&[
                "inspect",
                "ollama",
                "--active=api-probe",
                "--api-addr=10.0.0.1",
                "--allow-remote"
            ]),
            to
        ),
        v(&[
            "inspect",
            "ollama",
            "--active=api-probe",
            "--allow-remote",
            "--api-addr",
            to
        ])
    );
    // Without one, it is added; a command without `--active` is left alone.
    assert_eq!(
        isolate_probe(&v(&["inspect", "ollama", "--active", "api-probe"]), to),
        v(&[
            "inspect",
            "ollama",
            "--active",
            "api-probe",
            "--api-addr",
            to
        ])
    );
    assert_eq!(
        isolate_probe(&v(&["inspect", "ollama", "--out", "o"]), to),
        v(&["inspect", "ollama", "--out", "o"])
    );
}

// --- --install-dir (PR-4a) ---------------------------------------------------------------------

/// A synthetic installation: no file is an official one, so the release is not established.
fn install_tree() -> TempDir {
    let d = TempDir::new().unwrap();
    fs::create_dir_all(d.path().join("bin")).unwrap();
    fs::create_dir_all(d.path().join("lib/ollama")).unwrap();
    fs::write(d.path().join("bin/ollama"), b"not the official binary").unwrap();
    fs::write(d.path().join("lib/ollama/libggml.so.0.13.1"), b"lib").unwrap();
    d
}

#[test]
fn install_dir_adds_the_install_root_and_its_summary_line() {
    let models = store(true);
    let install = install_tree();
    let r = inspect(models.path(), &[&"--install-dir", &install.path()]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert!(s
        .request
        .roots
        .iter()
        .any(|root| root.id.as_str() == "install"));
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == "artifacts.release"));
    assert!(
        r.stderr.contains("release: not established ("),
        "{}",
        r.stderr
    );
    let r = inspect(models.path(), &[&"--install-dir", &"/nonexistent/sigil"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("release: install not found"),
        "{}",
        r.stderr
    );
    // Without --install-dir there is no release line.
    let r = inspect(models.path(), &[]);
    assert!(!r.stderr.contains("release:"), "{}", r.stderr);
}

#[test]
fn out_inside_the_install_dir_is_a_usage_error_and_writes_nothing() {
    let models = store(true);
    let install = install_tree();
    let out = install.path().join("report.md");
    let r = inspect(
        models.path(),
        &[
            &"--install-dir",
            &install.path(),
            &"--format",
            &"md",
            &"--out",
            &out,
        ],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr.contains("inside the install directory"),
        "{}",
        r.stderr
    );
    assert!(!out.exists());
}

#[test]
fn install_budgets_apply_with_install_dir_only() {
    let models = store(true);
    let install = install_tree();
    let r = inspect(
        models.path(),
        &[
            &"--install-dir",
            &install.path(),
            &"--budget",
            &"install_bytes=0",
            &"--budget",
            &"install_files_discovered=7",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["install_bytes"], 0);
    assert_eq!(s.request.budgets["install_files_discovered"], 7);
    let discovery = s
        .coverage
        .iter()
        .find(|c| c.check.as_str() == "artifacts.discovery")
        .unwrap();
    assert!(
        matches!(&discovery.state, CoverageState::BudgetExceeded { budget, .. } if budget == "install_bytes"),
        "{discovery:?}"
    );
    let r = inspect(models.path(), &[&"--budget", &"install_bytes=1"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("--install-dir"), "{}", r.stderr);
    // The depth and hop limits of the install walk are fixed.
    let r = inspect(
        models.path(),
        &[
            &"--install-dir",
            &install.path(),
            &"--budget",
            &"install_walk_depth=3",
        ],
    );
    assert_eq!(r.code, 2, "{}", r.stderr);
}

#[test]
fn a_saved_install_session_is_reverified_by_render_and_explain() {
    let models = store(true);
    let install = install_tree();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.json");
    let r = inspect(
        models.path(),
        &[&"--install-dir", &install.path(), &"--out", &path],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(run(&[&"session", &"render", &path]).code, 0);
    assert_eq!(run(&[&"explain", &path, &"--verdict"]).code, 0);
    // Tamper with one expected value: validate still passes, the verifier does not.
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let rows = v["reference_matches"].as_array_mut().unwrap();
    let absent = rows
        .iter_mut()
        .find(|r| r["result"]["Absent"]["kind"] == "File")
        .unwrap();
    absent["result"] = serde_json::json!({"Absent": {"kind": "Directory"}});
    fs::write(&path, v.to_string()).unwrap();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("disagree with the embedded reference set"),
        "{}",
        r.stderr
    );
    assert_eq!(run(&[&"explain", &path, &"--verdict"]).code, 1);
}

/// PR-4c-2c: `install_tree()` with the fixture `libdata.so`, which reports `LLAMA_COMMIT`
/// `6f3a9f3de`, as `lib/ollama/libllama-common.so.0.0.1`.
fn install_tree_with_a_commit() -> TempDir {
    let d = install_tree();
    fs::copy(
        elf_fixture("libdata.so"),
        d.path().join("lib/ollama/libllama-common.so.0.0.1"),
    )
    .unwrap();
    d
}

#[test]
fn an_open_release_claim_is_reported_and_reverified_by_render() {
    let models = store(true);
    let install = install_tree_with_a_commit();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.json");
    let r = inspect(
        models.path(),
        &[&"--install-dir", &install.path(), &"--out", &path],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains(
            "; consistent with ollama v0.30.5, v0.30.6, v0.30.7 by self-reported commit 6f3a9f3de \
             (open)"
        ),
        "{}",
        r.stderr
    );
    let rendered = run(&[&"session", &"render", &path]);
    assert_eq!(rendered.code, 0, "{}", rendered.stderr);
    let piece = |text: &str| sigil_model::UntrustedText::new(text).markdown_inline();
    let commits = format!(
        "{} {} {} ({})",
        piece("Self-reported commits:"),
        piece("LLAMA_COMMIT"),
        piece("6f3a9f3de"),
        piece("lib/ollama/libllama-common.so.0.0.1")
    );
    // The one commit the tree reports, and nothing after it on the line.
    assert!(
        rendered.stdout.lines().any(|l| l == commits),
        "{}",
        rendered.stdout
    );
    // Other candidates: validate still passes, the verifier does not.
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    v["releases"][0]["candidates"] = serde_json::json!(["v0.30.6"]);
    fs::write(&path, v.to_string()).unwrap();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("release claims disagree with the embedded reference set"),
        "{}",
        r.stderr
    );
}

#[test]
fn the_embedded_set_under_another_id_is_refused_by_render() {
    let models = store(true);
    let install = install_tree_with_a_commit();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.json");
    let r = inspect(
        models.path(),
        &[&"--install-dir", &install.path(), &"--out", &path],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    // The set renamed in the knowledge entry, the rows, and the claims.
    let text = fs::read_to_string(&path)
        .unwrap()
        .replace("\"ollama-official\"", "\"x\"");
    assert!(!text.contains("ollama-official"));
    fs::write(&path, text).unwrap();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr.contains("reference knowledge disagrees with"),
        "{}",
        r.stderr
    );
}

/// A saved session with an open claim, made by `inspect` over `install_tree_with_a_commit()`.
fn saved_open_claim_session() -> (TempDir, std::path::PathBuf) {
    let models = store(true);
    let install = install_tree_with_a_commit();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.json");
    let r = inspect(
        models.path(),
        &[&"--install-dir", &install.path(), &"--out", &path],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    (dir, path)
}

#[test]
fn an_open_claim_of_an_older_set_version_is_noted_not_reverified() {
    let (_dir, path) = saved_open_claim_session();
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    for k in v["knowledge"].as_array_mut().unwrap() {
        if k["kind"] == "ReferenceManifest" {
            k["sha256"] = serde_json::Value::from("0".repeat(64));
        }
    }
    // Not re-verified, so even other candidates render.
    v["releases"][0]["candidates"] = serde_json::json!(["v0.30.6"]);
    fs::write(&path, v.to_string()).unwrap();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("reference matches and release claims were made with another reference set"),
        "{}",
        r.stderr
    );
}

#[test]
fn explain_refuses_a_session_with_changed_release_claims() {
    let (_dir, path) = saved_open_claim_session();
    assert_eq!(run(&[&"explain", &path, &"--coverage"]).code, 0);
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    v["releases"][0]["candidates"] = serde_json::json!(["v0.30.6"]);
    fs::write(&path, v.to_string()).unwrap();
    let r = run(&[&"explain", &path, &"--coverage"]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("release claims disagree with the embedded reference set"),
        "{}",
        r.stderr
    );
}

#[test]
fn a_session_made_with_another_reference_set_is_rendered_with_a_note() {
    let models = store(true);
    let install = install_tree();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("s.json");
    let r = inspect(
        models.path(),
        &[&"--install-dir", &install.path(), &"--out", &path],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    for k in v["knowledge"].as_array_mut().unwrap() {
        if k["kind"] == "ReferenceManifest" {
            k["sha256"] = serde_json::Value::from("0".repeat(64));
        }
    }
    fs::write(&path, v.to_string()).unwrap();
    let r = run(&[&"session", &"render", &path]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("another reference set"), "{}", r.stderr);
}

#[test]
fn documented_install_dirs_are_pointed_at_the_test_tree() {
    let v = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    assert_eq!(
        isolate_install(
            &v(&["inspect", "ollama", "--install-dir", "/usr/local"]),
            "/t"
        ),
        v(&["inspect", "ollama", "--install-dir", "/t"])
    );
    assert_eq!(
        isolate_install(&v(&["inspect", "ollama", "--install-dir=/usr/local"]), "/t"),
        v(&["inspect", "ollama", "--install-dir=/t"])
    );
    assert_eq!(
        isolate_install(&v(&["inspect", "ollama", "--out", "o"]), "/t"),
        v(&["inspect", "ollama", "--out", "o"])
    );
}

#[test]
fn binary_budgets_apply_with_install_dir_only() {
    let models = store(true);
    let install = install_tree();
    let r = inspect(
        models.path(),
        &[
            &"--install-dir",
            &install.path(),
            &"--budget",
            &"binary_parse_bytes=4096",
            &"--budget",
            &"binary_imports=2",
            &"--budget",
            &"binary_scan_bytes=8192",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["binary_parse_bytes"], 4096);
    assert_eq!(s.request.budgets["binary_imports"], 2);
    assert_eq!(s.request.budgets["binary_scan_bytes"], 8192);
    for budget in ["binary_imports=2", "binary_scan_bytes=2"] {
        let r = inspect(models.path(), &[&"--budget", &budget]);
        assert_eq!(r.code, 2, "{budget}: {}", r.stderr);
        assert!(r.stderr.contains("--install-dir"), "{budget}: {}", r.stderr);
    }
}

// --- binary inspect (PR-4b-2a) ------------------------------------------------------------------

fn elf_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sigil-engine/tests/fixtures/elf")
        .join(name)
}

/// The inputs in a temporary directory: `libdata.so`, `net.o`, and `NOTES.txt`.
fn inputs() -> TempDir {
    let d = TempDir::new().unwrap();
    fs::copy(elf_fixture("libdata.so"), d.path().join("libdata.so")).unwrap();
    fs::copy(elf_fixture("net.o"), d.path().join("net.o")).unwrap();
    fs::write(d.path().join("NOTES.txt"), b"notes").unwrap();
    d
}

fn binary(extra: &[&dyn AsRef<std::ffi::OsStr>]) -> Run {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"binary", &"inspect"];
    args.extend_from_slice(extra);
    run(&args)
}

fn sha_of(path: &Path) -> String {
    sha256_hex(&fs::read(path).unwrap())
}

#[test]
fn binary_inspect_writes_a_valid_session_and_a_line_per_input() {
    let d = inputs();
    let (so, o) = (d.path().join("libdata.so"), d.path().join("net.o"));
    let r = binary(&[&so, &o]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    assert!(r.stderr.contains("audit=binary"), "{}", r.stderr);
    let lines: Vec<&str> = r
        .stderr
        .lines()
        .filter(|l| l.starts_with("binary: "))
        .collect();
    assert_eq!(lines.len(), 2, "{}", r.stderr);
    assert!(
        lines[0].contains("libdata.so")
            && lines[0].contains("ELF Dyn x86_64")
            && lines[0].ends_with("complete"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("net.o") && lines[1].contains("ELF Rel x86_64"),
        "{}",
        lines[1]
    );
    assert!(!r.stderr.contains("model blob hashing"), "{}", r.stderr);
    // Deterministic but for the observation.
    let mut again = session_of(&binary(&[&so, &o]));
    again.observation = s.observation.clone();
    assert_eq!(again, s);
}

#[test]
fn eleven_inputs_are_summarized_in_argument_order() {
    let d = TempDir::new().unwrap();
    let paths: Vec<PathBuf> = (1..=11)
        .map(|n| {
            let p = d.path().join(format!("f{n}.txt"));
            fs::write(&p, format!("{n}")).unwrap();
            p
        })
        .collect();
    let args: Vec<&dyn AsRef<std::ffi::OsStr>> = paths
        .iter()
        .map(|p| p as &dyn AsRef<std::ffi::OsStr>)
        .collect();
    let r = binary(&args);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let lines: Vec<&str> = r
        .stderr
        .lines()
        .filter(|l| l.starts_with("binary: "))
        .collect();
    assert_eq!(lines.len(), 11, "{}", r.stderr);
    for (k, line) in lines.iter().enumerate() {
        assert!(line.contains(&format!("/f{}.txt ", k + 1)), "{k}: {line}");
    }
    let roots = r.stderr.lines().find(|l| l.starts_with("roots: ")).unwrap();
    assert!(
        roots.find("(binary-2)").unwrap() < roots.find("(binary-10)").unwrap(),
        "{roots}"
    );
}

#[test]
fn two_hundred_inputs_fit_in_32_file_descriptors() {
    // Review P2-3: one SafeFs per input, dropped after its read.
    let d = TempDir::new().unwrap();
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg("ulimit -n 32 && exec \"$0\" \"$@\"")
        .arg(assert_cmd::cargo::cargo_bin("sigil"))
        .args(["binary", "inspect"]);
    for n in 0..200 {
        let p = d.path().join(format!("f{n}"));
        fs::write(&p, format!("{n}")).unwrap();
        cmd.arg(p);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s: Session = serde_json::from_slice(&out.stdout).unwrap();
    // One binary.container and one binary.identity entry per input (PR-4c-2a).
    assert_eq!(s.coverage.len(), 2 * 200);
}

#[test]
fn an_unsupported_input_is_incomplete_and_exits_0_or_4() {
    let d = inputs();
    let notes = d.path().join("NOTES.txt");
    let r = binary(&[&notes]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(matches!(
        session_of(&r).outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    assert!(
        r.stderr
            .contains("unsupported: not a supported ELF or Mach-O"),
        "{}",
        r.stderr
    );
    assert_eq!(binary(&[&notes, &"--fail-on-incomplete"]).code, 4);
}

#[test]
fn binary_inspect_takes_a_policy() {
    let d = inputs();
    let notes = d.path().join("NOTES.txt");
    let o = TempDir::new().unwrap();
    let none = write(
        o.path(),
        "none.toml",
        "schema = \"sigil-policy/1\"\nname = \"none\"\n[scope]\nbinary_audit = []\n",
    );
    let r = binary(&[&notes, &"--policy", &none]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).outcome.completeness, Completeness::Complete);
    let bad = write(o.path(), "bad.toml", "schema = \"nope\"\n");
    assert_eq!(binary(&[&notes, &"--policy", &bad]).code, 1);
}

#[test]
fn inputs_that_cannot_be_inspected_exit_1_and_write_nothing() {
    let d = inputs();
    let o = TempDir::new().unwrap();
    let out = o.path().join("report.json");
    for input in [d.path().join("missing"), d.path().to_path_buf()] {
        let r = binary(&[&input, &"--out", &out]);
        assert_eq!(r.code, 1, "{}: {}", input.display(), r.stderr);
        assert!(!out.exists());
    }
}

#[test]
fn out_on_an_input_or_a_hard_link_of_one_is_refused_and_the_input_kept() {
    use std::os::unix::fs::symlink;
    let d = inputs();
    let so = d.path().join("libdata.so");
    let before = sha_of(&so);
    let link = d.path().join("link.so");
    symlink(&so, &link).unwrap();
    let hard = d.path().join("hard.json");
    fs::hard_link(&so, &hard).unwrap();
    for out in [&so, &link, &hard] {
        let r = binary(&[&so, &"--out", out]);
        assert_eq!(r.code, 2, "{}: {}", out.display(), r.stderr);
        assert_eq!(sha_of(&so), before, "{}", out.display());
    }
    // Next to the input is fine.
    let next = d.path().join("report.md");
    let r = binary(&[&so, &"--format", &"md", &"--out", &next]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(fs::read_to_string(&next).unwrap().contains("## Binaries"));
    assert_eq!(sha_of(&so), before);
}

#[test]
fn binary_budgets_are_recorded_and_others_refused() {
    let d = inputs();
    let so = d.path().join("libdata.so");
    let r = binary(&[
        &so,
        &"--budget",
        &"binary_bytes=1000000",
        &"--budget",
        &"binary_parse_bytes=1048576",
        &"--budget",
        &"binary_imports=10",
        &"--budget",
        &"binary_scan_bytes=2048",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let b = session_of(&r).request.budgets;
    assert_eq!(b["binary_bytes"], 1_000_000);
    assert_eq!(b["binary_parse_bytes"], 1_048_576);
    assert_eq!(b["binary_imports"], 10);
    assert_eq!(b["binary_scan_bytes"], 2048);
    for bad in ["install_bytes=1", "files_discovered=1", "nope=1"] {
        assert_eq!(binary(&[&so, &"--budget", &bad]).code, 2, "{bad}");
    }
    let models = store(true);
    assert_eq!(
        inspect(models.path(), &[&"--budget", &"binary_bytes=1"]).code,
        2
    );
}

#[test]
fn binary_inspect_help_lists_its_flags() {
    let r = binary(&[&"--help"]);
    assert_eq!(r.code, 0);
    for flag in [
        "--policy",
        "--budget",
        "--policy-time",
        "--format",
        "--out",
        "--fail-on",
        "--fail-on-incomplete",
        "<PATH>...",
    ] {
        assert!(r.stdout.contains(flag), "{flag}: {}", r.stdout);
    }
}

#[test]
fn a_saved_binary_session_is_rendered_and_explained() {
    let d = inputs();
    let o = TempDir::new().unwrap();
    let saved = o.path().join("s.json");
    let r = binary(&[
        &d.path().join("libdata.so"),
        &d.path().join("NOTES.txt"),
        &"--out",
        &saved,
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let md = run(&[&"session", &"render", &saved]);
    assert_eq!(md.code, 0, "{}", md.stderr);
    assert!(md.stdout.contains("## Binaries"));
    let bom = run(&[&"session", &"render", &saved, &"--format", &"aibom"]);
    assert_eq!(bom.code, 0, "{}", bom.stderr);
    let ex = run(&[&"explain", &saved, &"--coverage"]);
    assert_eq!(ex.code, 0, "{}", ex.stderr);
    assert!(ex.stdout.contains("binary.container"), "{}", ex.stdout);
}

// --- binary inspect: review of Part B -----------------------------------------------------------

/// `--out` is refused before anything is read: a FIFO named as the input and as `--out` exits 2
/// (refused), not 1 (the FIFO, read as an input, would be fatal). The hard-link refusal says so.
#[test]
fn out_on_an_input_is_refused_before_the_read() {
    let d = TempDir::new().unwrap();
    let fifo = d.path().join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let r = binary(&[&fifo, &"--out", &fifo]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("is the input"), "{}", r.stderr);
    let d = inputs();
    let so = d.path().join("libdata.so");
    let hard = d.path().join("hard.json");
    fs::hard_link(&so, &hard).unwrap();
    let r = binary(&[&so, &"--out", &hard]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr.contains("is a hard link of the input"),
        "{}",
        r.stderr
    );
}

/// A partial input: its summary line, and a `missing` line naming only the entries that keep the
/// check open.
#[test]
fn the_summary_names_partial_inputs_and_only_the_open_entries() {
    let d = inputs();
    fs::write(
        d.path().join("cut.so"),
        &fs::read(elf_fixture("libdata.so")).unwrap()[..300],
    )
    .unwrap();
    let r = binary(&[
        &d.path().join("libdata.so"),
        &d.path().join("cut.so"),
        &d.path().join("NOTES.txt"),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = |needle: &str| {
        r.stderr
            .lines()
            .find(|l| l.starts_with("binary: ") && l.contains(needle))
            .unwrap_or_else(|| panic!("{needle}: {}", r.stderr))
            .to_string()
    };
    assert!(line("cut.so").contains("partial ("), "{}", r.stderr);
    let missing = r
        .stderr
        .lines()
        .find(|l| l.trim_start().starts_with("missing  binary.container"))
        .unwrap();
    assert!(missing.contains("inst:binary-2/cut.so"), "{missing}");
    assert!(missing.contains("inst:binary-3/NOTES.txt"), "{missing}");
    assert!(!missing.contains("inst:binary-1/libdata.so"), "{missing}");
}

/// An input over `binary_bytes`: `not read` on its line, and in the Markdown.
#[test]
fn an_input_over_binary_bytes_is_shown_as_not_read() {
    let d = inputs();
    let size = fs::metadata(d.path().join("libdata.so")).unwrap().len();
    let budget = format!("binary_bytes={}", size + 10);
    let o = TempDir::new().unwrap();
    let md = o.path().join("r.md");
    let r = binary(&[
        &d.path().join("libdata.so"),
        &d.path().join("net.o"),
        &"--budget",
        &budget,
        &"--format",
        &"md",
        &"--out",
        &md,
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let net = r
        .stderr
        .lines()
        .find(|l| l.starts_with("binary: ") && l.contains("net.o"))
        .unwrap();
    assert!(net.contains("not read"), "{net}");
    assert!(net.contains("budget exceeded"), "{net}");
    let text = fs::read_to_string(&md).unwrap();
    assert!(
        text.contains(&UntrustedText::new("not read: BudgetExceeded").markdown_inline()),
        "{text}"
    );
}

/// A policy that requires nothing of a binary inspection is said so in the summary.
#[test]
fn a_policy_that_requires_nothing_is_noted() {
    let d = inputs();
    let o = TempDir::new().unwrap();
    let none = write(
        o.path(),
        "none.toml",
        "schema = \"sigil-policy/1\"\nname = \"none\"\n[scope]\nbinary_audit = []\n",
    );
    let r = binary(&[&d.path().join("NOTES.txt"), &"--policy", &none]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("requires no check"), "{}", r.stderr);
    let r = binary(&[&d.path().join("NOTES.txt")]);
    assert!(!r.stderr.contains("requires no check"), "{}", r.stderr);
}

/// A long path is cut in the message, the reason is kept.
#[test]
fn a_fatal_message_keeps_its_reason_after_a_long_path() {
    let d = TempDir::new().unwrap();
    let long = d
        .path()
        .join("d".repeat(200))
        .join("e".repeat(200))
        .join("f".repeat(200));
    let r = binary(&[&long]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("not found"), "{}", r.stderr);
}

// --- binary inspect --code (PR-5a-2; #46) ------------------------------------------------------

fn code_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sigil-engine/tests/fixtures/code")
        .join(name)
}

/// `text` as the Markdown report shows it.
fn esc_md(text: &str) -> String {
    UntrustedText::new(text).markdown_inline()
}

/// The `binary.code` entry of input `n` (0-based, in argument order).
fn code_entry(s: &Session, n: usize) -> &sigil_model::Coverage {
    sigil_model::render::binary_inputs(s)[n]
        .code
        .unwrap_or_else(|| panic!("input {n} has no binary.code entry"))
}

#[test]
fn binary_code_md_shows_the_kernels_connect_call_site() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let r = binary(&[&"--code", &kernel, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let row = format!(
        "| {} | {} | {} |",
        esc_md("posix.network"),
        esc_md("connect"),
        esc_md("1: kernel @ 0x4d: connect(rdi=0, rsi=0, rdx=0)")
    );
    assert!(r.stdout.contains(&row), "{row}\n{}", r.stdout);
    assert!(
        r.stdout.contains(&esc_md("binary.code: complete; ")),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains(&esc_md(CODE_CAVEAT)), "{}", r.stdout);
}

#[test]
fn binary_code_session_is_byte_identical_but_for_the_observation() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let args: [&dyn AsRef<std::ffi::OsStr>; 4] = [
        &"--code",
        &kernel,
        &"--policy-time",
        &"2026-10-18T00:00:00Z",
    ];
    let (first, second) = (binary(&args), binary(&args));
    assert_eq!((first.code, second.code), (0, 0), "{}", first.stderr);
    let a = session_of(&first);
    let mut b = session_of(&second);
    assert!(a.request.code);
    assert_eq!(a.request.budgets["binary_code_bytes"], 256 << 20);
    assert_eq!(a.code.len(), 1);
    assert_eq!(code_entry(&a, 0).state, CoverageState::Complete);
    assert_eq!(a.to_canonical_json().unwrap(), first.stdout);
    // Only the run's own times (one-second resolution) may differ.
    b.observation.started_at = a.observation.started_at.clone();
    b.observation.finished_at = a.observation.finished_at.clone();
    assert_eq!(b.to_canonical_json().unwrap(), first.stdout);
}

#[test]
fn binary_code_help_documents_the_flag_and_its_budget() {
    let r = binary(&[&"--help"]);
    assert_eq!(r.code, 0);
    for text in [
        "--code",
        "With --code, the direct call sites of capability imports are recorded too",
        "direct call sites of capability imports",
        "x86-64 ELF only",
        "never run",
        "binary_code_bytes, which needs --code",
        "binary_code_audit with --code",
    ] {
        assert!(r.stdout.contains(text), "{text}: {}", r.stdout);
    }
    // inspect ollama has no --code (parent spec §10).
    let models = store(true);
    assert_eq!(inspect(models.path(), &[&"--code"]).code, 2);
}

#[test]
fn binary_code_bytes_needs_code() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let r = binary(&[&kernel, &"--budget", &"binary_code_bytes=4096"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("--budget binary_code_bytes=4096: needs --code"),
        "{}",
        r.stderr
    );
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    // With --code it is recorded.
    let r = binary(&[&"--code", &kernel, &"--budget", &"binary_code_bytes=4096"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).request.budgets["binary_code_bytes"], 4096);
    // inspect ollama knows no code budget.
    let models = store(true);
    assert_eq!(
        inspect(models.path(), &[&"--budget", &"binary_code_bytes=4096"]).code,
        2
    );
}

/// The rule is checked once every argument is parsed: the budget may come before `--code`.
#[test]
fn binary_code_bytes_before_code_is_accepted() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let r = binary(&[&"--budget", &"binary_code_bytes=4096", &"--code", &kernel]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert!(s.request.code);
    assert_eq!(s.request.budgets["binary_code_bytes"], 4096);
}

#[test]
fn binary_code_a_small_budget_is_partial_and_fails_on_incomplete() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let r = binary(&[&"--code", &kernel, &"--budget", &"binary_code_bytes=1"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.request.budgets["binary_code_bytes"], 1);
    let c = code_entry(&s, 0);
    assert!(
        matches!(&c.state, CoverageState::Partial { missing }
            if missing.iter().any(|m| m == "binary_code_bytes: 1 exceeded")),
        "{:?}",
        c.state
    );
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    let r = binary(&[
        &"--code",
        &kernel,
        &"--budget",
        &"binary_code_bytes=1",
        &"--fail-on-incomplete",
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);
}

#[test]
fn binary_code_an_unsupported_input_exits_0() {
    let d = inputs();
    let notes = d.path().join("NOTES.txt");
    let r = binary(&[&"--code", &notes]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(
        code_entry(&s, 0).state,
        CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string()
        }
    );
    assert_eq!(
        binary(&[&"--code", &notes, &"--fail-on-incomplete"]).code,
        4
    );
}

#[test]
fn binary_code_audit_empty_completes_and_the_note_names_both_lists() {
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let d = inputs();
    let notes = d.path().join("NOTES.txt");
    let o = TempDir::new().unwrap();
    let policy = |name: &str, scope: &str| {
        write(
            o.path(),
            &format!("{name}.toml"),
            &format!("schema = \"sigil-policy/1\"\nname = \"{name}\"\n[scope]\n{scope}"),
        )
    };
    let code_none = policy("code-none", "binary_code_audit = []\n");
    let both = policy("both", "binary_audit = []\nbinary_code_audit = []\n");
    let container_none = policy("container-none", "binary_audit = []\n");
    // binary.code is Partial but not required: COMPLETE, and no note (binary.container is).
    let r = binary(&[
        &"--code",
        &kernel,
        &"--budget",
        &"binary_code_bytes=1",
        &"--policy",
        &code_none,
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    assert!(matches!(
        code_entry(&s, 0).state,
        CoverageState::Partial { .. }
    ));
    assert!(!r.stderr.contains("requires no check"), "{}", r.stderr);
    // Both lists empty: the note names both.
    let r = binary(&[&"--code", &notes, &"--policy", &both]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(session_of(&r).outcome.completeness, Completeness::Complete);
    assert!(
        r.stderr.contains(
            "note: the policy requires no check of a binary inspection \
             (binary_audit = [] and binary_code_audit = []): the result is COMPLETE whatever \
             the inputs"
        ),
        "{}",
        r.stderr
    );
    // binary_audit = [] alone, with --code: binary.code is still required, and no note.
    let r = binary(&[&"--code", &notes, &"--policy", &container_none]);
    assert!(matches!(
        session_of(&r).outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    assert!(!r.stderr.contains("requires no check"), "{}", r.stderr);
    // Without --code, the note names binary_audit alone.
    let r = binary(&[&notes, &"--policy", &container_none]);
    assert!(
        r.stderr
            .contains("(binary_audit = []): the result is COMPLETE"),
        "{}",
        r.stderr
    );
}

#[test]
fn binary_code_summary_lines_show_the_code_state() {
    let d = inputs();
    let kernel = code_fixture("suspicious_kernel-gcc-O2.o");
    let cfg = code_fixture("cfg.so");
    let notes = d.path().join("NOTES.txt");
    let r = binary(&[&"--code", &kernel, &cfg, &notes]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = |needle: &str| {
        r.stderr
            .lines()
            .find(|l| l.starts_with("binary: ") && l.contains(needle))
            .unwrap_or_else(|| panic!("{needle}: {}", r.stderr))
            .to_string()
    };
    assert!(
        line("suspicious_kernel-gcc-O2.o")
            .ends_with("  complete  signature scan: complete  code: complete"),
        "{}",
        r.stderr
    );
    assert!(
        line("cfg.so").ends_with("  code: partial (3 gaps)"),
        "{}",
        r.stderr
    );
    assert!(
        line("NOTES.txt").ends_with(&format!("  code: unsupported: {BINARY_UNSUPPORTED}")),
        "{}",
        r.stderr
    );
    // Without --code, no code state.
    let r = binary(&[&kernel]);
    assert!(!r.stderr.contains("code: "), "{}", r.stderr);
}

// --- capability hints without --code (#47) ------------------------------------------------------

/// The session's hints as (feature, value).
fn hint_pairs(s: &Session) -> Vec<(String, String)> {
    s.hints
        .iter()
        .map(|h| (h.feature.to_string(), h.value.as_str().unwrap().to_string()))
        .collect()
}

/// A row of a Capabilities table, as the Markdown shows it.
fn capability_row(feature: &str, import: &str, cell: &str) -> String {
    format!(
        "| {} | {} | {} |",
        esc_md(feature),
        esc_md(import),
        esc_md(cell)
    )
}

/// Whether the one input's ELF facts say it is stripped.
fn stripped(s: &Session) -> Option<bool> {
    match &s.binaries[0].container {
        ContainerFacts::Elf(e) => e.stripped,
        ContainerFacts::MachO(_) => None,
    }
}

/// #47: a stripped copy of a linked file that imports `connect`. `strip` (binutils) makes the
/// copy; the test fails, rather than skips, without it.
#[test]
fn capability_hints_survive_stripping() {
    let d = TempDir::new().unwrap();
    let original = code_fixture("net-plt-gcc.so");
    let copy = d.path().join("net-stripped.so");
    let status = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg("-o")
        .arg(&copy)
        .arg(&original)
        .status()
        .unwrap_or_else(|e| panic!("strip (binutils) is required by this test: {e}"));
    assert!(status.success(), "strip failed: {status}");
    // The copy is stripped, and the original is not: the test is not vacuous.
    let r = binary(&[&original]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        stripped(&session_of(&r)),
        Some(false),
        "the fixture must keep .symtab, and strip -o must leave it untouched"
    );
    let r = binary(&[&copy]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(stripped(&s), Some(true));
    assert_eq!(
        hint_pairs(&s),
        [("posix.network".to_string(), "connect".to_string())]
    );
    let r = binary(&[&copy, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(&capability_row("posix.network", "connect", NOT_ANALYZED)),
        "{}",
        r.stdout
    );
}

#[test]
fn capability_hints_of_dynamic_loading() {
    // dl.so imports dlsym (not dlopen: plan P-h).
    let dl = code_fixture("dl.so");
    let r = binary(&[&dl]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(
        hint_pairs(&s),
        [("posix.dynamic_loading".to_string(), "dlsym".to_string())]
    );
    let r = binary(&[&dl, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains(&capability_row(
            "posix.dynamic_loading",
            "dlsym",
            NOT_ANALYZED
        )),
        "{}",
        r.stdout
    );
}

#[test]
fn capability_hints_none_is_an_empty_non_failing_report() {
    // No undefined symbol at all.
    let clean = code_fixture("clean_kernel-gcc-O2.o");
    let r = binary(&[&clean]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert!(s.hints.is_empty(), "{:?}", s.hints);
    assert_eq!(s.outcome.completeness, Completeness::Complete);
    let r = binary(&[&clean, &"--format", &"md", &"--fail-on-incomplete"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(&format!("\n{}\n", esc_md(NO_CAPABILITY_IMPORTS))),
        "{}",
        r.stdout
    );
    // With --code too: no call site, and binary.code is complete.
    let r = binary(&[
        &"--code",
        &clean,
        &"--format",
        &"md",
        &"--fail-on-incomplete",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(&format!("\n{}\n", esc_md(NO_CAPABILITY_IMPORTS))),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(&esc_md("binary.code: complete; ")),
        "{}",
        r.stdout
    );
}

/// Plan P-r: an import list cut short at `binary_imports` keeps no hint past the cut, so "no
/// hint" is not "No capability imports.". `net-plt-gcc.so` calls `connect`, and
/// `binary_imports=0` keeps none of its imports; its code is still searched in full.
#[test]
fn capability_hints_of_a_cut_short_import_list() {
    let net = code_fixture("net-plt-gcc.so");
    let r = binary(&[&"--code", &"--budget", &"binary_imports=0", &net]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert!(s.hints.is_empty(), "{:?}", s.hints);
    assert!(
        s.binaries[0].imports_cut_short(),
        "{:?}",
        s.binaries[0].gaps
    );
    assert_eq!(code_entry(&s, 0).state, CoverageState::Complete);
    assert!(
        s.code.iter().flat_map(|c| &c.call_sites).any(|c| matches!(
            &c.target,
            CallTarget::Import { symbol, .. } if symbol.as_str() == Some("connect")
        )),
        "{:?}",
        s.code
    );
    let r = binary(&[
        &"--code",
        &"--budget",
        &"binary_imports=0",
        &net,
        &"--format",
        &"md",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(&format!("\n{}\n", esc_md(&no_capability_imports_kept(0)))),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout
            .contains(&format!("\n{}\n", esc_md(NO_CAPABILITY_IMPORTS))),
        "{}",
        r.stdout
    );
}

/// PR-5a-2 spec §5 Install: an installation whose binary imports `connect` shows the column.
#[test]
fn capability_hints_in_an_install_report() {
    let models = store(true);
    let tree = TempDir::new().unwrap();
    fs::create_dir_all(tree.path().join("bin")).unwrap();
    fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    fs::copy(elf_fixture("libdata.so"), tree.path().join("bin/ollama")).unwrap();
    let r = inspect(
        models.path(),
        &[&"--install-dir", &tree.path(), &"--format", &"md"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let at = r
        .stdout
        .find(&esc_md("Binaries:"))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    let binaries = &r.stdout[at..];
    assert!(
        binaries.contains(&format!("| {} |", esc_md("Capabilities (imports)"))),
        "{binaries}"
    );
    let row = binaries
        .lines()
        .find(|l| l.starts_with(&format!("| {} |", esc_md("bin/ollama"))))
        .unwrap_or_else(|| panic!("{binaries}"));
    assert!(
        row.contains(&format!("| {} |", esc_md("posix.network"))),
        "{row}"
    );
}

// --- Component identification (PR-4c-1) -------------------------------------------------------

/// `libdata.so` (SONAME `libdata.so.1`, the four `LLAMA_*` values) copied as libllama-common.
fn llama_common() -> (TempDir, PathBuf) {
    let d = TempDir::new().unwrap();
    let path = d.path().join("libllama-common.so.0.0.1");
    fs::copy(elf_fixture("libdata.so"), &path).unwrap();
    (d, path)
}

#[test]
fn a_binary_s_component_is_on_its_summary_line_and_in_its_facts() {
    let (_d, path) = llama_common();
    let r = binary(&[&path]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = r
        .stderr
        .lines()
        .find(|l| l.starts_with("binary: "))
        .unwrap_or_else(|| panic!("{}", r.stderr));
    assert!(
        line.ends_with(
            "  complete  signature scan: complete  component: llama.cpp/common (name only)"
        ),
        "{line}"
    );
    let r = binary(&[&path, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    for (label, value) in [
        ("Component", "llama.cpp/common"),
        ("Identity", "name only"),
        ("Versions", "0.0.1 (file name), 1 (LLAMA_BUILD_NUMBER)"),
    ] {
        let row = format!("| {} | {} |", esc_md(label), esc_md(value));
        assert!(r.stdout.contains(&row), "{row}\n{}", r.stdout);
    }
    // The AI-BOM of the saved session projects the claim.
    let saved = path.with_file_name("session.json");
    let r = binary(&[&path, &"--out", &saved]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let r = run(&[&"session", &"render", &saved, &"--format", &"aibom"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let bom: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    let component = &bom["artifacts"][0]["slices"][0]["components"][0];
    assert_eq!(component["component"], "llama.cpp/common", "{bom}");
    assert_eq!(component["status"], "NameOnly", "{bom}");
    assert_eq!(
        component["versions"],
        serde_json::json!(["0.0.1", "1"]),
        "{bom}"
    );
    // A name the database does not know: no claim, and the line ends at its status.
    let d = inputs();
    let r = binary(&[&d.path().join("libdata.so")]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = r
        .stderr
        .lines()
        .find(|l| l.starts_with("binary: "))
        .unwrap_or_else(|| panic!("{}", r.stderr));
    assert!(
        line.ends_with("  complete  signature scan: complete"),
        "{line}"
    );
}

/// `ggml_version()`'s returned value is a version of libggml-base, and F-I2 holds on it (PR-4c-2b).
#[test]
fn ggml_version_is_a_version_and_f_i2_holds_on_the_fixtures() {
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../sigil-engine/tests/fixtures/returns");
    for (fixture, versions, identity) in [
        (
            "version-gcc-O2.so",
            "0 (SONAME), 0.13.1 (ggml_version), 0.13.1 (file name)",
            "name only",
        ),
        (
            "version-1.0.0-gcc-O2.so",
            "0 (SONAME), 0.13.1 (file name), 1.0.0 (ggml_version)",
            "conflicting",
        ),
    ] {
        let d = TempDir::new().unwrap();
        let path = d.path().join("libggml-base.so.0.13.1");
        fs::copy(fixtures.join(fixture), &path).unwrap();
        let r = binary(&[&path, &"--format", &"md"]);
        assert_eq!(r.code, 0, "{}", r.stderr);
        for (label, value) in [("Versions", versions), ("Identity", identity)] {
            let row = format!("| {} | {} |", esc_md(label), esc_md(value));
            assert!(r.stdout.contains(&row), "{fixture}: {row}\n{}", r.stdout);
        }
    }
}

#[test]
fn the_install_report_shows_each_binary_s_component() {
    let models = store(true);
    let tree = TempDir::new().unwrap();
    fs::create_dir_all(tree.path().join("bin")).unwrap();
    fs::create_dir_all(tree.path().join("lib/ollama")).unwrap();
    fs::copy(elf_fixture("libdata.so"), tree.path().join("bin/ollama")).unwrap();
    let r = inspect(
        models.path(),
        &[&"--install-dir", &tree.path(), &"--format", &"md"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let at = r
        .stdout
        .find(&esc_md("Binaries:"))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    let row = r.stdout[at..]
        .lines()
        .find(|l| l.starts_with(&format!("| {} |", esc_md("bin/ollama"))))
        .unwrap_or_else(|| panic!("{}", r.stdout));
    let start = format!(
        "| {} | {} | {} |",
        esc_md("bin/ollama"),
        esc_md("Dyn x86_64"),
        esc_md("ollama (name only)")
    );
    assert!(row.starts_with(&start), "{row}");
}

/// PR-4c-2a: each `binary:` line has the input's `binary.identity` state (`signature scan: …`),
/// and the Markdown its Signature scan column and Signatures. A Mach-O is not scanned: the
/// inspection is incomplete.
#[test]
fn a_binary_s_identity_is_on_its_summary_line_and_in_its_report() {
    let d = inputs();
    let hello = d.path().join("hello");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sigil-engine/tests/fixtures/macho/hello-universal"),
        &hello,
    )
    .unwrap();
    let (so, notes) = (d.path().join("libdata.so"), d.path().join("NOTES.txt"));
    let r = binary(&[&so, &notes, &hello]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = |needle: &str| {
        r.stderr
            .lines()
            .find(|l| l.starts_with("binary: ") && l.contains(needle))
            .unwrap_or_else(|| panic!("{needle}: {}", r.stderr))
            .to_string()
    };
    assert!(
        line("libdata.so").ends_with("  complete  signature scan: complete"),
        "{}",
        r.stderr
    );
    assert!(
        line("NOTES.txt").ends_with(&format!(
            "  signature scan: unsupported: {BINARY_UNSUPPORTED}"
        )),
        "{}",
        r.stderr
    );
    assert!(
        line("hello").ends_with("  complete  signature scan: unsupported: string scan: ELF only"),
        "{}",
        r.stderr
    );
    let s = session_of(&r);
    assert!(
        matches!(&s.outcome.completeness, Completeness::Incomplete { missing_required, .. }
            if missing_required.iter().any(|c| c.as_str() == "binary.identity")),
        "{:?}",
        s.outcome.completeness
    );
    let r = binary(&[&so, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(r"| Path | SHA\-256 | Size | Type | Container facts | Signature scan |"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(&esc_md("No signature found.")),
        "{}",
        r.stdout
    );
}

/// PR-4c-2a, ADR-010: a file named as NVIDIA's runtime is identified by name and hash only. Its
/// `binary.identity` is `OutOfScope`, which closes the check, and its report says it was not
/// scanned rather than that no signature was found.
#[test]
fn an_nvidia_named_file_is_not_scanned_and_its_report_says_so() {
    let d = inputs();
    let cudart = d.path().join("libcudart.so.12");
    fs::copy(d.path().join("libdata.so"), &cudart).unwrap();
    let r = binary(&[&cudart]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = r
        .stderr
        .lines()
        .find(|l| l.starts_with("binary: "))
        .unwrap_or_else(|| panic!("{}", r.stderr));
    assert!(
        line.contains(&format!(
            "  complete  signature scan: out of scope: {NAME_AND_HASH_ONLY_WHY}"
        )),
        "{line}"
    );
    assert_eq!(session_of(&r).outcome.completeness, Completeness::Complete);
    let r = binary(&[&cudart, &"--format", &"md"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains(&esc_md(NOT_SCANNED)), "{}", r.stdout);
    assert!(!r.stdout.contains(&esc_md(NO_SIGNATURES)), "{}", r.stdout);
}

// --- capability denials (#51) --------------------------------------------------------------------

/// A policy file in `d` that denies `posix.process_spawn`.
fn deny_spawn(d: &Path) -> PathBuf {
    let path = d.join("deny-spawn.toml");
    fs::write(
        &path,
        "schema = \"sigil-policy/1\"\nname = \"no-spawn\"\n[[capabilities.deny]]\nfeature = \"posix.process_spawn\"\naction = \"fail\"\nreason = \"no processes\"\n",
    )
    .unwrap();
    path
}

/// #51's acceptance criterion end to end: under a policy that denies `posix.process_spawn`, a file
/// that calls `execve` FAILs (exit 3 with `--fail-on fail`), its report shows the violation with
/// its call site, and a file that calls only `connect` passes.
#[test]
fn a_denied_capability_s_call_fails_binary_inspect() {
    let d = TempDir::new().unwrap();
    let policy = deny_spawn(d.path());
    let spawn = code_fixture("spawn.so");
    let r = binary(&[
        &"--code",
        &spawn,
        &"--policy",
        &policy,
        &"--fail-on",
        &"fail",
        &"--format",
        &"md",
    ]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    let slice = format!("sha256:{}#x86_64@0", sha_of(&spawn));
    let row = format!(
        "| {} | fail | {} | {} |",
        esc_md("policy:capabilities.deny.posix.process_spawn"),
        esc_md(&slice),
        esc_md("cs:0x1124")
    );
    assert!(r.stdout.contains(&row), "{row}\n{}", r.stdout);

    let net = code_fixture("net-plt-gcc.so");
    let r = binary(&[&"--code", &net, &"--policy", &policy, &"--fail-on", &"fail"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let s = session_of(&r);
    assert!(s.policy_violations.is_empty() && s.open_questions.is_empty());
}

/// Without `--code`, the call is not known: an open question, INCOMPLETE (exit 4 with
/// `--fail-on-incomplete`), never a pass; `explain --finding` explains it.
#[test]
fn without_code_a_denied_import_is_an_open_question_explain_can_explain() {
    let d = TempDir::new().unwrap();
    let policy = deny_spawn(d.path());
    let spawn = code_fixture("spawn.so");
    let r = binary(&[&spawn, &"--policy", &policy, &"--fail-on-incomplete"]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    let s = session_of(&r);
    assert_eq!(s.open_questions.len(), 1);
    let saved = d.path().join("session.json");
    fs::write(&saved, &r.stdout).unwrap();
    let id = s.open_questions[0].id.to_string();
    let r = run(&[&"explain", &saved, &"--finding", &id]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains(
            "calls:posix.process_spawn: unknown, not modeled: calls in code that was not analyzed"
        ),
        "{}",
        r.stdout
    );
}

/// Plan review P2-2: `session verify` says whether a saved session is what its policy gives. A
/// session whose violation was removed and whose verdict was set to PASS is consistent in itself,
/// so it still renders; it does not verify.
#[test]
fn session_verify_checks_a_session_against_its_policy() {
    let d = TempDir::new().unwrap();
    let policy = deny_spawn(d.path());
    let spawn = code_fixture("spawn.so");
    let r = binary(&[&"--code", &spawn, &"--policy", &policy]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let saved = d.path().join("session.json");
    fs::write(&saved, &r.stdout).unwrap();
    let time = session_of(&r).outcome.policy_time;
    let r = run(&[&"session", &"verify", &saved, &"--policy", &policy]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!(
            "verified: {} is what the policy no-spawn ({}) gives at {time}: FAIL + COMPLETE\n",
            saved.display(),
            sha_of(&policy)
        )
    );

    // The built-in policy is another policy.
    let r = run(&[&"session", &"verify", &saved]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.stderr
            .contains("the session records the policy no-spawn sigil-policy/1 ("),
        "{}",
        r.stderr
    );

    // The violation removed and the verdict set to PASS.
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&saved).unwrap()).unwrap();
    v["policy_violations"] = serde_json::json!([]);
    v["outcome"]["verdict"] = serde_json::json!("Pass");
    let tampered = d.path().join("tampered.json");
    fs::write(&tampered, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let r = run(&[&"session", &"render", &tampered]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let r = run(&[&"session", &"verify", &tampered, &"--policy", &policy]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.stderr.contains(&format!(
            "{} is not what the policy no-spawn gives: policy violations the policy gives, and \
             the session lacks: policy:capabilities.deny.posix.process_spawn on sha256:{}#x86_64@0; \
             the outcome is PASS + COMPLETE, and the policy gives FAIL + COMPLETE",
            tampered.display(),
            sha_of(&spawn)
        )),
        "{}",
        r.stderr
    );
}
