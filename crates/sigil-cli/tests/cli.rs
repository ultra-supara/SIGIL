//! The v2 command line, end to end (plan §4.8, §4.9): `inspect ollama`, `session render`,
//! `explain` (#21), and `rules`, with their outputs and exit codes.

#![allow(clippy::disallowed_methods, clippy::disallowed_types)] // runs the CLI binary (assert_cmd)

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use sha2::{Digest, Sha256};
use sigil_model::render::markdown::render_session;
use sigil_model::{Completeness, Mode, Session, Verdict};
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

/// A store with one model; with a license layer, or without one (a WARN).
fn store(licensed: bool) -> TempDir {
    let d = TempDir::new().unwrap();
    let weights = blob(d.path(), b"weights");
    let license;
    let mut layers = vec![(MODEL_MEDIA, weights.as_str())];
    if licensed {
        license = blob(d.path(), b"MIT");
        layers.push((LICENSE_MEDIA, license.as_str()));
    }
    manifest(d.path(), LIB, &layers);
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
