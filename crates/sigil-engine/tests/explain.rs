//! `explain` (#21; plan §4.8): a finding, the verdict, or the coverage of a session, explained
//! from the session's facts and the rule catalog. Deterministic, and every value is escaped.

use std::path::Path;

use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::explain::{self, ExplainError, Format};
use sigil_engine::inspect::{observe_session, ActiveInput, ObserveRequest, StoreRequest};
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::catalog::RULES;
use sigil_engine::policy::Policy;
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::proc::*;
use common::*;

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-08T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: BOOT_ID.to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

fn store(d: &Path, path: &str, license: bool) {
    let weights = blob(d, b"weights");
    let mut layers = vec![(MODEL_MEDIA, weights.as_str())];
    let text;
    if license {
        text = blob(d, b"MIT");
        layers.push((LICENSE_MEDIA_TYPE, text.as_str()));
    }
    manifest(d, path, None, &layers);
}

fn session(store: &Path, fake: &FakeProc) -> Session {
    session_with(store, fake, &ActiveInput::default())
}

fn session_with(store: &Path, fake: &FakeProc, active: &ActiveInput) -> Session {
    let req = ObserveRequest {
        store: StoreRequest {
            models_dir: store.to_path_buf(),
            model_filter: None,
            budgets: FsBudgets::default(),
            manifest_limit: DEFAULT_MANIFEST_LIMIT,
        },
        proc_root: fake.path().to_path_buf(),
        proc_budgets: ProcBudgets::default(),
    };
    observe_session(
        &req,
        active,
        &Policy::builtin_default().unwrap(),
        ToolInfo {
            name: "sigil".to_string(),
            version: "0.0.0-test".to_string(),
            git_rev: None,
        },
        observation(),
        observation().started_at,
    )
    .unwrap()
}

fn serve<'a>(sockets: &'a [u64]) -> Proc<'a> {
    Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        sockets,
        start_ticks: 4000,
        ..Proc::default()
    }
}

/// `ollama serve` bound to `address`, a licensed model.
fn runtime_on(address: &str) -> Session {
    let d = TempDir::new().unwrap();
    store(d.path(), LIB, true);
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen(address, 11434, 7001);
    session(d.path(), &fake)
}

const PUBLIC: &str = "finding:exposure.bind_public@listener:tcp/0.0.0.0:11434#7001";

#[test]
fn every_rule_has_a_remediation() {
    for rule in RULES {
        assert!(!rule.remediation.trim().is_empty(), "{}", rule.id);
    }
}

#[test]
fn a_finding_is_explained_from_the_session_and_the_catalog() {
    let s = runtime_on("0.0.0.0");
    let text = explain::finding(&s, PUBLIC, Format::Text).unwrap();
    let rule = RULES
        .iter()
        .find(|r| r.id == "exposure.bind_public")
        .unwrap();
    for expected in [
        PUBLIC,
        rule.id,
        rule.summary,
        rule.remediation,
        "default:exposure.bind_public",
        // The listener and the process it rests on, resolved from the session.
        "0.0.0.0",
        "11434",
        "process 4242",
        "ollama serve",
        "/usr/local/bin/ollama serve",
    ] {
        assert!(text.contains(expected), "{expected:?} missing:\n{text}");
    }
    // The decision raises the verdict to WARN.
    assert!(text.contains("WARN"), "{text}");

    let md = explain::finding(&s, PUBLIC, Format::Markdown).unwrap();
    assert!(md.starts_with("# "), "{md}");
    assert!(
        md.contains(&UntrustedText::new(PUBLIC).markdown_inline()),
        "{md}"
    );
}

#[test]
fn an_unknown_finding_names_the_findings_present() {
    let s = runtime_on("0.0.0.0");
    let err = explain::finding(&s, "finding:nope", Format::Text).unwrap_err();
    assert!(matches!(err, ExplainError::UnknownFinding { .. }));
    let message = err.to_string();
    assert!(message.contains("finding:nope"), "{message}");
    assert!(message.contains(PUBLIC), "{message}");

    let s = runtime_on("127.0.0.1");
    let message = explain::finding(&s, PUBLIC, Format::Text)
        .unwrap_err()
        .to_string();
    assert!(message.contains("no findings"), "{message}");
}

#[test]
fn without_findings_only_the_verdict_is_explained() {
    let s = runtime_on("127.0.0.1");
    assert!(s.findings.is_empty());
    let text = explain::verdict(&s, Format::Text);
    assert!(text.contains("PASS"), "{text}");
    assert!(text.contains("COMPLETE"), "{text}");
    assert!(text.contains("Nothing raises the verdict"), "{text}");
}

#[test]
fn the_verdict_lists_what_raised_it_and_what_is_missing() {
    // WARN, and INCOMPLETE: no license layer, and other users' processes may be hidden.
    let d = TempDir::new().unwrap();
    store(d.path(), LIB, false);
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.hide_pid1();
    let s = session(d.path(), &fake);
    assert_eq!(s.outcome.verdict, Verdict::Warn);
    let text = explain::verdict(&s, Format::Text);
    for f in &s.findings {
        assert!(text.contains(f.id.as_str()), "{} missing:\n{text}", f.id);
    }
    assert!(text.contains("INCOMPLETE"), "{text}");
    assert!(text.contains("exposure.binds"), "{text}");
    assert!(text.contains("unavailable: permission denied"), "{text}");

    let coverage = explain::coverage(&s, Format::Text);
    for c in &s.coverage {
        assert!(
            coverage.contains(c.check.as_str()),
            "{}:\n{coverage}",
            c.check
        );
    }
}

#[test]
fn explanations_are_byte_identical_for_the_same_session() {
    let s = runtime_on("0.0.0.0");
    let reloaded: Session = serde_json::from_str(&s.to_canonical_json().unwrap()).unwrap();
    for format in [Format::Text, Format::Markdown] {
        assert_eq!(
            explain::finding(&s, PUBLIC, format).unwrap(),
            explain::finding(&reloaded, PUBLIC, format).unwrap()
        );
        assert_eq!(
            explain::verdict(&s, format),
            explain::verdict(&reloaded, format)
        );
        assert_eq!(
            explain::coverage(&s, format),
            explain::coverage(&reloaded, format)
        );
    }
}

#[test]
fn input_text_is_escaped_in_every_format() {
    // A model whose manifest path carries Markdown, HTML, and a terminal escape, with no license
    // layer: `model.license_missing` is about it.
    let d = TempDir::new().unwrap();
    let path = "registry.ollama.ai/library/<b>|x`[l](u)\u{1b}[31m/latest";
    store(d.path(), path, false);
    let s = session(d.path(), &FakeProc::new());
    let finding = s
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "model.license_missing")
        .expect("a license finding");
    let md = explain::finding(&s, finding.id.as_str(), Format::Markdown).unwrap();
    for raw in ["<b>", ">|x", "`[l]", "](u)", "\u{1b}"] {
        assert!(!md.contains(raw), "{raw:?} reached the Markdown:\n{md}");
    }
    let text = explain::finding(&s, finding.id.as_str(), Format::Text).unwrap();
    assert!(
        !text.contains('\u{1b}'),
        "an escape reached the terminal:\n{text}"
    );
    assert!(text.contains("\\u{001B}"), "{text}");
}

#[test]
fn a_probe_is_explained_in_the_coverage() {
    let d = TempDir::new().unwrap();
    let fake = FakeProc::new();
    let target: std::net::SocketAddr = "127.0.0.1:11434".parse().unwrap();
    let active = ActiveInput {
        features: vec![ActiveFeature::ApiProbe {
            address: "127.0.0.1".to_string(),
            port: 11434,
            allow_remote: false,
        }],
        probes: vec![ApiProbe {
            id: ProbeId::api(target),
            address: "127.0.0.1".to_string(),
            port: 11434,
            at: Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
            result: ProbeResult::Refused,
        }],
        budgets: Default::default(),
    };
    let s = session_with(d.path(), &fake, &active);
    let text = explain::coverage(&s, Format::Text);
    assert!(text.contains("runtime_api.version"), "{text}");
    assert!(text.contains("probe:api/127.0.0.1:11434"), "{text}");
    assert!(
        text.contains("connection refused at 127.0.0.1:11434 from this host"),
        "{text}"
    );
}
