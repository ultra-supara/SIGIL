//! An observe-mode session: the model store and the runtime's exposure, with the built-in policy
//! (plan §4.6.8, §6.3). The exposure migration rows and the v0.1 runtime cases are stated on the
//! outcome, and every session passes `Session::validate`.

use std::path::Path;

use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{observe_session, ObserveRequest, StoreRequest};
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::{evaluate, Policy};
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::proc::*;
use common::*;

const BINDS: &str = "exposure.binds";

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

/// One model, complete, so that the model-store checks close.
fn good_store(d: &Path) {
    let weights = blob(d, b"weights");
    let license = blob(d, b"MIT");
    manifest(
        d,
        LIB,
        None,
        &[(MODEL_MEDIA, &weights), (LICENSE_MEDIA_TYPE, &license)],
    );
}

fn session(store: &Path, fake: &FakeProc) -> Session {
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
    let s = observe_session(
        &req,
        &Policy::builtin_default().unwrap(),
        ToolInfo {
            name: "sigil".to_string(),
            version: "0.0.0-test".to_string(),
            git_rev: None,
        },
        observation(),
        observation().started_at,
    )
    .unwrap();
    if let Err(errors) = s.validate() {
        let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
        panic!("invalid session:\n{}", text.join("\n"));
    }
    s
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

/// The outcome with a complete store and `ollama serve` holding socket 7001 bound as given.
fn outcome_with_runtime_on(address: &str) -> (Session, Verdict, Completeness) {
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen(address, 11434, 7001);
    let s = session(store.path(), &fake);
    let (v, c) = (s.outcome.verdict, s.outcome.completeness.clone());
    (s, v, c)
}

fn rules(s: &Session) -> Vec<&str> {
    s.findings.iter().map(|f| f.rule.as_str()).collect()
}

fn missing_binds() -> Completeness {
    Completeness::Incomplete {
        missing_required: vec![CheckId::new(BINDS).unwrap()],
        gaps: vec![],
    }
}

// --- v0.1 runtime cases ------------------------------------------------------------------------

#[test]
fn a_public_bind_warns() {
    let (s, verdict, completeness) = outcome_with_runtime_on("0.0.0.0");
    assert_eq!(rules(&s), ["exposure.bind_public"]);
    assert_eq!(
        (verdict, completeness),
        (Verdict::Warn, Completeness::Complete)
    );
}

#[test]
fn a_loopback_bind_passes() {
    let (s, verdict, completeness) = outcome_with_runtime_on("127.0.0.1");
    assert!(s.findings.is_empty());
    assert_eq!(
        (verdict, completeness),
        (Verdict::Pass, Completeness::Complete)
    );
}

#[test]
fn a_lan_bind_warns() {
    let (s, verdict, _) = outcome_with_runtime_on("10.0.0.5");
    assert_eq!(rules(&s), ["exposure.bind_lan"]);
    assert_eq!(verdict, Verdict::Warn);
}

// --- migration rows (§6.3) ---------------------------------------------------------------------

#[test]
fn an_ipv4_mapped_loopback_bind_is_loopback() {
    // I-09: v0.1 reported `::ffff:127.0.0.1` as a public bind.
    let (s, verdict, completeness) = outcome_with_runtime_on("::ffff:127.0.0.1");
    assert!(s.findings.is_empty());
    assert_eq!(
        (verdict, completeness),
        (Verdict::Pass, Completeness::Complete)
    );
}

#[test]
fn a_fronting_process_never_lowers_the_runtimes_class() {
    // I-10: v0.1 reported nginx on 0.0.0.0 as `proxy`, below `public_bind`.
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.process(&Proc {
        pid: 200,
        comm: "nginx",
        argv: &["nginx"],
        exe: Some("/usr/sbin/nginx"),
        sockets: &[9001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 443, 9001);
    let s = session(store.path(), &fake);
    assert_eq!(rules(&s), ["exposure.bind_public"]);
    assert_eq!(s.listeners.len(), 2, "the nginx listener is kept as a hint");
    assert_eq!(s.outcome.verdict, Verdict::Warn);
}

#[test]
fn an_unreadable_owner_is_incomplete_not_attributed() {
    // I-08: v0.1 continued silently with no owner and matched by port.
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    if !fake.deny_fds(4242) {
        eprintln!("SKIPPED: an unreadable fd table needs an unprivileged user");
        return;
    }
    let s = session(store.path(), &fake);
    assert!(s.findings.is_empty());
    assert_eq!(
        s.listeners[0].owner,
        ListenerOwner::Unknown {
            why: NotObservable::PermissionDenied
        }
    );
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Pass, missing_binds())
    );
}

#[test]
fn a_runtime_in_another_network_namespace_is_incomplete() {
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let fake = FakeProc::new();
    fake.process(&Proc {
        net_ns: 999,
        ..serve(&[])
    });
    let s = session(store.path(), &fake);
    assert_eq!(s.observation.net_ns, Some(OWN_NET_NS));
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Pass, missing_binds())
    );
}

// --- the request -------------------------------------------------------------------------------

#[test]
fn observe_mode_requires_the_exposure_check() {
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let s = session(store.path(), &FakeProc::new());
    assert_eq!(s.request.mode, Mode::Observe);
    assert!(s
        .request
        .required_checks
        .contains(&CheckId::new(BINDS).unwrap()));
    // No runtime is running: nothing of it listens.
    assert!(s.processes.is_empty());
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Pass, Completeness::Complete)
    );
}

#[test]
fn a_session_is_reproducible_and_re_evaluates_after_a_round_trip() {
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    let first = session(store.path(), &fake).to_canonical_json().unwrap();
    assert_eq!(
        first,
        session(store.path(), &fake).to_canonical_json().unwrap()
    );

    let mut reloaded: Session = serde_json::from_str(&first).unwrap();
    let time = reloaded.outcome.policy_time.clone();
    evaluate(&mut reloaded, &Policy::builtin_default().unwrap(), time).unwrap();
    assert_eq!(reloaded.to_canonical_json().unwrap(), first);
}

#[test]
fn a_process_that_may_be_the_runtime_is_incomplete_not_absent() {
    // Review of #74: `comm` says ollama, `cmdline` is over its limit, and it listens publicly.
    // Not knowing whether it is the runtime is not knowing that the runtime is absent.
    let long = "x".repeat(70 << 10);
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve", &long],
        exe: None,
        sockets: &[7001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 11434, 7001);
    let s = session(store.path(), &fake);
    assert!(
        s.findings.is_empty(),
        "no finding is made up: {:?}",
        rules(&s)
    );
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Pass, missing_binds())
    );
}

#[test]
fn a_runtime_whose_stat_cannot_be_read_is_incomplete() {
    // Review of #74: a confirmed runtime that cannot be recorded is not dropped silently.
    use std::os::unix::fs::PermissionsExt;
    for unreadable in [false, true] {
        let store = TempDir::new().unwrap();
        good_store(store.path());
        let mut fake = FakeProc::new();
        fake.process(&serve(&[7001]));
        fake.listen("0.0.0.0", 11434, 7001);
        let stat = fake.pid_dir(4242).join("stat");
        if unreadable {
            std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&stat).is_ok() {
                eprintln!("SKIPPED: an unreadable stat needs an unprivileged user");
                continue;
            }
        } else {
            std::fs::write(&stat, b"4242 (ollama) S").unwrap();
        }
        let s = session(store.path(), &fake);
        std::fs::set_permissions(&stat, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(s.findings.is_empty(), "{:?}", rules(&s));
        assert_eq!(
            (s.outcome.verdict, s.outcome.completeness.clone()),
            (Verdict::Pass, missing_binds()),
            "unreadable: {unreadable}"
        );
    }
}

#[test]
fn hidden_processes_leave_the_audit_incomplete_but_a_visible_finding_stands() {
    let store = TempDir::new().unwrap();
    good_store(store.path());
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.hide_pid1();
    let s = session(store.path(), &fake);
    assert_eq!(rules(&s), ["exposure.bind_public"]);
    assert_eq!(
        (s.outcome.verdict, s.outcome.completeness.clone()),
        (Verdict::Warn, missing_binds())
    );
}
