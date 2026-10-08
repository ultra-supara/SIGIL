//! Exposure findings and `exposure.binds` coverage from observed facts (plan §4.6.8, §6.3).

use std::fs;

use sigil_engine::analyze::exposure::{analyze, bind_class, BindClass, BINDS};
use sigil_engine::observe::proc::{observe, ProcBudgets, ProcFacts};
use sigil_model::*;

mod common;
use common::proc::*;

fn facts(fake: &FakeProc) -> ProcFacts {
    observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        BOOT_ID,
        ProcBudgets::default(),
    )
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

fn rules(findings: &[Finding]) -> Vec<(&str, &str)> {
    findings
        .iter()
        .map(|f| (f.rule.as_str(), f.id.as_str()))
        .collect()
}

fn runtime_scope(f: &ProcFacts) -> Ref {
    Ref::Process(f.processes[0].process.clone())
}

fn binds<'a>(coverage: &'a [Coverage], scope: &Ref) -> Option<&'a CoverageState> {
    coverage
        .iter()
        .find(|c| c.check.as_str() == BINDS && c.scope == *scope)
        .map(|c| &c.state)
}

// --- bind classes (v0.1 classification cases, and I-09) ---------------------------------------

#[test]
fn bind_classes_come_from_the_address_alone() {
    for (address, class) in [
        ("127.0.0.1", BindClass::Loopback),
        ("0.0.0.0", BindClass::Wildcard),
        ("8.8.8.8", BindClass::Global),
        ("192.168.1.10", BindClass::Private),
        ("10.0.0.5", BindClass::Private),
        ("169.254.1.1", BindClass::Private),
        ("::1", BindClass::Loopback),
        ("::", BindClass::Wildcard),
        ("fd00::1", BindClass::Private),
        ("fe80::1", BindClass::Private),
        ("2001:db8::7", BindClass::Global),
        // I-09: v0.1 classed IPv4-mapped loopback as global.
        ("::ffff:127.0.0.1", BindClass::Loopback),
        ("::ffff:10.0.0.5", BindClass::Private),
        ("::ffff:8.8.8.8", BindClass::Global),
        ("::ffff:0.0.0.0", BindClass::Wildcard),
    ] {
        assert_eq!(bind_class(address.parse().unwrap()), class, "{address}");
    }
}

// --- findings ---------------------------------------------------------------------------------

#[test]
fn the_runtimes_public_and_lan_binds_are_findings() {
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001, 7002, 7003, 7004]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.listen("10.0.0.5", 11435, 7002);
    fake.listen("127.0.0.1", 11436, 7003);
    fake.listen("::ffff:127.0.0.1", 11437, 7004);
    let f = facts(&fake);
    let (findings, coverage) = analyze(&f);
    assert_eq!(
        rules(&findings),
        [
            (
                "exposure.bind_public",
                "finding:exposure.bind_public@listener:tcp/0.0.0.0:11434#7001"
            ),
            (
                "exposure.bind_lan",
                "finding:exposure.bind_lan@listener:tcp/10.0.0.5:11435#7002"
            ),
        ]
    );
    assert_eq!(
        binds(&coverage, &runtime_scope(&f)),
        Some(&CoverageState::Complete)
    );
    // Each rests on the observed listener and the process that holds it.
    for finding in &findings {
        let CondState::Met {
            evidence: CondEvidence::Observed { facts },
        } = &finding.conditions[0].state
        else {
            panic!("{}: not observed", finding.id);
        };
        assert!(matches!(facts[0], EvidenceRef::Listener { .. }));
        assert!(matches!(facts[1], EvidenceRef::Process { .. }));
    }
}

#[test]
fn a_public_listener_of_a_fronting_process_is_a_hint_not_a_finding() {
    // §6.3 "nginx on 0.0.0.0": the runtime's own bind decides; a process name never lowers it.
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
    let f = facts(&fake);
    assert_eq!(f.listeners.len(), 2, "the nginx listener is recorded");
    let (findings, _) = analyze(&f);
    assert_eq!(
        rules(&findings),
        [(
            "exposure.bind_public",
            "finding:exposure.bind_public@listener:tcp/0.0.0.0:11434#7001"
        )]
    );
}

// --- coverage ---------------------------------------------------------------------------------

#[test]
fn without_a_runtime_the_audit_is_complete_unless_processes_are_hidden() {
    let mut fake = FakeProc::new();
    fake.listen("0.0.0.0", 22, 8001);
    let (findings, coverage) = analyze(&facts(&fake));
    assert!(findings.is_empty());
    assert_eq!(
        binds(&coverage, &Ref::Audit),
        Some(&CoverageState::Complete)
    );

    fake.hide_pid1();
    let (_, coverage) = analyze(&facts(&fake));
    assert_eq!(
        binds(&coverage, &Ref::Audit),
        Some(&CoverageState::Unavailable {
            why: Unavailability::PermissionDenied
        })
    );
}

#[test]
fn an_unreadable_fd_table_leaves_the_runtimes_binds_unavailable() {
    // I-08: "bind observed, owner unknown" is not a finding about the runtime.
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    if !fake.deny_fds(4242) {
        eprintln!("SKIPPED: an unreadable fd table needs an unprivileged user");
        return;
    }
    let f = facts(&fake);
    let (findings, coverage) = analyze(&f);
    assert!(findings.is_empty());
    assert_eq!(
        binds(&coverage, &runtime_scope(&f)),
        Some(&CoverageState::Unavailable {
            why: Unavailability::PermissionDenied
        })
    );
}

#[test]
fn another_network_namespace_leaves_the_runtimes_binds_open() {
    let fake = FakeProc::new();
    fake.process(&Proc {
        net_ns: 999,
        ..serve(&[])
    });
    let f = facts(&fake);
    let (_, coverage) = analyze(&f);
    assert_eq!(
        binds(&coverage, &runtime_scope(&f)),
        Some(&CoverageState::Partial {
            missing: vec!["listeners in another network namespace".to_string()]
        })
    );

    // An unreadable namespace leaves it open too, but the binds seen in SIGIL's table stand.
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fs::remove_file(fake.pid_dir(4242).join("ns/net")).unwrap();
    let f = facts(&fake);
    let (findings, coverage) = analyze(&f);
    assert_eq!(findings.len(), 1);
    assert!(matches!(
        binds(&coverage, &runtime_scope(&f)),
        Some(CoverageState::Partial { .. })
    ));
}

#[test]
fn read_gaps_leave_the_binds_open() {
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    let f = observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        BOOT_ID,
        ProcBudgets {
            max_table_bytes: 16,
            ..ProcBudgets::default()
        },
    );
    let (findings, coverage) = analyze(&f);
    assert!(findings.is_empty(), "the table was not read");
    assert!(matches!(
        binds(&coverage, &runtime_scope(&f)),
        Some(CoverageState::Partial { .. })
    ));
}

#[test]
fn a_runtime_fd_table_listed_in_part_leaves_its_binds_open() {
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001, 7002, 7003]));
    fake.listen("0.0.0.0", 11434, 7001);
    let f = observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        BOOT_ID,
        ProcBudgets {
            max_fds: 1,
            ..ProcBudgets::default()
        },
    );
    let (_, coverage) = analyze(&f);
    assert!(
        matches!(
            binds(&coverage, &runtime_scope(&f)),
            Some(CoverageState::Partial { .. })
        ),
        "{coverage:?}"
    );
}

#[test]
fn a_hidden_process_table_is_kept_on_the_audit_next_to_a_visible_runtime() {
    // Review of #74: PID 1 hidden, and a runtime that is visible binds publicly.
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.hide_pid1();
    let f = facts(&fake);
    let (findings, coverage) = analyze(&f);
    // The visible runtime's finding stands.
    assert_eq!(findings.len(), 1);
    // Other users' processes may be hidden: the audit keeps that.
    assert_eq!(
        binds(&coverage, &Ref::Audit),
        Some(&CoverageState::Unavailable {
            why: Unavailability::PermissionDenied
        })
    );
}

#[test]
fn an_incomplete_process_list_is_partial_not_a_denial() {
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    let f = observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        BOOT_ID,
        ProcBudgets {
            max_processes: 0,
            ..ProcBudgets::default()
        },
    );
    let (_, coverage) = analyze(&f);
    assert!(
        matches!(
            binds(&coverage, &Ref::Audit),
            Some(CoverageState::Partial { .. })
        ),
        "{coverage:?}"
    );
}

#[test]
fn a_denied_process_list_is_unavailable() {
    use std::os::unix::fs::PermissionsExt;
    let fake = FakeProc::new();
    let mode = |m| fs::Permissions::from_mode(m);
    fs::set_permissions(fake.path(), mode(0o000)).unwrap();
    if fs::read_dir(fake.path()).is_ok() {
        fs::set_permissions(fake.path(), mode(0o755)).unwrap();
        eprintln!("SKIPPED: a denied proc root needs an unprivileged user");
        return;
    }
    let f = facts(&fake);
    fs::set_permissions(fake.path(), mode(0o755)).unwrap();
    assert_eq!(
        f.process_list,
        Observability::NotObservable(NotObservable::PermissionDenied)
    );
    let (_, coverage) = analyze(&f);
    assert_eq!(
        binds(&coverage, &Ref::Audit),
        Some(&CoverageState::Unavailable {
            why: Unavailability::PermissionDenied
        })
    );
}

#[test]
fn an_unknown_boot_leaves_the_runtimes_binds_open() {
    // Review of #75: without the boot ID, a process is known by PID and start time only, which
    // do not identify it across boots.
    let mut fake = FakeProc::new();
    fake.process(&serve(&[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    let f = observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        "",
        ProcBudgets::default(),
    );
    let (findings, coverage) = analyze(&f);
    assert_eq!(findings.len(), 1, "the bind observed in this run stands");
    match binds(&coverage, &runtime_scope(&f)) {
        Some(CoverageState::Partial { missing }) => {
            assert!(missing.iter().any(|m| m.contains("boot ID")), "{missing:?}")
        }
        other => panic!("{other:?}"),
    }
    // Which processes were seen does not depend on it.
    assert_eq!(
        binds(&coverage, &Ref::Audit),
        Some(&CoverageState::Complete)
    );
}
