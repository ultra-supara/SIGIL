//! The `/proc` collector on a fake proc root (plan §4.6.8): which processes are the runtime, who
//! holds each listening socket, and what is recorded when something cannot be read.

use sigil_engine::observe::proc::{observe, ProcBudgets, ProcFacts};
use sigil_model::*;

mod common;
use common::proc::*;

fn at() -> Timestamp {
    Timestamp::new("2026-10-08T00:00:00Z").unwrap()
}

fn run(fake: &FakeProc) -> ProcFacts {
    run_with(fake, ProcBudgets::default())
}

fn run_with(fake: &FakeProc, budgets: ProcBudgets) -> ProcFacts {
    observe(fake.path(), &at(), BOOT_ID, budgets)
}

fn serve<'a>(pid: u32, sockets: &'a [u64]) -> Proc<'a> {
    Proc {
        pid,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        sockets,
        start_ticks: 4000,
        ..Proc::default()
    }
}

fn process_ref(pid: u32, start_ticks: u64) -> ProcessRef {
    ProcessRef {
        pid,
        start_ticks,
        boot_id: BOOT_ID.to_string(),
    }
}

fn t(text: &str) -> UntrustedText {
    UntrustedText::new(text)
}

#[test]
fn the_runtime_and_its_listeners_are_recorded() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    // Another owner: neither runtime nor fronting, so not recorded.
    fake.process(&Proc {
        pid: 100,
        sockets: &[8001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 22, 8001);

    let f = run(&fake);
    assert_eq!(f.own_net_ns, Some(OWN_NET_NS));
    assert!(f.pid1_visible);
    assert!(f.gaps.is_empty(), "{:?}", f.gaps);
    assert_eq!(
        f.processes,
        [ProcessObs {
            process: process_ref(4242, 4000),
            at: at(),
            roles: vec![ProcessRole::new("ollama serve").unwrap()],
            exe: ProcessExe::Path {
                path: t("/usr/local/bin/ollama"),
                deleted: false
            },
            mappings: vec![],
            name: Some(t("ollama")),
            argv: Some(vec![t("/usr/local/bin/ollama"), t("serve")]),
            net_ns: NsInode::Inode(OWN_NET_NS),
            fd_table: Observability::Observed,
        }]
    );
    assert_eq!(
        f.listeners,
        [Listener {
            id: ListenerId::new("listener:tcp/0.0.0.0:11434#7001").unwrap(),
            protocol: Protocol::Tcp,
            address: "0.0.0.0".to_string(),
            port: 11434,
            socket_inode: 7001,
            owner: ListenerOwner::Process {
                process: process_ref(4242, 4000)
            },
        }]
    );
}

#[test]
fn a_cmdline_that_the_exe_contradicts_is_not_the_runtime() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        exe: Some("/usr/bin/python3"),
        ..serve(4242, &[7001])
    });
    fake.listen("0.0.0.0", 11434, 7001);
    let f = run(&fake);
    assert!(f.processes.is_empty());
    assert!(
        f.listeners.is_empty(),
        "a known, non-runtime owner is not recorded"
    );
}

#[test]
fn an_unreadable_exe_leaves_the_role_on_the_cmdline() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        exe: None,
        ..serve(4242, &[7001])
    });
    fake.listen("127.0.0.1", 11434, 7001);
    let f = run(&fake);
    assert_eq!(f.processes.len(), 1);
    assert_eq!(
        f.processes[0].roles,
        [ProcessRole::new("ollama serve").unwrap()]
    );
    assert!(matches!(f.processes[0].exe, ProcessExe::NotObservable(_)));
}

#[test]
fn an_unreadable_fd_table_leaves_owners_unknown() {
    // I-08: v0.1 continued silently with no owner and matched by port.
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    if !fake.deny_fds(4242) {
        eprintln!("SKIPPED: an unreadable fd table needs an unprivileged user");
        return;
    }
    let f = run(&fake);
    assert_eq!(
        f.processes[0].fd_table,
        Observability::NotObservable(NotObservable::PermissionDenied)
    );
    assert_eq!(
        f.listeners[0].owner,
        ListenerOwner::Unknown {
            why: NotObservable::PermissionDenied
        }
    );
}

#[test]
fn fronting_listeners_are_kept_as_hints() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 200,
        comm: "nginx",
        argv: &["nginx: master process /usr/sbin/nginx"],
        exe: Some("/usr/sbin/nginx"),
        sockets: &[9001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 443, 9001);
    let f = run(&fake);
    assert_eq!(f.processes.len(), 1);
    let nginx = &f.processes[0];
    assert_eq!(nginx.name, Some(t("nginx")));
    assert!(nginx.roles.is_empty());
    assert_eq!(
        nginx.argv, None,
        "arguments are read only where a role rests on them"
    );
    assert_eq!(
        f.listeners[0].owner,
        ListenerOwner::Process {
            process: nginx.process.clone()
        }
    );
}

#[test]
fn a_socket_no_fd_table_holds_is_unheld() {
    let mut fake = FakeProc::new();
    fake.listen("127.0.0.1", 5000, 6001);
    let f = run(&fake);
    assert_eq!(f.listeners[0].owner, ListenerOwner::Unheld);
}

#[test]
fn ipv6_and_mapped_addresses_are_kept_as_read() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7002, 7003]));
    fake.listen("::ffff:127.0.0.1", 11434, 7002);
    fake.listen("::", 8080, 7003);
    let f = run(&fake);
    let ids: Vec<&str> = f.listeners.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "listener:tcp6/[::]:8080#7003",
            "listener:tcp6/[::ffff:127.0.0.1]:11434#7002"
        ]
    );
    assert_eq!(f.listeners[1].address, "::ffff:127.0.0.1");
    assert_eq!(f.listeners[1].protocol, Protocol::Tcp6);
}

#[test]
fn network_namespaces_are_recorded() {
    let fake = FakeProc::new();
    fake.process(&Proc {
        net_ns: 999,
        ..serve(4242, &[])
    });
    let f = run(&fake);
    assert_eq!(f.own_net_ns, Some(OWN_NET_NS));
    assert_eq!(f.processes[0].net_ns, NsInode::Inode(999));
}

#[test]
fn a_hidden_pid_1_is_reported() {
    let fake = FakeProc::new();
    fake.hide_pid1();
    assert!(!run(&fake).pid1_visible);
}

#[test]
fn budgets_bound_what_is_read() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.process(&Proc {
        pid: 100,
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 11434, 7001);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_processes: 1,
            ..ProcBudgets::default()
        },
    );
    assert!(!f.gaps.is_empty());
    let f = run_with(
        &fake,
        ProcBudgets {
            max_table_bytes: 16,
            ..ProcBudgets::default()
        },
    );
    assert!(!f.gaps.is_empty());
    assert!(f.listeners.is_empty());
}

#[test]
fn only_ollama_serve_is_the_runtime() {
    let mut fake = FakeProc::new();
    // A client command of the same binary.
    fake.process(&Proc {
        pid: 300,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "run", "gemma4"],
        exe: Some("/usr/local/bin/ollama"),
        ..Proc::default()
    });
    // `cmdline` is read only for processes named `ollama`: another name is not considered.
    fake.process(&Proc {
        pid: 301,
        comm: "renamed",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 1, 1);
    assert!(run(&fake).processes.is_empty());
}

#[test]
fn a_socket_the_runtime_shares_with_a_fronting_process_is_the_runtimes() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.process(&Proc {
        pid: 200,
        comm: "nginx",
        argv: &["nginx"],
        exe: Some("/usr/sbin/nginx"),
        sockets: &[7001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 11434, 7001);
    let f = run(&fake);
    assert_eq!(
        f.listeners[0].owner,
        ListenerOwner::Process {
            process: process_ref(4242, 4000)
        }
    );
}

#[test]
fn the_fd_budget_bounds_each_table() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001, 7002]));
    fake.listen("0.0.0.0", 11434, 7001);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_fds: 1,
            ..ProcBudgets::default()
        },
    );
    // Recorded on the process: what was listed stands, the rest leaves its binds open.
    assert_eq!(
        f.processes[0].fd_table,
        Observability::NotObservable(NotObservable::ReadIncomplete)
    );
}

// --- what could not be seen is not absent (review of #74) --------------------------------------

#[test]
fn a_process_that_cannot_be_identified_is_a_gap_not_absent() {
    // `comm` says ollama, but `cmdline` is over its limit: it may be the runtime.
    let long = "x".repeat(70 << 10);
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
    let f = run(&fake);
    assert!(
        f.gaps.iter().any(|g| g.contains("4242")),
        "the unidentified process is a gap: {:?}",
        f.gaps
    );
    // Its listener is kept, held by it, with no role claimed.
    assert_eq!(f.listeners.len(), 1);
    let ListenerOwner::Process { process } = &f.listeners[0].owner else {
        panic!("{:?}", f.listeners[0].owner);
    };
    assert_eq!(process.pid, 4242);
    assert!(f.processes.iter().all(|p| p.roles.is_empty()));
}

#[test]
fn a_partially_listed_fd_table_never_makes_a_listener_unheld() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 100,
        sockets: &[8001, 8002, 8003],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 22, 8003);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_fds: 1,
            ..ProcBudgets::default()
        },
    );
    assert!(
        matches!(f.listeners[0].owner, ListenerOwner::Unknown { .. }),
        "{:?}",
        f.listeners[0].owner
    );
}

#[test]
fn an_unreadable_process_directory_is_a_gap() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    if !fake.deny_dir(4242) {
        eprintln!("SKIPPED: an unreadable process directory needs an unprivileged user");
        return;
    }
    let f = run(&fake);
    assert!(f.gaps.iter().any(|g| g.contains("4242")), "{:?}", f.gaps);
    assert!(matches!(
        f.listeners[0].owner,
        ListenerOwner::Unknown { .. }
    ));
}

#[test]
fn a_malformed_listen_row_is_a_gap_and_the_others_stand() {
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.raw_tcp("   9: ZZZZZZZZ:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8917 1 0 100 0 0 10 0");
    let f = run(&fake);
    assert!(f.gaps.iter().any(|g| g.contains("net/tcp")), "{:?}", f.gaps);
    assert_eq!(f.listeners.len(), 1);
}

#[test]
fn an_fd_link_that_cannot_be_read_leaves_the_table_incomplete() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 100,
        sockets: &[8001],
        ..Proc::default()
    });
    // Not a link: `readlinkat` fails, so this table was not read completely.
    std::fs::write(fake.pid_dir(100).join("fd/9"), b"").unwrap();
    fake.listen("0.0.0.0", 22, 8002);
    let f = run(&fake);
    assert!(
        matches!(f.listeners[0].owner, ListenerOwner::Unknown { .. }),
        "{:?}",
        f.listeners[0].owner
    );
}

#[test]
fn a_process_whose_name_cannot_be_read_is_a_gap() {
    use std::os::unix::fs::PermissionsExt;
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    let comm = fake.pid_dir(4242).join("comm");
    std::fs::set_permissions(&comm, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&comm).is_ok() {
        eprintln!("SKIPPED: an unreadable comm needs an unprivileged user");
        return;
    }
    let f = run(&fake);
    std::fs::set_permissions(&comm, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f.gaps.iter().any(|g| g.contains("4242")), "{:?}", f.gaps);
}
