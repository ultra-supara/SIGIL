//! The `/proc` collector on a fake proc root (plan §4.6.8): which processes are the runtime, who
//! holds each listening socket, and what is recorded when something cannot be read.

use std::os::unix::fs::PermissionsExt;

use sigil_engine::observe::proc::{observe, Detail, ProcBudgets, ProcFacts, RUNTIME_ROLE};
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
    assert_eq!(f.process_list, Observability::Observed);
    assert!(f.gaps.is_empty(), "{:?}", f.gaps);
    assert_eq!(
        f.processes,
        [ProcessObs {
            process: process_ref(4242, 4000),
            at: at(),
            roles: vec![ProcessRole::new("ollama serve").unwrap()],
            exe: ProcessExe::Path {
                path: t(fake.fs("/usr/local/bin/ollama").to_str().unwrap()),
                deleted: false
            },
            mappings: vec![],
            maps_read: MapsRead::Whole,
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
    // Re-review of PR-4d-2: its state says it is alive, so a missing `exe` is a gap, not an exit.
    let d = detail(&f, 4242);
    assert_eq!(d.exe_id, None);
    assert_eq!(d.missing, ["exe: its identity cannot be read (NoProcess)"]);
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
    // Review of R1: outside the runtime's tree, it is not read again, and says so.
    assert_eq!(f.outside, std::slice::from_ref(&nginx.process));
    assert!(f.details.is_empty(), "{:?}", f.details);
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
    // Which fd entry is listed first depends on the file system, so the listener's socket is one
    // no table holds: it is unmatched whatever part of the table was listed.
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 100,
        sockets: &[8001, 8002, 8003],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 22, 8009);
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

#[test]
fn an_incomplete_process_list_never_makes_a_listener_unheld() {
    // A socket no listed process holds. Which PIDs fit in the budget depends on the listing
    // order, so the socket is one no process holds at all: whatever was listed, it is unmatched.
    let mut fake = FakeProc::new();
    for pid in [100, 200, 300] {
        fake.process(&Proc {
            pid,
            ..Proc::default()
        });
    }
    fake.listen("0.0.0.0", 22, 9001);
    // No process is listed (the budget is zero): no table was read, so nothing is unheld. The
    // list was cut short by its budget, which is not a denial: PID 1 not being listed says
    // nothing about `hidepid` here.
    let f = run_with(
        &fake,
        ProcBudgets {
            max_processes: 0,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(
        f.process_list,
        Observability::NotObservable(NotObservable::ReadIncomplete)
    );
    assert_eq!(
        f.listeners[0].owner,
        ListenerOwner::Unknown {
            why: NotObservable::ReadIncomplete
        }
    );
    // The same store, listed completely: unheld.
    assert_eq!(run(&fake).listeners[0].owner, ListenerOwner::Unheld);
}

#[test]
fn a_hidden_process_table_never_makes_a_listener_unheld() {
    // Under `hidepid`, other users' processes are not listed at all.
    let mut fake = FakeProc::new();
    fake.listen("0.0.0.0", 22, 9001);
    fake.hide_pid1();
    let f = run(&fake);
    assert_eq!(
        f.listeners[0].owner,
        ListenerOwner::Unknown {
            why: NotObservable::PermissionDenied
        }
    );
}

#[test]
fn a_runtime_that_cannot_be_recorded_is_a_gap_and_its_listener_is_unknown() {
    // `ollama serve`, confirmed, but its `stat` cannot be parsed: it cannot be recorded.
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    std::fs::write(fake.pid_dir(4242).join("stat"), b"garbage").unwrap();
    let f = run(&fake);
    assert!(f.processes.is_empty());
    assert!(f.gaps.iter().any(|g| g.contains("4242")), "{:?}", f.gaps);
    assert!(
        matches!(f.listeners[0].owner, ListenerOwner::Unknown { .. }),
        "{:?}",
        f.listeners[0].owner
    );
}

#[test]
fn a_runtime_whose_stat_is_gone_has_exited() {
    // `stat` missing (ENOENT) means the process exited between the listing and the read: its
    // sockets went with it, so it is skipped, not a gap.
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    std::fs::remove_file(fake.pid_dir(4242).join("stat")).unwrap();
    let f = run(&fake);
    assert!(f.processes.is_empty());
    assert!(f.gaps.is_empty(), "{:?}", f.gaps);
}

#[test]
fn cmdline_is_opened_only_for_processes_named_ollama_and_again_only_for_the_runtime() {
    // Re-review of #74: the role rests on `cmdline`, and the argv recorded must be that same
    // evidence, so it is one read. It is never opened for a process whose `comm` is not
    // `ollama`, even one that is recorded (nginx, fronting). Code review of PR-4d-2, R-B: the
    // second pass opens the runtime's once more, only to compare it with that read. Review of
    // R2: never a descendant's: one named `ollama` is opened once, by the listing pass, and
    // another not at all.
    let mut fake = FakeProc::new();
    fake.process(&serve(4242, &[7001]));
    fake.listen("0.0.0.0", 11434, 7001);
    fake.process(&Proc {
        pid: 4300,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "runner", "--port", "1"],
        exe: Some("/usr/local/bin/ollama"),
        ppid: 4242,
        start_ticks: 4100,
        ..Proc::default()
    });
    fake.process(&Proc {
        pid: 4301,
        comm: "llama-server",
        argv: &["/usr/local/lib/ollama/llama-server"],
        exe: Some("/usr/local/lib/ollama/llama-server"),
        ppid: 4242,
        start_ticks: 4101,
        ..Proc::default()
    });
    fake.process(&Proc {
        pid: 200,
        comm: "nginx",
        argv: &["nginx"],
        exe: Some("/usr/sbin/nginx"),
        sockets: &[9001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 443, 9001);
    fake.process(&Proc::default());
    let opens = Opens::watch(&[
        fake.pid_dir(4242).join("cmdline"),
        fake.pid_dir(4300).join("cmdline"),
        fake.pid_dir(4301).join("cmdline"),
        fake.pid_dir(200).join("cmdline"),
        fake.pid_dir(100).join("cmdline"),
        fake.pid_dir(1).join("cmdline"),
    ]);
    let f = run(&fake);
    assert_eq!(opens.counts(), [2, 1, 0, 0, 0, 0]);
    // Both descendants were read by the second pass.
    for pid in [4300, 4301] {
        assert!(detail(&f, pid).missing.is_empty(), "{:?}", detail(&f, pid));
    }

    let runtime = f.processes.iter().find(|p| p.process.pid == 4242).unwrap();
    assert_eq!(runtime.roles, [ProcessRole::new(RUNTIME_ROLE).unwrap()]);
    let argv: Vec<&[u8]> = runtime
        .argv
        .as_ref()
        .expect("the runtime's argv is recorded")
        .iter()
        .map(UntrustedText::as_bytes)
        .collect();
    assert_eq!(argv, [&b"/usr/local/bin/ollama"[..], b"serve"]);
    let nginx = f.processes.iter().find(|p| p.process.pid == 200).unwrap();
    assert_eq!(nginx.argv, None);
}

fn serve_at(fake: &FakeProc, maps: &str) {
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        start_ticks: 4000,
        maps,
        ..Proc::default()
    });
}

fn detail(f: &ProcFacts, pid: u32) -> &Detail {
    f.details
        .iter()
        .find(|d| d.process.pid == pid)
        .unwrap_or_else(|| panic!("no detail for {pid}: {:?}", f.details))
}

/// PR-4d-2: the runtime's children and theirs are recorded, an unrelated process is not; each
/// one's executable identity is its target's, and its file-backed mappings are listed once per
/// distinct (dev, ino, path, deleted), unlinked.
#[test]
fn the_runtime_and_its_descendants_are_observed() {
    let fake = FakeProc::new();
    let lib = fake.fs("/usr/local/lib/ollama/libggml-cpu.so");
    std::fs::create_dir_all(lib.parent().unwrap()).unwrap();
    std::fs::write(&lib, b"lib").unwrap();
    let line = maps_line(&lib);
    let maps = format!("{line}\n{line}\n7f00-7f10 rw-p 00000000 00:00 0 [heap]\n");
    serve_at(&fake, "");
    fake.process(&Proc {
        pid: 4300,
        comm: "llama-server",
        argv: &["/usr/local/lib/ollama/llama-server", "--port", "1"],
        exe: Some("/usr/local/lib/ollama/llama-server"),
        ppid: 4242,
        start_ticks: 4100,
        maps: &maps,
        ..Proc::default()
    });
    // A lower PID than its parent: one pass in PID order would miss it.
    fake.process(&Proc {
        pid: 4250,
        comm: "gpu-discover",
        ppid: 4300,
        start_ticks: 4200,
        ..Proc::default()
    });
    fake.process(&Proc {
        pid: 4500,
        comm: "bash",
        ppid: 1,
        start_ticks: 4300,
        ..Proc::default()
    });
    let f = run(&fake);
    let pids: Vec<u32> = f.processes.iter().map(|p| p.process.pid).collect();
    assert_eq!(pids, [4242, 4250, 4300]);
    let runner = &f.processes[2];
    assert!(runner.roles.is_empty());
    assert_eq!(runner.argv, None);
    assert_eq!(runner.name, Some(t("llama-server")));
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(&lib).unwrap();
    assert_eq!(runner.mappings.len(), 1, "{:?}", runner.mappings);
    let mapping = &runner.mappings[0];
    assert_eq!((mapping.dev, mapping.ino), (m.dev(), m.ino()));
    assert_eq!(mapping.path_text, t(lib.to_str().unwrap()));
    assert_eq!(mapping.process, runner.process);
    assert!(!mapping.deleted);
    assert_eq!(mapping.instance, None);
    assert!(matches!(mapping.same_mount_ns, Tri::Yes { .. }));
    let exe = std::fs::metadata(fake.fs("/usr/local/bin/ollama")).unwrap();
    assert_eq!(detail(&f, 4242).exe_id, Some((exe.dev(), exe.ino())));
    for p in &f.processes {
        assert_eq!(p.maps_read, MapsRead::Whole, "{}", p.process.pid);
    }
    for pid in [4242, 4250, 4300] {
        assert!(
            detail(&f, pid).missing.is_empty(),
            "{pid}: {:?}",
            detail(&f, pid)
        );
        assert!(!detail(&f, pid).denied);
    }
    assert!(f.process_gaps.is_empty(), "{:?}", f.process_gaps);
}

#[test]
fn a_mapping_in_another_mount_namespace_says_so() {
    let fake = FakeProc::new();
    let lib = fake.fs("/lib.so");
    std::fs::write(&lib, b"x").unwrap();
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        mnt_ns: 4026532000,
        maps: &maps_line(&lib),
        ..Proc::default()
    });
    let f = run(&fake);
    assert!(matches!(
        f.processes[0].mappings[0].same_mount_ns,
        Tri::No { .. }
    ));
}

#[test]
fn maps_over_its_budget_keeps_the_lines_read() {
    let fake = FakeProc::new();
    let a = fake.fs("/a.so");
    let b = fake.fs("/b.so");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let first = maps_line(&a);
    let maps = format!("{first}\n{}\n", maps_line(&b));
    serve_at(&fake, &maps);
    // The first line, its newline, and two bytes of the second: that cut line is not read.
    let limit = first.len() as u64 + 3;
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_bytes: limit,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(f.processes[0].mappings.len(), 1);
    assert_eq!(f.processes[0].maps_read, MapsRead::Part);
    assert_eq!(
        detail(&f, 4242).missing,
        [format!("maps: over proc_maps_bytes ({limit} bytes read)")]
    );
}

#[test]
fn a_maps_line_not_understood_is_a_gap_and_the_others_stand() {
    let fake = FakeProc::new();
    let a = fake.fs("/a.so");
    std::fs::write(&a, b"a").unwrap();
    serve_at(&fake, &format!("{}\ngarbage\n", maps_line(&a)));
    let f = run(&fake);
    assert_eq!(f.processes[0].mappings.len(), 1);
    assert_eq!(f.processes[0].maps_read, MapsRead::Part);
    assert_eq!(detail(&f, 4242).missing, ["maps: 1 lines not understood"]);
}

#[test]
fn unreadable_maps_and_executable_are_denied() {
    let fake = FakeProc::new();
    serve_at(&fake, "");
    if !fake.deny(4242, "maps") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    // `stat` through `exe` needs search permission on the target's directory.
    let bin = fake.fs("/usr/local/bin");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o000)).unwrap();
    let f = run(&fake);
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let d = detail(&f, 4242);
    assert!(d.denied, "{d:?}");
    assert_eq!(d.exe_id, None);
    assert!(f.processes[0].mappings.is_empty());
    assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
}

#[test]
fn unreadable_maps_alone_is_a_gap_not_a_denial() {
    let fake = FakeProc::new();
    serve_at(&fake, "");
    if !fake.deny(4242, "maps") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let f = run(&fake);
    let d = detail(&f, 4242);
    assert!(!d.denied);
    assert_eq!(d.missing, ["maps: cannot be read (PermissionDenied)"]);
    assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
}

#[test]
fn a_process_whose_parent_cannot_be_read_is_a_process_gap() {
    let fake = FakeProc::new();
    serve_at(&fake, "");
    fake.process(&Proc {
        pid: 4500,
        comm: "bash",
        start_ticks: 4300,
        ..Proc::default()
    });
    if !fake.deny(4500, "stat") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let f = run(&fake);
    assert_eq!(
        f.process_gaps,
        ["process 4500: its parent cannot be read (PermissionDenied)"]
    );
}

/// External review of PR-4d-2: a process that may be the runtime may have descendants that
/// were not observed. Its gap is a process gap too; the rest stands as before.
#[test]
fn a_process_that_may_be_the_runtime_is_a_process_gap() {
    let fake = FakeProc::new();
    serve_at(&fake, "");
    if !fake.deny(4242, "comm") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let f = run(&fake);
    let gap = "process 4242 may be the runtime: its name cannot be read";
    assert_eq!(f.process_gaps, [gap]);
    assert_eq!(f.gaps, [gap]);
    assert!(f.processes.is_empty(), "{:?}", f.processes);
    assert!(f.details.is_empty(), "{:?}", f.details);
}

/// The runtime (one `maps` line per given file) and its child 4300 (one line).
fn two_observed(fake: &FakeProc, runtime: &[&std::path::Path], child: &std::path::Path) {
    let mut maps = String::new();
    for path in runtime {
        maps += &maps_line(path);
        maps += "\n";
    }
    serve_at(fake, &maps);
    fake.process(&Proc {
        pid: 4300,
        comm: "llama-server",
        ppid: 4242,
        start_ticks: 4100,
        maps: &format!("{}\n", maps_line(child)),
        ..Proc::default()
    });
}

fn so(fake: &FakeProc, name: &str) -> std::path::PathBuf {
    let path = fake.fs(name);
    std::fs::write(&path, name).unwrap();
    path
}

/// External review of PR-4d-2: `maps` is bounded over all processes too. Once the total is
/// spent, a process's `maps` is not read.
#[test]
fn the_total_maps_budget_spent_leaves_the_next_maps_unread() {
    let fake = FakeProc::new();
    let (a, b) = (so(&fake, "/a.so"), so(&fake, "/b.so"));
    two_observed(&fake, &[&a], &b);
    let total = maps_line(&a).len() as u64 + 1;
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_total_bytes: total,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(f.processes[0].mappings.len(), 1);
    assert_eq!(f.processes[0].maps_read, MapsRead::Whole);
    assert!(
        detail(&f, 4242).missing.is_empty(),
        "{:?}",
        detail(&f, 4242)
    );
    assert!(f.processes[1].mappings.is_empty());
    assert_eq!(f.processes[1].maps_read, MapsRead::NotRead);
    let d = detail(&f, 4300);
    assert_eq!(
        d.missing,
        ["maps: not read (proc_maps_total_bytes reached)"]
    );
    assert!(!d.denied);
}

#[test]
fn a_maps_cut_by_the_total_budget_says_so() {
    let fake = FakeProc::new();
    let (a, b) = (so(&fake, "/a.so"), so(&fake, "/b.so"));
    two_observed(&fake, &[&a, &b], &b);
    // The first line, its newline, and two bytes of the second.
    let total = maps_line(&a).len() as u64 + 3;
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_total_bytes: total,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(f.processes[0].mappings.len(), 1);
    assert_eq!(f.processes[0].maps_read, MapsRead::Part);
    assert_eq!(f.processes[1].maps_read, MapsRead::NotRead);
    assert_eq!(
        detail(&f, 4242).missing,
        [format!(
            "maps: over proc_maps_total_bytes ({total} bytes were left)"
        )]
    );
    assert_eq!(
        detail(&f, 4300).missing,
        ["maps: not read (proc_maps_total_bytes reached)"]
    );
}

/// Review of R1: a `maps` cut short before its first line keeps no mapping. It is `NotRead`, not
/// a read in part of nothing, and its gap stands.
#[test]
fn a_maps_cut_before_its_first_line_is_not_read() {
    let fake = FakeProc::new();
    let a = so(&fake, "/a.so");
    serve_at(&fake, &format!("{}\n", maps_line(&a)));
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_total_bytes: 3,
            ..ProcBudgets::default()
        },
    );
    assert!(f.processes[0].mappings.is_empty());
    assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
    assert_eq!(
        detail(&f, 4242).missing,
        ["maps: over proc_maps_total_bytes (3 bytes were left)"]
    );
}

/// The paths of a process's mappings, in the order kept.
fn paths(p: &ProcessObs) -> Vec<UntrustedText> {
    p.mappings.iter().map(|m| m.path_text.clone()).collect()
}

/// A fixture file's path, as its `maps` line names it.
fn text(path: &std::path::Path) -> UntrustedText {
    t(path.to_str().unwrap())
}

/// Code review of PR-4d-2, R-D: the mappings kept are bounded over all processes too
/// (`proc_maps_entries`). A process keeps those within it, in the order first seen; the one that
/// would exceed it is not kept, and no line after it is parsed (the line not understood at the
/// end is no gap).
#[test]
fn the_entries_budget_keeps_the_first_mappings_and_says_so() {
    let fake = FakeProc::new();
    let (a, b, c) = (so(&fake, "/a.so"), so(&fake, "/b.so"), so(&fake, "/c.so"));
    let maps = format!(
        "{}\n{}\n{}\ngarbage\n",
        maps_line(&a),
        maps_line(&b),
        maps_line(&c)
    );
    serve_at(&fake, &maps);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_entries: 2,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(paths(&f.processes[0]), [text(&a), text(&b)]);
    assert_eq!(f.processes[0].maps_read, MapsRead::Part);
    assert_eq!(
        detail(&f, 4242).missing,
        ["maps: over proc_maps_entries (2 records kept)"]
    );
}

/// Code review of PR-4d-2, R-D: a duplicate is not kept, so it uses none of the budget, before
/// the budget is reached or once it is: three lines naming two objects are read whole.
#[test]
fn a_duplicate_mapping_uses_none_of_the_entries_budget() {
    for duplicate_last in [false, true] {
        let fake = FakeProc::new();
        let (a, b) = (so(&fake, "/a.so"), so(&fake, "/b.so"));
        let lines = if duplicate_last {
            [&a, &b, &a]
        } else {
            [&a, &a, &b]
        };
        let maps: String = lines.iter().map(|p| maps_line(p) + "\n").collect();
        serve_at(&fake, &maps);
        let f = run_with(
            &fake,
            ProcBudgets {
                max_maps_entries: 2,
                ..ProcBudgets::default()
            },
        );
        assert_eq!(
            paths(&f.processes[0]),
            [text(&a), text(&b)],
            "{duplicate_last}"
        );
        assert_eq!(
            f.processes[0].maps_read,
            MapsRead::Whole,
            "{duplicate_last}"
        );
        assert!(
            detail(&f, 4242).missing.is_empty(),
            "{duplicate_last}: {:?}",
            detail(&f, 4242)
        );
    }
}

/// Code review of PR-4d-2, R-D: once the mappings kept reach the budget, a process's `maps` is
/// not read: never opened, so none of the byte budget goes to it.
#[test]
fn the_entries_budget_reached_leaves_the_next_maps_unopened() {
    let fake = FakeProc::new();
    let (a, b) = (so(&fake, "/a.so"), so(&fake, "/b.so"));
    two_observed(&fake, &[&a], &b);
    let opens = Opens::watch(&[
        fake.pid_dir(4242).join("maps"),
        fake.pid_dir(4300).join("maps"),
    ]);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_entries: 1,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(opens.counts(), [1, 0]);
    assert_eq!(paths(&f.processes[0]), [text(&a)]);
    assert_eq!(f.processes[0].maps_read, MapsRead::Whole);
    assert!(
        detail(&f, 4242).missing.is_empty(),
        "{:?}",
        detail(&f, 4242)
    );
    assert!(f.processes[1].mappings.is_empty());
    assert_eq!(f.processes[1].maps_read, MapsRead::NotRead);
    let d = detail(&f, 4300);
    assert_eq!(d.missing, ["maps: not read (proc_maps_entries reached)"]);
    assert!(!d.denied);
}

/// Code review of PR-4d-2, R-D: a process that a byte budget and the entries budget both stop
/// lists each reason once, the byte budget's first. In its read: `proc_maps_bytes` cuts the third
/// line, and the entries budget stops at the second. Before it: the runtime spent both.
#[test]
fn a_maps_stopped_by_both_budgets_lists_each_once_the_bytes_first() {
    let fake = FakeProc::new();
    let (a, b, c) = (so(&fake, "/a.so"), so(&fake, "/b.so"), so(&fake, "/c.so"));
    let (first, second) = (maps_line(&a), maps_line(&b));
    serve_at(&fake, &format!("{first}\n{second}\n{}\n", maps_line(&c)));
    // The first two lines, their newlines, and two bytes of the third.
    let limit = (first.len() + second.len()) as u64 + 4;
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_bytes: limit,
            max_maps_entries: 1,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(paths(&f.processes[0]), [text(&a)]);
    assert_eq!(f.processes[0].maps_read, MapsRead::Part);
    assert_eq!(
        detail(&f, 4242).missing,
        [
            format!("maps: over proc_maps_bytes ({limit} bytes read)"),
            "maps: over proc_maps_entries (1 records kept)".to_string(),
        ]
    );

    let fake = FakeProc::new();
    let (a, b) = (so(&fake, "/a.so"), so(&fake, "/b.so"));
    two_observed(&fake, &[&a], &b);
    let f = run_with(
        &fake,
        ProcBudgets {
            max_maps_total_bytes: maps_line(&a).len() as u64 + 1,
            max_maps_entries: 1,
            ..ProcBudgets::default()
        },
    );
    assert_eq!(f.processes[0].maps_read, MapsRead::Whole);
    assert_eq!(f.processes[1].maps_read, MapsRead::NotRead);
    assert_eq!(
        detail(&f, 4300).missing,
        [
            "maps: not read (proc_maps_total_bytes reached)",
            "maps: not read (proc_maps_entries reached)",
        ]
    );
}

/// Review of R1: a `maps` none of whose lines is understood keeps no mapping: `NotRead`.
#[test]
fn a_maps_with_no_line_understood_is_not_read() {
    let fake = FakeProc::new();
    serve_at(&fake, "garbage\n");
    let f = run(&fake);
    assert!(f.processes[0].mappings.is_empty());
    assert_eq!(f.processes[0].maps_read, MapsRead::NotRead);
    assert_eq!(detail(&f, 4242).missing, ["maps: 1 lines not understood"]);
}

/// Review of R1: a `maps` read to its end with no file-backed line has no mapping, and that is
/// all of it: `Whole`.
#[test]
fn a_maps_read_whole_with_no_file_backed_line_is_whole() {
    let fake = FakeProc::new();
    serve_at(&fake, "7f00-7f10 rw-p 00000000 00:00 0 [heap]\n");
    let f = run(&fake);
    assert!(f.processes[0].mappings.is_empty());
    assert_eq!(f.processes[0].maps_read, MapsRead::Whole);
    assert!(
        detail(&f, 4242).missing.is_empty(),
        "{:?}",
        detail(&f, 4242)
    );
}

/// External review of PR-4d-2: a mapping is one per distinct (dev, ino, path, deleted), not one
/// per object: one inode reached by two paths gives two.
#[test]
fn one_inode_mapped_by_two_paths_is_two_mappings() {
    let fake = FakeProc::new();
    let a = so(&fake, "/a.so");
    let b = fake.fs("/b.so");
    std::fs::hard_link(&a, &b).unwrap();
    serve_at(&fake, &format!("{}\n{}\n", maps_line(&a), maps_line(&b)));
    let f = run(&fake);
    let m = &f.processes[0].mappings;
    assert_eq!(m.len(), 2, "{m:?}");
    assert_eq!((m[0].dev, m[0].ino), (m[1].dev, m[1].ino));
    assert_ne!(m[0].path_text, m[1].path_text);
}
