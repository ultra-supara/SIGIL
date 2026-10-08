//! The `/proc` collector with few file descriptors (its own test binary, since it lowers this
//! process's `RLIMIT_NOFILE`): a process table larger than the fd limit is still read to the end,
//! because each process's directory is closed before the next one is opened.

use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
use sigil_engine::observe::proc::{observe, ProcBudgets};
use sigil_model::*;

mod common;
use common::proc::*;

#[test]
fn a_runtime_listed_after_more_processes_than_open_files_is_found() {
    let mut fake = FakeProc::new();
    for pid in 1000..1300 {
        fake.process(&Proc {
            pid,
            ..Proc::default()
        });
    }
    fake.process(&Proc {
        pid: 5000,
        comm: "ollama",
        argv: &["/usr/local/bin/ollama", "serve"],
        exe: Some("/usr/local/bin/ollama"),
        sockets: &[7001],
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 11434, 7001);

    let limit = getrlimit(Resource::Nofile);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(64),
            maximum: limit.maximum,
        },
    )
    .unwrap();
    let f = observe(
        fake.path(),
        &Timestamp::new("2026-10-08T00:00:00Z").unwrap(),
        BOOT_ID,
        ProcBudgets::default(),
    );
    setrlimit(Resource::Nofile, limit).unwrap();

    assert!(f.gaps.is_empty(), "{:?}", f.gaps);
    assert_eq!(f.processes.len(), 1);
    assert_eq!(f.processes[0].process.pid, 5000);
    assert!(matches!(
        f.listeners[0].owner,
        ListenerOwner::Process { ref process } if process.pid == 5000
    ));
}
