//! Observe mode links the runtime's and its descendants' executables and mappings to the scanned
//! files by dev:ino, and covers what it observed (`processes.observed`; PR-4d-2). Synthetic proc
//! roots and trees only.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sigil_engine::analyze::runtime_processes::OUTSIDE_THE_RUNTIME;
use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::inspect::{
    observe_session, ActiveInput, InstallRequest, InstallSource, ObserveRequest, StoreRequest,
};
use sigil_engine::observe::proc::ProcBudgets;
use sigil_engine::policy::Policy;
use sigil_model::*;
use tempfile::TempDir;

mod common;
use common::proc::*;
use common::{blob, hex, inst, manifest, LIB, MODEL_MEDIA};

fn elf(e_type: u16) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[6] = 1;
    h[16..18].copy_from_slice(&e_type.to_le_bytes());
    h[18..20].copy_from_slice(&62u16.to_le_bytes());
    h
}

/// An installation under the fixture's file tree at `/opt/ollama`, and the canonical prefix.
fn install(fake: &FakeProc) -> PathBuf {
    let prefix = fake.fs("/opt/ollama");
    std::fs::create_dir_all(prefix.join("bin")).unwrap();
    std::fs::create_dir_all(prefix.join("lib/ollama")).unwrap();
    std::fs::write(prefix.join("bin/ollama"), elf(2)).unwrap();
    std::fs::write(prefix.join("lib/ollama/libggml-cpu.so"), elf(3)).unwrap();
    std::fs::canonicalize(prefix).unwrap()
}

fn tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: "0.0.0-test".to_string(),
        git_rev: None,
    }
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-11-01T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-11-01T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: BOOT_ID.to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

fn session(fake: &FakeProc, models: &Path, install: Option<PathBuf>) -> Session {
    session_with(fake, models, install, ProcBudgets::default())
}

fn session_with(
    fake: &FakeProc,
    models: &Path,
    install: Option<PathBuf>,
    proc_budgets: ProcBudgets,
) -> Session {
    let req = ObserveRequest {
        store: StoreRequest {
            models_dir: models.to_path_buf(),
            model_filter: None,
            budgets: FsBudgets::default(),
            manifest_limit: DEFAULT_MANIFEST_LIMIT,
            install: install.map(|dir| InstallRequest {
                source: InstallSource::Dir(dir),
                budgets: InstallBudgets::default(),
            }),
        },
        proc_root: fake.path().to_path_buf(),
        proc_budgets,
    };
    let s = observe_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        tool(),
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

fn serve(fake: &FakeProc, exe: &str, maps: &str) {
    fake.process(&Proc {
        pid: 4242,
        comm: "ollama",
        argv: &["/opt/ollama/bin/ollama", "serve"],
        exe: Some(exe),
        start_ticks: 4000,
        maps,
        ..Proc::default()
    });
}

fn observed(s: &Session, scope: &Ref) -> Option<CoverageState> {
    s.coverage
        .iter()
        .find(|c| c.check.as_str() == PROCESSES_OBSERVED && c.scope == *scope)
        .map(|c| c.state.clone())
}

#[test]
fn the_executable_and_the_mappings_are_linked_by_dev_ino() {
    let fake = FakeProc::new();
    let prefix = install(&fake);
    let libc = fake.fs("/usr/lib/libc.so.6");
    std::fs::create_dir_all(libc.parent().unwrap()).unwrap();
    std::fs::write(&libc, b"libc").unwrap();
    let maps = [
        maps_line(&prefix.join("bin/ollama")),
        maps_line(&prefix.join("lib/ollama/libggml-cpu.so")),
        maps_line(&libc),
    ]
    .join("\n");
    serve(&fake, "/opt/ollama/bin/ollama", &maps);
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), Some(prefix));
    let p = &s.processes[0];
    assert_eq!(
        p.exe,
        ProcessExe::Instance {
            instance: InstanceId::new("inst:install/bin/ollama").unwrap()
        }
    );
    let bin = s
        .instances
        .iter()
        .find(|i| i.id.as_str() == "inst:install/bin/ollama")
        .unwrap();
    assert_eq!(
        bin.discovered_by,
        vec![
            DiscoverySource::Walk,
            DiscoverySource::ProcessExe {
                process: p.process.clone()
            }
        ]
    );
    let linked: Vec<Option<&str>> = p
        .mappings
        .iter()
        .map(|m| m.instance.as_ref().map(|i| i.as_str()))
        .collect();
    assert_eq!(
        linked,
        [
            Some("inst:install/bin/ollama"),
            Some("inst:install/lib/ollama/libggml-cpu.so"),
            None
        ]
    );
    assert_eq!(p.maps_read, MapsRead::Whole);
    assert_eq!(observed(&s, &Ref::Audit), Some(CoverageState::Complete));
    assert_eq!(
        observed(&s, &Ref::Process(p.process.clone())),
        Some(CoverageState::Complete)
    );
    assert!(s
        .request
        .required_checks
        .iter()
        .any(|c| c.as_str() == PROCESSES_OBSERVED));
    assert_eq!(s.request.budgets.get("proc_maps_bytes"), Some(&(16 << 20)));
}

#[test]
fn without_an_installation_the_executable_stays_a_path() {
    let fake = FakeProc::new();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    assert!(matches!(s.processes[0].exe, ProcessExe::Path { .. }));
    assert_eq!(observed(&s, &Ref::Audit), Some(CoverageState::Complete));
}

#[test]
fn no_runtime_is_complete_on_the_audit_alone() {
    let fake = FakeProc::new();
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    assert!(s.processes.is_empty());
    let entries: Vec<&Ref> = s
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == PROCESSES_OBSERVED)
        .map(|c| &c.scope)
        .collect();
    assert_eq!(entries, [&Ref::Audit]);
    assert_eq!(observed(&s, &Ref::Audit), Some(CoverageState::Complete));
}

/// External plan review, P1: a process that may be the runtime (its `comm` cannot be read) leaves
/// the audit open: its executable and descendants were not observed.
#[test]
fn a_process_that_may_be_the_runtime_leaves_the_audit_open() {
    let fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4500,
        comm: "ollama",
        argv: &["/opt/ollama/bin/ollama", "serve"],
        start_ticks: 4300,
        ..Proc::default()
    });
    if !fake.deny(4500, "comm") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    assert!(
        matches!(
            observed(&s, &Ref::Audit),
            Some(CoverageState::Partial { .. })
        ),
        "{:?}",
        observed(&s, &Ref::Audit)
    );
}

/// Code review of PR-4d-2, R-C: a fronting process outside the runtime's tree, recorded because
/// it holds a listener, has an entry too: `OutOfScope`, as its executable and mappings are not
/// read. The session validates, and the runtime's entries stand.
#[test]
fn a_fronting_listener_holder_outside_the_runtime_s_tree_is_out_of_scope() {
    let mut fake = FakeProc::new();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    fake.process(&Proc {
        pid: 200,
        comm: "nginx",
        argv: &["nginx"],
        exe: Some("/usr/sbin/nginx"),
        sockets: &[7002],
        start_ticks: 300,
        ..Proc::default()
    });
    fake.listen("0.0.0.0", 80, 7002);
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    let pids: Vec<u32> = s.processes.iter().map(|p| p.process.pid).collect();
    assert_eq!(pids, [200, 4242]);
    let nginx = &s.processes[0];
    assert!(nginx.mappings.is_empty());
    assert_eq!(nginx.maps_read, MapsRead::NotRead);
    assert_eq!(
        observed(&s, &Ref::Process(nginx.process.clone())),
        Some(CoverageState::OutOfScope {
            why: OUTSIDE_THE_RUNTIME.to_string()
        })
    );
    assert_eq!(
        observed(&s, &Ref::Process(s.processes[1].process.clone())),
        Some(CoverageState::Complete)
    );
    assert_eq!(observed(&s, &Ref::Audit), Some(CoverageState::Complete));
    // Review of R1: it says what was observed, that it was not found among them, which is all a
    // search through readable parents can say.
    let coverage = sigil_engine::explain::coverage(&s, sigil_engine::explain::Format::Text);
    assert!(
        coverage.contains("out of scope: not found among the runtime and its descendants"),
        "{coverage}"
    );
}

/// Code review of PR-4d-2, R-C: a listener's holder that may be the runtime (its `comm` cannot be
/// read) is outside any runtime's tree, so it is not read again. Its entry is `Partial`, and says
/// why.
#[test]
fn a_listener_holder_that_may_be_the_runtime_is_partial() {
    let mut fake = FakeProc::new();
    fake.process(&Proc {
        pid: 4500,
        comm: "ollama",
        argv: &["/opt/ollama/bin/ollama", "serve"],
        sockets: &[7001],
        start_ticks: 4300,
        ..Proc::default()
    });
    fake.listen("127.0.0.1", 11434, 7001);
    if !fake.deny(4500, "comm") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    let p = &s.processes[0];
    assert_eq!(p.process.pid, 4500);
    assert_eq!(p.maps_read, MapsRead::NotRead);
    assert_eq!(
        observed(&s, &Ref::Process(p.process.clone())),
        Some(CoverageState::Partial {
            missing: vec![
                "the process may be the runtime (its name cannot be read); its executable and \
                 mappings were not read"
                    .to_string()
            ]
        })
    );
}

/// Review of R1: a descendant of the runtime that holds a recorded listener, and whose `comm`
/// cannot be read (so it may be the runtime), is read by the second pass. It has that one entry,
/// never a second one as a listener's holder that may be the runtime.
#[test]
fn a_descendant_that_may_be_the_runtime_and_holds_a_listener_has_one_entry() {
    let mut fake = FakeProc::new();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    fake.process(&Proc {
        pid: 4300,
        comm: "ollama",
        argv: &["/opt/ollama/bin/ollama", "runner"],
        exe: Some("/opt/ollama/bin/ollama"),
        sockets: &[7001],
        start_ticks: 4100,
        ppid: 4242,
        ..Proc::default()
    });
    fake.listen("127.0.0.1", 11434, 7001);
    if !fake.deny(4300, "comm") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    let child = s.processes.iter().find(|p| p.process.pid == 4300).unwrap();
    assert!(child.roles.is_empty());
    assert_eq!(child.maps_read, MapsRead::Whole);
    let entries: Vec<&CoverageState> = s
        .coverage
        .iter()
        .filter(|c| {
            c.check.as_str() == PROCESSES_OBSERVED && c.scope == Ref::Process(child.process.clone())
        })
        .map(|c| &c.state)
        .collect();
    assert_eq!(entries, [&CoverageState::Complete]);
}

#[test]
fn a_dev_ino_two_instances_share_links_neither() {
    let fake = FakeProc::new();
    let prefix = install(&fake);
    // `lib/ollama/ollama-copy` is the same file as `bin/ollama` (a hard link).
    std::fs::hard_link(
        prefix.join("bin/ollama"),
        prefix.join("lib/ollama/ollama-copy"),
    )
    .unwrap();
    serve(
        &fake,
        "/opt/ollama/bin/ollama",
        &maps_line(&prefix.join("bin/ollama")),
    );
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), Some(prefix));
    assert!(matches!(s.processes[0].exe, ProcessExe::Path { .. }));
    assert_eq!(s.processes[0].mappings[0].instance, None);
    assert!(s.instances.iter().all(|i| !i
        .discovered_by
        .iter()
        .any(|d| matches!(d, DiscoverySource::ProcessExe { .. }))));
}

#[test]
fn an_unreadable_runtime_is_unavailable_and_incomplete() {
    let fake = FakeProc::new();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    if !fake.deny(4242, "maps") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    // `stat` through `exe` needs search permission on the target's directory: without it, the
    // executable's identity is refused, as for another user's process. `readlink` still works.
    let bin = fake.fs("/opt/ollama/bin");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o000)).unwrap();
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), None);
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let scope = Ref::Process(s.processes[0].process.clone());
    assert_eq!(
        observed(&s, &scope),
        Some(CoverageState::Unavailable {
            why: Unavailability::PermissionDenied
        })
    );
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
}

/// Code review of PR-4d-2, R-A: the executable's identity is read and linked, but `maps` is
/// refused. The entry is `Partial`, not `Unavailable`, and `maps` is `NotRead`: the Markdown says
/// it was not observed, never "0 (0 linked)".
#[test]
fn a_runtime_whose_maps_is_refused_is_not_read_and_partial() {
    let fake = FakeProc::new();
    let prefix = install(&fake);
    serve(&fake, "/opt/ollama/bin/ollama", "");
    if !fake.deny(4242, "maps") {
        eprintln!("skipped: root reads a mode-000 file");
        return;
    }
    let models = TempDir::new().unwrap();
    let s = session(&fake, models.path(), Some(prefix));
    let p = &s.processes[0];
    assert_eq!(
        p.exe,
        ProcessExe::Instance {
            instance: InstanceId::new("inst:install/bin/ollama").unwrap()
        }
    );
    assert!(p.mappings.is_empty());
    assert_eq!(p.maps_read, MapsRead::NotRead);
    assert_eq!(
        observed(&s, &Ref::Process(p.process.clone())),
        Some(CoverageState::Partial {
            missing: vec!["maps: cannot be read (PermissionDenied)".to_string()]
        })
    );
    let md = sigil_model::render::markdown::render_session(&s);
    assert!(md.contains("| not observed |"), "{md}");
    assert!(!md.contains("0 \\(0 linked"), "{md}");
}

/// Review of a93bfef: what was not observed of a process leaves its entry `Partial`, and the
/// session incomplete.
#[test]
fn a_runtime_s_maps_over_its_budget_is_partial() {
    let fake = FakeProc::new();
    let lines: Vec<String> = ["/usr/lib/liba.so", "/usr/lib/libb.so"]
        .iter()
        .map(|path| {
            let file = fake.fs(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, path.as_bytes()).unwrap();
            maps_line(&std::fs::canonicalize(&file).unwrap())
        })
        .collect();
    serve(&fake, "/opt/ollama/bin/ollama", &lines.join("\n"));
    let models = TempDir::new().unwrap();
    // The first line and its newline: the second is over the budget.
    let budgets = ProcBudgets {
        max_maps_bytes: lines[0].len() as u64 + 1,
        ..ProcBudgets::default()
    };
    let s = session_with(&fake, models.path(), None, budgets);
    let p = &s.processes[0];
    assert_eq!(p.mappings.len(), 1);
    assert_eq!(p.maps_read, MapsRead::Part);
    match observed(&s, &Ref::Process(p.process.clone())) {
        Some(CoverageState::Partial { missing }) => assert!(
            missing[0].starts_with("maps: over proc_maps_bytes"),
            "{missing:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(observed(&s, &Ref::Audit), Some(CoverageState::Complete));
    let Completeness::Incomplete {
        missing_required, ..
    } = &s.outcome.completeness
    else {
        panic!("a runtime observed in part is complete");
    };
    assert!(
        missing_required
            .iter()
            .any(|c| c.as_str() == PROCESSES_OBSERVED),
        "{missing_required:?}"
    );
}

/// Review of a93bfef: a process list cut short may hide a descendant, so the audit is `Partial`.
#[test]
fn a_process_list_cut_short_leaves_the_audit_partial() {
    let fake = FakeProc::new();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    let models = TempDir::new().unwrap();
    // PID 1 and the runtime: one of them is listed, whichever comes first.
    let budgets = ProcBudgets {
        max_processes: 1,
        ..ProcBudgets::default()
    };
    let s = session_with(&fake, models.path(), None, budgets);
    match observed(&s, &Ref::Audit) {
        Some(CoverageState::Partial { missing }) => assert!(
            missing
                .iter()
                .any(|m| m.starts_with("the process list was not read to its end")),
            "{missing:?}"
        ),
        other => panic!("{other:?}"),
    }
}

/// Review of a93bfef: a runner, a child of `ollama serve` that runs the same executable, maps the
/// model blob it serves. The mapping is linked to the store's blob, and the executable names both
/// processes.
#[test]
fn a_runner_s_mapping_of_a_model_blob_is_linked() {
    let fake = FakeProc::new();
    let prefix = install(&fake);
    let models = TempDir::new().unwrap();
    let weights = blob(models.path(), b"weights");
    manifest(models.path(), LIB, None, &[(MODEL_MEDIA, &weights)]);
    let rel = format!("blobs/sha256-{}", hex(b"weights"));
    let path = std::fs::canonicalize(models.path().join(&rel)).unwrap();
    serve(&fake, "/opt/ollama/bin/ollama", "");
    fake.process(&Proc {
        pid: 4300,
        comm: "ollama",
        argv: &[
            "/opt/ollama/bin/ollama",
            "runner",
            "--model",
            path.to_str().unwrap(),
        ],
        exe: Some("/opt/ollama/bin/ollama"),
        start_ticks: 4100,
        ppid: 4242,
        maps: &maps_line(&path),
        ..Proc::default()
    });
    let s = session(&fake, models.path(), Some(prefix));
    let by_pid = |pid| s.processes.iter().find(|p| p.process.pid == pid).unwrap();
    let (server, runner) = (by_pid(4242), by_pid(4300));
    let linked: Vec<Option<&InstanceId>> = runner
        .mappings
        .iter()
        .map(|m| m.instance.as_ref())
        .collect();
    assert_eq!(linked, [Some(&inst(&rel))]);
    let bin = s
        .instances
        .iter()
        .find(|i| i.id.as_str() == "inst:install/bin/ollama")
        .unwrap();
    assert_eq!(
        bin.discovered_by,
        vec![
            DiscoverySource::Walk,
            DiscoverySource::ProcessExe {
                process: server.process.clone()
            },
            DiscoverySource::ProcessExe {
                process: runner.process.clone()
            }
        ]
    );
    for p in [server, runner] {
        assert_eq!(
            p.exe,
            ProcessExe::Instance {
                instance: bin.id.clone()
            }
        );
    }
    assert_eq!(
        observed(&s, &Ref::Process(runner.process.clone())),
        Some(CoverageState::Complete)
    );
}
