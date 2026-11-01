//! Observe mode links the runtime's and its descendants' executables and mappings to the scanned
//! files by dev:ino, and covers what it observed (`processes.observed`; PR-4d-2). Synthetic proc
//! roots and trees only.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
        proc_budgets: ProcBudgets::default(),
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
