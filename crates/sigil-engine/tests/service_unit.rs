//! `inspect ollama --service-unit` (PR-4d-1): the installation a unit's `ExecStart=` names is
//! inspected as `--install-dir` inspects it, and its `bin/ollama` records the unit. Synthetic
//! trees only: no test reads a real installation or unit.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use sigil_engine::collect::fs::FsBudgets;
use sigil_engine::collect::install::InstallBudgets;
use sigil_engine::collect::ollama_store::DEFAULT_MANIFEST_LIMIT;
use sigil_engine::collect::service_unit::{self, DEFAULT_UNIT_BYTES};
use sigil_engine::inspect::{
    store_session, ActiveInput, InspectError, InstallRequest, InstallSource, StoreRequest,
};
use sigil_engine::policy::Policy;
use sigil_model::*;
use tempfile::TempDir;

fn tool() -> ToolInfo {
    ToolInfo {
        name: "sigil".to_string(),
        version: "0.0.0-test".to_string(),
        git_rev: None,
    }
}

fn observation() -> ObservationMeta {
    ObservationMeta {
        started_at: Timestamp::new("2026-10-31T00:00:00Z").unwrap(),
        finished_at: Timestamp::new("2026-10-31T00:00:01Z").unwrap(),
        uid: 1000,
        gid: 1000,
        capabilities: vec![],
        boot_id: "00000000-0000-4000-8000-000000000000".to_string(),
        kernel: "6.8.0".to_string(),
        net_ns: None,
        mnt_ns: None,
    }
}

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

/// `inst/bin/ollama`, `inst/lib/ollama/libggml.so.0.13.1`, and `units/`, at a canonical path.
struct Tree {
    _dir: TempDir,
    root: PathBuf,
}

impl Tree {
    fn new() -> Tree {
        let dir = TempDir::new().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("inst/bin")).unwrap();
        std::fs::create_dir_all(root.join("inst/lib/ollama")).unwrap();
        std::fs::create_dir_all(root.join("units")).unwrap();
        std::fs::write(root.join("inst/bin/ollama"), elf(2)).unwrap();
        std::fs::write(root.join("inst/lib/ollama/libggml.so.0.13.1"), elf(3)).unwrap();
        Tree { _dir: dir, root }
    }

    fn inst(&self) -> PathBuf {
        self.root.join("inst")
    }

    /// `units/ollama.service`: `ExecStart=` (line 4) runs `exec serve`.
    fn unit(&self, exec: &str) -> PathBuf {
        self.unit_at("units/ollama.service", exec)
    }

    /// The same unit, at `rel` under the tree.
    fn unit_at(&self, rel: &str, exec: &str) -> PathBuf {
        let path = self.root.join(rel);
        let text = format!("[Unit]\nDescription=Ollama\n[Service]\nExecStart={exec} serve\n");
        std::fs::write(&path, text).unwrap();
        path
    }
}

/// The unit read, as the CLI reads it before the inspection.
fn from_unit(path: &Path) -> InstallSource {
    InstallSource::ServiceUnit(Box::new(
        service_unit::collect(path, DEFAULT_UNIT_BYTES).unwrap(),
    ))
}

fn inspect(models: &Path, source: InstallSource) -> Result<Session, InspectError> {
    inspect_with(models, source, InstallBudgets::default())
}

fn inspect_with(
    models: &Path,
    source: InstallSource,
    budgets: InstallBudgets,
) -> Result<Session, InspectError> {
    let req = StoreRequest {
        models_dir: models.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest { source, budgets }),
    };
    store_session(
        &req,
        &ActiveInput::default(),
        &Policy::builtin_default().unwrap(),
        tool(),
        observation(),
        observation().started_at,
    )
}

fn root_path(s: &Session, id: &str) -> Option<Vec<u8>> {
    s.request
        .roots
        .iter()
        .find(|r| r.id.as_str() == id)
        .map(|r| r.path.as_bytes().to_vec())
}

#[test]
fn a_unit_names_the_installation_it_runs() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let s = inspect(models.path(), from_unit(&unit)).unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert_eq!(
        root_path(&s, INSTALL_ROOT),
        Some(t.inst().as_os_str().as_bytes().to_vec())
    );
    assert_eq!(
        root_path(&s, SERVICE_UNIT_ROOT),
        Some(unit.as_os_str().as_bytes().to_vec())
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
            DiscoverySource::ServiceUnit {
                config: ConfigRef {
                    file: InstanceId::new("inst:service-unit/ollama.service").unwrap(),
                    key: UntrustedText::new("ExecStart"),
                    line: 4,
                }
            }
        ]
    );
    assert_eq!(
        s.request.budgets.get("service_unit_bytes"),
        Some(&DEFAULT_UNIT_BYTES)
    );
}

#[test]
fn the_session_is_the_install_dir_s_plus_the_unit() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let mut a = inspect(models.path(), from_unit(&unit)).unwrap();
    let b = inspect(models.path(), InstallSource::Dir(t.inst())).unwrap();
    let unit_artifact = a
        .instances
        .iter()
        .find(|i| i.root.as_str() == SERVICE_UNIT_ROOT)
        .and_then(|i| match &i.content {
            InstanceContent::Read { artifact } => Some(artifact.clone()),
            InstanceContent::NotRead { .. } => None,
        })
        .unwrap();
    a.request
        .roots
        .retain(|r| r.id.as_str() != SERVICE_UNIT_ROOT);
    a.request.budgets.remove("service_unit_bytes");
    a.instances.retain(|i| i.root.as_str() != SERVICE_UNIT_ROOT);
    a.artifacts.retain(|x| x.id != unit_artifact);
    for i in &mut a.instances {
        i.discovered_by
            .retain(|d| !matches!(d, DiscoverySource::ServiceUnit { .. }));
    }
    assert_eq!(a, b);
}

#[test]
fn a_symlinked_bin_directory_resolves_to_its_installation() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    std::fs::create_dir_all(t.root.join("other")).unwrap();
    symlink(t.inst().join("bin"), t.root.join("other/bin")).unwrap();
    let unit = t.unit(&format!("{}/other/bin/ollama", t.root.display()));
    let s = inspect(models.path(), from_unit(&unit)).unwrap();
    assert_eq!(
        root_path(&s, INSTALL_ROOT),
        Some(t.inst().as_os_str().as_bytes().to_vec())
    );
}

#[test]
fn the_walk_s_gaps_are_the_installation_s() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    std::fs::remove_dir_all(t.inst().join("lib")).unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let s = inspect(models.path(), from_unit(&unit)).unwrap();
    assert_eq!(s.validate(), Ok(()));
    assert!(matches!(
        s.outcome.completeness,
        Completeness::Incomplete { .. }
    ));
    let b = inspect(models.path(), InstallSource::Dir(t.inst())).unwrap();
    let state = |s: &Session| {
        s.coverage
            .iter()
            .find(|c| c.check.as_str() == ARTIFACTS_DISCOVERY)
            .map(|c| c.state.clone())
    };
    assert_eq!(state(&s), state(&b));
}

fn input_error(result: Result<Session, InspectError>, why: &str) {
    match result {
        Err(InspectError::Input(e)) => {
            assert!(e.starts_with("--service-unit "), "{e}");
            assert!(e.contains(why), "{why}: {e}");
        }
        other => panic!("{why}: {other:?}"),
    }
}

/// External plan review, P1: the installation is replaced between the unit's read (where `--out`
/// was pinned against it) and the walk. The walk's root is not the prefix resolved.
#[test]
fn an_installation_replaced_after_the_unit_was_read_is_an_input_error() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let source = from_unit(&unit);
    // The old directory is kept under another name, so the new one cannot reuse its inode.
    std::fs::rename(t.inst(), t.root.join("inst.old")).unwrap();
    std::fs::create_dir_all(t.inst().join("bin")).unwrap();
    std::fs::write(t.inst().join("bin/ollama"), elf(2)).unwrap();
    let result = inspect(models.path(), source);
    // The root check's message, not the executable's.
    match &result {
        Err(InspectError::Input(e)) => assert!(e.contains("the installation "), "{e}"),
        other => panic!("{other:?}"),
    }
    input_error(result, "was replaced after it was resolved");
}

/// The executable alone replaced between the unit's read and the walk.
#[test]
fn an_executable_replaced_after_the_unit_was_read_is_an_input_error() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let source = from_unit(&unit);
    std::fs::rename(t.inst().join("bin/ollama"), t.inst().join("bin/ollama.old")).unwrap();
    std::fs::write(t.inst().join("bin/ollama"), elf(2)).unwrap();
    input_error(
        inspect(models.path(), source),
        "was replaced after it was resolved",
    );
}

/// Skipped as root, who opens and lists what mode 0100 refuses.
fn is_root() -> bool {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipped: root opens a mode-000 directory");
        return true;
    }
    false
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The prefix is searchable (the unit resolves) but not readable (the walk cannot open it).
#[test]
fn an_unreadable_prefix_is_an_input_error_that_says_so() {
    if is_root() {
        return;
    }
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let source = from_unit(&unit);
    chmod(&t.inst(), 0o100);
    let result = inspect(models.path(), source);
    chmod(&t.inst(), 0o755);
    match &result {
        Err(InspectError::Input(e)) => assert!(!e.contains("replaced"), "{e}"),
        other => panic!("{other:?}"),
    }
    input_error(result, "could not be opened: permission denied");
}

#[test]
fn an_unlistable_bin_is_an_input_error_that_says_so() {
    if is_root() {
        return;
    }
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let source = from_unit(&unit);
    chmod(&t.inst().join("bin"), 0o100);
    let result = inspect(models.path(), source);
    chmod(&t.inst().join("bin"), 0o755);
    input_error(result, "bin/ollama: PermissionDenied");
}

/// Task 5 re-review: a budget reached under `lib/ollama` (here `install_bytes`, which never keeps
/// `bin/ollama` from being recorded) does not hide why `bin/ollama` was not recorded.
#[test]
fn an_unlistable_bin_is_named_whatever_budget_the_walk_reached() {
    if is_root() {
        return;
    }
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let source = from_unit(&unit);
    let budgets = InstallBudgets {
        bytes: 1,
        ..InstallBudgets::default()
    };
    chmod(&t.inst().join("bin"), 0o100);
    let result = inspect_with(models.path(), source, budgets);
    chmod(&t.inst().join("bin"), 0o755);
    match &result {
        Err(InspectError::Input(e)) => assert!(!e.contains("install_bytes"), "{e}"),
        other => panic!("{other:?}"),
    }
    input_error(result, "bin/ollama: PermissionDenied");
}

#[test]
fn a_files_budget_that_stops_the_walk_is_an_input_error_that_says_so() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit(&format!("{}/bin/ollama", t.inst().display()));
    let budgets = InstallBudgets {
        files: 0,
        ..InstallBudgets::default()
    };
    input_error(
        inspect_with(models.path(), from_unit(&unit), budgets),
        "install_files_discovered reached",
    );
}

/// A unit placed inside the installation is one file seen twice: two instances, one artifact.
#[test]
fn a_unit_inside_the_installation_shares_its_artifact() {
    let t = Tree::new();
    let models = TempDir::new().unwrap();
    let unit = t.unit_at(
        "inst/lib/ollama/ollama.service",
        &format!("{}/bin/ollama", t.inst().display()),
    );
    let s = inspect(models.path(), from_unit(&unit)).unwrap();
    assert_eq!(s.validate(), Ok(()));
    let artifact_of = |id: &str| {
        let i = s.instances.iter().find(|i| i.id.as_str() == id).unwrap();
        match &i.content {
            InstanceContent::Read { artifact } => artifact.clone(),
            InstanceContent::NotRead { .. } => panic!("{id} was not read"),
        }
    };
    let walked = artifact_of("inst:install/lib/ollama/ollama.service");
    let unit_read = artifact_of("inst:service-unit/ollama.service");
    assert_eq!(walked, unit_read);
    assert_eq!(s.artifacts.iter().filter(|a| a.id == walked).count(), 1);
}
