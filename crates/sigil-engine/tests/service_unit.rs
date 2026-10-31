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
        let path = self.root.join("units/ollama.service");
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
    let req = StoreRequest {
        models_dir: models.to_path_buf(),
        model_filter: None,
        budgets: FsBudgets::default(),
        manifest_limit: DEFAULT_MANIFEST_LIMIT,
        install: Some(InstallRequest {
            source,
            budgets: InstallBudgets::default(),
        }),
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
    input_error(
        inspect(models.path(), source),
        "was replaced after it was resolved",
    );
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
