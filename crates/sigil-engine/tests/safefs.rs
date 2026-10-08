//! SafeFs on real temporary trees: what is read, what is recorded and not read, and what bounds
//! hold (plan §4.6.2, §4.9). Adversarial cases: symlinks out of the roots, symlink loops, FIFOs,
//! unreadable files, oversized files.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use sigil_engine::collect::fs::{FsBudgets, ReadOutcome, ReadSpec, RelPath, SafeFs};
use sigil_model::{
    DiscoverySource, InstanceContent, NotReadReason, RootId, ScanRoot, Session, Stability,
    UntrustedText,
};
use tempfile::TempDir;

const ALL: ReadSpec = ReadSpec {
    keep: 0,
    limit: None,
};

fn root() -> RootId {
    RootId::new("models").unwrap()
}

fn rel(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

fn safefs(dir: &Path) -> SafeFs {
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_root(root(), dir).unwrap();
    fs
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// True when the process can read a mode-000 file (it runs as root), so permission cases cannot
/// be observed.
fn privileged(dir: &Path) -> bool {
    let probe = dir.join(".probe");
    fs::write(&probe, b"x").unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read(&probe).is_ok();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&probe).unwrap();
    readable
}

/// A session example with this root, the instance, and its artifact added, which must validate.
fn assert_valid_in_a_session(fs: &SafeFs, read: &sigil_engine::collect::fs::FileRead) {
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/session-v1/01-complete-pass.json");
    let mut s: Session = serde_json::from_str(&fs::read_to_string(example).unwrap()).unwrap();
    s.request.roots.push(ScanRoot {
        id: root(),
        path: UntrustedText::new(fs.root_path(&root()).unwrap().to_string_lossy()),
    });
    s.instances.extend(read.instance.clone());
    s.artifacts.extend(read.artifact.clone());
    if let Err(errors) = s.validate() {
        panic!("{errors:?}");
    }
}

#[test]
fn a_regular_file_is_hashed_in_one_pass() {
    let dir = TempDir::new().unwrap();
    let body = b"{\"schemaVersion\":2,\"layers\":[]}".repeat(1000);
    fs::create_dir_all(dir.path().join("manifests/registry.ollama.ai/library/m")).unwrap();
    fs::write(
        dir.path()
            .join("manifests/registry.ollama.ai/library/m/latest"),
        &body,
    )
    .unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(
        &root(),
        &rel("manifests/registry.ollama.ai/library/m/latest"),
        ReadSpec {
            keep: 16,
            limit: None,
        },
        vec![DiscoverySource::Walk],
    );
    assert_eq!(read.outcome, ReadOutcome::Complete);
    let artifact = read.artifact.clone().unwrap();
    assert_eq!(artifact.id.as_str(), format!("sha256:{}", sha256(&body)));
    assert_eq!(artifact.size, body.len() as u64);
    assert_eq!(read.prefix, body[..16]);
    let instance = read.instance.clone().unwrap();
    assert_eq!(
        instance.id.as_str(),
        "inst:models/manifests/registry.ollama.ai/library/m/latest"
    );
    assert_eq!(
        instance.content,
        InstanceContent::Read {
            artifact: artifact.id.clone()
        }
    );
    assert_eq!(instance.stability, Stability::NoChangeDetected);
    assert_eq!(instance.stat.size, body.len() as u64);
    assert!(instance.link_chain.is_empty() && instance.resolved.is_none());
    assert_valid_in_a_session(&fs, &read);
}

#[test]
fn a_file_over_the_limit_is_not_hashed() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("huge"), vec![b'x'; 4096]).unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(
        &root(),
        &rel("huge"),
        ReadSpec {
            keep: 64,
            limit: Some(1024),
        },
        vec![DiscoverySource::Walk],
    );
    assert_eq!(
        read.outcome,
        ReadOutcome::LimitExceeded {
            limit: 1024,
            size: 4096
        }
    );
    assert!(read.artifact.is_none());
    assert_eq!(
        read.instance.as_ref().unwrap().content,
        InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded
        }
    );
    assert_valid_in_a_session(&fs, &read);

    let exact = fs.read_file(
        &root(),
        &rel("huge"),
        ReadSpec {
            keep: 0,
            limit: Some(4096),
        },
        vec![],
    );
    assert_eq!(exact.outcome, ReadOutcome::Complete);
}

#[test]
fn a_symlink_inside_the_root_is_followed_and_recorded() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("blobs")).unwrap();
    fs::write(dir.path().join("blobs/real"), b"weights").unwrap();
    symlink("real", dir.path().join("blobs/alias")).unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(&root(), &rel("blobs/alias"), ALL, vec![]);
    assert_eq!(read.outcome, ReadOutcome::Complete);
    let instance = read.instance.clone().unwrap();
    assert_eq!(instance.id.as_str(), "inst:models/blobs/alias");
    assert_eq!(instance.link_chain.len(), 1);
    assert_eq!(instance.link_chain[0].target.as_str(), Some("real"));
    assert!(instance
        .resolved
        .as_ref()
        .unwrap()
        .as_str()
        .unwrap()
        .ends_with("/blobs/real"));
    assert_eq!(
        read.artifact.as_ref().unwrap().id.as_str(),
        format!("sha256:{}", sha256(b"weights"))
    );
    assert_valid_in_a_session(&fs, &read);
}

#[test]
fn a_symlink_out_of_the_roots_is_recorded_and_not_read() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret"), b"not for SIGIL").unwrap();
    symlink(outside.path().join("secret"), dir.path().join("blob")).unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(
        &root(),
        &rel("blob"),
        ReadSpec {
            keep: 64,
            limit: None,
        },
        vec![],
    );
    assert_eq!(
        read.outcome,
        ReadOutcome::NotRead(NotReadReason::OutsideScanRoots)
    );
    assert!(read.artifact.is_none() && read.prefix.is_empty());
    let instance = read.instance.clone().unwrap();
    assert_eq!(
        instance.content,
        InstanceContent::NotRead {
            why: NotReadReason::OutsideScanRoots
        }
    );
    assert_eq!(instance.link_chain.len(), 1);
    assert_eq!(
        instance.resolved.as_ref().unwrap().as_bytes(),
        outside.path().join("secret").as_os_str().as_encoded_bytes()
    );
    assert_valid_in_a_session(&fs, &read);
}

#[test]
fn a_fifo_is_not_opened_for_reading() {
    let dir = TempDir::new().unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        dir.path().join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    let fs = safefs(dir.path());
    // Opening a FIFO for reading would block forever; this returns.
    let read = fs.read_file(&root(), &rel("pipe"), ALL, vec![]);
    assert_eq!(
        read.outcome,
        ReadOutcome::NotRead(NotReadReason::NotRegularFile)
    );
    assert!(read.artifact.is_none());
    assert_valid_in_a_session(&fs, &read);

    fs::create_dir(dir.path().join("dir")).unwrap();
    let read = fs.read_file(&root(), &rel("dir"), ALL, vec![]);
    assert_eq!(
        read.outcome,
        ReadOutcome::NotRead(NotReadReason::NotRegularFile)
    );
}

#[test]
fn an_unreadable_file_is_recorded_as_permission_denied() {
    let dir = TempDir::new().unwrap();
    if privileged(dir.path()) {
        eprintln!("SKIPPED: running with privileges that read mode-000 files");
        return;
    }
    fs::write(dir.path().join("locked"), b"x").unwrap();
    fs::set_permissions(dir.path().join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(&root(), &rel("locked"), ALL, vec![]);
    assert_eq!(
        read.outcome,
        ReadOutcome::NotRead(NotReadReason::PermissionDenied)
    );
    assert_eq!(
        read.instance.as_ref().unwrap().content,
        InstanceContent::NotRead {
            why: NotReadReason::PermissionDenied
        }
    );
    assert_valid_in_a_session(&fs, &read);
}

#[test]
fn missing_paths_and_loops_have_no_instance() {
    let dir = TempDir::new().unwrap();
    symlink("b", dir.path().join("a")).unwrap();
    symlink("a", dir.path().join("b")).unwrap();
    symlink("nothing", dir.path().join("dangling")).unwrap();
    let fs = safefs(dir.path());
    let read = fs.read_file(&root(), &rel("missing"), ALL, vec![]);
    assert_eq!(read.outcome, ReadOutcome::NotFound);
    assert!(read.instance.is_none());
    let read = fs.read_file(&root(), &rel("dangling"), ALL, vec![]);
    assert_eq!(read.outcome, ReadOutcome::NotFound);
    let read = fs.read_file(&root(), &rel("a"), ALL, vec![]);
    assert!(
        matches!(read.outcome, ReadOutcome::Failed(_)),
        "{:?}",
        read.outcome
    );
    assert!(read.instance.is_none());
    let unknown = fs.read_file(&RootId::new("other").unwrap(), &rel("x"), ALL, vec![]);
    assert!(matches!(unknown.outcome, ReadOutcome::Failed(_)));
}
