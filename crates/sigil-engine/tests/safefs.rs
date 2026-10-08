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
fn a_file_larger_than_its_stat_size_still_stops_at_the_limit() {
    // procfs reports `st_size` 0 for files with content, so only the check while streaming can
    // stop this read. It stands in for a file that grows while it is read.
    let proc = RootId::new("proc").unwrap();
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_root(proc.clone(), Path::new("/proc/self")).unwrap();
    let read = fs.read_file(
        &proc,
        &rel("status"),
        ReadSpec {
            keep: 0,
            limit: Some(16),
        },
        vec![],
    );
    assert!(
        matches!(read.outcome, ReadOutcome::LimitExceeded { limit: 16, size } if size > 16),
        "{:?}",
        read.outcome
    );
    assert!(read.artifact.is_none());
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

// --- walk -------------------------------------------------------------------------------------

use sigil_engine::collect::fs::{Skip, Walk, WalkError};

fn walk(fs: &SafeFs, dir: &str) -> Walk {
    let dir = if dir.is_empty() {
        RelPath::root()
    } else {
        rel(dir)
    };
    fs.walk(&root(), &dir).unwrap()
}

fn listed(w: &Walk) -> Vec<String> {
    w.files.iter().map(RelPath::display).collect()
}

fn skipped(w: &Walk) -> Vec<(String, Skip)> {
    w.skipped
        .iter()
        .map(|(p, s)| (p.display(), s.clone()))
        .collect()
}

#[test]
fn a_walk_lists_regular_files_in_a_stable_order() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir_all(p.join("a/c")).unwrap();
    for f in ["z", "a/b", "a/c/d", "a/.hidden"] {
        fs::write(p.join(f), f).unwrap();
    }
    let fs = safefs(p);
    let w = walk(&fs, "");
    assert_eq!(listed(&w), ["a/.hidden", "a/b", "a/c/d", "z"]);
    assert!(w.skipped.is_empty() && w.unscanned.is_empty() && w.exceeded.is_empty());
    assert_eq!(listed(&walk(&fs, "a/c")), ["a/c/d"]);
}

#[test]
fn directory_links_are_followed_once_and_loops_end() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir_all(p.join("real")).unwrap();
    fs::create_dir_all(p.join("a")).unwrap();
    fs::create_dir_all(p.join("b")).unwrap();
    fs::write(p.join("real/x"), b"x").unwrap();
    fs::write(p.join("b/y"), b"y").unwrap();
    symlink("real", p.join("alias")).unwrap();
    symlink(".", p.join("real/self")).unwrap();
    symlink("..", p.join("real/up")).unwrap();
    symlink("../b", p.join("a/link")).unwrap();
    symlink(outside.path(), p.join("away")).unwrap();
    let fs = safefs(p);

    // The physical tree first; a link to a directory already walked is recorded, not re-walked.
    let w = walk(&fs, "");
    assert_eq!(listed(&w), ["b/y", "real/x"]);
    assert_eq!(
        skipped(&w),
        [
            ("a/link".to_string(), Skip::AlreadyVisited),
            ("alias".to_string(), Skip::AlreadyVisited),
            ("away".to_string(), Skip::OutsideScanRoots),
            ("real/self".to_string(), Skip::AlreadyVisited),
            ("real/up".to_string(), Skip::AlreadyVisited),
        ]
    );

    // A link to a directory not under the walked one is followed under the link's own path.
    let w = walk(&fs, "a");
    assert_eq!(listed(&w), ["a/link/y"]);

    // A link up to an ancestor walks the ancestor once; the walked directory, met again below
    // it, is not walked twice.
    let w = walk(&fs, "real");
    assert_eq!(listed(&w), ["real/up/b/y", "real/x"]);
    assert!(skipped(&w).contains(&("real/up/real".to_string(), Skip::AlreadyVisited)));
}

#[test]
fn special_files_dangling_links_and_unreadable_directories_are_recorded() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        p.join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    symlink("nothing", p.join("dangling")).unwrap();
    fs::write(p.join("ok"), b"ok").unwrap();
    let locked = !privileged(p);
    if locked {
        fs::create_dir(p.join("locked")).unwrap();
        fs::write(p.join("locked/f"), b"f").unwrap();
        fs::set_permissions(p.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    }
    let fs = safefs(p);
    let w = walk(&fs, "");
    if locked {
        fs::set_permissions(p.join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert_eq!(listed(&w), ["ok"]);
    let mut expected = vec![
        ("dangling".to_string(), Skip::Dangling),
        ("pipe".to_string(), Skip::NotRegularFile),
    ];
    if locked {
        expected.insert(1, ("locked".to_string(), Skip::PermissionDenied));
    } else {
        eprintln!("SKIPPED: the unreadable-directory case needs an unprivileged user");
    }
    assert_eq!(skipped(&w), expected);
}

#[test]
fn the_file_budget_stops_the_walk_and_names_what_was_not_scanned() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir_all(p.join("d/sub")).unwrap();
    for f in ["d/1", "d/2", "d/3", "d/4", "d/sub/5"] {
        fs::write(p.join(f), f).unwrap();
    }
    let mut fs = SafeFs::new(FsBudgets {
        max_files: 3,
        ..FsBudgets::default()
    });
    fs.add_root(root(), p).unwrap();
    let w = walk(&fs, "d");
    assert_eq!(listed(&w), ["d/1", "d/2", "d/3"]);
    assert_eq!(w.exceeded.len(), 1);
    assert_eq!(w.exceeded[0].budget, "files_discovered");
    assert_eq!((w.exceeded[0].used, w.exceeded[0].limit), (3, 3));
    let unscanned: Vec<String> = w.unscanned.iter().map(RelPath::display).collect();
    assert_eq!(unscanned, ["d"]);

    // The budget is shared by every walk of this SafeFs.
    let again = walk(&fs, "d/sub");
    assert!(again.files.is_empty());
    assert_eq!(again.exceeded[0].budget, "files_discovered");

    // The budget runs out exactly at the end of a directory: the next directory is named as
    // unscanned, and none of its subdirectories is entered.
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir_all(p.join("a")).unwrap();
    fs::create_dir_all(p.join("b/c")).unwrap();
    fs::write(p.join("a/f"), b"f").unwrap();
    fs::write(p.join("b/c/g"), b"g").unwrap();
    let mut fs = SafeFs::new(FsBudgets {
        max_files: 1,
        ..FsBudgets::default()
    });
    fs.add_root(root(), p).unwrap();
    let w = walk(&fs, "");
    assert_eq!(listed(&w), ["a/f"]);
    let unscanned: Vec<String> = w.unscanned.iter().map(RelPath::display).collect();
    assert_eq!(unscanned, ["b"]);
}

#[test]
fn the_depth_budget_leaves_deeper_directories_unscanned() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir_all(p.join("a/b/c")).unwrap();
    for f in ["top", "a/one", "a/b/two", "a/b/c/three"] {
        fs::write(p.join(f), f).unwrap();
    }
    // A directory link counts at the depth where the link is, not where it points.
    symlink("b/c", p.join("a/deep")).unwrap();
    let mut fs = SafeFs::new(FsBudgets {
        max_depth: 1,
        ..FsBudgets::default()
    });
    fs.add_root(root(), p).unwrap();
    let w = walk(&fs, "");
    assert_eq!(listed(&w), ["a/one", "top"]);
    let unscanned: Vec<String> = w.unscanned.iter().map(RelPath::display).collect();
    assert_eq!(unscanned, ["a/b", "a/deep"]);
    assert_eq!(w.exceeded[0].budget, "walk_depth");
    assert_eq!(w.exceeded[0].limit, 1);
}

#[test]
fn walking_something_that_is_not_a_directory_is_an_error() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(dir.path().join("file"), b"f").unwrap();
    symlink(outside.path(), dir.path().join("away")).unwrap();
    let fs = safefs(dir.path());
    assert_eq!(
        fs.walk(&root(), &rel("missing")).unwrap_err(),
        WalkError::NotFound
    );
    assert_eq!(
        fs.walk(&root(), &rel("file")).unwrap_err(),
        WalkError::NotADirectory
    );
    assert_eq!(
        fs.walk(&root(), &rel("away")).unwrap_err(),
        WalkError::OutsideRoots
    );
}

#[test]
fn a_walk_that_starts_at_a_link_into_another_root_lists_that_root() {
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let (pa, pb) = (a.path(), b.path().canonicalize().unwrap());
    fs::create_dir(pb.join("sub")).unwrap();
    fs::write(pb.join("only-in-b"), b"b").unwrap();
    fs::write(pb.join("sub/deeper-in-b"), b"b").unwrap();
    // Same names in A, so opening the wrong root shows in the result.
    fs::create_dir(pa.join("sub")).unwrap();
    fs::write(pa.join("only-in-a"), b"a").unwrap();
    fs::write(pa.join("sub/decoy-in-a"), b"a").unwrap();
    symlink(&pb, pa.join("to-b")).unwrap();
    symlink(pb.join("sub"), pa.join("to-b-sub")).unwrap();
    let ra = RootId::new("a").unwrap();
    let mut fs = SafeFs::new(FsBudgets::default());
    fs.add_root(ra.clone(), pa).unwrap();
    fs.add_root(RootId::new("b").unwrap(), &pb).unwrap();

    // The link leads to root B itself.
    let w = fs.walk(&ra, &rel("to-b")).unwrap();
    assert_eq!(listed(&w), ["to-b/only-in-b", "to-b/sub/deeper-in-b"]);
    // The link leads to a directory directly under root B.
    let w = fs.walk(&ra, &rel("to-b-sub")).unwrap();
    assert_eq!(listed(&w), ["to-b-sub/deeper-in-b"]);
}

#[test]
fn a_directory_over_the_entry_limit_is_not_listed() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    fs::create_dir(p.join("big")).unwrap();
    fs::create_dir(p.join("small")).unwrap();
    // Entries that are not regular files, so the file budget never moves.
    for name in ["a", "b", "c", "d"] {
        symlink("nothing", p.join("big").join(name)).unwrap();
    }
    for name in ["x", "y", "z"] {
        fs::write(p.join("small").join(name), name).unwrap();
    }
    let mut fs = SafeFs::new(FsBudgets {
        max_dir_entries: 3,
        ..FsBudgets::default()
    });
    fs.add_root(root(), p).unwrap();
    let w = walk(&fs, "");
    // A directory at the limit is listed. One over it is named as unscanned, and none of its
    // entries is recorded: they cannot all be held to be sorted.
    assert_eq!(listed(&w), ["small/x", "small/y", "small/z"]);
    assert!(w.skipped.is_empty());
    let unscanned: Vec<String> = w.unscanned.iter().map(RelPath::display).collect();
    assert_eq!(unscanned, ["big"]);
    assert_eq!(w.exceeded.len(), 1);
    assert_eq!(w.exceeded[0].budget, "directory_entries");
    assert_eq!((w.exceeded[0].used, w.exceeded[0].limit), (4, 3));
}

#[test]
fn the_entry_budget_counts_every_entry_and_stops_the_walk() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    // No regular file anywhere: empty directories and dangling links only.
    for d in ["d1", "d2", "d3"] {
        fs::create_dir_all(p.join("top").join(d)).unwrap();
        symlink("nothing", p.join("top").join(d).join("link")).unwrap();
    }
    let budget = |max_entries| {
        let mut fs = SafeFs::new(FsBudgets {
            max_entries,
            ..FsBudgets::default()
        });
        fs.add_root(root(), p).unwrap();
        fs
    };
    let unscanned =
        |w: &Walk| -> Vec<String> { w.unscanned.iter().map(RelPath::display).collect() };

    // `top` has 3 entries, then d1 and d2 one each: the budget of 5 is spent before d3.
    let w = walk(&budget(5), "top");
    assert!(w.files.is_empty());
    assert_eq!(
        skipped(&w),
        [
            ("top/d1/link".to_string(), Skip::Dangling),
            ("top/d2/link".to_string(), Skip::Dangling),
        ]
    );
    assert_eq!(unscanned(&w), ["top/d3"]);
    assert_eq!(w.exceeded[0].budget, "entries_listed");
    assert_eq!((w.exceeded[0].used, w.exceeded[0].limit), (5, 5));

    // Spent while `top` is read: `top` itself is unscanned, and nothing from it is recorded.
    let w = walk(&budget(2), "top");
    assert!(w.files.is_empty() && w.skipped.is_empty());
    assert_eq!(unscanned(&w), ["top"]);
    assert_eq!(w.exceeded[0].budget, "entries_listed");
    assert_eq!((w.exceeded[0].used, w.exceeded[0].limit), (2, 2));
}
