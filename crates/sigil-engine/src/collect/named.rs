//! The files named on the command line (`sigil binary inspect <PATH>...`; PR-4b-2a spec §4.1).
//!
//! An argument is explicit input, so symlinks in it are resolved, as a scan root's path is. The
//! file itself is then opened without following anything, and must be the file resolved (by
//! `dev:ino`). Each input is read through its own
//! `SafeFs`, dropped before the next, so the open file descriptors do not grow with the number
//! of inputs. Its directory is opened with `O_PATH`: it is never listed. An input that cannot be
//! read is a fatal error; only an input over `binary_bytes` is recorded unread.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sigil_model::{
    binary_root, Artifact, BinaryFacts, DiscoverySource, FileInstance, InstanceContent, InstanceId,
    NotReadReason, ScanRoot, SliceId, UntrustedText,
};

use super::binread::{self, Scanning};
use super::fs::{recorded, FsBudgets, ReadOutcome, RelPath, RootError, SafeFs};
use crate::binary::scan::ScanOutcome;
use crate::binary::BinaryBudgets;
use crate::code::CodeOutcome;

/// The budgets of a binary inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedBudgets {
    /// Bytes hashed over all inputs, as `binary_bytes`.
    pub bytes: u64,
    /// Each artifact's parse and scan, as `binary_parse_bytes`, `binary_imports`, and
    /// `binary_scan_bytes`.
    pub binary: BinaryBudgets,
}

impl Default for NamedBudgets {
    fn default() -> Self {
        NamedBudgets {
            bytes: 64 << 30,
            binary: BinaryBudgets::default(),
        }
    }
}

/// What the inputs gave, in argument order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NamedFacts {
    pub collection_usage: Option<super::code_collection::CollectionUsage>,
    /// Recognition only; does not authorize retaining evidence from an unstable read.
    pub recognized_multiarch: bool,
    /// `binary-<n>`, each at its file's canonical path.
    pub roots: Vec<ScanRoot>,
    pub instances: Vec<FileInstance>,
    pub artifacts: Vec<Artifact>,
    pub binaries: Vec<BinaryFacts>,
    /// When `NamedBudgets.binary.code` asked for code (PR-5a): the code outcome of every slice
    /// of each content parsed by a read that saw no change, sorted by slice. A slice without
    /// container facts (a Mach-O slice not parsed) has one too: `Unsupported`, as every Mach-O
    /// slice's is.
    pub code: Vec<(SliceId, CodeOutcome)>,
    /// The signature scan of every ELF slice of each content parsed by a read that saw no
    /// change, sorted by slice (PR-4c-2a).
    pub scans: Vec<(SliceId, ScanOutcome)>,
    /// For each input over `binary_bytes`: the bytes hashed before it (its `used`).
    pub over: BTreeMap<InstanceId, u64>,
    pub bytes_read: u64,
}

/// Reads `paths`. `Err` is the fatal input error of exit 1: the path and the reason, each escaped
/// for a terminal line (the path cut to 512 characters, the reason whole).
pub fn collect(paths: &[PathBuf], budgets: NamedBudgets) -> Result<NamedFacts, String> {
    collect_with(paths, budgets, &|_| {}, &|_| {})
}

fn shown(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    UntrustedText::from_bytes(path.as_os_str().as_bytes()).terminal_line()
}

/// `path: why`, escaped for a terminal line.
fn fatal(path: &Path, why: &str) -> String {
    format!(
        "{}: {}",
        shown(path),
        UntrustedText::new(why).terminal_line()
    )
}

/// As [`collect`], calling `before_open` with each canonical path after it was resolved and
/// before its directory is opened, and `during_read` while the file is open: the tests' ways to
/// change it.
fn collect_with(
    paths: &[PathBuf],
    budgets: NamedBudgets,
    before_open: &dyn Fn(&Path),
    during_read: &dyn Fn(&RelPath),
) -> Result<NamedFacts, String> {
    collect_strategy(paths, budgets, before_open, during_read, true)
}

fn collect_strategy(
    paths: &[PathBuf],
    budgets: NamedBudgets,
    before_open: &dyn Fn(&Path),
    during_read: &dyn Fn(&RelPath),
    deferred: bool,
) -> Result<NamedFacts, String> {
    if paths.is_empty() {
        return Err("no input: name at least one file".to_string());
    }
    // Each input with the `dev:ino` it resolved to: the file that must be opened (review of #89).
    // A file replaced later, even while the inputs before it are hashed, is not that file. A new
    // file that reuses the number of the one it replaced is not told apart.
    let mut inputs: Vec<(PathBuf, (u64, u64))> = vec![];
    let mut seen = BTreeSet::new();
    for p in paths {
        let canonical = std::fs::canonicalize(p).map_err(|e| {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => "not found".to_string(),
                std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
                _ => e.to_string(),
            };
            fatal(p, &why)
        })?;
        if seen.insert(canonical.clone()) {
            use std::os::unix::fs::MetadataExt;
            let st = std::fs::symlink_metadata(&canonical).map_err(|e| {
                let why = match e.kind() {
                    std::io::ErrorKind::NotFound => "vanished after it was resolved".to_string(),
                    _ => e.to_string(),
                };
                fatal(p, &why)
            })?;
            inputs.push((canonical, (st.dev(), st.ino())));
        }
    }
    let scanning = Scanning::embedded().map_err(|e| format!("internal error: {e}"))?;
    let mut facts = NamedFacts::default();
    let mut artifacts = BTreeSet::new();
    let mut parsed = BTreeMap::new();
    let mut collection = budgets
        .binary
        .code
        .filter(|_| deferred)
        .map(|_| super::code_collection::Collection::new(budgets.bytes));
    for (k, (path, resolved)) in inputs.iter().enumerate() {
        let n = u32::try_from(k + 1).map_err(|_| "too many inputs".to_string())?;
        let root = binary_root(n).ok_or_else(|| format!("binary-{n} is not a root ID"))?;
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(fatal(path, "a directory"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| fatal(path, "the file name is not UTF-8"))?;
        let rel = RelPath::parse(name).map_err(|e| fatal(path, &e.to_string()))?;
        before_open(path);
        // This input's own SafeFs: its directory fd is closed before the next input.
        let mut fs = SafeFs::new(FsBudgets::default());
        fs.add_unlisted_root(root.clone(), parent).map_err(|e| {
            let why = match e {
                RootError::NotFound => "not found".to_string(),
                RootError::PermissionDenied => "permission denied".to_string(),
                RootError::NotADirectory => "not a directory".to_string(),
                RootError::Duplicate => "named twice".to_string(),
                RootError::Failed(m) => m,
            };
            fatal(path, &format!("its directory {}: {why}", shown(parent)))
        })?;
        // The directory opened must be the one resolved: a swap in between would read elsewhere.
        if fs.root_path(&root) != Some(parent) {
            return Err(fatal(path, "its directory changed after it was resolved"));
        }
        let left = budgets.bytes.saturating_sub(facts.bytes_read);
        let read = if let Some(collection) = collection.as_mut() {
            collection.discover(
                &fs,
                &root,
                &rel,
                left,
                vec![DiscoverySource::Argument],
                budgets.binary,
                scanning,
                during_read,
            )
        } else {
            binread::read(
                &fs,
                &root,
                &rel,
                left,
                vec![DiscoverySource::Argument],
                budgets.binary,
                scanning,
                &mut parsed,
                during_read,
                &mut facts.recognized_multiarch,
            )
        };
        let Some(mut instance) = read.instance else {
            return Err(fatal(path, &outcome(&read.outcome)));
        };
        // A file read, or over budget, is recorded with its open fd's `stat`: it must be the file
        // resolved.
        let replaced = (instance.stat.dev, instance.stat.ino) != *resolved;
        match &instance.content {
            InstanceContent::Read { .. }
            | InstanceContent::NotRead {
                why: NotReadReason::BudgetExceeded,
            } if replaced => {
                return Err(fatal(
                    path,
                    "replaced by another file after it was resolved",
                ));
            }
            InstanceContent::Read { .. } => {}
            InstanceContent::NotRead {
                why: NotReadReason::BudgetExceeded,
            } => {
                facts.over.insert(instance.id.clone(), facts.bytes_read);
            }
            InstanceContent::NotRead { why } => {
                let what = match why {
                    NotReadReason::NotRegularFile
                        if instance.stat.mode & 0o170_000 == 0o040_000 =>
                    {
                        "a directory".to_string()
                    }
                    // Swapped in after the argument was resolved: never followed.
                    NotReadReason::NotRegularFile
                        if instance.stat.mode & 0o170_000 == 0o120_000 =>
                    {
                        "a symlink now, not followed".to_string()
                    }
                    NotReadReason::NotRegularFile => "not a regular file".to_string(),
                    NotReadReason::PermissionDenied => "permission denied".to_string(),
                    NotReadReason::Vanished => "vanished before it was read".to_string(),
                    other => format!("{other:?}"),
                };
                return Err(fatal(path, &what));
            }
        }
        if let Some(artifact) = read.artifact {
            facts.bytes_read = facts.bytes_read.saturating_add(artifact.size);
            if artifacts.insert(artifact.id.clone()) {
                facts.artifacts.push(artifact);
            }
        }
        facts.roots.push(ScanRoot {
            id: root,
            path: recorded(path),
        });
        instance.path_proof = None;
        facts.instances.push(instance);
    }
    if let Some(mut collection) = collection {
        collection.analyze(budgets.binary, scanning, &mut facts.instances, &mut parsed);
        facts.recognized_multiarch = collection.multiarch;
        facts.collection_usage = Some(collection.usage);
    }
    (facts.binaries, facts.code, facts.scans) = binread::binaries(parsed, &mut facts.artifacts);
    Ok(facts)
}

/// Why a read gave no instance.
fn outcome(o: &ReadOutcome) -> String {
    match o {
        ReadOutcome::NotFound => "vanished after it was resolved".to_string(),
        ReadOutcome::Failed(m) => m.clone(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use sigil_model::Stability;

    use super::{collect_with, NamedBudgets};

    fn dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::TempDir::new().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    fn libdata() -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so"))
            .unwrap()
    }

    #[test]
    fn scannable_x86_alias_does_not_run_code_twice() {
        let (_dir, root) = dir();
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code/spawn.so"),
        )
        .unwrap();
        let hidden = root.join("libcudart.so.12");
        let scanned = root.join("ordinary.so");
        std::fs::write(&hidden, &bytes).unwrap();
        std::fs::write(&scanned, &bytes).unwrap();
        let mut budgets = NamedBudgets::default();
        budgets.binary.code = Some(Default::default());
        crate::code::CODE_ANALYSES.with(|n| n.set(0));
        let result = super::collect(&[hidden, scanned], budgets).unwrap();
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(crate::code::CODE_ANALYSES.with(|n| n.get()), 1);
    }

    #[test]
    fn alias_aggregation_keeps_positive_identity_evidence_with_one_code_analysis() {
        let (_dir, root) = dir();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/returns/version-gcc-O2.so");
        let hidden = root.join("libcudart.so.12");
        let scanned = root.join("libggml-base.so.0.13.1");
        std::fs::copy(&source, &hidden).unwrap();
        std::fs::copy(&source, &scanned).unwrap();
        let mut budgets = NamedBudgets::default();
        budgets.binary.code = Some(Default::default());
        for paths in [
            vec![hidden.clone(), scanned.clone()],
            vec![scanned.clone(), hidden.clone()],
        ] {
            crate::code::CODE_ANALYSES.with(|n| n.set(0));
            let result = super::collect(&paths, budgets).unwrap();
            assert_eq!(crate::code::CODE_ANALYSES.with(|n| n.get()), 1);
            assert!(result.binaries.iter().any(|b| matches!(&b.container, sigil_model::ContainerFacts::Elf(e) if !e.returns.is_empty())));
            assert!(result
                .scans
                .iter()
                .all(|(_, s)| *s != crate::binary::scan::ScanOutcome::NameAndHashOnly));
        }
    }

    #[test]
    fn discovery_selects_shared_x86_work_limits_in_both_input_orders() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86 = manifest.join("tests/fixtures/code/shared-refs.so");
        let a64 = manifest.join("tests/fixtures/code-aarch64/elf-clang-plt.so");
        let macho = manifest.join("tests/fixtures/macho/hello-universal");
        let mut budgets = NamedBudgets::default();
        budgets.binary.code = Some(crate::code::CodeBudgets {
            references: 1,
            ..Default::default()
        });
        crate::code::CODE_RUNS.with(|r| r.borrow_mut().clear());
        super::collect(std::slice::from_ref(&x86), budgets).unwrap();
        let baseline = crate::code::CODE_RUNS.with(|r| r.borrow().clone());
        assert_eq!(baseline.len(), 1);
        assert!(baseline[0].0);
        assert_eq!(
            baseline[0].1, 1,
            "fixture must also exercise candidate-reference work"
        );
        assert!(
            baseline[0].2 > 0,
            "fixture must exercise text relocation accounting"
        );
        for other in [a64, macho] {
            for paths in [
                vec![x86.clone(), other.clone()],
                vec![other.clone(), x86.clone()],
            ] {
                crate::code::CODE_RUNS.with(|r| r.borrow_mut().clear());
                let result = super::collect(&paths, budgets).unwrap();
                assert!(result.recognized_multiarch);
                let runs = crate::code::CODE_RUNS.with(|r| r.borrow().clone());
                assert_eq!(runs.len(), 1);
                assert!(!runs[0].0, "legacy x86 work began before mode selection");
                assert!(runs[0].1 > 0 && runs[0].1 <= 1);
                assert_eq!(
                    runs[0].2, 0,
                    "marked work must use the combined reference counter"
                );
            }
        }
    }

    #[test]
    fn deferred_x86_collection_matches_all_legacy_facts_and_budget_edges() {
        let (_dir, root) = dir();
        for fixture in ["spawn.so", "values.so"] {
            let bytes = std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/code")
                    .join(fixture),
            )
            .unwrap();
            let hidden = root.join("libcudart.so.12");
            let scanned = root.join("ordinary.so");
            std::fs::write(&hidden, &bytes).unwrap();
            std::fs::write(&scanned, &bytes).unwrap();
            for parse in [0, 512, 4096, 64 << 20] {
                for code in [0, 128, 256 << 20] {
                    let mut budgets = NamedBudgets::default();
                    budgets.binary.parse_bytes = parse;
                    budgets.binary.code = Some(crate::code::CodeBudgets {
                        bytes: code,
                        ..Default::default()
                    });
                    for paths in [
                        vec![hidden.clone()],
                        vec![scanned.clone()],
                        vec![hidden.clone(), scanned.clone()],
                        vec![scanned.clone(), hidden.clone()],
                    ] {
                        let legacy =
                            super::collect_strategy(&paths, budgets, &|_| {}, &|_| {}, false)
                                .unwrap();
                        let mut actual = super::collect(&paths, budgets).unwrap();
                        assert!(!actual.recognized_multiarch);
                        actual.collection_usage = None;
                        assert_eq!(
                            actual, legacy,
                            "{fixture}: parse={parse}, code={code}, paths={paths:?}"
                        );
                    }
                }
            }
        }
    }

    /// A file swapped for a symlink after it was resolved: the symlink is not followed.
    #[test]
    fn a_file_swapped_for_a_symlink_is_fatal() {
        let (_d, p) = dir();
        std::fs::write(p.join("input.so"), b"input").unwrap();
        std::fs::write(p.join("secret"), b"secret").unwrap();
        let swap = |path: &Path| {
            std::fs::remove_file(path).unwrap();
            symlink("secret", path).unwrap();
        };
        let e = collect_with(
            &[p.join("input.so")],
            NamedBudgets::default(),
            &swap,
            &|_| {},
        )
        .unwrap_err();
        assert!(e.contains("symlink"), "{e}");
    }

    /// Removed, or replaced by a directory, after it was resolved: fatal, saying what it is now.
    #[test]
    fn a_file_removed_or_replaced_after_it_was_resolved_is_fatal() {
        let (_d, p) = dir();
        std::fs::write(p.join("gone.so"), b"x").unwrap();
        let remove = |path: &Path| std::fs::remove_file(path).unwrap();
        let e = collect_with(
            &[p.join("gone.so")],
            NamedBudgets::default(),
            &remove,
            &|_| {},
        )
        .unwrap_err();
        assert!(e.contains("vanished"), "{e}");
        std::fs::write(p.join("dir.so"), b"x").unwrap();
        let to_dir = |path: &Path| {
            std::fs::remove_file(path).unwrap();
            std::fs::create_dir(path).unwrap();
        };
        let e = collect_with(
            &[p.join("dir.so")],
            NamedBudgets::default(),
            &to_dir,
            &|_| {},
        )
        .unwrap_err();
        assert!(e.contains("a directory"), "{e}");
    }

    /// Review of Part B: the input's directory swapped (for a symlink to another one) between
    /// its resolution and its opening: an input error, not an invalid session.
    #[test]
    fn a_directory_swapped_after_resolution_is_an_input_error() {
        let (_d, p) = dir();
        std::fs::create_dir(p.join("a")).unwrap();
        std::fs::create_dir(p.join("b")).unwrap();
        std::fs::write(p.join("a/x.so"), b"a").unwrap();
        std::fs::write(p.join("b/x.so"), b"b").unwrap();
        let swap = |path: &Path| {
            let dir = path.parent().unwrap();
            std::fs::rename(dir, dir.with_extension("old")).unwrap();
            symlink(dir.with_file_name("b"), dir).unwrap();
        };
        let e =
            collect_with(&[p.join("a/x.so")], NamedBudgets::default(), &swap, &|_| {}).unwrap_err();
        assert!(e.contains("changed after it was resolved"), "{e}");
    }

    /// Review of #89 (P1): the resolved file replaced by another regular file (a rename over it)
    /// before it is opened. The file read is not the one resolved: an input error.
    #[test]
    fn a_file_replaced_by_another_after_resolution_is_fatal() {
        let (_d, p) = dir();
        let replace = |path: &Path| {
            std::fs::rename(path.with_file_name("clean.so"), path).unwrap();
        };
        for bytes in [64 << 30, 1] {
            std::fs::write(p.join("target.so"), b"target").unwrap();
            std::fs::write(p.join("clean.so"), b"clean").unwrap();
            let budgets = NamedBudgets {
                bytes,
                ..NamedBudgets::default()
            };
            // Read, or over budget (recorded unread): either way the fd is not the file resolved.
            let e = collect_with(&[p.join("target.so")], budgets, &replace, &|_| {}).unwrap_err();
            assert!(e.contains("replaced by another file"), "{e}");
        }
        // The same file under a new entry (the name removed, then a hard link of it renamed
        // there) is the file resolved. A rename between two links of one inode does nothing.
        std::fs::hard_link(p.join("target.so"), p.join("clean.so")).unwrap();
        let relink = |path: &Path| {
            std::fs::remove_file(path).unwrap();
            std::fs::rename(path.with_file_name("clean.so"), path).unwrap();
        };
        let f = collect_with(
            &[p.join("target.so")],
            NamedBudgets::default(),
            &relink,
            &|_| {},
        )
        .unwrap();
        assert!(!p.join("clean.so").exists());
        assert_eq!(f.instances[0].stability, Stability::NoChangeDetected);
    }

    /// Review of the #89 fixes: an input replaced while the inputs before it are read (here,
    /// before the first one's directory is opened) is not the file resolved either.
    #[test]
    fn an_input_replaced_while_an_earlier_one_is_read_is_fatal() {
        let (_d, p) = dir();
        std::fs::write(p.join("first.so"), b"first").unwrap();
        std::fs::write(p.join("second.so"), b"second").unwrap();
        std::fs::write(p.join("clean.so"), b"clean").unwrap();
        let replace_second = |path: &Path| {
            if path.ends_with("first.so") {
                std::fs::rename(
                    path.with_file_name("clean.so"),
                    path.with_file_name("second.so"),
                )
                .unwrap();
            }
        };
        let e = collect_with(
            &[p.join("first.so"), p.join("second.so")],
            NamedBudgets::default(),
            &replace_second,
            &|_| {},
        )
        .unwrap_err();
        assert!(e.contains("second.so"), "{e}");
        assert!(e.contains("replaced by another file"), "{e}");
    }

    /// Review of Part B: a file changed, or removed, while it is read is recorded (not fatal),
    /// with its stability, and without facts.
    #[test]
    fn a_file_changed_or_removed_during_its_read_is_recorded_without_facts() {
        use std::io::Write;
        let (_d, p) = dir();
        std::fs::write(p.join("grows.so"), libdata()).unwrap();
        let grow = |rel: &crate::collect::fs::RelPath| {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(p.join(rel.display()))
                .unwrap();
            f.write_all(b"more").unwrap();
        };
        let f = collect_with(
            &[p.join("grows.so")],
            NamedBudgets::default(),
            &|_| {},
            &grow,
        )
        .unwrap();
        assert_eq!(f.instances[0].stability, Stability::ChangedDuringRead);
        assert!(f.binaries.is_empty());
        std::fs::write(p.join("goes.so"), libdata()).unwrap();
        let remove = |rel: &crate::collect::fs::RelPath| {
            std::fs::remove_file(p.join(rel.display())).unwrap();
        };
        let f = collect_with(
            &[p.join("goes.so")],
            NamedBudgets::default(),
            &|_| {},
            &remove,
        )
        .unwrap();
        assert_eq!(f.instances[0].stability, Stability::Vanished);
        assert!(f.binaries.is_empty());
    }

    /// PR-5a: a code outcome is kept, as the container facts are, only from a read that saw no
    /// change.
    #[test]
    fn a_code_outcome_is_kept_only_from_a_read_that_saw_no_change() {
        use std::io::Write;
        let budgets = NamedBudgets {
            binary: crate::binary::BinaryBudgets {
                code: Some(crate::code::CodeBudgets::default()),
                ..crate::binary::BinaryBudgets::default()
            },
            ..NamedBudgets::default()
        };
        let (_d, p) = dir();
        std::fs::write(p.join("stable.so"), libdata()).unwrap();
        let f = collect_with(&[p.join("stable.so")], budgets, &|_| {}, &|_| {}).unwrap();
        assert_eq!(f.instances[0].stability, Stability::NoChangeDetected);
        assert_eq!(f.code.len(), 1);
        assert_eq!(f.code[0].0, f.binaries[0].slice);
        std::fs::write(p.join("grows.so"), libdata()).unwrap();
        let grow = |rel: &crate::collect::fs::RelPath| {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(p.join(rel.display()))
                .unwrap();
            f.write_all(b"more").unwrap();
        };
        let f = collect_with(&[p.join("grows.so")], budgets, &|_| {}, &grow).unwrap();
        assert_eq!(f.instances[0].stability, Stability::ChangedDuringRead);
        assert!(f.binaries.is_empty());
        assert!(f.code.is_empty());
        // Without a code request, no outcome.
        let f = collect_with(
            &[p.join("stable.so")],
            NamedBudgets::default(),
            &|_| {},
            &|_| {},
        )
        .unwrap();
        assert_eq!(f.binaries.len(), 1);
        assert!(f.code.is_empty());
    }
}
