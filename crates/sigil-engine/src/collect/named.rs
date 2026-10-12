//! The files named on the command line (`sigil binary inspect <PATH>...`; PR-4b-2a spec §4.1).
//!
//! An argument is explicit input, so symlinks in it are resolved, as a scan root's path is. The
//! file itself is then read without following anything. Each input is read through its own
//! `SafeFs`, dropped before the next, so the open file descriptors do not grow with the number
//! of inputs. Its directory is opened with `O_PATH`: it is never listed. An input that cannot be
//! read is a fatal error; only an input over `binary_bytes` is recorded unread.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sigil_model::{
    binary_root, Artifact, BinaryFacts, DiscoverySource, FileInstance, InstanceContent, InstanceId,
    NotReadReason, ScanRoot, UntrustedText,
};

use super::binread;
use super::fs::{recorded, FsBudgets, ReadOutcome, RelPath, RootError, SafeFs};
use crate::binary::BinaryBudgets;

/// The budgets of a binary inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedBudgets {
    /// Bytes hashed over all inputs, as `binary_bytes`.
    pub bytes: u64,
    /// Each artifact's parse, as `binary_parse_bytes` and `binary_imports`.
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
    /// `binary-<n>`, each at its file's canonical path.
    pub roots: Vec<ScanRoot>,
    pub instances: Vec<FileInstance>,
    pub artifacts: Vec<Artifact>,
    pub binaries: Vec<BinaryFacts>,
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
    if paths.is_empty() {
        return Err("no input: name at least one file".to_string());
    }
    let mut inputs: Vec<PathBuf> = vec![];
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
            inputs.push(canonical);
        }
    }
    let mut facts = NamedFacts::default();
    let mut artifacts = BTreeSet::new();
    let mut parsed = BTreeMap::new();
    for (k, path) in inputs.iter().enumerate() {
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
        let read = binread::read(
            &fs,
            &root,
            &rel,
            left,
            vec![DiscoverySource::Argument],
            budgets.binary,
            &mut parsed,
            during_read,
        );
        let Some(instance) = read.instance else {
            return Err(fatal(path, &outcome(&read.outcome)));
        };
        match &instance.content {
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
        facts.instances.push(instance);
    }
    facts.binaries = binread::binaries(parsed, &facts.artifacts);
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
}
