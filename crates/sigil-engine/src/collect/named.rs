//! The files named on the command line (`sigil binary inspect <PATH>...`; PR-4b-2a spec §4.1).
//!
//! An argument is explicit input, so symlinks in it are resolved, as a scan root's path is. The
//! file itself is then read without following anything. Each input is read through its own
//! `SafeFs`, dropped before the next, so the open file descriptors do not grow with the number
//! of inputs. An input that cannot be read is a fatal error; only an input over `binary_bytes`
//! is recorded unread.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sigil_model::{
    binary_root, Artifact, BinaryFacts, DiscoverySource, FileInstance, InstanceContent, InstanceId,
    NotReadReason, ScanRoot, UntrustedText,
};

use super::binread;
use super::fs::{recorded, FsBudgets, ReadOutcome, RelPath, SafeFs};
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

/// Reads `paths`. `Err` is the fatal input error of exit 1, naming the path.
pub fn collect(paths: &[PathBuf], budgets: NamedBudgets) -> Result<NamedFacts, String> {
    collect_with(paths, budgets, &|_| {})
}

fn shown(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    UntrustedText::from_bytes(path.as_os_str().as_bytes()).terminal_line()
}

/// As [`collect`], calling `before_read` with each canonical path after it was resolved and
/// before it is read: the tests' way to swap it.
fn collect_with(
    paths: &[PathBuf],
    budgets: NamedBudgets,
    before_read: &dyn Fn(&Path),
) -> Result<NamedFacts, String> {
    let mut inputs: Vec<PathBuf> = vec![];
    for p in paths {
        let canonical = std::fs::canonicalize(p).map_err(|e| {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => "not found".to_string(),
                std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
                _ => e.to_string(),
            };
            format!("{}: {why}", shown(p))
        })?;
        if !inputs.contains(&canonical) {
            inputs.push(canonical);
        }
    }
    let mut facts = NamedFacts::default();
    let mut parsed = BTreeMap::new();
    for (k, path) in inputs.iter().enumerate() {
        let n = u32::try_from(k + 1).map_err(|_| "too many inputs".to_string())?;
        let root = binary_root(n).ok_or_else(|| format!("binary-{n} is not a root ID"))?;
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(format!("{}: a directory", shown(path)));
        };
        let name = name
            .to_str()
            .ok_or_else(|| format!("{}: the file name is not UTF-8", shown(path)))?;
        let rel = RelPath::parse(name).map_err(|e| format!("{}: {e}", shown(path)))?;
        // This input's own SafeFs: its directory fd is closed before the next input.
        let mut fs = SafeFs::new(FsBudgets::default());
        fs.add_root(root.clone(), parent)
            .map_err(|e| format!("{}: its directory: {e:?}", shown(path)))?;
        before_read(path);
        let left = budgets.bytes.saturating_sub(facts.bytes_read);
        let read = binread::read(
            &fs,
            &root,
            &rel,
            left,
            vec![DiscoverySource::Argument],
            budgets.binary,
            &mut parsed,
            &|_| {},
        );
        let Some(instance) = read.instance else {
            return Err(format!("{}: {}", shown(path), outcome(&read.outcome)));
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
                return Err(format!("{}: {what}", shown(path)));
            }
        }
        if let Some(artifact) = read.artifact {
            facts.bytes_read = facts.bytes_read.saturating_add(artifact.size);
            if !facts.artifacts.iter().any(|a| a.id == artifact.id) {
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

    use super::{collect_with, NamedBudgets};

    /// A file swapped for a symlink after it was resolved: the symlink is not followed.
    #[test]
    fn a_file_swapped_for_a_symlink_is_fatal() {
        let d = tempfile::TempDir::new().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        std::fs::write(p.join("input.so"), b"input").unwrap();
        std::fs::write(p.join("secret"), b"secret").unwrap();
        let swap = |path: &std::path::Path| {
            std::fs::remove_file(path).unwrap();
            symlink("secret", path).unwrap();
        };
        let e = collect_with(&[p.join("input.so")], NamedBudgets::default(), &swap).unwrap_err();
        assert!(e.contains("symlink"), "{e}");
    }
}
