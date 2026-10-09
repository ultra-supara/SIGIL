//! The installation's own files (PR-4a; plan §4.6.2): `bin/ollama` and every entry under
//! `lib/ollama/` of `--install-dir`, through a SafeFs whose only root is the install.
//!
//! No symlink is followed, wherever it leads: a symlink placement is its own `lstat` and target
//! text, which is what a release lists for it, and a symlink at or on the way to either place
//! leaves that place uninspected (a gap). So nothing outside the two places is read, inside the
//! install or outside it.

use std::path::Path;

use sigil_model::{
    Artifact, BudgetUse, CheckId, Coverage, CoverageState, DiscoverySource, FileInstance, Format,
    InstanceContent, LinkHop, NotReadReason, Ref, RootId, Slice, SliceId, Stability,
    Unavailability, UntrustedText, ARTIFACTS_DISCOVERY, INSTALL_ROOT,
};

use super::fs::{
    instance_id, recorded, Entry, EntryType, FsBudgets, ReadOutcome, ReadSpec, RelPath, RootError,
    SafeFs, WalkError,
};
use crate::binary::header;

/// Budgets of the install scan, recorded with an `install_` prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallBudgets {
    /// Entries found (`bin/ollama` and every entry under `lib/ollama/`), as
    /// `install_files_discovered`.
    pub files: u64,
    /// Directory entries read, as `install_entries_listed`.
    pub entries: u64,
    /// Bytes read for hashing, over the whole scan, as `install_bytes`.
    pub bytes: u64,
}

impl Default for InstallBudgets {
    fn default() -> Self {
        InstallBudgets {
            files: 4096,
            entries: 16_384,
            bytes: 64 << 30,
        }
    }
}

/// What the install scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFacts {
    /// The canonical path SafeFs opened, or the path as given when it could not be opened.
    pub root_path: UntrustedText,
    pub instances: Vec<FileInstance>,
    pub artifacts: Vec<Artifact>,
    /// Coverage of `artifacts.discovery`, scope `Root(install)`.
    pub discovery: Coverage,
    pub bytes_read: u64,
}

const BIN: &str = "bin/ollama";
const LIB: &str = "lib/ollama";

/// Scans `dir`. An error only for an invalid built-in identifier.
pub fn collect(dir: &Path, budgets: InstallBudgets) -> Result<InstallFacts, String> {
    collect_with(dir, budgets, &|_| {})
}

/// As [`collect`], calling `after_read` with each file's or link's path right after it was read:
/// the tests' way to change an entry between a link's two `readlinkat`.
fn collect_with(
    dir: &Path,
    budgets: InstallBudgets,
    after_read: &dyn Fn(&RelPath),
) -> Result<InstallFacts, String> {
    let root = RootId::new(INSTALL_ROOT).map_err(|e| e.to_string())?;
    let check = CheckId::new(ARTIFACTS_DISCOVERY).map_err(|e| e.to_string())?;
    let mut fs = SafeFs::new(FsBudgets {
        max_files: budgets.files,
        max_entries: budgets.entries,
        ..FsBudgets::default()
    });
    let opened = fs.add_root(root.clone(), dir);
    let root_path = recorded(fs.root_path(&root).unwrap_or(dir));
    let mut c = Collector {
        fs: &fs,
        root: root.clone(),
        root_path: root_path.clone(),
        budget: budgets.bytes,
        used: 0,
        bytes_exceeded: false,
        instances: vec![],
        artifacts: vec![],
        missing: vec![],
        errors: vec![],
        exceeded: vec![],
        found: 0,
        after_read,
    };
    let state = match opened {
        Err(RootError::NotFound) => CoverageState::Unavailable {
            why: Unavailability::NotFound,
        },
        Err(RootError::PermissionDenied) => CoverageState::Unavailable {
            why: Unavailability::PermissionDenied,
        },
        Err(e) => CoverageState::Error {
            message: UntrustedText::new(format!("the install directory: {e:?}")),
        },
        Ok(()) => {
            c.places()?;
            c.state()
        }
    };
    Ok(InstallFacts {
        root_path,
        instances: c.instances,
        artifacts: c.artifacts,
        discovery: Coverage {
            check,
            scope: Ref::Root(root),
            state,
            budget: None,
        },
        bytes_read: c.used,
    })
}

struct Collector<'a> {
    fs: &'a SafeFs,
    root: RootId,
    root_path: UntrustedText,
    budget: u64,
    used: u64,
    bytes_exceeded: bool,
    instances: Vec<FileInstance>,
    artifacts: Vec<Artifact>,
    /// `Partial` entries.
    missing: Vec<String>,
    /// `Error` entries: an entry vanished or changed during the scan.
    errors: Vec<String>,
    exceeded: Vec<BudgetUse>,
    /// How many of the two places exist.
    found: u32,
    after_read: &'a dyn Fn(&RelPath),
}

impl Collector<'_> {
    fn places(&mut self) -> Result<(), String> {
        let bin = RelPath::parse(BIN).map_err(|e| format!("{e:?}"))?;
        match self.fs.entry_at(&self.root, &bin) {
            Ok(entry) => {
                self.found += 1;
                // `bin/ollama` counts against the file budget like every entry of the walk.
                if self.fs.take_file() {
                    self.entry(entry)?;
                } else {
                    let limit = self.fs.budgets.max_files;
                    self.exceeded.push(BudgetUse {
                        budget: "files_discovered".to_string(),
                        used: limit,
                        limit,
                    });
                }
            }
            Err(e) => self.place_missing(BIN, &e),
        }
        let lib = RelPath::parse(LIB).map_err(|e| format!("{e:?}"))?;
        match self.fs.walk_entries(&self.root, &lib) {
            Ok(walk) => {
                self.found += 1;
                for entry in walk.entries {
                    self.entry(entry)?;
                }
                for (rel, why) in walk.skipped {
                    self.missing.push(format!("{}: {why:?}", rel.display()));
                }
                for rel in walk.unscanned {
                    self.missing.push(format!("{}: not listed", rel.display()));
                }
                self.exceeded.extend(walk.exceeded);
            }
            Err(e) => self.place_missing(LIB, &e),
        }
        Ok(())
    }

    /// A place that could not be inspected. A symlink at it, or on the way to it, is there but
    /// not followed: a gap, not an absence.
    fn place_missing(&mut self, place: &str, e: &WalkError) {
        match e {
            WalkError::NotFound => self.missing.push(format!("{place}: not found")),
            WalkError::LinkNotFollowed { at } => {
                self.found += 1;
                self.missing
                    .push(format!("{}: a symlink, not followed", at.display()));
            }
            other => {
                self.found += 1;
                self.missing.push(format!("{place}: {other:?}"));
            }
        }
    }

    fn state(&self) -> CoverageState {
        if self.found == 0 {
            return CoverageState::Unavailable {
                why: Unavailability::NotFound,
            };
        }
        if let Some(first) = self.errors.first() {
            return CoverageState::Error {
                message: UntrustedText::new(first.clone()),
            };
        }
        if self.bytes_exceeded {
            return CoverageState::BudgetExceeded {
                budget: "install_bytes".into(),
                used: self.used,
                limit: self.budget,
            };
        }
        if let Some(b) = self.exceeded.first() {
            return CoverageState::BudgetExceeded {
                budget: format!("install_{}", b.budget),
                used: b.used,
                limit: b.limit,
            };
        }
        let mut gaps = self.missing.clone();
        for i in &self.instances {
            if let InstanceContent::NotRead { why } = &i.content {
                // A directory has no content, and a symlink is observed by its target text.
                if !matches!(why, NotReadReason::Directory | NotReadReason::NotFollowed) {
                    gaps.push(format!("{}: {why:?}", i.path.terminal_line()));
                }
            }
        }
        gaps.sort();
        gaps.dedup();
        if gaps.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial { missing: gaps }
        }
    }

    fn entry(&mut self, entry: Entry) -> Result<(), String> {
        match entry.kind.clone() {
            EntryType::Vanished => {
                self.errors
                    .push(format!("{}: vanished during the walk", entry.rel.display()));
                Ok(())
            }
            EntryType::Directory => self.placed(
                &entry,
                vec![],
                InstanceContent::NotRead {
                    why: NotReadReason::Directory,
                },
            ),
            EntryType::Special => self.placed(
                &entry,
                vec![],
                InstanceContent::NotRead {
                    why: NotReadReason::NotRegularFile,
                },
            ),
            EntryType::File => self.read(&entry),
            EntryType::Symlink { target } => self.link(&entry, &target),
        }
    }

    /// A placement that is not read: a directory, a special file, a symlink, or a file over the
    /// byte budget. A symlink's `resolved` is its target text: it was not followed further.
    fn placed(
        &mut self,
        entry: &Entry,
        link_chain: Vec<LinkHop>,
        content: InstanceContent,
    ) -> Result<(), String> {
        let Some(stat) = entry.stat else {
            return Ok(());
        };
        let resolved = link_chain.first().map(|hop| hop.target.clone());
        self.instances.push(FileInstance {
            id: instance_id(&self.root, &entry.rel)?,
            root: self.root.clone(),
            path: self.path(&entry.rel),
            link_chain,
            resolved,
            content,
            stat,
            stability: Stability::NoChangeDetected,
            discovered_by: vec![DiscoverySource::Walk],
        });
        Ok(())
    }

    fn path(&self, rel: &RelPath) -> UntrustedText {
        let mut path = self.root_path.as_bytes().to_vec();
        for c in rel.components() {
            path.push(b'/');
            path.extend_from_slice(c.as_bytes());
        }
        UntrustedText::from_bytes(path)
    }

    /// A symlink: its own `lstat` and its target text, compared as such. It is never followed,
    /// wherever it leads, so nothing outside the two places is read through it. It is stable if a
    /// second `readlinkat` gives the same text.
    fn link(&mut self, entry: &Entry, target: &str) -> Result<(), String> {
        let Some(stat) = entry.stat else {
            return Ok(());
        };
        let hop = LinkHop {
            path: self.path(&entry.rel),
            target: UntrustedText::new(target),
            uid: stat.uid,
            mode: stat.mode,
        };
        self.placed(
            entry,
            vec![hop],
            InstanceContent::NotRead {
                why: NotReadReason::NotFollowed,
            },
        )?;
        (self.after_read)(&entry.rel);
        let unchanged = matches!(
            self.fs.entry_at(&self.root, &entry.rel).map(|e| e.kind),
            Ok(EntryType::Symlink { target: now }) if now == target
        );
        if !unchanged {
            if let Some(last) = self.instances.last_mut() {
                last.stability = Stability::ChangedDuringRead;
            }
            self.errors
                .push(format!("{}: ChangedDuringRead", entry.rel.display()));
        }
        Ok(())
    }

    /// Reads a regular file, without following any symlink, within the cumulative byte budget.
    fn read(&mut self, entry: &Entry) -> Result<(), String> {
        let left = self.budget.saturating_sub(self.used);
        if left == 0 {
            self.bytes_exceeded = true;
            return self.placed(
                entry,
                vec![],
                InstanceContent::NotRead {
                    why: NotReadReason::BudgetExceeded,
                },
            );
        }
        let read = self.fs.read_entry(
            &self.root,
            &entry.rel,
            ReadSpec {
                keep: 64,
                limit: Some(left),
            },
            vec![DiscoverySource::Walk],
        );
        (self.after_read)(&entry.rel);
        let Some(instance) = read.instance else {
            self.errors
                .push(format!("{}: {:?}", entry.rel.display(), read.outcome));
            return Ok(());
        };
        // Listed as a regular file: anything else now changed during the scan.
        if instance.content
            == (InstanceContent::NotRead {
                why: NotReadReason::NotRegularFile,
            })
        {
            self.errors
                .push(format!("{}: no longer a regular file", entry.rel.display()));
            return Ok(());
        }
        if let ReadOutcome::LimitExceeded { .. } = read.outcome {
            self.bytes_exceeded = true;
        }
        if instance.stability != Stability::NoChangeDetected {
            self.errors
                .push(format!("{}: {:?}", entry.rel.display(), instance.stability));
        }
        if let Some(mut artifact) = read.artifact {
            self.used = self.used.saturating_add(artifact.size);
            if let Some((kind, arch)) = header::read(&read.prefix) {
                artifact.format = Format::Elf { kind };
                let hex = artifact
                    .id
                    .as_str()
                    .trim_start_matches("sha256:")
                    .to_string();
                if let Ok(sha256) = sigil_model::Sha256Hex::new(hex) {
                    artifact.slices = vec![Slice {
                        id: SliceId::from_parts(&artifact.id, arch, 0),
                        arch,
                        offset: 0,
                        size: artifact.size,
                        sha256,
                    }];
                }
            }
            if !self.artifacts.iter().any(|a| a.id == artifact.id) {
                self.artifacts.push(artifact);
            }
        }
        self.instances.push(instance);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use sigil_model::{CoverageState, Stability};

    use super::{collect_with, InstallBudgets};

    /// A link retargeted between its two `readlinkat`: its target is never read, so only the
    /// second `readlinkat` can see the change.
    #[test]
    fn a_symlink_retargeted_during_the_read_is_unstable() {
        let d = tempfile::TempDir::new().unwrap();
        let lib = d.path().join("lib/ollama");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("a.so"), b"a").unwrap();
        std::fs::write(lib.join("b.so"), b"b").unwrap();
        symlink("a.so", lib.join("link.so")).unwrap();
        let retarget = |rel: &crate::collect::fs::RelPath| {
            if rel.display() == "lib/ollama/link.so" {
                std::fs::remove_file(lib.join("link.so")).unwrap();
                symlink("b.so", lib.join("link.so")).unwrap();
            }
        };
        let f = collect_with(d.path(), InstallBudgets::default(), &retarget).unwrap();
        let link = f
            .instances
            .iter()
            .find(|i| i.path.as_bytes().ends_with(b"/link.so"))
            .unwrap();
        assert_eq!(link.stability, Stability::ChangedDuringRead);
        assert!(
            matches!(&f.discovery.state, CoverageState::Error { .. }),
            "{:?}",
            f.discovery.state
        );
        // Without a change, the same tree is stable.
        let f = collect_with(d.path(), InstallBudgets::default(), &|_| {}).unwrap();
        assert!(f
            .instances
            .iter()
            .all(|i| i.stability == Stability::NoChangeDetected));
    }
}
