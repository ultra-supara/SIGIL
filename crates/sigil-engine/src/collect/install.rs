//! The installation's own files (PR-4a; plan §4.6.2): `bin/ollama` and every entry under
//! `lib/ollama/` of `--install-dir`, through a SafeFs whose only root is the install. A link out
//! of it, including into the models directory, leads outside every root and is not read.

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
    /// Entries listed (every kind), as `install_files_discovered`.
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
}

impl Collector<'_> {
    fn places(&mut self) -> Result<(), String> {
        let bin = RelPath::parse(BIN).map_err(|e| format!("{e:?}"))?;
        match self.fs.entry_at(&self.root, &bin) {
            Some(entry) => {
                self.found += 1;
                self.entry(entry)?;
            }
            None => self.missing.push(format!("{BIN}: not found")),
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
            Err(WalkError::NotFound) => self.missing.push(format!("{LIB}: not found")),
            Err(e) => self.missing.push(format!("{LIB}: {e:?}")),
        }
        Ok(())
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
                if !matches!(
                    why,
                    NotReadReason::Directory | NotReadReason::LinkToDirectory
                ) {
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
                None,
                InstanceContent::NotRead {
                    why: NotReadReason::Directory,
                },
            ),
            EntryType::Special => self.placed(
                &entry,
                vec![],
                None,
                InstanceContent::NotRead {
                    why: NotReadReason::NotRegularFile,
                },
            ),
            EntryType::File => self.read(&entry, None),
            EntryType::Symlink { target } => self.read(&entry, Some(target)),
        }
    }

    /// A placement that is not read: a directory, a special file, a dangling link, or a file over
    /// the byte budget.
    fn placed(
        &mut self,
        entry: &Entry,
        link_chain: Vec<LinkHop>,
        resolved: Option<UntrustedText>,
        content: InstanceContent,
    ) -> Result<(), String> {
        let Some(stat) = entry.stat else {
            return Ok(());
        };
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

    /// Reads a file, or the file a symlink leads to, within the cumulative byte budget.
    fn read(&mut self, entry: &Entry, link_text: Option<String>) -> Result<(), String> {
        let left = self.budget.saturating_sub(self.used);
        if left == 0 {
            self.bytes_exceeded = true;
            return self.placed(
                entry,
                vec![],
                None,
                InstanceContent::NotRead {
                    why: NotReadReason::BudgetExceeded,
                },
            );
        }
        let read = self.fs.read_file(
            &self.root,
            &entry.rel,
            ReadSpec {
                keep: 64,
                limit: Some(left),
            },
            vec![DiscoverySource::Walk],
        );
        let Some(mut instance) = read.instance else {
            match (&link_text, &read.outcome) {
                // Nothing at the link's end: a dangling link, kept with its target text.
                (Some(target), ReadOutcome::NotFound) => {
                    let (uid, mode) = entry.stat.as_ref().map_or((0, 0), |s| (s.uid, s.mode));
                    let hop = LinkHop {
                        path: self.path(&entry.rel),
                        target: UntrustedText::new(target.clone()),
                        uid,
                        mode,
                    };
                    self.placed(
                        entry,
                        vec![hop],
                        Some(UntrustedText::new(target.clone())),
                        InstanceContent::NotRead {
                            why: NotReadReason::Dangling,
                        },
                    )?;
                    self.recheck_link(entry, link_text.as_deref());
                }
                (_, outcome) => self
                    .errors
                    .push(format!("{}: {outcome:?}", entry.rel.display())),
            }
            return Ok(());
        };
        if let ReadOutcome::LimitExceeded { .. } = read.outcome {
            self.bytes_exceeded = true;
        }
        // A link to a directory: recorded, not entered.
        if link_text.is_some()
            && instance.content
                == (InstanceContent::NotRead {
                    why: NotReadReason::NotRegularFile,
                })
            && rustix::fs::FileType::from_raw_mode(instance.stat.mode)
                == rustix::fs::FileType::Directory
        {
            instance.content = InstanceContent::NotRead {
                why: NotReadReason::LinkToDirectory,
            };
        }
        // A link is stable only if its target text is the same after the read.
        if !self.link_unchanged(entry, link_text.as_deref()) {
            instance.stability = Stability::ChangedDuringRead;
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

    /// Whether a link (if `before` is its target text) still has that text.
    fn link_unchanged(&self, entry: &Entry, before: Option<&str>) -> bool {
        let Some(before) = before else {
            return true;
        };
        matches!(
            self.fs.entry_at(&self.root, &entry.rel).map(|e| e.kind),
            Some(EntryType::Symlink { target }) if target == before
        )
    }

    /// For a dangling link: marks it changed, and an error, if its text changed meanwhile.
    fn recheck_link(&mut self, entry: &Entry, before: Option<&str>) {
        if !self.link_unchanged(entry, before) {
            if let Some(last) = self.instances.last_mut() {
                last.stability = Stability::ChangedDuringRead;
            }
            self.errors
                .push(format!("{}: ChangedDuringRead", entry.rel.display()));
        }
    }
}
