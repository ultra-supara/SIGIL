//! The installation's own files (PR-4a; plan §4.6.2): `bin/ollama` and every entry under
//! `lib/ollama/` of `--install-dir`, through a SafeFs whose only root is the install.
//!
//! No symlink is followed, wherever it leads: a symlink placement is its own `lstat` and target
//! text, which is what a release lists for it, and a symlink at or on the way to either place
//! leaves that place uninspected (a gap). So nothing outside the two places is read, inside the
//! install or outside it.

use std::collections::BTreeMap;
use std::path::Path;

use sigil_model::{
    Artifact, BudgetUse, CheckId, Coverage, CoverageState, DiscoverySource, FileInstance,
    InstanceContent, LinkHop, NotReadReason, Ref, RootId, Stability, Unavailability, UntrustedText,
    ARTIFACTS_DISCOVERY, INSTALL_ROOT,
};

use super::binread::Scanning;
use super::fs::{
    instance_id, recorded, Entry, EntryType, FsBudgets, ReadOutcome, RelPath, RootError, SafeFs,
    WalkError,
};
use crate::binary::scan::ScanOutcome;
use crate::binary::{BinaryBudgets, ParsedArtifact};
use crate::code::CodeOutcome;

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
    /// Each ELF or Mach-O artifact's parse and scan, as `binary_parse_bytes`, `binary_imports`,
    /// and `binary_scan_bytes`.
    pub binary: BinaryBudgets,
}

impl Default for InstallBudgets {
    fn default() -> Self {
        InstallBudgets {
            files: 4096,
            entries: 16_384,
            bytes: 64 << 30,
            binary: BinaryBudgets::default(),
        }
    }
}

/// What the install scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFacts {
    /// Recognition only; unstable reads still supply no code or inventory witnesses.
    pub recognized_multiarch: bool,
    /// The canonical path SafeFs opened, or the path as given when it could not be opened.
    pub root_path: UntrustedText,
    /// The `dev:ino` of the directory the walk opened as its root (`SafeFs::root_id`), or `None`
    /// when it could not be opened: what a service unit's prefix is compared with (PR-4d-1).
    pub root_id: Option<(u64, u64)>,
    pub instances: Vec<FileInstance>,
    pub artifacts: Vec<Artifact>,
    /// Coverage of `artifacts.discovery`, scope `Root(install)`.
    pub discovery: Coverage,
    /// What the walk recorded while handling `bin/ollama` (a gap, an error, or the files
    /// budget), or `None` if it recorded nothing there: why a service unit's executable may have
    /// no placement, which a summary state reached elsewhere would hide (PR-4d-1).
    pub bin_gap: Option<String>,
    pub bytes_read: u64,
    /// The container facts of each ELF or Mach-O slice, parsed once on the fd that hashed it.
    pub binaries: Vec<sigil_model::BinaryFacts>,
    /// Code outcomes for slices parsed from stable reads when requested in `binary.code`.
    pub code: Vec<(sigil_model::SliceId, CodeOutcome)>,
    /// The signature scan of each ELF slice, on the same fd (PR-4c-2a), sorted by slice.
    pub scans: Vec<(sigil_model::SliceId, ScanOutcome)>,
}

const BIN: &str = "bin/ollama";
const LIB: &str = "lib/ollama";

/// Scans `dir`. An error only for an invalid built-in identifier.
pub fn collect(dir: &Path, budgets: InstallBudgets) -> Result<InstallFacts, String> {
    collect_with(
        dir,
        InstallBudgets {
            binary: BinaryBudgets {
                code: None,
                ..budgets.binary
            },
            ..budgets
        },
        &|_| {},
    )
}

/// Scans the installation with the optional code analysis in `budgets.binary.code`.
/// Outcomes are returned to the caller for coverage and policy assembly.
pub fn collect_with_code(dir: &Path, budgets: InstallBudgets) -> Result<InstallFacts, String> {
    collect_with(dir, budgets, &|_| {})
}

/// As [`collect`], calling `during_read` with the path of each file while it is read (after
/// hashing, before the post-read checks) and of each link between its two `readlinkat`: the
/// tests' way to change an entry during its read.
fn collect_with(
    dir: &Path,
    budgets: InstallBudgets,
    during_read: &dyn Fn(&RelPath),
) -> Result<InstallFacts, String> {
    let root = RootId::new(INSTALL_ROOT).map_err(|e| e.to_string())?;
    let check = CheckId::new(ARTIFACTS_DISCOVERY).map_err(|e| e.to_string())?;
    let scanning = Scanning::embedded().map_err(|e| format!("internal error: {e}"))?;
    let mut fs = SafeFs::new(FsBudgets {
        max_files: budgets.files,
        max_entries: budgets.entries,
        ..FsBudgets::default()
    });
    let opened = fs.add_root(root.clone(), dir);
    let root_path = recorded(fs.root_path(&root).unwrap_or(dir));
    let root_id = fs.root_id(&root);
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
        bin_gap: None,
        found: 0,
        during_read,
        binary: budgets.binary,
        scanning,
        parsed: BTreeMap::new(),
        recognized_multiarch: false,
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
    let (binaries, code, scans) = super::binread::binaries(c.parsed, &mut c.artifacts);
    Ok(InstallFacts {
        recognized_multiarch: c.recognized_multiarch,
        root_path,
        root_id,
        instances: c.instances,
        artifacts: c.artifacts,
        binaries,
        code,
        scans,
        discovery: Coverage {
            check,
            scope: Ref::Root(root),
            state,
            budget: None,
        },
        bin_gap: c.bin_gap,
        bytes_read: c.used,
    })
}

struct Collector<'a> {
    recognized_multiarch: bool,
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
    /// What was recorded while `bin/ollama` was handled.
    bin_gap: Option<String>,
    /// How many of the two places exist.
    found: u32,
    during_read: &'a dyn Fn(&RelPath),
    binary: BinaryBudgets,
    scanning: Scanning<'static>,
    /// Each recognized binary artifact parsed so far, by content.
    parsed: BTreeMap<sigil_model::ArtifactId, ParsedArtifact>,
}

impl Collector<'_> {
    fn places(&mut self) -> Result<(), String> {
        let bin = RelPath::parse(BIN).map_err(|e| format!("{e:?}"))?;
        let before = (self.missing.len(), self.errors.len(), self.exceeded.len());
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
        // What `bin/ollama`'s handling recorded is why it may have no placement (PR-4d-1).
        self.bin_gap = self.missing[before.0..]
            .iter()
            .chain(&self.errors[before.1..])
            .cloned()
            .chain(
                self.exceeded[before.2..]
                    .iter()
                    .map(|b| format!("install_{} reached ({} of {})", b.budget, b.used, b.limit)),
            )
            .next();
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
        let needs_proof = matches!(
            &content,
            InstanceContent::NotRead {
                why: NotReadReason::Directory | NotReadReason::NotFollowed
            }
        );
        let mut placement_stability = Stability::NoChangeDetected;
        let mut path_proof = None;
        if needs_proof {
            // For directories and own links, the test hook separates two placement
            // observations; it does not parse or open the link target.
            let first = self.fs.observe_entry(&self.root, &entry.rel);
            (self.during_read)(&entry.rel);
            let last = self.fs.observe_entry(&self.root, &entry.rel);
            match (first, last) {
                (Ok(a), Ok(b))
                    if a.entry.stat == entry.stat
                        && b.entry.stat == entry.stat
                        && a.entry.kind == entry.kind
                        && b.entry.kind == entry.kind
                        && a.trace == b.trace =>
                {
                    path_proof = a.trace.proof();
                }
                (_, Err(WalkError::NotFound)) => placement_stability = Stability::Vanished,
                _ => placement_stability = Stability::ChangedDuringRead,
            }
            if placement_stability != Stability::NoChangeDetected {
                self.errors
                    .push(format!("{}: {placement_stability:?}", entry.rel.display()));
            }
        }
        let resolved = link_chain.first().map(|hop| hop.target.clone());
        self.instances.push(FileInstance {
            id: instance_id(&self.root, &entry.rel)?,
            root: self.root.clone(),
            path: self.path(&entry.rel),
            path_proof,
            link_chain,
            resolved,
            content,
            stat,
            stability: placement_stability,
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
    /// second strict observation gives the same link identity, target and parent chain.
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
        )
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
        let read = super::binread::read(
            self.fs,
            &self.root,
            &entry.rel,
            left,
            vec![DiscoverySource::Walk],
            self.binary,
            self.scanning,
            &mut self.parsed,
            self.during_read,
            &mut self.recognized_multiarch,
        );
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
        if let Some(artifact) = read.artifact {
            self.used = self.used.saturating_add(artifact.size);
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
    use crate::collect::fs::RelPath;

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

    /// A file that changes while it is parsed (the hook runs after hashing, before the post-read
    /// check): the read is unstable, and its facts are dropped with it.
    #[test]
    fn a_file_changed_while_it_is_parsed_has_no_facts() {
        use std::io::Write;
        let d = tempfile::TempDir::new().unwrap();
        let lib = d.path().join("lib/ollama");
        std::fs::create_dir_all(&lib).unwrap();
        let so = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so"),
        )
        .unwrap();
        std::fs::write(lib.join("libx.so"), &so).unwrap();
        let grow = |rel: &RelPath| {
            if rel.display() == "lib/ollama/libx.so" {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(lib.join("libx.so"))
                    .unwrap();
                f.write_all(b"!").unwrap();
            }
        };
        let f = collect_with(d.path(), InstallBudgets::default(), &grow).unwrap();
        let x = f
            .instances
            .iter()
            .find(|i| i.path.as_bytes().ends_with(b"/libx.so"))
            .unwrap();
        assert_eq!(x.stability, Stability::ChangedDuringRead);
        assert!(f.binaries.is_empty(), "{:?}", f.binaries);
        let f = collect_with(d.path(), InstallBudgets::default(), &|_| {}).unwrap();
        assert_eq!(f.binaries.len(), 1);
    }

    #[test]
    fn code_outcomes_match_named_reads_and_require_stability() {
        use crate::code::CodeBudgets;
        use crate::collect::named::{self, NamedBudgets};
        use std::io::Write;

        let d = tempfile::TempDir::new().unwrap();
        let lib = d.path().join("lib/ollama");
        std::fs::create_dir_all(&lib).unwrap();
        let path = lib.join("libx.so");
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/code/spawn.so");
        std::fs::copy(fixture, &path).unwrap();
        let mut budgets = InstallBudgets::default();
        budgets.binary.code = Some(CodeBudgets::default());
        let installed = super::collect_with_code(d.path(), budgets).unwrap();
        let named = named::collect(
            std::slice::from_ref(&path),
            NamedBudgets {
                binary: budgets.binary,
                ..NamedBudgets::default()
            },
        )
        .unwrap();
        assert!(!installed.code.is_empty());
        assert_eq!(installed.code, named.code);

        let grow = |rel: &RelPath| {
            if rel.display() == "lib/ollama/libx.so" {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"!")
                    .unwrap();
            }
        };
        let changed = collect_with(d.path(), budgets, &grow).unwrap();
        assert!(changed.code.is_empty());
        assert!(changed.binaries.is_empty());
        assert!(super::collect(d.path(), budgets).unwrap().code.is_empty());
    }
    #[test]
    fn unstable_reads_discard_slice_witnesses_and_stable_duplicates_restore_content() {
        use crate::code::{CodeBudgets, CodeOutcome};
        use std::io::Write;

        for change in ["grow", "replace", "vanish"] {
            for duplicate in [false, true] {
                let d = tempfile::TempDir::new().unwrap();
                let lib = d.path().join("lib/ollama");
                std::fs::create_dir_all(&lib).unwrap();
                let bytes = std::fs::read(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/code/spawn.so"),
                )
                .unwrap();
                let path = lib.join("a.so");
                std::fs::write(&path, &bytes).unwrap();
                if duplicate {
                    std::fs::write(lib.join("z.so"), &bytes).unwrap();
                }
                let mut budgets = InstallBudgets::default();
                budgets.binary.code = Some(CodeBudgets::default());
                let mut facts = collect_with(d.path(), budgets, &|rel| {
                    if rel.display() != "lib/ollama/a.so" {
                        return;
                    }
                    match change {
                        "grow" => std::fs::OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap()
                            .write_all(b"!")
                            .unwrap(),
                        "replace" => {
                            let replacement = d.path().join("replacement");
                            std::fs::write(&replacement, &bytes).unwrap();
                            std::fs::rename(replacement, &path).unwrap();
                        }
                        "vanish" => std::fs::remove_file(&path).unwrap(),
                        _ => unreachable!(),
                    }
                })
                .unwrap();
                assert!(!facts.recognized_multiarch);
                assert!(!crate::analyze::multiarch_code::prepare(
                    &mut facts.artifacts,
                    &facts.instances,
                    true,
                    facts.recognized_multiarch,
                ));
                assert!(facts
                    .artifacts
                    .iter()
                    .all(|a| a.code_slice_inventory.is_none()));
                let unstable = facts
                    .instances
                    .iter()
                    .find(|i| i.path.as_bytes().ends_with(b"/a.so"))
                    .unwrap();
                assert_ne!(unstable.stability, Stability::NoChangeDetected);
                assert_eq!(facts.artifacts.len(), 1);
                if duplicate {
                    assert_eq!(facts.binaries.len(), 1, "{change}: stable duplicate");
                    assert_eq!(facts.code.len(), 1);
                    assert_eq!(facts.artifacts[0].slices.len(), 1);
                    assert!(matches!(&facts.code[0].1,
                        CodeOutcome::Analyzed { call_sites, .. } if !call_sites.is_empty()));
                } else {
                    assert!(facts.binaries.is_empty(), "{change}");
                    assert!(facts.code.is_empty(), "{change}");
                    assert!(
                        facts.artifacts[0].slices.is_empty(),
                        "{change}: unstable reads must not retain slice witnesses"
                    );
                    assert!(facts.artifacts[0].code_slice_inventory.is_none());
                    let coverage = crate::analyze::install_code::coverage(
                        &facts,
                        budgets.binary.code.unwrap().bytes,
                    )
                    .unwrap();
                    let content = coverage
                        .iter()
                        .find(|c| matches!(c.scope, sigil_model::Ref::Artifact(_)))
                        .expect("recognized unstable content retains its not-parsed summary");
                    assert_eq!(
                        content.state,
                        CoverageState::Partial {
                            missing: vec![sigil_model::BINARY_NOT_PARSED.to_string()],
                        }
                    );
                    assert_eq!(content.budget.as_ref().unwrap().used, 0);
                }
            }
        }
    }

    #[test]
    fn aarch64_unstable_recognition_is_separate_from_stable_evidence() {
        use crate::code::{CodeBudgets, CodeOutcome};
        use std::io::Write;

        for change in ["grow", "replace", "vanish"] {
            for duplicate in [false, true] {
                let d = tempfile::TempDir::new().unwrap();
                let lib = d.path().join("lib/ollama");
                std::fs::create_dir_all(&lib).unwrap();
                let bytes = std::fs::read(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/code-aarch64/elf-clang-plt.so"),
                )
                .unwrap();
                let path = lib.join("a.so");
                std::fs::write(&path, &bytes).unwrap();
                if duplicate {
                    std::fs::write(lib.join("z.so"), &bytes).unwrap();
                }
                let mut budgets = InstallBudgets::default();
                budgets.binary.code = Some(CodeBudgets::default());
                let mut facts = collect_with(d.path(), budgets, &|rel| {
                    if rel.display() != "lib/ollama/a.so" {
                        return;
                    }
                    match change {
                        "grow" => std::fs::OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap()
                            .write_all(b"!")
                            .unwrap(),
                        "replace" => {
                            let replacement = d.path().join("replacement");
                            std::fs::write(&replacement, &bytes).unwrap();
                            std::fs::rename(replacement, &path).unwrap();
                        }
                        "vanish" => std::fs::remove_file(&path).unwrap(),
                        _ => unreachable!(),
                    }
                })
                .unwrap();
                assert!(facts.recognized_multiarch);
                assert!(crate::analyze::multiarch_code::prepare(
                    &mut facts.artifacts,
                    &facts.instances,
                    true,
                    facts.recognized_multiarch
                ));
                let unstable = facts
                    .instances
                    .iter()
                    .find(|i| i.path.as_bytes().ends_with(b"/a.so"))
                    .unwrap();
                assert_ne!(unstable.stability, Stability::NoChangeDetected);
                assert_eq!(facts.artifacts.len(), 1);
                if duplicate {
                    assert_eq!(facts.binaries.len(), 1, "{change}: stable duplicate");
                    assert_eq!(facts.code.len(), 1);
                    assert_eq!(facts.artifacts[0].slices.len(), 1);
                    assert!(matches!(&facts.code[0].1,
                        CodeOutcome::Analyzed { call_sites, .. } if !call_sites.is_empty()));
                } else {
                    assert!(facts.binaries.is_empty(), "{change}");
                    assert!(facts.code.is_empty(), "{change}");
                    assert!(
                        facts.artifacts[0].slices.is_empty(),
                        "{change}: unstable reads must not retain slice witnesses"
                    );
                    assert!(facts.artifacts[0].code_slice_inventory.is_none());
                    let coverage = crate::analyze::install_code::coverage(
                        &facts,
                        budgets.binary.code.unwrap().bytes,
                    )
                    .unwrap();
                    let content = coverage
                        .iter()
                        .find(|c| matches!(c.scope, sigil_model::Ref::Artifact(_)))
                        .expect("recognized unstable content retains its not-parsed summary");
                    assert_eq!(
                        content.state,
                        CoverageState::Partial {
                            missing: vec![sigil_model::BINARY_NOT_PARSED.to_string()],
                        }
                    );
                    assert_eq!(content.budget.as_ref().unwrap().used, 0);
                }
            }
        }
    }

    #[test]
    fn a_parent_swap_preserving_the_leaf_inode_cannot_mint_a_path_proof() {
        use std::cell::Cell;
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::TempDir::new().unwrap();
        let lib = d.path().join("lib/ollama");
        let replacement = d.path().join("replacement");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf/libdata.so"),
        )
        .unwrap();
        std::fs::write(lib.join("libx.so"), &bytes).unwrap();
        std::fs::hard_link(lib.join("libx.so"), replacement.join("libx.so")).unwrap();
        let seen = std::fs::symlink_metadata(lib.join("libx.so")).unwrap();
        let switched = Cell::new(false);
        let swap = |rel: &RelPath| {
            if rel.display() == "lib/ollama/libx.so" && !switched.replace(true) {
                std::fs::rename(&lib, d.path().join("old-ollama")).unwrap();
                std::fs::rename(&replacement, &lib).unwrap();
            }
        };
        let facts = collect_with(d.path(), InstallBudgets::default(), &swap).unwrap();
        assert!(switched.get());
        let now = std::fs::symlink_metadata(lib.join("libx.so")).unwrap();
        assert_eq!((seen.dev(), seen.ino()), (now.dev(), now.ino()));
        let x = facts
            .instances
            .iter()
            .find(|i| i.path.as_bytes().ends_with(b"/libx.so"))
            .unwrap();
        assert_eq!((x.stat.dev, x.stat.ino), (seen.dev(), seen.ino()));
        assert_eq!(x.stability, Stability::ChangedDuringRead);
        assert!(x.path_proof.is_none());
        assert!(matches!(
            x.content,
            sigil_model::InstanceContent::Read { .. }
        ));
        assert!(
            facts.binaries.is_empty(),
            "unstable placement cannot publish parsed facts"
        );
        assert!(matches!(facts.discovery.state, CoverageState::Error { .. }));
    }

    #[test]
    fn replacing_a_link_with_identical_target_text_is_still_an_identity_change() {
        use std::cell::Cell;
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::TempDir::new().unwrap();
        let lib = d.path().join("lib/ollama");
        std::fs::create_dir_all(&lib).unwrap();
        let path = lib.join("link.so");
        symlink("unread-target.so", &path).unwrap();
        let seen = std::fs::symlink_metadata(&path).unwrap();
        let switched = Cell::new(false);
        let swap = |rel: &RelPath| {
            if rel.display() == "lib/ollama/link.so" && !switched.replace(true) {
                // Keep the old link alive elsewhere so immediate inode reuse cannot mask the test.
                std::fs::rename(&path, d.path().join("old-link.so")).unwrap();
                symlink("unread-target.so", &path).unwrap();
            }
        };
        let facts = collect_with(d.path(), InstallBudgets::default(), &swap).unwrap();
        assert!(switched.get());
        let now = std::fs::symlink_metadata(&path).unwrap();
        assert_ne!((seen.dev(), seen.ino()), (now.dev(), now.ino()));
        let link = facts
            .instances
            .iter()
            .find(|i| i.path.as_bytes().ends_with(b"/link.so"))
            .unwrap();
        assert_eq!(link.link_chain[0].target.as_bytes(), b"unread-target.so");
        assert_eq!(link.stability, Stability::ChangedDuringRead);
        assert!(link.path_proof.is_none());
        assert!(matches!(
            link.content,
            sigil_model::InstanceContent::NotRead {
                why: sigil_model::NotReadReason::NotFollowed
            }
        ));
        assert!(matches!(facts.discovery.state, CoverageState::Error { .. }));
    }
}
