//! Walking a directory under a scan root (plan §4.6.2).
//!
//! Depth-first over the physical tree first, entries sorted by name. A symlink to a directory is
//! followed only after the physical tree, under the link's own path, and only if the directory
//! was not entered yet: one visited set of `dev:ino` per walk, so loops end and every directory
//! is listed once, under its physical path when it has one.

use std::collections::HashSet;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::rc::Rc;

use rustix::fs::{AtFlags, FileType, OFlags};
use rustix::io::Errno;
use sigil_model::{BudgetUse, RootId};

use super::path::RelPath;
use super::read::Snapshot;
use super::resolve::End;
use super::SafeFs;

/// The result of [`SafeFs::walk`]. Every list is sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Walk {
    /// Regular files, and symlinks that lead to one, by the path they were found at.
    pub files: Vec<RelPath>,
    /// Entries that were not listed or entered, and why.
    pub skipped: Vec<(RelPath, Skip)>,
    /// Directories not (fully) scanned because a budget was exhausted.
    pub unscanned: Vec<RelPath>,
    /// The budgets that were exhausted: `files_discovered` and `entries_listed` (shared by every
    /// walk of a SafeFs), `directory_entries` (a directory had more entries than one may; `used` is
    /// the first entry over the limit), and `walk_depth`.
    pub exceeded: Vec<BudgetUse>,
}

/// Why an entry was not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// A FIFO, socket, or device (directly or through a link).
    NotRegularFile,
    PermissionDenied,
    /// A link to a directory this walk already entered (this is how loops end).
    AlreadyVisited,
    /// A link that leads outside every scan root.
    OutsideScanRoots,
    /// A link whose target does not exist.
    Dangling,
    Failed(String),
}

/// Why a walk could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    NotFound,
    PermissionDenied,
    NotADirectory,
    OutsideRoots,
    Failed(String),
}

/// A directory waiting to be listed.
struct Pending {
    rel: RelPath,
    depth: u32,
    dir: Handle,
}

/// How a pending directory is reached. A subdirectory is opened only when it is listed, so a walk
/// holds one fd per level: the directories whose subdirectories are still pending.
enum Handle {
    /// Already open: where the walk starts, or where a followed link leads.
    Open(OwnedFd),
    /// `name` in `parent`, with the `dev:ino` it had when it was found.
    Child {
        parent: Rc<OwnedFd>,
        name: String,
        id: (u64, u64),
    },
}

/// A budget shared by every walk of a SafeFs.
#[derive(Debug, Clone, Copy)]
enum Shared {
    Files,
    Entries,
}

/// The state of one walk.
struct Walker<'a> {
    fs: &'a SafeFs,
    root: usize,
    out: Walk,
    visited: HashSet<(u64, u64)>,
    physical: Vec<Pending>,
    /// Links to directories, entered after the physical tree: `(path, depth)`.
    linked: Vec<(RelPath, u32)>,
    deepest: Option<u32>,
    /// A directory had more entries than `max_dir_entries`.
    oversized: bool,
}

impl SafeFs {
    /// Lists the files under `dir` (depth-first, sorted), within the depth and file budgets.
    pub fn walk(&self, root: &RootId, dir: &RelPath) -> Result<Walk, WalkError> {
        let index = self
            .root_index(root)
            .ok_or_else(|| WalkError::Failed(format!("unknown scan root {root}")))?;
        // A link can lead into another scan root: the directory is opened in the root the path
        // resolved to, while the walk keeps reporting paths under `dir` in `root`.
        let start = match self.resolve(index, dir).end {
            End::Dir { root: at, fd, .. } => self.dir_fd(at, fd),
            End::Entry {
                root: at,
                parent,
                name,
                lstat,
                ..
            } if FileType::from_raw_mode(lstat.st_mode) == FileType::Directory => {
                let parent = parent
                    .as_ref()
                    .map_or_else(|| self.roots[at].fd.as_fd(), |fd| fd.as_fd());
                self.open_dir(parent, &name)
            }
            End::Entry { .. } | End::NotADirectory => return Err(WalkError::NotADirectory),
            End::NotFound => return Err(WalkError::NotFound),
            End::OutsideRoots { .. } => return Err(WalkError::OutsideRoots),
            End::PermissionDenied => return Err(WalkError::PermissionDenied),
            End::TooManyHops => return Err(WalkError::Failed("too many symlink hops".into())),
            End::Failed(m) => return Err(WalkError::Failed(m)),
        }
        .map_err(|e| match e {
            Errno::ACCESS | Errno::PERM => WalkError::PermissionDenied,
            other => WalkError::Failed(other.to_string()),
        })?;
        let mut walker = Walker {
            fs: self,
            root: index,
            out: Walk::default(),
            visited: HashSet::new(),
            physical: vec![],
            linked: vec![],
            deepest: None,
            oversized: false,
        };
        if let Some(id) = dev_ino(start.as_fd()) {
            walker.visited.insert(id);
        }
        walker.physical.push(Pending {
            rel: dir.clone(),
            depth: 0,
            dir: Handle::Open(start),
        });
        walker.run();
        Ok(walker.finish())
    }

    /// An fd on a directory reached as a whole (`None` is the root's own fd).
    fn dir_fd(&self, root: usize, fd: Option<OwnedFd>) -> Result<OwnedFd, Errno> {
        match fd {
            Some(fd) => Ok(fd),
            None => self.open_at(
                self.roots[root].fd.as_fd(),
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY,
            ),
        }
    }

    /// Counts one more discovered file; `false` once the budget is exhausted.
    fn take_file(&self) -> bool {
        let seen = self.files_seen.get();
        if seen >= self.budgets.max_files {
            return false;
        }
        self.files_seen.set(seen + 1);
        true
    }

    /// Counts one more directory entry read; `false` once the budget is exhausted.
    fn take_entry(&self) -> bool {
        let seen = self.entries_seen.get();
        if seen >= self.budgets.max_entries {
            return false;
        }
        self.entries_seen.set(seen + 1);
        true
    }

    /// The shared budget that is exhausted, if any.
    fn spent(&self) -> Option<Shared> {
        if self.files_seen.get() >= self.budgets.max_files {
            Some(Shared::Files)
        } else if self.entries_seen.get() >= self.budgets.max_entries {
            Some(Shared::Entries)
        } else {
            None
        }
    }
}

fn dev_ino(fd: BorrowedFd<'_>) -> Option<(u64, u64)> {
    rustix::fs::fstat(fd).ok().map(|st| {
        let s = Snapshot::of(&st);
        (s.dev, s.ino)
    })
}

impl Walker<'_> {
    fn skip(&mut self, rel: RelPath, why: Skip) {
        self.out.skipped.push((rel, why));
    }

    fn run(&mut self) {
        loop {
            let next = match self.physical.pop() {
                Some(next) => next,
                None if self.linked.is_empty() => return,
                None => match self.next_linked() {
                    Some(next) => next,
                    None => continue,
                },
            };
            if let Some(budget) = self.fs.spent() {
                self.out.unscanned.push(next.rel);
                self.exhausted(budget);
                return;
            }
            let Some((rel, fd, depth)) = self.open(next) else {
                continue;
            };
            if let Err(budget) = self.list(rel, fd, depth) {
                self.exhausted(budget);
                return;
            }
        }
    }

    /// Enters the first pending directory link, if it leads to a directory not entered yet.
    fn next_linked(&mut self) -> Option<Pending> {
        self.linked.sort();
        if self.linked.is_empty() {
            return None;
        }
        let (rel, depth) = self.linked.remove(0);
        if depth > self.fs.budgets.max_depth {
            self.deepest = self.deepest.max(Some(depth));
            self.out.unscanned.push(rel);
            return None;
        }
        let fd = match self.fs.resolve(self.root, &rel).end {
            End::Dir { root, fd, .. } => self.fs.dir_fd(root, fd),
            End::Entry {
                root, parent, name, ..
            } => {
                let parent = parent
                    .as_ref()
                    .map_or_else(|| self.fs.roots[root].fd.as_fd(), |fd| fd.as_fd());
                self.fs.open_dir(parent, &name)
            }
            _ => Err(Errno::NOENT),
        };
        let fd = match fd {
            Ok(fd) => fd,
            Err(Errno::ACCESS | Errno::PERM) => {
                self.skip(rel, Skip::PermissionDenied);
                return None;
            }
            Err(e) => {
                self.skip(rel, Skip::Failed(e.to_string()));
                return None;
            }
        };
        match dev_ino(fd.as_fd()) {
            Some(id) if self.visited.insert(id) => Some(Pending {
                rel,
                depth,
                dir: Handle::Open(fd),
            }),
            Some(_) => {
                self.skip(rel, Skip::AlreadyVisited);
                None
            }
            None => {
                self.skip(rel, Skip::Failed("fstat failed".into()));
                None
            }
        }
    }

    /// Opens a pending directory. A subdirectory must still be the directory that was found.
    fn open(&mut self, pending: Pending) -> Option<(RelPath, OwnedFd, u32)> {
        let Pending { rel, depth, dir } = pending;
        let fd = match dir {
            Handle::Open(fd) => fd,
            Handle::Child { parent, name, id } => match self.fs.open_dir(parent.as_fd(), &name) {
                Ok(fd) if dev_ino(fd.as_fd()) == Some(id) => fd,
                Ok(_) => {
                    let why = "the directory was replaced during the walk";
                    self.skip(rel, Skip::Failed(why.into()));
                    return None;
                }
                Err(Errno::ACCESS | Errno::PERM) => {
                    self.skip(rel, Skip::PermissionDenied);
                    return None;
                }
                Err(Errno::NOENT) => return None,
                Err(e) => {
                    self.skip(rel, Skip::Failed(e.to_string()));
                    return None;
                }
            },
        };
        Some((rel, fd, depth))
    }

    /// Lists one directory. Fails with the shared budget that ran out inside it.
    ///
    /// Every entry read counts against `max_entries`. A directory with more than `max_dir_entries`
    /// entries is unscanned as a whole: listing part of it would depend on the order the kernel
    /// returns entries in.
    fn list(&mut self, rel: RelPath, fd: OwnedFd, depth: u32) -> Result<(), Shared> {
        let mut names = vec![];
        let mut not_utf8 = vec![];
        let mut failed = None;
        let mut count: u64 = 0;
        match rustix::fs::Dir::read_from(fd.as_fd()) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            failed = Some(e.to_string());
                            break;
                        }
                    };
                    let name = entry.file_name();
                    if matches!(name.to_bytes(), b"." | b"..") {
                        continue;
                    }
                    if !self.fs.take_entry() {
                        self.out.unscanned.push(rel);
                        return Err(Shared::Entries);
                    }
                    count += 1;
                    if count > self.fs.budgets.max_dir_entries {
                        self.oversized = true;
                        self.out.unscanned.push(rel);
                        return Ok(());
                    }
                    match name.to_str() {
                        Ok(name) => names.push(name.to_string()),
                        Err(_) => not_utf8.push(name.to_string_lossy().into_owned()),
                    }
                }
            }
            Err(Errno::ACCESS | Errno::PERM) => {
                self.skip(rel, Skip::PermissionDenied);
                return Ok(());
            }
            Err(e) => {
                self.skip(rel, Skip::Failed(e.to_string()));
                return Ok(());
            }
        }
        for lossy in not_utf8 {
            if let Ok(child) = rel.join(&lossy) {
                self.skip(child, Skip::Failed("the name is not UTF-8".into()));
            }
        }
        if let Some(message) = failed {
            self.skip(rel.clone(), Skip::Failed(message));
        }
        names.sort();
        let parent = Rc::new(fd);
        let mut subdirs = vec![];
        for name in names {
            let Ok(child) = rel.join(&name) else {
                continue;
            };
            let lstat = match rustix::fs::statat(
                parent.as_fd(),
                name.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(st) => st,
                Err(Errno::NOENT) => continue,
                Err(Errno::ACCESS | Errno::PERM) => {
                    self.skip(child, Skip::PermissionDenied);
                    continue;
                }
                Err(e) => {
                    self.skip(child, Skip::Failed(e.to_string()));
                    continue;
                }
            };
            match FileType::from_raw_mode(lstat.st_mode) {
                FileType::RegularFile => {
                    if !self.fs.take_file() {
                        self.out.unscanned.push(rel);
                        self.out
                            .unscanned
                            .extend(subdirs.into_iter().map(|p: Pending| p.rel));
                        return Err(Shared::Files);
                    }
                    self.out.files.push(child);
                }
                FileType::Directory => {
                    let depth = depth + 1;
                    if depth > self.fs.budgets.max_depth {
                        self.deepest = self.deepest.max(Some(depth));
                        self.out.unscanned.push(child);
                        continue;
                    }
                    let found = Snapshot::of(&lstat);
                    let id = (found.dev, found.ino);
                    if self.visited.insert(id) {
                        subdirs.push(Pending {
                            rel: child,
                            depth,
                            dir: Handle::Child {
                                parent: Rc::clone(&parent),
                                name,
                                id,
                            },
                        });
                    } else {
                        self.skip(child, Skip::AlreadyVisited);
                    }
                }
                FileType::Symlink => {
                    if !self.link(child, depth + 1) {
                        self.out.unscanned.push(rel);
                        self.out
                            .unscanned
                            .extend(subdirs.into_iter().map(|p: Pending| p.rel));
                        return Err(Shared::Files);
                    }
                }
                _ => self.skip(child, Skip::NotRegularFile),
            }
        }
        // Pushed in reverse so that they are popped in name order.
        self.physical.extend(subdirs.into_iter().rev());
        Ok(())
    }

    /// Classifies a symlink. Returns `false` when it is a file and the file budget ran out.
    fn link(&mut self, child: RelPath, depth: u32) -> bool {
        match self.fs.resolve(self.root, &child).end {
            End::Entry { lstat, .. } => match FileType::from_raw_mode(lstat.st_mode) {
                FileType::RegularFile => {
                    if !self.fs.take_file() {
                        return false;
                    }
                    self.out.files.push(child);
                }
                FileType::Directory => self.linked.push((child, depth)),
                _ => self.skip(child, Skip::NotRegularFile),
            },
            End::Dir { .. } => self.linked.push((child, depth)),
            End::OutsideRoots { .. } => self.skip(child, Skip::OutsideScanRoots),
            End::NotFound | End::NotADirectory => self.skip(child, Skip::Dangling),
            End::PermissionDenied => self.skip(child, Skip::PermissionDenied),
            End::TooManyHops => self.skip(
                child,
                Skip::Failed(format!(
                    "more than {} symlink hops",
                    self.fs.budgets.max_link_hops
                )),
            ),
            End::Failed(message) => self.skip(child, Skip::Failed(message)),
        }
        true
    }

    /// A shared budget ran out: every directory still pending is unscanned.
    fn exhausted(&mut self, budget: Shared) {
        let pending: Vec<RelPath> = self.physical.drain(..).map(|p| p.rel).collect();
        self.out.unscanned.extend(pending);
        let linked: Vec<RelPath> = self.linked.drain(..).map(|(rel, _)| rel).collect();
        self.out.unscanned.extend(linked);
        let (budget, used, limit) = match budget {
            Shared::Files => (
                "files_discovered",
                self.fs.files_seen.get(),
                self.fs.budgets.max_files,
            ),
            Shared::Entries => (
                "entries_listed",
                self.fs.entries_seen.get(),
                self.fs.budgets.max_entries,
            ),
        };
        self.out.exceeded.push(BudgetUse {
            budget: budget.to_string(),
            used,
            limit,
        });
    }

    fn finish(mut self) -> Walk {
        if self.oversized {
            let limit = self.fs.budgets.max_dir_entries;
            self.out.exceeded.push(BudgetUse {
                budget: "directory_entries".to_string(),
                used: limit.saturating_add(1),
                limit,
            });
        }
        if let Some(depth) = self.deepest {
            self.out.exceeded.push(BudgetUse {
                budget: "walk_depth".to_string(),
                used: u64::from(depth),
                limit: u64::from(self.fs.budgets.max_depth),
            });
        }
        self.out.files.sort();
        self.out.skipped.sort_by(|a, b| a.0.cmp(&b.0));
        self.out.unscanned.sort();
        self.out.unscanned.dedup();
        self.out
    }
}
