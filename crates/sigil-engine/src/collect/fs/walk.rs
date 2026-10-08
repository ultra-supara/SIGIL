//! Walking a directory under a scan root (plan §4.6.2).
//!
//! Depth-first over the physical tree first, entries sorted by name. A symlink to a directory is
//! followed only after the physical tree, under the link's own path, and only if the directory
//! was not entered yet: one visited set of `dev:ino` per walk, so loops end and every directory
//! is listed once, under its physical path when it has one.

use std::collections::HashSet;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

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
    /// The budgets that were exhausted: `files_discovered` (shared by every walk of a SafeFs) and
    /// `walk_depth`.
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

struct Pending {
    rel: RelPath,
    fd: OwnedFd,
    depth: u32,
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
}

impl SafeFs {
    /// Lists the files under `dir` (depth-first, sorted), within the depth and file budgets.
    pub fn walk(&self, root: &RootId, dir: &RelPath) -> Result<Walk, WalkError> {
        let index = self
            .root_index(root)
            .ok_or_else(|| WalkError::Failed(format!("unknown scan root {root}")))?;
        let start = match self.resolve(index, dir).end {
            End::Dir { fd, .. } => self.dir_fd(index, fd),
            End::Entry {
                parent,
                name,
                lstat,
                ..
            } if FileType::from_raw_mode(lstat.st_mode) == FileType::Directory => {
                let parent = parent
                    .as_ref()
                    .map_or_else(|| self.roots[index].fd.as_fd(), |fd| fd.as_fd());
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
        };
        if let Some(id) = dev_ino(start.as_fd()) {
            walker.visited.insert(id);
        }
        walker.physical.push(Pending {
            rel: dir.clone(),
            fd: start,
            depth: 0,
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
            if self.fs.files_seen.get() >= self.fs.budgets.max_files {
                self.out.unscanned.push(next.rel);
                self.exhausted();
                return;
            }
            if !self.list(next) {
                self.exhausted();
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
            Some(id) if self.visited.insert(id) => Some(Pending { rel, fd, depth }),
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

    /// Lists one directory. Returns `false` when the file budget ran out inside it.
    fn list(&mut self, dir: Pending) -> bool {
        let mut names = vec![];
        match rustix::fs::Dir::read_from(dir.fd.as_fd()) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) => match entry.file_name().to_str() {
                            Ok("." | "..") => {}
                            Ok(name) => names.push(name.to_string()),
                            Err(_) => {
                                let lossy = entry.file_name().to_string_lossy().into_owned();
                                if let Ok(rel) = dir.rel.join(&lossy) {
                                    self.skip(rel, Skip::Failed("the name is not UTF-8".into()));
                                }
                            }
                        },
                        Err(e) => {
                            self.skip(dir.rel.clone(), Skip::Failed(e.to_string()));
                            break;
                        }
                    }
                }
            }
            Err(Errno::ACCESS | Errno::PERM) => {
                self.skip(dir.rel, Skip::PermissionDenied);
                return true;
            }
            Err(e) => {
                self.skip(dir.rel, Skip::Failed(e.to_string()));
                return true;
            }
        }
        names.sort();
        let mut subdirs = vec![];
        for name in names {
            let Ok(child) = dir.rel.join(&name) else {
                continue;
            };
            let lstat = match rustix::fs::statat(
                dir.fd.as_fd(),
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
                        self.out.unscanned.push(dir.rel);
                        self.out
                            .unscanned
                            .extend(subdirs.into_iter().map(|p: Pending| p.rel));
                        return false;
                    }
                    self.out.files.push(child);
                }
                FileType::Directory => {
                    let depth = dir.depth + 1;
                    if depth > self.fs.budgets.max_depth {
                        self.deepest = self.deepest.max(Some(depth));
                        self.out.unscanned.push(child);
                        continue;
                    }
                    match self.fs.open_dir(dir.fd.as_fd(), &name) {
                        Ok(fd) => match dev_ino(fd.as_fd()) {
                            Some(id) if self.visited.insert(id) => subdirs.push(Pending {
                                rel: child,
                                fd,
                                depth,
                            }),
                            Some(_) => self.skip(child, Skip::AlreadyVisited),
                            None => self.skip(child, Skip::Failed("fstat failed".into())),
                        },
                        Err(Errno::ACCESS | Errno::PERM) => {
                            self.skip(child, Skip::PermissionDenied)
                        }
                        Err(Errno::NOENT) => {}
                        Err(e) => self.skip(child, Skip::Failed(e.to_string())),
                    }
                }
                FileType::Symlink => {
                    if !self.link(child, dir.depth + 1) {
                        self.out.unscanned.push(dir.rel);
                        self.out
                            .unscanned
                            .extend(subdirs.into_iter().map(|p: Pending| p.rel));
                        return false;
                    }
                }
                _ => self.skip(child, Skip::NotRegularFile),
            }
        }
        // Pushed in reverse so that they are popped in name order.
        self.physical.extend(subdirs.into_iter().rev());
        true
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

    /// The file budget ran out: every directory still pending is unscanned.
    fn exhausted(&mut self) {
        let pending: Vec<RelPath> = self.physical.drain(..).map(|p| p.rel).collect();
        self.out.unscanned.extend(pending);
        let linked: Vec<RelPath> = self.linked.drain(..).map(|(rel, _)| rel).collect();
        self.out.unscanned.extend(linked);
        self.out.exceeded.push(BudgetUse {
            budget: "files_discovered".to_string(),
            used: self.fs.files_seen.get(),
            limit: self.fs.budgets.max_files,
        });
    }

    fn finish(mut self) -> Walk {
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
