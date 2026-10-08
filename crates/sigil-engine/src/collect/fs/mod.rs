//! `SafeFs`: the only way the engine reads files (plan §4.6.2).
//!
//! - **Anchored.** Each scan root is opened once as a directory fd. Every further open is relative
//!   to a directory fd SafeFs already holds, one component at a time, with
//!   `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` and `O_NOFOLLOW`
//!   (`openat` with `O_NOFOLLOW` on kernels without `openat2`). No path string is ever handed to
//!   the kernel to resolve.
//! - **Symlinks are resolved here, not by the kernel.** Each hop is read with `readlinkat` and
//!   recorded. A target inside a scan root is followed through that root's anchored walk; a target
//!   outside every root is recorded and not read.
//! - **Read-only and bounded.** Files are read with `read(2)` (never `mmap`), hashed as a stream,
//!   and stopped at a byte limit. Walks have budgets for depth, for files found, for directory
//!   entries read, and for the entries of one directory. They hold one directory fd per level
//!   (a subdirectory is opened only when it is listed), so the fds a walk holds are bounded by
//!   its depth.
//!
//! System calls SafeFs makes (the list PR-3b's safety test enforces): `openat2`, `openat`,
//! `newfstatat`, `fstat`, `readlinkat`, `read`, `getdents64`, `fcntl`, `close`; and, once per scan
//! root, `open` plus what `std::fs::canonicalize` needs. All are read-only (contract C-5).

use std::cell::Cell;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use sigil_model::RootId;

mod path;
mod read;
mod resolve;
mod walk;

pub use path::{link_target, LinkTarget, PathError, RelPath};
pub use read::{FileRead, ReadOutcome, ReadSpec};
pub use walk::{Skip, Walk, WalkError};

/// Budgets that bound a scan (plan §4.9). Exceeding one is recorded, never fatal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsBudgets {
    /// Files discovered by walks, across all roots.
    pub max_files: u64,
    /// Directory entries read by walks, of any type, across all roots.
    pub max_entries: u64,
    /// Entries in one directory. A larger directory is not listed: its names would all have to be
    /// held to be sorted. With names of at most 255 bytes, this also bounds that memory.
    pub max_dir_entries: u64,
    /// Directory depth below the directory a walk starts in.
    pub max_depth: u32,
    /// Symlink hops while resolving one path.
    pub max_link_hops: u32,
}

impl Default for FsBudgets {
    fn default() -> Self {
        FsBudgets {
            max_files: 4096,
            max_entries: 65_536,
            max_dir_entries: 16_384,
            max_depth: 32,
            max_link_hops: 40,
        }
    }
}

/// Why a scan root could not be opened. The caller records it as coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    NotFound,
    PermissionDenied,
    NotADirectory,
    /// A root with this ID was already added.
    Duplicate,
    Failed(String),
}

pub(crate) struct Root {
    pub id: RootId,
    /// The canonical absolute path: symlink targets are matched against it.
    pub path: PathBuf,
    pub fd: OwnedFd,
}

/// Anchored, bounded, read-only access to files under scan roots.
pub struct SafeFs {
    pub(crate) roots: Vec<Root>,
    pub(crate) budgets: FsBudgets,
    /// Files discovered by walks so far.
    pub(crate) files_seen: Cell<u64>,
    /// Directory entries read by walks so far.
    pub(crate) entries_seen: Cell<u64>,
    /// Cleared when the kernel lacks `openat2`; `openat` with `O_NOFOLLOW` is used instead.
    pub(crate) have_openat2: Cell<bool>,
}

impl SafeFs {
    pub fn new(budgets: FsBudgets) -> SafeFs {
        SafeFs {
            roots: vec![],
            budgets,
            files_seen: Cell::new(0),
            entries_seen: Cell::new(0),
            have_openat2: Cell::new(true),
        }
    }

    /// Opens `path` as scan root `id`. The root path itself is the caller's explicit input, so
    /// symlinks in it are resolved (by `canonicalize`); nothing below it is.
    pub fn add_root(&mut self, id: RootId, path: &Path) -> Result<(), RootError> {
        if self.roots.iter().any(|r| r.id == id) {
            return Err(RootError::Duplicate);
        }
        let canonical = std::fs::canonicalize(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => RootError::NotFound,
            std::io::ErrorKind::PermissionDenied => RootError::PermissionDenied,
            _ => RootError::Failed(e.to_string()),
        })?;
        let fd = rustix::fs::open(
            &canonical,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::NOTDIR => RootError::NotADirectory,
            rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => RootError::PermissionDenied,
            rustix::io::Errno::NOENT => RootError::NotFound,
            other => RootError::Failed(other.to_string()),
        })?;
        self.roots.push(Root {
            id,
            path: canonical,
            fd,
        });
        Ok(())
    }

    /// The canonical path of root `id`.
    pub fn root_path(&self, id: &RootId) -> Option<&Path> {
        self.roots
            .iter()
            .find(|r| r.id == *id)
            .map(|r| r.path.as_path())
    }

    pub(crate) fn root_index(&self, id: &RootId) -> Option<usize> {
        self.roots.iter().position(|r| r.id == *id)
    }

    pub(crate) fn canonical_roots(&self) -> Vec<PathBuf> {
        self.roots.iter().map(|r| r.path.clone()).collect()
    }
}
