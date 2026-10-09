//! Reading one file: a single streaming pass that hashes, keeps a bounded prefix, stops at a byte
//! limit, and records whether the file changed while it was read (plan §4.6.2).

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{FileType, OFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use sigil_model::{
    Artifact, ArtifactId, DiscoverySource, FileInstance, Format, InstanceContent, InstanceId,
    NotReadReason, RootId, Stability, StatInfo, UntrustedText,
};

use super::path::RelPath;
use super::resolve::{mode, End, Strict};
use super::SafeFs;

/// What to keep and how much to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSpec {
    /// Bytes kept in memory from the start of the file (e.g. a manifest, a license excerpt).
    pub keep: usize,
    /// The largest file that is hashed; a larger one is not. At most `limit + 1` bytes are read:
    /// the extra byte shows that a file is over the limit, also when its size from `fstat` is
    /// smaller than its contents (procfs) or it grows during the read. `None` reads the whole
    /// file.
    pub limit: Option<u64>,
}

/// The result of [`SafeFs::read_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRead {
    /// The placement. `None` only when nothing exists at the path or it cannot be `stat`ed.
    pub instance: Option<FileInstance>,
    /// The contents. `Some` exactly when the whole file was read and hashed.
    pub artifact: Option<Artifact>,
    /// At most [`ReadSpec::keep`] bytes from the start.
    pub prefix: Vec<u8>,
    pub outcome: ReadOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOutcome {
    Complete,
    /// Larger than the limit: not hashed; the instance is `NotRead { BudgetExceeded }`.
    LimitExceeded {
        limit: u64,
        /// The size from `fstat`, or the bytes read (`limit + 1`) when that is larger: a lower
        /// bound for a file that outgrew its `fstat` size.
        size: u64,
    },
    NotFound,
    NotRead(NotReadReason),
    /// Anything else (too many symlink hops, a component that is not a directory, an I/O error),
    /// with a message for `Coverage::Error`.
    Failed(String),
}

/// What is compared before and after a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

impl Snapshot {
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    pub(crate) fn of(st: &Stat) -> Snapshot {
        Snapshot {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            size: st.st_size as i64,
            mtime: (st.st_mtime as i64, st.st_mtime_nsec as i64),
            ctime: (st.st_ctime as i64, st.st_ctime_nsec as i64),
        }
    }
}

/// Whether a file changed while it was read: `before` and `after` are `fstat`s of the open file,
/// `now` the `dev:ino` the path resolves to afterwards (`None` when it no longer exists).
pub(crate) fn stability(before: &Snapshot, after: &Snapshot, now: Option<(u64, u64)>) -> Stability {
    match now {
        None => Stability::Vanished,
        Some(id) if before != after || id != (before.dev, before.ino) => {
            Stability::ChangedDuringRead
        }
        Some(_) => Stability::NoChangeDetected,
    }
}

/// `inst:<root>/<rel>`, with control characters, `%`, and trailing whitespace percent-encoded so
/// that every path gets a distinct, valid ID.
pub(crate) fn instance_id(root: &RootId, rel: &RelPath) -> Result<InstanceId, String> {
    let raw = format!("{root}/{}", rel.display());
    let keep = raw.trim_end().len();
    let mut id = String::from("inst:");
    for (i, c) in raw.char_indices() {
        if c == '%' || c.is_control() || i >= keep {
            let mut buf = [0u8; 4];
            for byte in c.encode_utf8(&mut buf).bytes() {
                id.push_str(&format!("%{byte:02X}"));
            }
        } else {
            id.push(c);
        }
    }
    InstanceId::new(id).map_err(|e| e.to_string())
}

/// `stat` values as recorded in the session.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
pub(crate) fn stat_info(st: &Stat) -> StatInfo {
    StatInfo {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        mode: mode(st),
        uid: st.st_uid,
        gid: st.st_gid,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mtime_ns: (st.st_mtime as i64)
            .saturating_mul(1_000_000_000)
            .saturating_add(st.st_mtime_nsec as i64),
        nlink: st.st_nlink as u64,
    }
}

impl SafeFs {
    /// Reads `rel` under root `root` through the anchored walk, following symlinks inside the scan
    /// roots. Never fails: every problem is an outcome.
    pub fn read_file(
        &self,
        root: &RootId,
        rel: &RelPath,
        spec: ReadSpec,
        discovered_by: Vec<DiscoverySource>,
    ) -> FileRead {
        let Some(index) = self.root_index(root) else {
            return FileRead::failed(format!("unknown scan root {root}"));
        };
        let id = match instance_id(root, rel) {
            Ok(id) => id,
            Err(e) => return FileRead::failed(e),
        };
        let resolved = self.resolve(index, rel);
        let place = Placement {
            id,
            root: root.clone(),
            path: rel.recorded_under(&self.roots[index].path),
            link_chain: resolved.hops,
            resolved: None,
            discovered_by,
        };
        match resolved.end {
            End::Entry {
                root: at,
                rel: physical,
                parent,
                name,
                lstat,
            } => {
                let place = place.resolved_to(&physical.under(&self.roots[at].path));
                if FileType::from_raw_mode(lstat.st_mode) != FileType::RegularFile {
                    return place.not_read(&lstat, NotReadReason::NotRegularFile);
                }
                let parent = parent
                    .as_ref()
                    .map_or_else(|| self.roots[at].fd.as_fd(), |fd| fd.as_fd());
                match self.open_at(parent, &name, OFlags::RDONLY | OFlags::NONBLOCK) {
                    Ok(fd) => self.read_open(index, rel, place, fd, spec, false),
                    Err(Errno::ACCESS | Errno::PERM) => {
                        place.not_read(&lstat, NotReadReason::PermissionDenied)
                    }
                    Err(Errno::NOENT) => place.not_read(&lstat, NotReadReason::Vanished),
                    Err(e) => FileRead::failed(e.to_string()),
                }
            }
            End::Dir {
                root: at,
                rel: physical,
                fd,
            } => {
                let fd = fd
                    .as_ref()
                    .map_or_else(|| self.roots[at].fd.as_fd(), |fd| fd.as_fd());
                match rustix::fs::fstat(fd) {
                    Ok(st) => place
                        .resolved_to(&physical.under(&self.roots[at].path))
                        .not_read(&st, NotReadReason::NotRegularFile),
                    Err(e) => FileRead::failed(e.to_string()),
                }
            }
            End::OutsideRoots { target, link } => {
                let mut place = place;
                place.resolved = Some(target);
                place.not_read(&link, NotReadReason::OutsideScanRoots)
            }
            End::NotFound => FileRead::without_instance(ReadOutcome::NotFound),
            End::PermissionDenied => {
                FileRead::without_instance(ReadOutcome::NotRead(NotReadReason::PermissionDenied))
            }
            End::TooManyHops => FileRead::failed(format!(
                "more than {} symlink hops",
                self.budgets.max_link_hops
            )),
            End::NotADirectory => FileRead::failed("a path component is not a directory".into()),
            End::Failed(message) => FileRead::failed(message),
        }
    }

    /// Reads the regular file `rel` under root `root` without following any symlink (PR-4a, the
    /// install): every directory on the way and the file itself are opened with `O_NOFOLLOW`, and
    /// the path is checked again the same way after the read. A symlink anywhere on the path is
    /// never opened, so nothing outside the path is read. Never fails: every problem is an
    /// outcome, and a path that is not a regular file now is `NotRead { NotRegularFile }`.
    pub fn read_entry(
        &self,
        root: &RootId,
        rel: &RelPath,
        spec: ReadSpec,
        discovered_by: Vec<DiscoverySource>,
    ) -> FileRead {
        let Some(index) = self.root_index(root) else {
            return FileRead::failed(format!("unknown scan root {root}"));
        };
        let id = match instance_id(root, rel) {
            Ok(id) => id,
            Err(e) => return FileRead::failed(e),
        };
        let place = Placement {
            id,
            root: root.clone(),
            path: rel.recorded_under(&self.roots[index].path),
            link_chain: vec![],
            resolved: None,
            discovered_by,
        };
        match self.resolve_strict(index, rel) {
            Strict::Entry {
                parent,
                name,
                lstat,
            } => {
                if FileType::from_raw_mode(lstat.st_mode) != FileType::RegularFile {
                    return place.not_read(&lstat, NotReadReason::NotRegularFile);
                }
                let parent = parent
                    .as_ref()
                    .map_or_else(|| self.roots[index].fd.as_fd(), |fd| fd.as_fd());
                match self.open_at(parent, &name, OFlags::RDONLY | OFlags::NONBLOCK) {
                    Ok(fd) => self.read_open(index, rel, place, fd, spec, true),
                    Err(Errno::ACCESS | Errno::PERM) => {
                        place.not_read(&lstat, NotReadReason::PermissionDenied)
                    }
                    Err(Errno::NOENT) => place.not_read(&lstat, NotReadReason::Vanished),
                    Err(Errno::LOOP) => FileRead::failed("it changed into a symlink".into()),
                    Err(e) => FileRead::failed(e.to_string()),
                }
            }
            Strict::Link { at } => {
                FileRead::failed(format!("{} is a symlink, not followed", at.display()))
            }
            Strict::NotFound => FileRead::without_instance(ReadOutcome::NotFound),
            Strict::PermissionDenied => {
                FileRead::without_instance(ReadOutcome::NotRead(NotReadReason::PermissionDenied))
            }
            Strict::Root | Strict::NotADirectory => {
                FileRead::failed("a path component is not a directory".into())
            }
            Strict::Failed(message) => FileRead::failed(message),
        }
    }

    /// Streams the open file: limit, hash, prefix, then stability. `strict`: the path is checked
    /// again afterwards without following symlinks.
    fn read_open(
        &self,
        index: usize,
        rel: &RelPath,
        place: Placement,
        fd: OwnedFd,
        spec: ReadSpec,
        strict: bool,
    ) -> FileRead {
        let st = match rustix::fs::fstat(&fd) {
            Ok(st) => st,
            Err(e) => return FileRead::failed(e.to_string()),
        };
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return place.not_read(&st, NotReadReason::NotRegularFile);
        }
        let size = u64::try_from(st.st_size).unwrap_or(0);
        let exceeded = |size| ReadOutcome::LimitExceeded {
            limit: spec.limit.unwrap_or(0),
            size,
        };
        if spec.limit.is_some_and(|limit| size > limit) {
            return place.over_limit(&st, exceeded(size));
        }
        let before = Snapshot::of(&st);
        let mut file = std::fs::File::from(fd);
        let mut hasher = Sha256::new();
        let mut prefix = Vec::new();
        let mut total: u64 = 0;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            // With a limit, read at most one byte past it: that byte shows the file is over it.
            let want = spec.limit.map_or(buffer.len(), |limit| {
                let left = limit.saturating_sub(total).saturating_add(1);
                usize::try_from(left).map_or(buffer.len(), |left| left.min(buffer.len()))
            });
            let n = match file.read(&mut buffer[..want]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return FileRead::failed(e.to_string()),
            };
            total = total.saturating_add(n as u64);
            if spec.limit.is_some_and(|limit| total > limit) {
                return place.over_limit(&st, exceeded(total.max(size)));
            }
            hasher.update(&buffer[..n]);
            let room = spec.keep.saturating_sub(prefix.len()).min(n);
            prefix.extend_from_slice(&buffer[..room]);
        }
        let after = match rustix::fs::fstat(file.as_fd()) {
            Ok(st) => Snapshot::of(&st),
            Err(e) => return FileRead::failed(e.to_string()),
        };
        let now = if strict {
            match self.resolve_strict(index, rel) {
                Strict::Entry { lstat, .. } => {
                    Some((Snapshot::of(&lstat).dev, Snapshot::of(&lstat).ino))
                }
                Strict::NotFound => None,
                // It is reached through a link now, or is no longer reached at all.
                _ => Some((u64::MAX, u64::MAX)),
            }
        } else {
            match self.resolve(index, rel).end {
                End::Entry { lstat, .. } => {
                    Some((Snapshot::of(&lstat).dev, Snapshot::of(&lstat).ino))
                }
                End::NotFound => None,
                // It resolves to something else now (a directory, a link out of the roots, ...).
                _ => Some((u64::MAX, u64::MAX)),
            }
        };
        let artifact_id = match ArtifactId::new(format!("sha256:{:x}", hasher.finalize())) {
            Ok(id) => id,
            Err(e) => return FileRead::failed(e.to_string()),
        };
        let artifact = Artifact {
            id: artifact_id.clone(),
            size: total,
            format: Format::Other,
            slices: vec![],
        };
        let instance = place.into_instance(
            stat_info(&st),
            InstanceContent::Read {
                artifact: artifact_id,
            },
            stability(&before, &after, now),
        );
        FileRead {
            instance: Some(instance),
            artifact: Some(artifact),
            prefix,
            outcome: ReadOutcome::Complete,
        }
    }
}

/// What is known about a placement before deciding how it was read.
struct Placement {
    id: InstanceId,
    root: RootId,
    path: UntrustedText,
    link_chain: Vec<sigil_model::LinkHop>,
    resolved: Option<UntrustedText>,
    discovered_by: Vec<DiscoverySource>,
}

impl Placement {
    /// Records the final path, when symlinks were followed to get there.
    fn resolved_to(mut self, path: &std::path::Path) -> Placement {
        if !self.link_chain.is_empty() {
            self.resolved = Some(super::path::recorded(path));
        }
        self
    }

    fn into_instance(
        self,
        stat: StatInfo,
        content: InstanceContent,
        stability: Stability,
    ) -> FileInstance {
        FileInstance {
            id: self.id,
            root: self.root,
            path: self.path,
            link_chain: self.link_chain,
            resolved: self.resolved,
            content,
            stat,
            stability,
            discovered_by: self.discovered_by,
        }
    }

    fn not_read(self, st: &Stat, why: NotReadReason) -> FileRead {
        let instance = self.into_instance(
            stat_info(st),
            InstanceContent::NotRead { why },
            Stability::NoChangeDetected,
        );
        FileRead {
            instance: Some(instance),
            artifact: None,
            prefix: vec![],
            outcome: ReadOutcome::NotRead(why),
        }
    }

    fn over_limit(self, st: &Stat, outcome: ReadOutcome) -> FileRead {
        let mut read = self.not_read(st, NotReadReason::BudgetExceeded);
        read.outcome = outcome;
        read
    }
}

impl FileRead {
    fn without_instance(outcome: ReadOutcome) -> FileRead {
        FileRead {
            instance: None,
            artifact: None,
            prefix: vec![],
            outcome,
        }
    }

    fn failed(message: String) -> FileRead {
        FileRead::without_instance(ReadOutcome::Failed(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(ino: u64, size: i64, mtime: i64) -> Snapshot {
        Snapshot {
            dev: 1,
            ino,
            size,
            mtime: (mtime, 0),
            ctime: (mtime, 0),
        }
    }

    #[test]
    fn instance_ids_are_valid_and_distinct_for_odd_names() {
        let root = RootId::new("models").unwrap();
        let id = |name: &str| {
            instance_id(&root, &RelPath::parse(name).unwrap())
                .unwrap()
                .as_str()
                .to_string()
        };
        assert_eq!(id("blobs/sha256-ab"), "inst:models/blobs/sha256-ab");
        assert_eq!(id("a\nb"), "inst:models/a%0Ab");
        assert_eq!(id("a%0Ab"), "inst:models/a%250Ab");
        assert_eq!(id("trailing "), "inst:models/trailing%20");
        assert_eq!(id("caf\u{e9}"), "inst:models/caf\u{e9}");
    }

    #[test]
    fn stability_compares_both_fstats_and_the_path_afterwards() {
        let before = snap(7, 10, 100);
        assert_eq!(
            stability(&before, &before, Some((1, 7))),
            Stability::NoChangeDetected
        );
        assert_eq!(
            stability(&before, &snap(7, 11, 100), Some((1, 7))),
            Stability::ChangedDuringRead
        );
        assert_eq!(
            stability(&before, &snap(7, 10, 101), Some((1, 7))),
            Stability::ChangedDuringRead
        );
        let mut touched = before;
        touched.ctime = (101, 0);
        assert_eq!(
            stability(&before, &touched, Some((1, 7))),
            Stability::ChangedDuringRead
        );
        assert_eq!(
            stability(&before, &before, Some((1, 8))),
            Stability::ChangedDuringRead
        );
        assert_eq!(stability(&before, &before, None), Stability::Vanished);
    }
}
