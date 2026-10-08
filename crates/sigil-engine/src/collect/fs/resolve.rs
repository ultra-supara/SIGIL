//! Anchored resolution of a root-relative path, one component at a time.
//!
//! The walker keeps the directories it opened as a stack of fds. A symlink is never opened: it is
//! `lstat`ed, read with `readlinkat`, recorded as a [`LinkHop`], and its target's components are
//! walked like any others. `..` pops the stack, so it returns to the directory actually walked,
//! and popping past a root leaves the scan roots.

use std::collections::VecDeque;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;
use sigil_model::{LinkHop, UntrustedText};

use super::path::{link_target, LinkTarget, RelPath};
use super::SafeFs;

/// The result of resolving a path: every symlink hop, then where it ended.
pub(crate) struct Resolved {
    pub hops: Vec<LinkHop>,
    pub end: End,
}

pub(crate) enum End {
    /// An entry of a directory: `rel` is its physical path in root `root`, `parent` the fd of the
    /// directory holding it (`None` for the root's own fd), and `lstat` its metadata. It is not a
    /// symlink.
    Entry {
        root: usize,
        rel: RelPath,
        parent: Option<OwnedFd>,
        name: String,
        lstat: Stat,
    },
    /// A directory reached as a whole (a root itself, or the end of a target such as `dir/..`):
    /// `fd` is open on it (`None` for the root's own fd).
    Dir {
        root: usize,
        rel: RelPath,
        fd: Option<OwnedFd>,
    },
    NotFound,
    /// A symlink led outside every scan root; `target` is that link's target text and `link`
    /// the link's own metadata.
    OutsideRoots {
        target: UntrustedText,
        link: Stat,
    },
    PermissionDenied,
    TooManyHops,
    /// A component before the last is not a directory.
    NotADirectory,
    Failed(String),
}

impl End {
    fn from_errno(e: Errno) -> End {
        match e {
            Errno::NOENT => End::NotFound,
            Errno::ACCESS | Errno::PERM => End::PermissionDenied,
            Errno::NOTDIR => End::NotADirectory,
            Errno::LOOP => {
                End::Failed("a component changed into a symlink during resolution".into())
            }
            other => End::Failed(other.to_string()),
        }
    }
}

impl SafeFs {
    /// Opens the directory `name` in `parent`, refusing symlinks and magic links.
    pub(crate) fn open_dir(&self, parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
        self.open_at(parent, name, OFlags::RDONLY | OFlags::DIRECTORY)
    }

    /// `openat2(parent, name, flags | O_NOFOLLOW | O_CLOEXEC, RESOLVE_BENEATH | NO_SYMLINKS |
    /// NO_MAGICLINKS)`, or `openat` with `O_NOFOLLOW` where `openat2` is missing. `name` is always a
    /// single plain component.
    pub(crate) fn open_at(
        &self,
        parent: BorrowedFd<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<OwnedFd, Errno> {
        let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if self.have_openat2.get() {
            let resolve =
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
            match rustix::fs::openat2(parent, name, flags, Mode::empty(), resolve) {
                Err(Errno::NOSYS) => self.have_openat2.set(false),
                other => return other,
            }
        }
        rustix::fs::openat(parent, name, flags, Mode::empty())
    }

    /// Resolves `rel` in root `root`, following and recording symlinks (plan §4.6.2).
    pub(crate) fn resolve(&self, root: usize, rel: &RelPath) -> Resolved {
        let roots = self.canonical_roots();
        let max_hops = self.budgets.max_link_hops as usize;
        let mut hops: Vec<LinkHop> = vec![];
        let mut last_link: Option<Stat> = None;
        let mut current = root;
        let mut stack: Vec<(String, OwnedFd)> = vec![];
        let mut queue: VecDeque<String> = rel.components().iter().cloned().collect();
        let done = |hops, end| Resolved { hops, end };
        loop {
            let Some(name) = queue.pop_front() else {
                let rel = names(&stack);
                let fd = stack.pop().map(|(_, fd)| fd);
                return done(
                    hops,
                    End::Dir {
                        root: current,
                        rel,
                        fd,
                    },
                );
            };
            if name == "." {
                continue;
            }
            if name == ".." {
                if stack.pop().is_none() {
                    // Only a symlink target can contain `..`, so there is a hop and a link.
                    let (Some(hop), Some(link)) = (hops.last(), last_link) else {
                        return done(hops, End::Failed("`..` above a scan root".into()));
                    };
                    let target = hop.target.clone();
                    return done(hops, End::OutsideRoots { target, link });
                }
                continue;
            }
            let parent = parent_fd(self, current, &stack);
            let lstat = match rustix::fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(e) => return done(hops, End::from_errno(e)),
            };
            match FileType::from_raw_mode(lstat.st_mode) {
                FileType::Symlink => {
                    if hops.len() >= max_hops {
                        return done(hops, End::TooManyHops);
                    }
                    let target = match rustix::fs::readlinkat(parent, name.as_str(), Vec::new()) {
                        Ok(t) => t.into_bytes(),
                        Err(e) => return done(hops, End::from_errno(e)),
                    };
                    let text = UntrustedText::from_bytes(target.clone());
                    last_link = Some(lstat);
                    hops.push(LinkHop {
                        path: UntrustedText::new(link_path(&roots[current], &stack, &name)),
                        target: text.clone(),
                        uid: lstat.st_uid,
                        mode: mode(&lstat),
                    });
                    let start = match std::str::from_utf8(&target) {
                        Ok(t) => link_target(&roots, t),
                        Err(_) => LinkTarget::Outside,
                    };
                    match start {
                        LinkTarget::Relative(parts) => prepend(&mut queue, parts),
                        LinkTarget::Absolute { root, rest } => {
                            current = root;
                            stack.clear();
                            prepend(&mut queue, rest);
                        }
                        LinkTarget::Outside => {
                            return done(
                                hops,
                                End::OutsideRoots {
                                    target: text,
                                    link: lstat,
                                },
                            )
                        }
                    }
                }
                FileType::Directory if !queue.is_empty() => {
                    let fd = match self.open_dir(parent, &name) {
                        Ok(fd) => fd,
                        Err(e) => return done(hops, End::from_errno(e)),
                    };
                    stack.push((name, fd));
                }
                _ if !queue.is_empty() => return done(hops, End::NotADirectory),
                _ => {
                    let mut parts: Vec<String> = stack.iter().map(|(n, _)| n.clone()).collect();
                    parts.push(name.clone());
                    let parent = stack.pop().map(|(_, fd)| fd);
                    return done(
                        hops,
                        End::Entry {
                            root: current,
                            rel: RelPath::from_components(parts),
                            parent,
                            name,
                            lstat,
                        },
                    );
                }
            }
        }
    }
}

fn names(stack: &[(String, OwnedFd)]) -> RelPath {
    RelPath::from_components(stack.iter().map(|(n, _)| n.clone()).collect())
}

fn prepend(queue: &mut VecDeque<String>, parts: Vec<String>) {
    for part in parts.into_iter().rev() {
        queue.push_front(part);
    }
}

/// The absolute path of a link, for display.
fn link_path(root: &std::path::Path, stack: &[(String, OwnedFd)], name: &str) -> String {
    let mut path = root.to_path_buf();
    path.extend(stack.iter().map(|(n, _)| n.as_str()));
    path.push(name);
    path.to_string_lossy().into_owned()
}

/// `st_mode` as `u32` (its width differs between targets).
#[allow(clippy::unnecessary_cast)]
pub(crate) fn mode(st: &Stat) -> u32 {
    st.st_mode as u32
}

/// The parent directory fd: the top of the stack, or the root's fd.
fn parent_fd<'a>(fs: &'a SafeFs, root: usize, stack: &'a [(String, OwnedFd)]) -> BorrowedFd<'a> {
    match stack.last() {
        Some((_, fd)) => fd.as_fd(),
        None => fs.roots[root].fd.as_fd(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use sigil_model::RootId;
    use tempfile::TempDir;

    use super::*;
    use crate::collect::fs::FsBudgets;

    struct Fixture {
        a: TempDir,
        b: TempDir,
        fs: SafeFs,
    }

    fn fixture() -> Fixture {
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        fs::create_dir_all(a.path().join("lib/ollama")).unwrap();
        fs::write(a.path().join("lib/ollama/libggml.so"), b"elf").unwrap();
        fs::write(b.path().join("blob"), b"data").unwrap();
        let mut fs = SafeFs::new(FsBudgets::default());
        fs.add_root(RootId::new("a").unwrap(), a.path()).unwrap();
        fs.add_root(RootId::new("b").unwrap(), b.path()).unwrap();
        Fixture { a, b, fs }
    }

    fn rel(text: &str) -> RelPath {
        RelPath::parse(text).unwrap()
    }

    /// `(root, physical rel)` of an entry, or a short name for the other ends.
    fn end(r: &Resolved) -> (String, usize) {
        let what = match &r.end {
            End::Entry { root, rel, .. } => format!("entry {root}:{}", rel.display()),
            End::Dir { root, rel, .. } => format!("dir {root}:{}", rel.display()),
            End::NotFound => "not found".into(),
            End::OutsideRoots { .. } => "outside".into(),
            End::PermissionDenied => "permission denied".into(),
            End::TooManyHops => "too many hops".into(),
            End::NotADirectory => "not a directory".into(),
            End::Failed(m) => format!("failed {m}"),
        };
        (what, r.hops.len())
    }

    #[test]
    fn a_plain_file_has_no_hops() {
        let f = fixture();
        let r = f.fs.resolve(0, &rel("lib/ollama/libggml.so"));
        assert_eq!(end(&r), ("entry 0:lib/ollama/libggml.so".into(), 0));
    }

    #[test]
    fn links_inside_the_root_are_followed_and_recorded() {
        let f = fixture();
        symlink("ollama/libggml.so", f.a.path().join("lib/rel")).unwrap();
        symlink("lib/ollama", f.a.path().join("dirlink")).unwrap();
        let abs =
            f.a.path()
                .canonicalize()
                .unwrap()
                .join("lib/ollama/libggml.so");
        symlink(&abs, f.a.path().join("abs")).unwrap();

        let r = f.fs.resolve(0, &rel("lib/rel"));
        assert_eq!(end(&r), ("entry 0:lib/ollama/libggml.so".into(), 1));
        assert_eq!(r.hops[0].target.as_str(), Some("ollama/libggml.so"));
        assert!(r.hops[0].path.as_str().unwrap().ends_with("/lib/rel"));

        let r = f.fs.resolve(0, &rel("dirlink/libggml.so"));
        assert_eq!(end(&r), ("entry 0:lib/ollama/libggml.so".into(), 1));

        let r = f.fs.resolve(0, &rel("abs"));
        assert_eq!(end(&r), ("entry 0:lib/ollama/libggml.so".into(), 1));
    }

    #[test]
    fn a_link_into_another_root_continues_there() {
        let f = fixture();
        let target = f.b.path().canonicalize().unwrap().join("blob");
        symlink(&target, f.a.path().join("to_b")).unwrap();
        let r = f.fs.resolve(0, &rel("to_b"));
        assert_eq!(end(&r), ("entry 1:blob".into(), 1));
    }

    #[test]
    fn links_out_of_every_root_are_not_followed() {
        let f = fixture();
        symlink("/etc/hostname", f.a.path().join("etc")).unwrap();
        symlink("../../..", f.a.path().join("lib/up")).unwrap();
        let r = f.fs.resolve(0, &rel("etc"));
        assert_eq!(end(&r), ("outside".into(), 1));
        let r = f.fs.resolve(0, &rel("lib/up/x"));
        assert_eq!(end(&r), ("outside".into(), 1));
    }

    #[test]
    fn dot_dot_returns_to_the_directory_actually_walked() {
        // x -> a/link/../d, where a/link -> ../b/c. Physically that is b/d, not a/d.
        let f = fixture();
        let root = f.a.path();
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b/c")).unwrap();
        fs::write(root.join("b/d"), b"physical").unwrap();
        fs::write(root.join("a/d"), b"lexical").unwrap();
        symlink("../b/c", root.join("a/link")).unwrap();
        symlink("a/link/../d", root.join("x")).unwrap();
        let r = f.fs.resolve(0, &rel("x"));
        assert_eq!(end(&r), ("entry 0:b/d".into(), 2));

        symlink("b/c/..", root.join("y")).unwrap();
        let r = f.fs.resolve(0, &rel("y"));
        assert_eq!(end(&r), ("dir 0:b".into(), 1));
    }

    #[test]
    fn link_loops_stop_at_the_hop_budget() {
        let f = fixture();
        symlink("q", f.a.path().join("p")).unwrap();
        symlink("p", f.a.path().join("q")).unwrap();
        let r = f.fs.resolve(0, &rel("p"));
        assert_eq!(end(&r).0, "too many hops");
        assert_eq!(r.hops.len(), 40);
    }

    #[test]
    fn missing_paths_and_files_used_as_directories() {
        let f = fixture();
        assert_eq!(end(&f.fs.resolve(0, &rel("nope"))).0, "not found");
        assert_eq!(end(&f.fs.resolve(0, &rel("lib/nope/x"))).0, "not found");
        assert_eq!(
            end(&f.fs.resolve(0, &rel("lib/ollama/libggml.so/x"))).0,
            "not a directory"
        );
        assert_eq!(end(&f.fs.resolve(0, &RelPath::root())).0, "dir 0:");
    }
}
