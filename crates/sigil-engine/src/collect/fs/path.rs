//! Root-relative paths, and where a symlink target starts.
//!
//! Nothing here touches the file system. The walker ([`super::SafeFs`]) resolves one component at
//! a time. When it meets a symlink, [`link_target`] says where the target starts: the link's own
//! directory, a scan root, or outside every root. The target's components, including `.` and
//! `..`, are then walked like any others, and `..` returns to the directory actually walked
//! before it. They are never collapsed as text, because a component before a `..` may itself be a
//! symlink.

use std::fmt;
use std::path::{Component, Path, PathBuf};

/// A path relative to a scan root: zero or more plain components. It never contains `.`, `..`,
/// an empty component, a `/` inside a component, or a NUL byte, so it cannot leave its root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(Vec<String>);

/// Why a string is not a [`RelPath`] or a component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError(pub String);

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid root-relative path {:?}", self.0)
    }
}

impl std::error::Error for PathError {}

/// Whether `name` is a plain component: not empty, not `.` or `..`, no `/` and no NUL.
pub(crate) fn is_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

impl RelPath {
    /// Parses `a/b/c`. The empty string is not accepted; use [`RelPath::root`] for the root.
    pub fn parse(text: &str) -> Result<RelPath, PathError> {
        let parts: Vec<String> = text.split('/').map(str::to_string).collect();
        if parts.iter().all(|p| is_component(p)) {
            Ok(RelPath(parts))
        } else {
            Err(PathError(text.to_string()))
        }
    }

    /// The root itself.
    pub fn root() -> RelPath {
        RelPath(vec![])
    }

    /// This path with one more component.
    pub fn join(&self, name: &str) -> Result<RelPath, PathError> {
        if !is_component(name) {
            return Err(PathError(name.to_string()));
        }
        let mut parts = self.0.clone();
        parts.push(name.to_string());
        Ok(RelPath(parts))
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }

    /// The path without its last component; `None` for the root.
    pub fn parent(&self) -> Option<RelPath> {
        let (_, parent) = self.0.split_last()?;
        Some(RelPath(parent.to_vec()))
    }

    /// The last component; `None` for the root.
    pub fn name(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    /// `a/b/c`, or the empty string for the root.
    pub fn display(&self) -> String {
        self.0.join("/")
    }

    /// `base` joined with this path.
    pub fn under(&self, base: &Path) -> PathBuf {
        let mut path = base.to_path_buf();
        path.extend(&self.0);
        path
    }

    /// From components the walker already knows are plain.
    pub(crate) fn from_components(parts: Vec<String>) -> RelPath {
        debug_assert!(parts.iter().all(|p| is_component(p)));
        RelPath(parts)
    }
}

/// Where a symlink target starts. The components may contain `.` and `..`; the walker resolves
/// them against the directories it actually opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// A relative target: continue from the link's own directory.
    Relative(Vec<String>),
    /// An absolute target inside scan root number `root`: continue from that root.
    Absolute { root: usize, rest: Vec<String> },
    /// Outside every scan root (or empty, or containing NUL): recorded, never read.
    Outside,
}

/// Where the symlink `target` starts. `roots` are the canonical absolute paths of the scan roots.
///
/// An absolute target belongs to the root with the longest path prefix, compared component by
/// component (`/models2` is not inside `/models`). The prefix must consist of plain components:
/// a target that reaches a root only through `..`, or through a symlink outside every root, is
/// outside. That is conservative: such a file is recorded and not read, never read by mistake.
pub fn link_target(roots: &[PathBuf], target: &str) -> LinkTarget {
    if target.is_empty() || target.contains('\0') {
        return LinkTarget::Outside;
    }
    let parts: Vec<String> = target
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if !target.starts_with('/') {
        return LinkTarget::Relative(parts);
    }
    let best = roots
        .iter()
        .enumerate()
        .filter_map(|(i, root)| {
            let prefix: Vec<&str> = root
                .components()
                .filter_map(|c| match c {
                    Component::Normal(name) => name.to_str(),
                    _ => None,
                })
                .collect();
            let matches =
                prefix.len() <= parts.len() && prefix.iter().zip(&parts).all(|(a, b)| a == b);
            matches.then_some((i, prefix.len()))
        })
        .max_by_key(|&(_, len)| len);
    match best {
        Some((root, len)) => LinkTarget::Absolute {
            root,
            rest: parts[len..].to_vec(),
        },
        None => LinkTarget::Outside,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(text: &str) -> RelPath {
        if text.is_empty() {
            RelPath::root()
        } else {
            RelPath::parse(text).unwrap()
        }
    }

    fn parts(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_accepts_plain_components() {
        let p = RelPath::parse("manifests/registry.ollama.ai/library").unwrap();
        assert_eq!(
            p.components(),
            ["manifests", "registry.ollama.ai", "library"]
        );
        assert_eq!(p.display(), "manifests/registry.ollama.ai/library");
        assert_eq!(p.name(), Some("library"));
        assert_eq!(
            p.parent().unwrap().display(),
            "manifests/registry.ollama.ai"
        );
        assert_eq!(RelPath::root().display(), "");
        assert_eq!(RelPath::root().parent(), None);
        assert_eq!(rel("a").join("b").unwrap(), rel("a/b"));
        assert_eq!(rel("a/b").under(Path::new("/r")), PathBuf::from("/r/a/b"));
    }

    #[test]
    fn parse_rejects_anything_that_could_leave_the_root() {
        for bad in [
            "", "/a", "a/", "a//b", "./a", "a/./b", "a/../b", "..", "a\0b",
        ] {
            assert!(RelPath::parse(bad).is_err(), "{bad:?} accepted");
        }
        for bad in ["", ".", "..", "a/b", "a\0"] {
            assert!(
                rel("x").join(bad).is_err(),
                "{bad:?} accepted as a component"
            );
        }
    }

    fn roots() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/srv"),
            PathBuf::from("/srv/models"),
            PathBuf::from("/usr/local"),
        ]
    }

    #[test]
    fn relative_targets_keep_their_components_for_the_walker() {
        let r = roots();
        assert_eq!(
            link_target(&r, "../x"),
            LinkTarget::Relative(parts(&["..", "x"]))
        );
        assert_eq!(
            link_target(&r, "ollama/./y//z"),
            LinkTarget::Relative(parts(&["ollama", ".", "y", "z"]))
        );
    }

    #[test]
    fn absolute_targets_use_the_longest_root_prefix() {
        let r = roots();
        let abs = |root, rest: &[&str]| LinkTarget::Absolute {
            root,
            rest: parts(rest),
        };
        assert_eq!(link_target(&r, "/usr/local/lib/x"), abs(2, &["lib", "x"]));
        assert_eq!(
            link_target(&r, "/srv/models/blobs/b"),
            abs(1, &["blobs", "b"])
        );
        assert_eq!(link_target(&r, "/srv/other"), abs(0, &["other"]));
        assert_eq!(link_target(&r, "/srv/models2/x"), abs(0, &["models2", "x"]));
        assert_eq!(link_target(&r, "/usr/local"), abs(2, &[]));
        assert_eq!(link_target(&r, "//usr/local/x"), abs(2, &["x"]));
        // The walker resolves `..` inside the root and finds that this one leaves it.
        assert_eq!(
            link_target(&r, "/usr/local/../etc/passwd"),
            abs(2, &["..", "etc", "passwd"])
        );
        assert_eq!(link_target(&r, "/usr/local2/x"), LinkTarget::Outside);
        assert_eq!(link_target(&r, "/etc/passwd"), LinkTarget::Outside);
        assert_eq!(link_target(&r, "/usr/./local/x"), LinkTarget::Outside);
        assert_eq!(link_target(&r, "/"), LinkTarget::Outside);
    }

    #[test]
    fn empty_and_nul_targets_lead_nowhere() {
        let r = roots();
        assert_eq!(link_target(&r, ""), LinkTarget::Outside);
        assert_eq!(link_target(&r, "a\0b"), LinkTarget::Outside);
    }
}
