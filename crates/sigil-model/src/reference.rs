//! Placement-level comparison with reference manifests (PR-4a; plan §4.4.2).
//!
//! A [`ReferenceMatch`] records one comparison: one placement of the install root (or one reference
//! member absent from it) with one release of a reference set. The expected and observed values
//! are both kept, so whether a row matches is recomputed from the row itself, and `validate`
//! checks the observed value against the placement's own facts. Which releases the observed
//! content matches (`ReleaseClaim`) and whether the install holds every member of them (coverage
//! of [`ARTIFACTS_RELEASE`]) are derived from these rows.

use serde::{Deserialize, Serialize};

use crate::artifact::{FileInstance, InstanceContent, NotReadReason};
use crate::id::{InstanceId, RefSetId, Sha256Hex};
use crate::text::UntrustedText;

/// The scan root of an installation (`--install-dir`).
pub const INSTALL_ROOT: &str = "install";
/// The install walk and reads: what was listed and read.
pub const ARTIFACTS_DISCOVERY: &str = "artifacts.discovery";
/// The comparison with the reference set: attribution and completeness.
pub const ARTIFACTS_RELEASE: &str = "artifacts.release";

/// One comparison of a placement, or of a reference member absent from the install, with one
/// release of a reference set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceMatch {
    pub reference: RefSetId,
    pub release: String,
    /// The member's path in the release archive, equal to the placement's path under the install
    /// root.
    pub member: String,
    /// The placement compared; `None` exactly for [`MemberResult::Absent`].
    pub instance: Option<InstanceId>,
    pub result: MemberResult,
}

/// The result of one comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum MemberResult {
    /// A regular file, by SHA-256 (any format).
    File {
        expected: Sha256Hex,
        observed: Sha256Hex,
    },
    /// A symlink, by its first-hop target text, exactly as stored.
    Symlink {
        expected: UntrustedText,
        observed: UntrustedText,
    },
    /// Both are directories. The entries under it are compared on their own.
    Directory,
    /// The release has a member of another kind at this path.
    KindDiffers {
        expected: MemberKind,
        observed: EntryKind,
    },
    /// The placement could not be compared (not read, or unstable). The reason is on the instance.
    NotCompared,
    /// The release has this member and the install has no entry at its path. Recorded only when
    /// discovery is complete: not observed is not absent.
    Absent { kind: MemberKind },
}

impl MemberResult {
    /// Whether the placement equals the member.
    pub fn matches(&self) -> bool {
        match self {
            MemberResult::File { expected, observed } => expected == observed,
            MemberResult::Symlink { expected, observed } => expected == observed,
            MemberResult::Directory => true,
            MemberResult::KindDiffers { .. }
            | MemberResult::NotCompared
            | MemberResult::Absent { .. } => false,
        }
    }
}

/// A member's kind in a release archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MemberKind {
    File,
    Symlink,
    Directory,
}

/// A placement's observed kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Symlink,
    Directory,
    /// A FIFO, socket, or device.
    Special,
}

impl EntryKind {
    /// The member kind of the same name, if any.
    pub fn member(self) -> Option<MemberKind> {
        match self {
            EntryKind::File => Some(MemberKind::File),
            EntryKind::Symlink => Some(MemberKind::Symlink),
            EntryKind::Directory => Some(MemberKind::Directory),
            EntryKind::Special => None,
        }
    }
}

impl FileInstance {
    /// The placement's kind: a symlink if it has a link chain, else from why it was not read.
    pub fn entry_kind(&self) -> EntryKind {
        if !self.link_chain.is_empty() {
            return EntryKind::Symlink;
        }
        match &self.content {
            InstanceContent::NotRead {
                why: NotReadReason::Directory,
            } => EntryKind::Directory,
            InstanceContent::NotRead {
                why: NotReadReason::NotRegularFile,
            } => EntryKind::Special,
            _ => EntryKind::File,
        }
    }
}
