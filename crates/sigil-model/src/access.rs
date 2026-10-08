//! Principals and write access (plan §4.4.6).
//!
//! A write-access record is built from **observed** metadata of a path and every ancestor and
//! symlink hop. Each write capability gets its own conclusion; anything not analyzed makes it
//! `Undetermined`, never safe.

use serde::{Deserialize, Serialize};

use crate::evidence::{TriState, UnknownReason};
use crate::id::{AccessId, ValueId};
use crate::text::UntrustedText;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAccess {
    pub id: AccessId,
    /// The search directory, candidate file, or symlink analyzed.
    pub target: UntrustedText,
    /// The principal the runtime process runs as.
    pub runtime: PrincipalClaim,
    /// From `target` up to `/`, including every hop of every symlink resolution.
    pub chain: Vec<NodeAccess>,
    /// One conclusion per write capability.
    pub capabilities: Vec<CapabilityAccess>,
}

/// The runtime principal: a process value (user from a unit, an observed uid), or unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PrincipalClaim {
    Value { value: ValueId },
    Unknown { reason: UnknownReason },
}

/// Observed metadata of one path node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAccess {
    pub path: UntrustedText,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub sticky: bool,
    pub is_symlink: bool,
    pub acl: AclState,
    pub read_only_mount: TriState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AclState {
    Absent,
    Present { entries: Vec<AclEntry> },
    NotReadable,
}

/// One POSIX ACL entry; `perms` holds the rwx bits (4/2/1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclEntry {
    pub tag: AclTag,
    pub perms: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTag {
    UserObj,
    User(u32),
    GroupObj,
    Group(u32),
    Mask,
    Other,
}

/// A write capability on a node (Linux semantics: `unlink(2)`, `rename(2)`,
/// `path_resolution(7)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WriteCapability {
    /// Write an existing file's contents (or change its mode as its owner).
    ModifyContent { file: UntrustedText },
    /// Unlink or rename an existing entry of `dir`.
    ReplaceEntry {
        dir: UntrustedText,
        entry: UntrustedText,
    },
    /// Create a new entry in `dir`, e.g. a new loader candidate. Not restricted by the sticky bit.
    CreateEntry { dir: UntrustedText },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAccess {
    pub capability: WriteCapability,
    pub conclusion: AccessConclusion,
}

/// Who holds a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AccessConclusion {
    /// Only trusted principals (by default root and the runtime user) hold it.
    TrustedOnly,
    /// An untrusted principal holds it, through the named node, by the named grant.
    UntrustedHolder {
        who: Principal,
        via: UntrustedText,
        how: Grant,
    },
    /// Something was not analyzed (unreadable ACL, unknown group members, unchecked ancestor).
    Undetermined { missing: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Principal {
    /// Any local user (the "other" permission bits).
    Anyone,
    User {
        uid: u32,
    },
    Group {
        gid: u32,
    },
}

/// The permission that grants a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grant {
    ModeOwner,
    ModeGroup,
    ModeOther,
    Acl,
    /// Ownership of the node (e.g. the owner of a sticky directory or of the entry).
    Ownership,
}
