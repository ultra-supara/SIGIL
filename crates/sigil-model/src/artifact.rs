//! Content identity, placement identity, and process observations (plan §4.4.2).
//!
//! - [`Artifact`] is **contents** (identified by SHA-256). It is never a path.
//! - [`FileInstance`] is **a placement** of contents at a path under a scan root, observed at one
//!   time. One artifact can have many instances; the same instance ID can hold a different
//!   artifact in another session.
//! - [`MappingObs`] is **an observation** that a process had an object (dev:ino) mapped at one
//!   instant. It says nothing about why it was mapped, whether a declared dependency or the
//!   analyzed loader caused it, whether it was ever used for inference, or what was mapped
//!   before or after.

use serde::{Deserialize, Serialize};

use crate::evidence::{ConfigRef, NotObservable, Observability, Tri};
use crate::id::{ArtifactId, InstanceId, ProcessRole, RootId, Sha256Hex, SliceId, Timestamp};
use crate::text::UntrustedText;

/// File contents, identified by the SHA-256 of the whole file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: ArtifactId,
    pub size: u64,
    pub format: Format,
    /// One slice per architecture (a fat Mach-O has several). Empty for non-binaries.
    pub slices: Vec<Slice>,
}

/// Container format of an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Format {
    Elf {
        kind: ElfType,
    },
    MachO,
    MachOFat,
    /// Not a recognized executable container (scripts, data, configuration).
    Other,
}

/// ELF object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElfType {
    Exec,
    Dyn,
    Rel,
}

/// One architecture slice of an artifact. For a thin binary there is one slice at offset 0 whose
/// hash equals the artifact's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slice {
    /// `<artifact>#<arch>@<offset>`; must agree with the fields below.
    pub id: SliceId,
    pub arch: Arch,
    pub offset: u64,
    pub size: u64,
    pub sha256: Sha256Hex,
}

/// Instruction-set architecture. Serialized lowercase, as in slice IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
    /// Any architecture SIGIL does not analyze; its checks are recorded as `Unsupported`.
    #[serde(rename = "other")]
    Other,
}

impl Arch {
    /// The name used in JSON and in slice IDs.
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::Other => "other",
        }
    }

    pub fn from_name(name: &str) -> Option<Arch> {
        [Arch::X86_64, Arch::Aarch64, Arch::Other]
            .into_iter()
            .find(|a| a.name() == name)
    }
}

/// A file found at a path under a scan root, with what was observed about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInstance {
    /// `inst:<scan-root-relative path>`.
    pub id: InstanceId,
    /// The scan root it was found under.
    pub root: RootId,
    /// The path as discovered.
    pub path: UntrustedText,
    /// Every symlink hop, in resolution order. Empty when the path is not a symlink.
    pub link_chain: Vec<LinkHop>,
    /// The final path after following `link_chain`; `None` exactly when `link_chain` is empty. For
    /// a link that was not followed (`OutsideScanRoots`, `NotFollowed`), its target text.
    pub resolved: Option<UntrustedText>,
    /// Whether the contents were read, and if not, why.
    pub content: InstanceContent,
    pub stat: StatInfo,
    pub stability: Stability,
    pub discovered_by: Vec<DiscoverySource>,
}

/// Whether an instance's contents were read. "Not read" always says why; it never means "empty"
/// or "safe".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum InstanceContent {
    Read { artifact: ArtifactId },
    NotRead { why: NotReadReason },
}

/// Why an instance's contents were not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotReadReason {
    /// A symlink target outside every scan root: recorded, deliberately not followed.
    OutsideScanRoots,
    PermissionDenied,
    /// A FIFO, device, or socket.
    NotRegularFile,
    /// The path disappeared during the scan.
    Vanished,
    /// A file-count or byte budget was exhausted first.
    BudgetExceeded,
    /// A symlink of the install walk: its own `lstat` and target text are recorded, and it is not
    /// followed, wherever it leads (PR-4a).
    NotFollowed,
    /// A directory placement: listed and entered; it has no content to read.
    Directory,
}

/// One symlink hop: the link, its target text, and the link's owner and mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkHop {
    pub path: UntrustedText,
    pub target: UntrustedText,
    pub uid: u32,
    pub mode: u32,
}

/// Observed `stat` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatInfo {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub nlink: u64,
}

/// Whether the file changed while it was read (plan §4.6.2). `NoChangeDetected` means only that
/// no change was detected within what was observed; it is not a guarantee about later times.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stability {
    NoChangeDetected,
    ChangedDuringRead,
    Vanished,
}

/// How an instance was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DiscoverySource {
    /// Walking a scan root.
    Walk,
    /// Named by a service unit (e.g. `ExecStart=`).
    ServiceUnit { config: ConfigRef },
    /// The executable of an observed process.
    ProcessExe { process: ProcessRef },
    /// Named by a model manifest (a blob of the model store).
    Manifest { manifest: InstanceId },
}

/// A process, guarded against PID reuse by its start time and boot ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRef {
    pub pid: u32,
    pub start_ticks: u64,
    /// Empty when the boot ID could not be read: the PID and start time then do not identify
    /// the process across boots (see `ObservationMeta::boot_id`).
    pub boot_id: String,
}

/// What was observed about a running process (observe mode). Its environment, cwd, and user are
/// [`crate::ProcessValue`]s with an `ObservedProcess` origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObs {
    pub process: ProcessRef,
    pub at: Timestamp,
    /// Roles assigned to this process by topology rules; empty if none applied.
    pub roles: Vec<ProcessRole>,
    pub exe: ProcessExe,
    /// Mappings observed in this process at `at`.
    pub mappings: Vec<MappingObs>,
    /// Its name (`comm`), as the process set it; `None` when it could not be read.
    pub name: Option<UntrustedText>,
    /// Its arguments (`cmdline`), as the process set them; `None` when not read. Read only for
    /// processes whose role rests on them.
    pub argv: Option<Vec<UntrustedText>>,
    /// Its network namespace.
    pub net_ns: NsInode,
    /// Whether its file descriptors could be listed (needed to attribute sockets to it).
    pub fd_table: Observability,
}

/// A namespace's inode, or why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NsInode {
    Inode(u64),
    NotObservable(NotObservable),
}

/// The executable of an observed process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProcessExe {
    /// Matched to a scanned instance by dev:ino.
    Instance {
        instance: InstanceId,
    },
    /// Readable but not matched to any scanned instance.
    Path {
        path: UntrustedText,
        deleted: bool,
    },
    NotObservable(NotObservable),
}

/// One mapping of one object in one process at one instant (plan §4.4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingObs {
    pub process: ProcessRef,
    pub at: Timestamp,
    pub dev: u64,
    pub ino: u64,
    pub path_text: UntrustedText,
    pub deleted: bool,
    /// The scanned instance with the same dev:ino; `None` when none matched. Never matched by
    /// path.
    pub instance: Option<InstanceId>,
    pub same_mount_ns: Tri<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_names_round_trip() {
        for arch in [Arch::X86_64, Arch::Aarch64, Arch::Other] {
            assert_eq!(Arch::from_name(arch.name()), Some(arch));
            assert_eq!(
                serde_json::to_string(&arch).unwrap(),
                format!("\"{}\"", arch.name())
            );
        }
        assert_eq!(Arch::from_name("mips"), None);
    }
}
