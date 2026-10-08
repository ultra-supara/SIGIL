//! Level A: component and origin identification (plan §4.4.3).
//!
//! Every source of identity is kept as its own assertion; nothing is collapsed into one name,
//! one version, or one "confidence". Conflicting assertions coexist and the conflict is the
//! status. There is no "exact" identity, and a release is a **set** of candidates, never a pick.

use serde::{Deserialize, Serialize};

use crate::code::CheckResult;
use crate::evidence::EvidenceRef;
use crate::id::{ComponentKey, InstanceId, ObligationId, ProfileRef, RefSetId, SliceId};
use crate::text::UntrustedText;

/// What is claimed about which component a slice is, with every source kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentClaim {
    pub subject: SliceId,
    pub component: ComponentKey,
    pub assertions: Vec<IdentityAssertion>,
    /// Derived by the engine from `assertions` (table in plan §4.4.3). Validation rejects a status
    /// stronger than the assertions support.
    pub status: IdentityStatus,
    /// Every version value, with its source. Never collapsed into one.
    pub versions: Vec<VersionAssertion>,
}

/// One source of identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IdentityAssertion {
    /// The file names itself (file name, SONAME, install name, version string).
    SelfName {
        kind: NameKind,
        value: UntrustedText,
        at: EvidenceRef,
    },
    /// Another slice declares a dependency on this name. Not proof that the file was found.
    Required { by: SliceId, needed: UntrustedText },
    /// A value embedded in the binary, e.g. `LLAMA_COMMIT` or `go.version`.
    Embedded {
        field: String,
        value: UntrustedText,
        at: EvidenceRef,
        method: ExtractMethod,
    },
    /// A profile's identification check decided in this slice's code. Agrees with the result
    /// of obligation `check` when the slice's `ProfileMatch` records one.
    CodeCheck {
        profile: ProfileRef,
        check: ObligationId,
        result: CheckResult,
        at: Vec<EvidenceRef>,
    },
    /// Per-file match against a reference manifest (official release archives).
    KnownHash {
        reference: RefSetId,
        release: String,
        member: String,
        matched: bool,
    },
    /// Signature state. Always `NotChecked` in M0/M1: authenticity is never claimed.
    Signature { state: SigState },
}

/// Which self-reported name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameKind {
    Filename,
    Soname,
    InstallName,
    VersionString,
}

/// How an embedded value was extracted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExtractMethod {
    /// Followed the pointer value of an exported data symbol (e.g. via `R_X86_64_RELATIVE`).
    DataSymbolPointer { symbol: UntrustedText },
    /// Found by scanning read-only sections for a known needle.
    StringScan,
    /// Parsed from Go build info.
    GoBuildInfo,
}

/// Signature verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigState {
    NotChecked,
}

/// Identification status, derived from the assertions (evaluated top to bottom, plan §4.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    /// Two sources disagree on the same attribute. Both values are kept.
    Conflicting,
    /// A `KnownHash` matched.
    ReferenceMatched,
    /// A self-name or embedded value plus at least one independent code check that matched.
    Corroborated,
    /// Only self-names or `Required` names.
    NameOnly,
    Unidentified,
}

/// One version value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionAssertion {
    pub value: UntrustedText,
    pub source: VersionSource,
    pub at: EvidenceRef,
}

/// The source of a version value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum VersionSource {
    SelfName { kind: NameKind },
    Embedded { field: String },
}

/// Which releases an installation may come from. Always a set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseClaim {
    /// The product whose release is claimed, e.g. `ollama`.
    pub product: ComponentKey,
    pub candidates: Vec<String>,
    pub basis: ReleaseBasis,
}

/// Why the release set is what it is. Only reference matches close it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReleaseBasis {
    /// **Closed**: the relevant files matched the reference manifests of the candidates, per
    /// file.
    ReferenceMatches {
        reference: RefSetId,
        files: Vec<InstanceId>,
    },
    /// **Open**: only "consistent with the releases checked", from a self-reported value. A
    /// custom build, a mixed install, or an unlisted release is not excluded.
    SelfReportedCommit {
        field: String,
        value: UntrustedText,
        at: EvidenceRef,
    },
}
