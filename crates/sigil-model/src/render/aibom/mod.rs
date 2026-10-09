//! AI-BOM v2 (`schema: "sigil-aibom/2"`, `schemas/aibom-v2.schema.json`; plan §4.4.11): a compact,
//! versioned projection of a session for reviewers and downstream tools.
//!
//! - It carries the SHA-256 of the session it came from ([`SessionLink::sha256`]), so a reader can
//!   trace any line back to the evidence. Evidence, assertions, conditions, code facts,
//!   relations, and load facts are not copied.
//! - Identifiers keep their session form, and input-derived text stays [`UntrustedText`].
//! - [`project`] builds it from a session; [`markdown`] renders it. Both are pure and
//!   deterministic.

mod markdown;
mod project;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::artifact::{Arch, Format, ProcessExe, ProcessRef};
use crate::evidence::Ref;
use crate::finding::{FindingKind, Outcome, PolicyDecision, Severity};
use crate::id::{
    ArtifactId, CheckId, ComponentKey, FindingId, ModelId, PolicyRuleRef, ProcessRole, RuleId,
    Sha256Hex, SliceId, Timestamp,
};
use crate::identity::IdentityStatus;
use crate::listener::Listener;
use crate::model::{LayerRole, ModelProvenance};
use crate::probe::ApiProbe;
use crate::session::{KnowledgeRef, Mode, SchemaVersion, ToolInfo};
use crate::text::UntrustedText;

pub use markdown::markdown;
pub use project::{project, state_name, CLOSING_STATES, STATE_NAMES};

/// An AI-BOM v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiBom {
    pub schema: AiBomSchema,
    pub tool: ToolInfo,
    pub session: SessionLink,
    /// Verdict and completeness, side by side, as the session computed them.
    pub outcome: Outcome,
    pub runtime: BomRuntime,
    pub models: Vec<BomModel>,
    pub artifacts: Vec<BomArtifact>,
    pub findings: Vec<BomFinding>,
    pub policy_violations: Vec<BomViolation>,
    pub coverage: Vec<CheckSummary>,
}

/// The AI-BOM schema version. Only `sigil-aibom/2` is accepted (AI-BOM v1 has
/// `schema_version: "1.1"` instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiBomSchema {
    #[serde(rename = "sigil-aibom/2")]
    V2,
}

/// The session this AI-BOM was projected from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLink {
    pub schema: SchemaVersion,
    /// SHA-256 of the session's canonical JSON (`Session::to_canonical_json`), computed by the
    /// caller. A session SIGIL saved hashes to its file.
    pub sha256: Sha256Hex,
    pub mode: Mode,
    pub started_at: Timestamp,
    /// The policy applied: the session's knowledge entry of kind `Policy`.
    pub policy: Option<KnowledgeRef>,
}

/// What was seen of the running runtime (observe and active modes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomRuntime {
    pub processes: Vec<BomProcess>,
    pub listeners: Vec<Listener>,
    /// API probes: each the endpoint's own claim, from SIGIL's network namespace.
    pub api: Vec<ApiProbe>,
    pub releases: Vec<BomRelease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomProcess {
    pub process: ProcessRef,
    pub roles: Vec<ProcessRole>,
    pub name: Option<UntrustedText>,
    pub exe: ProcessExe,
}

/// A release identity claim, with its basis reduced to its kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomRelease {
    pub product: ComponentKey,
    pub candidates: Vec<String>,
    pub basis: ReleaseBasisKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseBasisKind {
    /// Closed: the files matched the reference manifests of the candidates.
    ReferenceMatches,
    /// Open: only consistent with a self-reported value.
    SelfReportedCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomModel {
    pub id: ModelId,
    pub name: UntrustedText,
    pub provenance: ModelProvenance,
    pub layers: Vec<BomLayer>,
    pub license: Option<BomLicense>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomLayer {
    pub role: LayerRole,
    pub media_type: Option<UntrustedText>,
    pub digest: UntrustedText,
    pub blob: BomBlob,
}

/// How a layer's blob lookup ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BomBlob {
    /// The digest is malformed, so no blob was looked up.
    NotLookedUp,
    /// The blob was found at `path`; `content` is what was read there, `None` if not read.
    Found {
        path: UntrustedText,
        content: Option<ArtifactId>,
    },
    Absent,
    Unresolved {
        why: UntrustedText,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomLicense {
    pub spdx: Option<String>,
    pub excerpt: UntrustedText,
}

/// A file content (an artifact), where it was found, and what was identified in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomArtifact {
    pub id: ArtifactId,
    pub size: u64,
    pub format: Format,
    /// The recorded paths of the instances that held this content, sorted.
    pub paths: Vec<UntrustedText>,
    pub slices: Vec<BomSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomSlice {
    pub id: SliceId,
    pub arch: Arch,
    pub sha256: Sha256Hex,
    pub components: Vec<BomComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomComponent {
    pub component: ComponentKey,
    pub status: IdentityStatus,
    pub versions: Vec<UntrustedText>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomFinding {
    pub id: FindingId,
    pub rule: RuleId,
    pub kind: FindingKind,
    pub subject: Ref,
    pub summary: String,
    pub default_severity: Severity,
    pub decision: PolicyDecision,
    pub limits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BomViolation {
    pub policy_rule: PolicyRuleRef,
    pub subject: Ref,
    pub decision: PolicyDecision,
}

/// One check: whether it is required, whether it is closed, and its entries by state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSummary {
    pub check: CheckId,
    pub required: bool,
    /// It has entries, and every one can close it.
    pub closed: bool,
    /// Entries per coverage state ([`STATE_NAMES`]).
    pub states: BTreeMap<String, u32>,
}

/// Why an AI-BOM v2 is inconsistent, beyond what its types and schema check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BomError {
    /// A coverage state name that is not one of [`STATE_NAMES`].
    UnknownState { check: CheckId, state: String },
    /// A state listed with no entries.
    EmptyState { check: CheckId, state: String },
    /// `closed` disagrees with the states: a check is closed exactly when it has entries and every
    /// one is in a [`CLOSING_STATES`] state.
    ClosedDisagrees { check: CheckId, closed: bool },
}

impl std::fmt::Display for BomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BomError::UnknownState { check, state } => {
                write!(f, "coverage[{check}]: {state:?} is not a coverage state")
            }
            BomError::EmptyState { check, state } => {
                write!(f, "coverage[{check}]: {state} is listed with no entries")
            }
            BomError::ClosedDisagrees { check, closed } => write!(
                f,
                "coverage[{check}]: closed is {closed}, but its states say otherwise"
            ),
        }
    }
}

impl AiBom {
    /// Checks what the types cannot. An AI-BOM that SIGIL projected always passes. The viewer
    /// refuses one that does not, instead of showing it.
    ///
    /// - Each coverage summary names only coverage states ([`STATE_NAMES`]), each with at least
    ///   one entry.
    /// - `closed` agrees with the states: true exactly when there are entries and every one is in
    ///   a closing state ([`CLOSING_STATES`]).
    pub fn validate(&self) -> Result<(), Vec<BomError>> {
        let mut errors = vec![];
        for c in &self.coverage {
            for (state, count) in &c.states {
                if !STATE_NAMES.contains(&state.as_str()) {
                    errors.push(BomError::UnknownState {
                        check: c.check.clone(),
                        state: state.clone(),
                    });
                }
                if *count == 0 {
                    errors.push(BomError::EmptyState {
                        check: c.check.clone(),
                        state: state.clone(),
                    });
                }
            }
            let closes = !c.states.is_empty()
                && c.states
                    .iter()
                    .all(|(state, count)| *count == 0 || CLOSING_STATES.contains(&state.as_str()));
            let entries: u64 = c.states.values().map(|n| u64::from(*n)).sum();
            if c.closed != (closes && entries > 0) {
                errors.push(BomError::ClosedDisagrees {
                    check: c.check.clone(),
                    closed: c.closed,
                });
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
