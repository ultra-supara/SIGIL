//! The analysis session: the root of everything SIGIL records about one run (plan §4.4.1).
//!
//! `analysis` is everything except [`ObservationMeta`]: a deterministic function of the same
//! observation snapshot, knowledge, and policy. Exports (AI-BOM, Markdown) are derived from the
//! session; the session is the source of truth.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::access::WriteAccess;
use crate::artifact::{Artifact, FileInstance, ProcessObs};
use crate::code::CodeFacts;
use crate::coverage::Coverage;
use crate::evidence::Assumption;
use crate::finding::{Finding, OpenQuestion, Outcome, PolicyViolation};
use crate::hint::FeatureHint;
use crate::id::{AuditScope, CheckId, RootId, Sha256Hex, Timestamp};
use crate::identity::{ComponentClaim, ReleaseClaim};
use crate::listener::Listener;
use crate::load::{LoadFacts, ProcessValue};
use crate::model::Model;
use crate::probe::{ActiveFeature, ApiProbe};
use crate::relation::{BindingPremise, Relation, RuleSupport};
use crate::text::UntrustedText;

/// One analysis run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub schema: SchemaVersion,
    pub tool: ToolInfo,
    /// Signature DB, profiles, rule set, policy, reference manifests: ID, version, SHA-256.
    pub knowledge: Vec<KnowledgeRef>,
    /// What was asked for (deterministic).
    pub request: RunRequest,
    /// When and as whom it ran (not part of analysis).
    pub observation: ObservationMeta,
    pub artifacts: Vec<Artifact>,
    pub instances: Vec<FileInstance>,
    /// Models in a model store (§4.6.7).
    pub models: Vec<Model>,
    pub processes: Vec<ProcessObs>,
    /// Listening sockets in SIGIL's network namespace (observe mode, §4.6.8).
    pub listeners: Vec<Listener>,
    /// Active probes (`request.active`, ADR-002 active mode).
    pub probes: Vec<ApiProbe>,
    pub values: Vec<ProcessValue>,
    /// A: component identification.
    pub components: Vec<ComponentClaim>,
    /// A: release identity (always a set).
    pub releases: Vec<ReleaseClaim>,
    /// B: feature presence.
    pub hints: Vec<FeatureHint>,
    /// C: code facts, one entry per analyzed slice.
    pub code: Vec<CodeFacts>,
    /// Declared/candidate dependencies, symbol candidates, profile matches, search paths,
    /// topology.
    pub relations: Vec<Relation>,
    /// D: the support of each applied profile rule for each slice.
    pub rule_support: Vec<RuleSupport>,
    pub bindings: Vec<BindingPremise>,
    pub loads: Vec<LoadFacts>,
    pub access: Vec<WriteAccess>,
    pub assumptions: Vec<Assumption>,
    pub coverage: Vec<Coverage>,
    /// E: technical findings (every condition established).
    pub findings: Vec<Finding>,
    /// E: rules whose conditions are not all established.
    pub open_questions: Vec<OpenQuestion>,
    pub policy_violations: Vec<PolicyViolation>,
    pub outcome: Outcome,
}

/// The session schema version. Only `sigil-session/1` is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaVersion {
    #[serde(rename = "sigil-session/1")]
    SessionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    /// `None` when not built from a git checkout.
    pub git_rev: Option<String>,
}

/// A piece of embedded knowledge the analysis used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRef {
    pub kind: KnowledgeKind,
    /// For a profile, the profile ID; [`crate::ProfileRef`] is `<id>@<version>`. For a reference
    /// manifest, the [`crate::RefSetId`].
    pub id: String,
    pub version: String,
    pub sha256: Sha256Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KnowledgeKind {
    SignatureDb,
    Profile,
    RuleSet,
    Policy,
    ReferenceManifest,
}

/// The request: everything the analysis depends on besides the observed system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub mode: Mode,
    pub roots: Vec<ScanRoot>,
    /// The requested audit scope.
    pub audit: Vec<AuditScope>,
    /// Checks required by the audit scope (derived from it, not from what was detected).
    pub required_checks: Vec<CheckId>,
    pub budgets: BTreeMap<String, u64>,
    /// Whether allowlisted environment keys were read from processes (`--observe-env`).
    pub observe_env: bool,
    /// Only the model with this display name is inventoried (exact match); `None` for all.
    pub model_filter: Option<String>,
    /// Active features explicitly requested (`--active`); empty for none.
    pub active: Vec<ActiveFeature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Static,
    Observe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRoot {
    pub id: RootId,
    pub path: UntrustedText,
}

/// Facts about the run itself. Not part of analysis; not compared by determinism tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationMeta {
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub uid: u32,
    pub gid: u32,
    pub capabilities: Vec<String>,
    /// The boot this run observed (`/proc/sys/kernel/random/boot_id`, a UUID). Empty when it was
    /// not read (static mode) or could not be read (observe mode); processes recorded then carry
    /// an empty boot ID too, and the checks that rest on their identity stay open.
    pub boot_id: String,
    pub kernel: String,
    /// SIGIL's own network namespace inode; `None` when not read in this mode.
    pub net_ns: Option<u64>,
    /// SIGIL's own mount namespace inode; `None` when not read in this mode.
    pub mnt_ns: Option<u64>,
}
