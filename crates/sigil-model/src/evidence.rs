//! Evidence, fact basis, claim support, and explicit unknowns (plan §4.4.4, §4.4.7).
//!
//! Three things are kept apart:
//! - [`Basis`]: **how a fact was obtained** — observed, derived from the target, modeled from a
//!   semantic profile, or assumed.
//! - [`Support`]: **what supports a behavior claim** about a specific artifact — a verified
//!   reference build, the target's own code, or only a feature match.
//! - [`EvidenceRef`]: **where the evidence is** — a typed pointer into the session's fact tables.
//!
//! `Support` has no ordering. "Weakest link" (plan §4.4.7) only needs to know whether a support is
//! verified ([`Support::is_verified`]); `ReferenceVerified` and `TargetVerified` are different
//! kinds of verification, not ranks.

use serde::{Deserialize, Serialize};

use crate::artifact::ProcessRef;
use crate::id::{
    AccessId, AnalyzerRef, ArtifactId, AssumptionId, CallId, CheckId, ComponentKey, FnId,
    GroundTruthRef, InstanceId, ListenerId, ModelId, ObligationId, PolicyRuleRef, PremiseId,
    ProbeId, ProcessRole, ProfileRef, ProfileRuleId, RootId, SliceId, ValueId,
};
use crate::relation::RuleSupportRef;
use crate::text::UntrustedText;

/// How a fact was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Basis {
    /// Read directly: a file, `/proc`, a configuration file.
    Observed { source: ObsSource },
    /// Mechanically derived from inspected inputs, e.g. by binary analysis of the target.
    Derived {
        analyzer: AnalyzerRef,
        inputs: Vec<EvidenceRef>,
    },
    /// Knowledge from a semantic profile rule applied to one slice. **Not** "confirmed in the
    /// target": what it may assert is the support recorded for that rule and slice
    /// ([`crate::RuleSupport`]), and a fact resting on it is no stronger than its own unresolved
    /// premises (weakest link, plan §4.4.7).
    Modeled(RuleSupportRef),
    /// An explicit, named assumption (e.g. the systemd default working directory).
    Assumed { assumption: AssumptionId },
}

/// Where an observation was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObsSource {
    File,
    Proc,
    Config,
}

/// A typed pointer to evidence in the session. Every variant is resolvable by
/// [`crate::Session::validate`]; there is no free-form evidence string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EvidenceRef {
    /// The content of an artifact (its hash), e.g. for a reference-manifest match.
    Artifact { artifact: ArtifactId },
    /// A location inside a binary slice. `Function`/`CallSite` locations refer to that slice's
    /// [`crate::CodeFacts`].
    Code { slice: SliceId, loc: Loc },
    /// A placed file with its observed metadata (stat, link chain, stability).
    Instance { instance: InstanceId },
    /// A configuration source: file, key, line.
    Config(ConfigRef),
    /// A process observation.
    Process { process: ProcessRef },
    /// A process value (configured / predicted / observed / child-derived).
    Value { value: ValueId },
    /// A write-access analysis: file-system metadata of a path and its ancestors.
    Access { access: AccessId },
    /// A semantic profile rule at a revision (its hash is in the session's `knowledge`).
    ProfileRule(ProfileRuleRef),
    /// A model: its manifest, layers, and the blobs found for them.
    Model { model: ModelId },
    /// A listening socket as read from `/proc/net/tcp{,6}`: an observation.
    Listener { listener: ListenerId },
    /// An active probe and its outcome.
    Probe { probe: ProbeId },
}

/// A location inside a binary slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Loc {
    FileOffset(u64),
    VAddr(u64),
    Section { name: UntrustedText, offset: u64 },
    Symbol(UntrustedText),
    Function(FnId),
    CallSite(CallId),
}

/// A configuration source: which file, which key or directive, which line (1-based).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRef {
    pub file: InstanceId,
    pub key: UntrustedText,
    pub line: u32,
}

/// A rule of a semantic profile at a revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRuleRef {
    pub profile: ProfileRef,
    pub rule: ProfileRuleId,
}

/// What supports a behavior claim (level D) about a specific artifact (plan §4.4.7).
///
/// Recorded once per profile rule and slice, in [`crate::RuleSupport`]; facts and conditions refer
/// to it by [`RuleSupportRef`]. File attributes, configuration, and process state have evidence
/// of their own kind ([`crate::CondEvidence`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Support {
    /// The artifact's SHA-256 equals `reference`, whose behavior for this rule was verified by
    /// ground truth. Scope: that reference build only.
    ReferenceVerified {
        reference: ArtifactId,
        verification: GroundTruthRef,
        rule: ProfileRuleId,
    },
    /// The rule's obligations were decided `Pass` in the target's own code. Never empty.
    TargetVerified { obligations: Vec<ObligationId> },
    /// Only symbols, strings, or part of the structure match: the behavior is **expected**, not
    /// established. Can never make a finding condition `Met`. `matched` obligations passed in
    /// the slice; `unverified` is never empty, and every fact or condition resting on this
    /// support carries these premises as unresolved.
    FeatureMatch {
        matched: Vec<ObligationId>,
        unverified: Vec<PremiseId>,
    },
    /// An explicit assumption. Supports a finding condition only if the policy accepted it.
    Assumed { assumption: AssumptionId },
}

impl Support {
    /// `ReferenceVerified` or `TargetVerified`. Used for the weakest-link rule: a claim that
    /// depends on an unverified support is itself unverified.
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            Support::ReferenceVerified { .. } | Support::TargetVerified { .. }
        )
    }
}

/// An explicit assumption and whether the policy accepted it (plan §4.4.7, §4.7 `[assumptions]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assumption {
    pub id: AssumptionId,
    pub statement: String,
    pub acceptance: AssumptionAcceptance,
}

/// Whether a finding condition may rest on an assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AssumptionAcceptance {
    NotAccepted,
    Accepted { source: PolicyRuleRef },
}

/// A fact that can be established, refuted, or unknown — with how it was obtained and which
/// premises it still depends on (plan §4.4.4).
///
/// `unresolved` lists premises that are **not** established. A fact with unresolved premises is
/// never verified (weakest link), and a premise is never dropped along a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Tri<T> {
    Yes {
        why: T,
        basis: Basis,
        unresolved: Vec<PremiseId>,
    },
    No {
        basis: Basis,
        unresolved: Vec<PremiseId>,
    },
    Unknown {
        reason: UnknownReason,
    },
}

/// A plain three-valued result where no basis is attached (e.g. a region's completeness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriState {
    Yes,
    No,
    Unknown,
}

/// Why something is unknown. Unknown is a result, never `false`, never a missing field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UnknownReason {
    /// Evidence exists but does not meet the sufficiency rule of its kind (plan §4.4.9), e.g.
    /// `FeatureMatch` behavior, `Undetermined` access, a value that is only configured.
    InsufficientEvidence,
    /// A premise listed in `unresolved` is not established.
    PremiseUnresolved,
    /// The fact could not be observed.
    NotObservable(NotObservable),
    /// Outside the modeled subset, e.g. an unmodeled systemd directive or an unsupported
    /// topology rule.
    NotModeled { what: String },
    /// Decided only at run time (score values, CPU features), which SIGIL never observes.
    RunTimeDependent { what: String },
    /// Needs an active-mode observation (e.g. tracing) that this run does not perform.
    RequiresActive { what: String },
    /// A check this depends on did not close; that check's [`crate::Coverage`] says why.
    CheckIncomplete { check: CheckId },
}

/// Why an observation was not possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotObservable {
    PermissionDenied,
    NoProcess,
    ModeDisabled,
    NamespaceMismatch,
    /// A listing or read ended before it was complete (a budget, or an error): what it found is
    /// kept, but it is not all there is.
    ReadIncomplete,
}

/// Whether process mappings could be observed at all. An empty mapping list means "not mapped
/// now" only when this is `Observed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observability {
    Observed,
    NotObservable(NotObservable),
}

/// The subject a coverage entry, finding, open question, or policy violation is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Ref {
    /// The whole requested audit (scope-wide checks such as discovery).
    Audit,
    /// A scan root from the request.
    Root(RootId),
    Artifact(ArtifactId),
    Slice(SliceId),
    Instance(InstanceId),
    /// A component identified in a slice.
    Component {
        slice: SliceId,
        component: ComponentKey,
    },
    /// A process role from a topology rule.
    Role(ProcessRole),
    /// One search path of a loader in one process role, e.g. `cwd` of `llama-server (per model)`.
    SearchPath {
        role: ProcessRole,
        search_path: String,
    },
    /// An observed process.
    Process(ProcessRef),
    /// A model in a model store.
    Model(ModelId),
    /// A listening socket.
    Listener(ListenerId),
    /// An active probe (its target, from this host).
    Probe(ProbeId),
}
