//! Level E, policy decisions, and the outcome (plan §4.4.9, §4.7).
//!
//! Three separate lists: technical [`Finding`]s (every condition established), [`OpenQuestion`]s
//! (some condition unknown), and [`PolicyViolation`]s (organizational policy). A finding's
//! technical content (`default_severity`, conditions, evidence) is never changed by policy; the
//! policy's treatment is its own field, [`PolicyDecision`].
//!
//! [`Verdict`] and [`Completeness`] are independent and always reported together: a gap never
//! lowers or hides a confirmed `Fail`, and `Pass` with `Incomplete` is not a clean pass.

use serde::{Deserialize, Serialize};

use crate::access::AccessConclusion;
use crate::evidence::{EvidenceRef, Ref, Support, UnknownReason};
use crate::id::{
    AssumptionId, CheckId, CondId, Date, FindingId, OpenQuestionId, PolicyRuleRef, PremiseId,
    RuleId, Timestamp,
};
use crate::identity::IdentityStatus;
use crate::load::ValueOrigin;
use crate::relation::BindingState;

/// One condition of a detection rule, with its state and the premises it still depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub id: CondId,
    pub state: CondState,
    pub unresolved: Vec<PremiseId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CondState {
    /// Established, with evidence that meets the sufficiency rule of its kind.
    Met { evidence: CondEvidence },
    /// Refuted, with evidence that meets the sufficiency rule of its kind.
    NotMet { evidence: CondEvidence },
    /// Neither. `evidence` holds what was gathered but is insufficient (e.g. a `FeatureMatch`);
    /// `None` when nothing of the condition's kind was established.
    Unknown {
        reason: UnknownReason,
        evidence: Option<CondEvidence>,
    },
}

/// Evidence for a condition, by kind. Each kind has its own sufficiency rule (plan §4.4.9).
/// File attributes and process values are never "verified in the target's code".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CondEvidence {
    /// Library or runtime behavior.
    Behavior(Support),
    /// Write capabilities from observed metadata.
    Access(AccessConclusion),
    /// A process value.
    Value(ValueOrigin),
    /// Symbol binding in a process role.
    Binding(BindingState),
    /// Identity of a component or release.
    Identity(IdentityStatus),
    /// A direct observation of files, configuration, or processes (e.g. a hash that differs from
    /// the reference manifest, a missing blob). `facts` may point only to artifacts, instances,
    /// configuration, and processes: code, values, and access have their own kinds and rules.
    Observed { facts: Vec<EvidenceRef> },
}

impl CondEvidence {
    /// Whether this evidence is sufficient for `Met` (plan §4.4.9). `accepted` says whether the
    /// policy accepted an assumption.
    ///
    /// | Kind | Sufficient | Not sufficient |
    /// |---|---|---|
    /// | Behavior | `ReferenceVerified`, `TargetVerified`, accepted `Assumed` | `FeatureMatch` |
    /// | Access | `TrustedOnly`, `UntrustedHolder` | `Undetermined` |
    /// | Value | `ObservedProcess`, `PredictedLaunch`, `ChildDerived` | `Configured` |
    /// | Binding | `Verified`, accepted `Assumed` | `Unknown`, `Mismatch` |
    /// | Identity | `ReferenceMatched` | everything else |
    /// | Observed | at least one fact, each an artifact, instance, configuration, or process | none, or any other reference |
    pub fn sufficient_for_met(&self, accepted: &dyn Fn(&AssumptionId) -> bool) -> bool {
        match self {
            CondEvidence::Behavior(support) => match support {
                Support::ReferenceVerified { .. } | Support::TargetVerified { .. } => true,
                Support::Assumed { assumption } => accepted(assumption),
                Support::FeatureMatch { .. } => false,
            },
            CondEvidence::Access(conclusion) => {
                !matches!(conclusion, AccessConclusion::Undetermined { .. })
            }
            CondEvidence::Value(origin) => !matches!(origin, ValueOrigin::Configured { .. }),
            CondEvidence::Binding(state) => match state {
                BindingState::Verified { .. } => true,
                BindingState::Assumed { assumption } => accepted(assumption),
                BindingState::Unknown { .. } | BindingState::Mismatch { .. } => false,
            },
            CondEvidence::Identity(status) => matches!(status, IdentityStatus::ReferenceMatched),
            CondEvidence::Observed { facts } => {
                !facts.is_empty()
                    && facts.iter().all(|f| {
                        matches!(
                            f,
                            EvidenceRef::Artifact { .. }
                                | EvidenceRef::Instance { .. }
                                | EvidenceRef::Config(_)
                                | EvidenceRef::Process { .. }
                        )
                    })
            }
        }
    }

    /// Whether this evidence is sufficient for `NotMet`. The same rules as for `Met`, except that
    /// a binding is refuted only by `Mismatch` (plan §4.4.9).
    pub fn sufficient_for_not_met(&self, accepted: &dyn Fn(&AssumptionId) -> bool) -> bool {
        match self {
            CondEvidence::Binding(state) => matches!(state, BindingState::Mismatch { .. }),
            other => other.sufficient_for_met(accepted),
        }
    }
}

/// A technical conclusion: a dangerous configuration established on every condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: FindingId,
    pub rule: RuleId,
    pub kind: FindingKind,
    pub subject: Ref,
    pub summary: String,
    /// Every condition the rule needs: all `Met`, each with sufficient evidence and no
    /// unresolved premise.
    pub conditions: Vec<Condition>,
    pub evidence: Vec<EvidenceRef>,
    /// What the analysis did not cover, e.g. "ACLs were evaluated only where readable".
    pub limits: Vec<String>,
    /// The rule's technical severity. Never changed by policy.
    pub default_severity: Severity,
    /// What the policy does with this finding.
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingKind {
    Integrity,
    Exposure,
    Loader,
    Precondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Warn,
    Fail,
}

/// A security-relevant question the analysis could not settle: no condition is refuted, and at
/// least one is unknown or rests on an unresolved premise. Not a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenQuestion {
    pub id: OpenQuestionId,
    pub rule: RuleId,
    pub subject: Ref,
    pub conditions: Vec<Condition>,
    pub evidence: Vec<EvidenceRef>,
    pub decision: OpenQuestionDecision,
}

/// An organizational-policy result (e.g. a denied component), separate from technical findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyViolation {
    pub policy_rule: PolicyRuleRef,
    pub subject: Ref,
    pub evidence: Vec<EvidenceRef>,
    pub decision: PolicyDecision,
}

/// What the policy does with a finding or policy violation. `Ignore` keeps the entry in the
/// output with its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub action: Action,
    pub source: PolicyRuleRef,
    /// Required for `Ignore`.
    pub reason: Option<String>,
    pub expires: Option<Date>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Fail,
    Warn,
    Ignore,
}

/// What the policy does with an open question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenQuestionDecision {
    pub treatment: OqTreatment,
    pub source: PolicyRuleRef,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OqTreatment {
    /// Counts toward `completeness` only (the default).
    CountAsGap,
    Warn,
    Fail,
    Ignore,
}

/// The final result: two independent values, always shown together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// From findings, policy violations, and open questions treated as `Warn`/`Fail`.
    pub verdict: Verdict,
    /// From required checks and open questions treated as `CountAsGap`.
    pub completeness: Completeness,
    /// Findings whose decision is `Fail`.
    pub confirmed_failures: u32,
    /// Findings whose decision is `Warn`.
    pub confirmed_warnings: u32,
    /// The instant used to evaluate policy `expires` (an input, reused on re-analysis).
    pub policy_time: Timestamp,
}

/// Ordered `Pass < Warn < Fail`: the verdict is the maximum action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Completeness {
    Complete,
    Incomplete {
        /// Required checks that are not closed.
        missing_required: Vec<CheckId>,
        /// Open questions treated as `CountAsGap`.
        gaps: Vec<OpenQuestionId>,
    },
}
