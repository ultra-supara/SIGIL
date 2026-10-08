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

use crate::access::{AccessConclusion, WriteCapability};
use crate::code::CallRef;
use crate::evidence::{AssumptionAcceptance, Basis, EvidenceRef, Ref, Support, UnknownReason};
use crate::id::{
    AccessId, AssumptionId, CheckId, ComponentKey, CondId, Date, FindingId, InstanceId,
    OpenQuestionId, PolicyRuleRef, PremiseId, ProcessRole, RuleId, SliceId, Timestamp, ValueId,
};
use crate::identity::IdentityStatus;
use crate::load::{LoadContext, LoadFact, TriValue, ValueOrigin};
use crate::relation::{BindingState, RuleSupport, RuleSupportRef};
use crate::session::Session;

/// One condition of a detection rule, with its state and the premises it still depends on.
/// `unresolved` carries the premises of what the evidence rests on; a `Met` or `NotMet`
/// condition has none.
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
    /// Established: the evidence settles `Met` (or is an observation).
    Met { evidence: CondEvidence },
    /// Refuted: the evidence settles `NotMet` (or is an observation).
    NotMet { evidence: CondEvidence },
    /// Neither. `evidence` names what was gathered but settles neither (e.g. a `FeatureMatch`
    /// rule support); `None` when nothing of the condition's kind was established.
    Unknown {
        reason: UnknownReason,
        evidence: Option<CondEvidence>,
    },
}

/// Evidence for a condition: a reference to the record that decides it, by kind (plan §4.4.9).
///
/// A condition never copies a record's conclusion. [`Session::settles`] reads the record, so a
/// condition cannot claim more than the record it names. File attributes and process values are
/// never "verified in the target's code".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CondEvidence {
    /// Library or runtime behavior: the support recorded for one profile rule on one slice.
    Behavior(RuleSupportRef),
    /// One loader fact of one file in one context, e.g. that the file would be evaluated.
    Load {
        instance: InstanceId,
        context: LoadContext,
        fact: LoadFact,
    },
    /// The conclusion for one write capability of an access record. The condition is that an
    /// untrusted principal holds the capability.
    Access {
        access: AccessId,
        capability: WriteCapability,
    },
    /// A process value, and the state the condition needs it in.
    Value { value: ValueId, needs: ValueNeed },
    /// Whether a process role binds a call site to the analyzed definition.
    Binding {
        process_role: ProcessRole,
        site: CallRef,
        definer: InstanceId,
    },
    /// The identity claim for a component of a slice.
    Identity {
        slice: SliceId,
        component: ComponentKey,
    },
    /// A direct observation of files, configuration, or processes (e.g. a hash that differs from
    /// the reference manifest, a missing blob). `facts` may point only to artifacts, instances,
    /// configuration, and processes: code, values, and access have their own kinds and rules.
    Observed { facts: Vec<EvidenceRef> },
}

/// The state of a process value that a condition needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueNeed {
    Known,
    Absent,
}

/// What a condition's evidence settles, read from the record it names ([`Session::settles`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settles {
    /// Sufficient for `Met`; contradicts `NotMet`.
    Met,
    /// Sufficient for `NotMet`; contradicts `Met`.
    NotMet,
    /// Sufficient for either: an observation, whose direction the rule decides.
    Either,
    /// Sufficient for neither: the condition can only be `Unknown`.
    Neither,
}

/// A record that a [`CondEvidence`] names and the session does not contain.
pub(crate) struct Missing {
    pub kind: &'static str,
    pub id: String,
}

impl Session {
    /// What `evidence` settles under the sufficiency rule of its kind (plan §4.4.9), or `None`
    /// when it names a record the session does not contain.
    ///
    /// | Kind | Names | `Met` | `NotMet` | Neither |
    /// |---|---|---|---|---|
    /// | Behavior | a `rule_support` entry | `ReferenceVerified`, `TargetVerified`, accepted `Assumed` | never (a refuted rule is a `ProfileMismatch`) | `FeatureMatch`, unaccepted `Assumed` |
    /// | Load | a fact of a `loads` entry | `Yes` | `No` | `Unknown`, an insufficient basis, or unresolved premises |
    /// | Access | a capability of an `access` entry | `UntrustedHolder` | `TrustedOnly` | `Undetermined` |
    /// | Value | a `values` entry | the needed state | the other state | `Unknown`, or a `Configured` origin |
    /// | Binding | a `bindings` entry | `Verified`, accepted `Assumed` | `Mismatch` | `Unknown`, unaccepted `Assumed` |
    /// | Identity | a `components` entry | `ReferenceMatched` | never | any other status |
    /// | Observed | its facts | either, with at least one fact, each an artifact, instance, configuration, or process | | otherwise |
    ///
    /// A basis is sufficient when it is observed, derived, a sufficient rule support, or an
    /// accepted assumption.
    pub fn settles(&self, evidence: &CondEvidence) -> Option<Settles> {
        self.resolve(evidence).ok()
    }

    pub(crate) fn resolve(&self, evidence: &CondEvidence) -> Result<Settles, Missing> {
        let missing = |kind, id: String| Missing { kind, id };
        let met_if = |met: bool| if met { Settles::Met } else { Settles::Neither };
        match evidence {
            CondEvidence::Behavior(key) => self
                .rule_support_of(key)
                .map(|r| met_if(self.support_sufficient(&r.support)))
                .ok_or_else(|| missing("rule support", rule_support_key(key))),
            CondEvidence::Load {
                instance,
                context,
                fact,
            } => {
                let load = self
                    .loads
                    .iter()
                    .find(|l| l.instance == *instance && l.context == *context)
                    .ok_or_else(|| {
                        missing(
                            "load facts",
                            format!("{instance} @ {} ({})", context.process_role, context.rule),
                        )
                    })?;
                Ok(match load.fact(*fact) {
                    Some((holds, basis, unresolved))
                        if unresolved.is_empty() && self.basis_sufficient(basis) =>
                    {
                        if holds {
                            Settles::Met
                        } else {
                            Settles::NotMet
                        }
                    }
                    _ => Settles::Neither,
                })
            }
            CondEvidence::Access { access, capability } => {
                let record = self
                    .access
                    .iter()
                    .find(|a| a.id == *access)
                    .ok_or_else(|| missing("access", access.to_string()))?;
                let entry = record
                    .capabilities
                    .iter()
                    .find(|c| c.capability == *capability)
                    .ok_or_else(|| {
                        missing("write capability", format!("{access}: {capability:?}"))
                    })?;
                Ok(match entry.conclusion {
                    AccessConclusion::UntrustedHolder { .. } => Settles::Met,
                    AccessConclusion::TrustedOnly => Settles::NotMet,
                    AccessConclusion::Undetermined { .. } => Settles::Neither,
                })
            }
            CondEvidence::Value { value, needs } => {
                let record = self
                    .values
                    .iter()
                    .find(|v| v.id == *value)
                    .ok_or_else(|| missing("value", value.to_string()))?;
                if matches!(record.origin, ValueOrigin::Configured { .. }) {
                    return Ok(Settles::Neither);
                }
                Ok(match (&record.value, needs) {
                    (TriValue::Unknown { .. }, _) => Settles::Neither,
                    (TriValue::Known(_), ValueNeed::Known)
                    | (TriValue::Absent, ValueNeed::Absent) => Settles::Met,
                    (TriValue::Known(_), ValueNeed::Absent)
                    | (TriValue::Absent, ValueNeed::Known) => Settles::NotMet,
                })
            }
            CondEvidence::Binding {
                process_role,
                site,
                definer,
            } => {
                let record = self
                    .bindings
                    .iter()
                    .find(|b| {
                        b.process_role == *process_role
                            && b.site == *site
                            && b.analyzed_definer == *definer
                    })
                    .ok_or_else(|| {
                        missing(
                            "binding",
                            format!("{} @ {process_role} -> {definer}", site.call),
                        )
                    })?;
                Ok(match &record.state {
                    BindingState::Verified { .. } => Settles::Met,
                    BindingState::Assumed { assumption } => met_if(self.accepted(assumption)),
                    BindingState::Mismatch { .. } => Settles::NotMet,
                    BindingState::Unknown { .. } => Settles::Neither,
                })
            }
            CondEvidence::Identity { slice, component } => self
                .components
                .iter()
                .find(|c| c.subject == *slice && c.component == *component)
                .map(|c| met_if(c.status == IdentityStatus::ReferenceMatched))
                .ok_or_else(|| missing("component", format!("{component} on {slice}"))),
            CondEvidence::Observed { facts } => {
                let observations = !facts.is_empty()
                    && facts.iter().all(|f| {
                        matches!(
                            f,
                            EvidenceRef::Artifact { .. }
                                | EvidenceRef::Instance { .. }
                                | EvidenceRef::Config(_)
                                | EvidenceRef::Process { .. }
                        )
                    });
                Ok(if observations {
                    Settles::Either
                } else {
                    Settles::Neither
                })
            }
        }
    }

    pub(crate) fn rule_support_of(&self, key: &RuleSupportRef) -> Option<&RuleSupport> {
        self.rule_support.iter().find(|r| r.is(key))
    }

    /// Whether the policy accepted `assumption`.
    pub(crate) fn accepted(&self, assumption: &AssumptionId) -> bool {
        self.assumptions.iter().any(|a| {
            a.id == *assumption && matches!(a.acceptance, AssumptionAcceptance::Accepted { .. })
        })
    }

    /// Verified, or an accepted assumption.
    pub(crate) fn support_sufficient(&self, support: &Support) -> bool {
        match support {
            Support::ReferenceVerified { .. } | Support::TargetVerified { .. } => true,
            Support::Assumed { assumption } => self.accepted(assumption),
            Support::FeatureMatch { .. } => false,
        }
    }

    /// Observed, derived, a sufficient rule support, or an accepted assumption.
    pub(crate) fn basis_sufficient(&self, basis: &Basis) -> bool {
        match basis {
            Basis::Observed { .. } | Basis::Derived { .. } => true,
            Basis::Modeled(key) => self
                .rule_support_of(key)
                .is_some_and(|r| self.support_sufficient(&r.support)),
            Basis::Assumed { assumption } => self.accepted(assumption),
        }
    }
}

pub(crate) fn rule_support_key(key: &RuleSupportRef) -> String {
    format!("{} {} on {}", key.profile, key.rule, key.slice)
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
