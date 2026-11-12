//! Judging a diff under a compare policy (#16, PR-16b).
//!
//! A compare policy never changes what changed. It gives each [`ChangeKind`] an action and each
//! [`Cause`] of an item not comparable a treatment, and so the diff a verdict and a completeness,
//! as a session's policy gives its findings decisions and the session an outcome. A diff is
//! complete only when both its inputs are: what a session could not see, a comparison with it
//! cannot see either. [`CompareRules`] is a complete table (every kind, every cause), so judging
//! is total. [`Evaluation`] is what a diff records of it, and it reads back only whole.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::diff::{Cause, Change, ChangeKind, NotComparable, Side};
use crate::finding::{Action, Completeness, OqTreatment, PolicyDecision, Verdict};
use crate::id::PolicyRuleRef;
use crate::session::KnowledgeRef;

/// What the changes of one kind weigh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareAction {
    Fail,
    Warn,
    Ignore,
    /// What the change's own decisions (the current session's) say: the maximum of their
    /// actions. Only for the kinds that carry decisions ([`ChangeKind::takes_decided`]).
    Decided,
}

/// The action of one change kind, where it came from, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeTreatment {
    pub action: CompareAction,
    /// `default:compare.<Kind>`, or `policy:compare.changes.<Kind>`.
    pub source: PolicyRuleRef,
    /// The policy's reason; a policy file must give one for `Ignore`.
    pub reason: Option<String>,
}

/// The treatment of the items not comparable for one cause, where it came from, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotComparableTreatment {
    pub treatment: OqTreatment,
    /// `default:compare.not_comparable.<Cause>`, or `policy:compare.not_comparable.<Cause>`.
    pub source: PolicyRuleRef,
    /// The policy's reason; a policy file must give one for `Ignore`.
    pub reason: Option<String>,
}

/// Whether the comparison saw everything it judged: both inputs complete, and no item not
/// comparable counted as a gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DiffCompleteness {
    Complete,
    Incomplete {
        /// The inputs whose own recorded completeness is `Incomplete`; `None` when both are
        /// complete.
        inputs: Option<Side>,
        /// The items not comparable whose cause is treated `CountAsGap`.
        not_comparable: u32,
    },
}

/// How a diff was judged: the policy's complete table, and the result. Built by
/// [`CompareRules::judge`]. Read back through [`CompareRules::new`]: a document whose table
/// misses a kind or a cause, or gives `Decided` to a kind without decisions, does not load. The
/// JSON form is flat: `policy`, `changes` and `not_comparable` (the table), then `verdict` and
/// `completeness`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EvaluationRecord", into = "EvaluationRecord")]
pub struct Evaluation {
    rules: CompareRules,
    verdict: Verdict,
    completeness: DiffCompleteness,
}

/// The JSON form of an [`Evaluation`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationRecord {
    policy: KnowledgeRef,
    changes: BTreeMap<ChangeKind, ChangeTreatment>,
    not_comparable: BTreeMap<Cause, NotComparableTreatment>,
    verdict: Verdict,
    completeness: DiffCompleteness,
}

impl TryFrom<EvaluationRecord> for Evaluation {
    type Error = RulesError;

    fn try_from(record: EvaluationRecord) -> Result<Evaluation, RulesError> {
        Ok(Evaluation {
            rules: CompareRules::new(record.policy, record.changes, record.not_comparable)?,
            verdict: record.verdict,
            completeness: record.completeness,
        })
    }
}

impl From<Evaluation> for EvaluationRecord {
    fn from(e: Evaluation) -> EvaluationRecord {
        EvaluationRecord {
            policy: e.rules.policy,
            changes: e.rules.changes,
            not_comparable: e.rules.not_comparable,
            verdict: e.verdict,
            completeness: e.completeness,
        }
    }
}

/// A complete compare table, built by [`CompareRules::new`] or [`CompareRules::defaults`]:
/// every kind and every cause has an entry, and `Decided` is given only where it applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRules {
    policy: KnowledgeRef,
    changes: BTreeMap<ChangeKind, ChangeTreatment>,
    not_comparable: BTreeMap<Cause, NotComparableTreatment>,
}

/// Why a table is not a complete compare table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesError {
    MissingKind(ChangeKind),
    MissingCause(Cause),
    /// `Decided` for a kind whose changes carry no decisions.
    Decided(ChangeKind),
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::MissingKind(k) => write!(f, "no action for {}", k.name()),
            RulesError::MissingCause(c) => write!(f, "no treatment for {}", c.name()),
            RulesError::Decided(k) => write!(
                f,
                "{} carries no decisions, so it cannot be decided",
                k.name()
            ),
        }
    }
}

impl std::error::Error for RulesError {}

impl ChangeKind {
    /// The action of the kind when the policy does not name it. Drift that a single session's
    /// verdict cannot see fails; a change that weakens the baseline warns; improvements, and
    /// changes that follow from others, are ignored; a new finding or violation weighs what its
    /// own decisions say.
    pub fn default_action(self) -> CompareAction {
        use ChangeKind as K;
        match self {
            K::LayerChanged | K::FileContentChanged | K::BindWidened => CompareAction::Fail,
            K::FindingNew | K::ViolationNew => CompareAction::Decided,
            K::PolicyChanged
            | K::CheckOpened
            | K::FindingDecisionChanged
            | K::ViolationDecisionChanged
            | K::ModelAdded
            | K::ModelRemoved
            | K::LicenseChanged
            | K::FileAdded
            | K::FileRemoved
            | K::ReleaseChanged
            | K::ComponentChanged
            | K::ListenerAdded => CompareAction::Warn,
            K::VerdictChanged
            | K::CompletenessChanged
            | K::CheckClosed
            | K::FindingResolved
            | K::ViolationResolved
            | K::ListenerRemoved
            | K::BindNarrowed => CompareAction::Ignore,
        }
    }

    /// Whether the kind's changes carry decisions, so that `Decided` applies.
    pub fn takes_decided(self) -> bool {
        matches!(self, ChangeKind::FindingNew | ChangeKind::ViolationNew)
    }
}

impl Cause {
    /// The treatment of the cause when the policy does not name it: a gap.
    pub fn default_treatment(self) -> OqTreatment {
        OqTreatment::CountAsGap
    }
}

impl CompareRules {
    /// A table, if it is complete: every kind and every cause, `Decided` only where it applies.
    pub fn new(
        policy: KnowledgeRef,
        changes: BTreeMap<ChangeKind, ChangeTreatment>,
        not_comparable: BTreeMap<Cause, NotComparableTreatment>,
    ) -> Result<CompareRules, RulesError> {
        for kind in ChangeKind::ALL {
            let Some(treatment) = changes.get(&kind) else {
                return Err(RulesError::MissingKind(kind));
            };
            if treatment.action == CompareAction::Decided && !kind.takes_decided() {
                return Err(RulesError::Decided(kind));
            }
        }
        for cause in Cause::ALL {
            if !not_comparable.contains_key(&cause) {
                return Err(RulesError::MissingCause(cause));
            }
        }
        Ok(CompareRules {
            policy,
            changes,
            not_comparable,
        })
    }

    /// The table of a policy that names no kind and no cause.
    pub fn defaults(policy: KnowledgeRef) -> CompareRules {
        let changes = ChangeKind::ALL
            .into_iter()
            .map(|kind| {
                let treatment = ChangeTreatment {
                    action: kind.default_action(),
                    source: PolicyRuleRef::from_static("default:compare.", kind.name()),
                    reason: None,
                };
                (kind, treatment)
            })
            .collect();
        let not_comparable = Cause::ALL
            .into_iter()
            .map(|cause| {
                let treatment = NotComparableTreatment {
                    treatment: cause.default_treatment(),
                    source: PolicyRuleRef::from_static(
                        "default:compare.not_comparable.",
                        cause.name(),
                    ),
                    reason: None,
                };
                (cause, treatment)
            })
            .collect();
        CompareRules {
            policy,
            changes,
            not_comparable,
        }
    }

    /// The policy the table is from.
    pub fn policy(&self) -> &KnowledgeRef {
        &self.policy
    }

    /// Every kind's action.
    pub fn changes(&self) -> &BTreeMap<ChangeKind, ChangeTreatment> {
        &self.changes
    }

    /// Every cause's treatment.
    pub fn not_comparable(&self) -> &BTreeMap<Cause, NotComparableTreatment> {
        &self.not_comparable
    }

    /// What `change` weighs: its kind's action, or for `Decided` the maximum action of its own
    /// decisions (`Fail` without any: an item whose decisions are unknown is never lighter than
    /// it could be), and whether its decisions gave it.
    pub fn weigh(&self, change: &Change) -> (Action, bool) {
        // Every kind has an entry (`new`, `defaults`). The fallback is never taken, and it would
        // not make a change lighter.
        let action = self
            .changes
            .get(&change.kind())
            .map_or(CompareAction::Fail, |t| t.action);
        match action {
            CompareAction::Fail => (Action::Fail, false),
            CompareAction::Warn => (Action::Warn, false),
            CompareAction::Ignore => (Action::Ignore, false),
            CompareAction::Decided => (decided(change.decisions().unwrap_or(&[])), true),
        }
    }

    /// How the items not comparable for `cause` count.
    pub fn treatment(&self, cause: Cause) -> OqTreatment {
        // Every cause has an entry; the fallback is never taken.
        self.not_comparable
            .get(&cause)
            .map_or(OqTreatment::CountAsGap, |t| t.treatment)
    }

    /// The evaluation of a diff under this table: its changes, its items not comparable, and the
    /// recorded completeness of its two inputs. Pure, and independent of the lists' order. The
    /// inputs' completeness never changes the verdict, as a gap never changes a session's.
    pub fn judge(
        &self,
        baseline: &Completeness,
        current: &Completeness,
        changes: &[Change],
        not_comparable: &[NotComparable],
    ) -> Evaluation {
        let mut verdict = Verdict::Pass;
        for change in changes {
            verdict = verdict.max(verdict_of(self.weigh(change).0));
        }
        let mut gaps = 0usize;
        for item in not_comparable {
            match self.treatment(item.cause) {
                OqTreatment::CountAsGap => gaps += 1,
                OqTreatment::Warn => verdict = verdict.max(Verdict::Warn),
                OqTreatment::Fail => verdict = Verdict::Fail,
                OqTreatment::Ignore => {}
            }
        }
        let inputs = match (is_incomplete(baseline), is_incomplete(current)) {
            (true, true) => Some(Side::Both),
            (true, false) => Some(Side::Baseline),
            (false, true) => Some(Side::Current),
            (false, false) => None,
        };
        let completeness = if inputs.is_none() && gaps == 0 {
            DiffCompleteness::Complete
        } else {
            DiffCompleteness::Incomplete {
                inputs,
                not_comparable: u32::try_from(gaps).unwrap_or(u32::MAX),
            }
        };
        Evaluation {
            rules: self.clone(),
            verdict,
            completeness,
        }
    }
}

impl Evaluation {
    /// The table the diff was judged by.
    pub fn rules(&self) -> &CompareRules {
        &self.rules
    }

    /// The policy the table is from.
    pub fn policy(&self) -> &KnowledgeRef {
        self.rules.policy()
    }

    /// Every kind's action.
    pub fn changes(&self) -> &BTreeMap<ChangeKind, ChangeTreatment> {
        self.rules.changes()
    }

    /// Every cause's treatment.
    pub fn not_comparable(&self) -> &BTreeMap<Cause, NotComparableTreatment> {
        self.rules.not_comparable()
    }

    /// The maximum weight of the changes, and of the items not comparable treated `Warn` or
    /// `Fail`; `Pass` without any.
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The inputs that are incomplete, and the items not comparable counted as gaps.
    pub fn completeness(&self) -> &DiffCompleteness {
        &self.completeness
    }

    /// What `change` weighs under the table ([`CompareRules::weigh`]).
    pub fn weigh(&self, change: &Change) -> (Action, bool) {
        self.rules.weigh(change)
    }

    /// How an item not comparable counts under the table.
    pub fn treatment(&self, item: &NotComparable) -> OqTreatment {
        self.rules.treatment(item.cause)
    }
}

fn is_incomplete(c: &Completeness) -> bool {
    matches!(c, Completeness::Incomplete { .. })
}

/// The maximum action of `decisions`, ordered as the verdicts they give (`Ignore < Warn <
/// Fail`). Without any, `Fail`.
fn decided(decisions: &[PolicyDecision]) -> Action {
    decisions
        .iter()
        .map(|d| d.action)
        .max_by_key(|a| verdict_of(*a))
        .unwrap_or(Action::Fail)
}

fn verdict_of(action: Action) -> Verdict {
    match action {
        Action::Fail => Verdict::Fail,
        Action::Warn => Verdict::Warn,
        Action::Ignore => Verdict::Pass,
    }
}
