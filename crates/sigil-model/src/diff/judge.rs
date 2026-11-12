//! Judging a diff under a compare policy (#16, PR-16b).
//!
//! A compare policy never changes what changed. It gives each [`ChangeKind`] an action and each
//! [`Cause`] of an item not comparable a treatment, and so the diff a verdict and a completeness,
//! as a session's policy gives its findings decisions and the session an outcome.
//! [`CompareRules`] is a complete table (every kind, every cause), so judging is total.
//! [`Evaluation`] is what a diff records of it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::diff::{Cause, Change, ChangeKind, NotComparable};
use crate::finding::{Action, OqTreatment, PolicyDecision, Verdict};
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

/// Whether every difference could be judged, as the policy counts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DiffCompleteness {
    Complete,
    Incomplete {
        /// The items not comparable whose cause is treated `CountAsGap`.
        not_comparable: u32,
    },
}

/// How a diff was judged: the policy, its whole table, and the result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    /// The policy's knowledge entry, as a session records the policy it applied.
    pub policy: KnowledgeRef,
    /// Every change kind's action, after the policy's entries.
    pub changes: BTreeMap<ChangeKind, ChangeTreatment>,
    /// Every cause's treatment, after the policy's entries.
    pub not_comparable: BTreeMap<Cause, NotComparableTreatment>,
    /// The maximum weight of the changes, and of the items not comparable treated `Warn` or
    /// `Fail`; `Pass` without any.
    pub verdict: Verdict,
    pub completeness: DiffCompleteness,
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

    /// The evaluation of `changes` and `not_comparable` under this table. Pure, and independent
    /// of the lists' order.
    pub fn judge(&self, changes: &[Change], not_comparable: &[NotComparable]) -> Evaluation {
        let mut verdict = Verdict::Pass;
        for change in changes {
            if let Some((action, _)) = weigh(&self.changes, change) {
                verdict = verdict.max(verdict_of(action));
            }
        }
        let mut gaps = 0usize;
        for item in not_comparable {
            match self.not_comparable.get(&item.cause).map(|t| t.treatment) {
                Some(OqTreatment::CountAsGap) => gaps += 1,
                Some(OqTreatment::Warn) => verdict = verdict.max(Verdict::Warn),
                Some(OqTreatment::Fail) => verdict = Verdict::Fail,
                Some(OqTreatment::Ignore) | None => {}
            }
        }
        let completeness = if gaps == 0 {
            DiffCompleteness::Complete
        } else {
            DiffCompleteness::Incomplete {
                not_comparable: u32::try_from(gaps).unwrap_or(u32::MAX),
            }
        };
        Evaluation {
            policy: self.policy.clone(),
            changes: self.changes.clone(),
            not_comparable: self.not_comparable.clone(),
            verdict,
            completeness,
        }
    }
}

impl Evaluation {
    /// What `change` weighs under the recorded table, and whether its own decisions gave it.
    /// `None` when the table has no entry for its kind (a document's table may be short).
    pub fn weigh(&self, change: &Change) -> Option<(Action, bool)> {
        weigh(&self.changes, change)
    }

    /// How an item not comparable counts under the recorded table; `None` without an entry.
    pub fn treatment(&self, item: &NotComparable) -> Option<OqTreatment> {
        self.not_comparable.get(&item.cause).map(|t| t.treatment)
    }
}

/// `change`'s kind's action, or for `Decided` the maximum action of its decisions, and whether
/// it was decided.
fn weigh(table: &BTreeMap<ChangeKind, ChangeTreatment>, change: &Change) -> Option<(Action, bool)> {
    let treatment = table.get(&change.kind())?;
    Some(match treatment.action {
        CompareAction::Fail => (Action::Fail, false),
        CompareAction::Warn => (Action::Warn, false),
        CompareAction::Ignore => (Action::Ignore, false),
        CompareAction::Decided => (decided(change.decisions().unwrap_or(&[])), true),
    })
}

/// The maximum action of `decisions`. Without any, `Fail`: an item whose decisions are unknown is
/// never lighter than it could be.
fn decided(decisions: &[PolicyDecision]) -> Action {
    let rank = |a: Action| match a {
        Action::Ignore => 0,
        Action::Warn => 1,
        Action::Fail => 2,
    };
    decisions
        .iter()
        .map(|d| d.action)
        .max_by_key(|a| rank(*a))
        .unwrap_or(Action::Fail)
}

fn verdict_of(action: Action) -> Verdict {
    match action {
        Action::Fail => Verdict::Fail,
        Action::Warn => Verdict::Warn,
        Action::Ignore => Verdict::Pass,
    }
}
