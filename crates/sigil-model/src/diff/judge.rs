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
use crate::finding::{
    Action, Completeness, OpenQuestionDecision, OqTreatment, PolicyDecision, Verdict,
};
use crate::id::PolicyRuleRef;
use crate::session::KnowledgeRef;

/// What the changes of one kind weigh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareAction {
    Fail,
    Warn,
    Ignore,
    /// What the change's own decisions (the current session's) say: the maximum of their
    /// actions. A changed decision weighs that only when it is heavier than the baseline's, and
    /// at least `Warn`; otherwise `Warn`. A changed verdict, which the decisions gave, weighs the
    /// current verdict when it is worse than the baseline's; otherwise nothing. An open
    /// question's decision weighs its treatment: `Fail` and `Warn` as those actions, `CountAsGap`
    /// and `Ignore` as nothing (a gap counts toward completeness); new and changed questions
    /// follow new findings and changed decisions. Only for the kinds that carry decisions or a
    /// verdict ([`ChangeKind::takes_decided`]).
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
/// misses a kind or a cause, gives `Decided` to a kind that cannot be decided, or holds a source
/// or a reason that SIGIL would not write, does not load. The JSON form is flat: `policy`,
/// `changes` and `not_comparable` (the table), then `verdict` and `completeness`.
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
/// every kind and every cause has an entry, as SIGIL writes it. `Decided` is given only where it
/// applies; each entry is the default (its source `default:compare.<Kind>` or
/// `default:compare.not_comparable.<Cause>`, the default action or treatment, no reason) or the
/// policy's (`policy:compare.changes.<Kind>` or `policy:compare.not_comparable.<Cause>`), whose
/// reason is never blank, and given for `Ignore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRules {
    policy: KnowledgeRef,
    changes: BTreeMap<ChangeKind, ChangeTreatment>,
    not_comparable: BTreeMap<Cause, NotComparableTreatment>,
}

/// Why a table is not a complete compare table as SIGIL writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesError {
    MissingKind(ChangeKind),
    MissingCause(Cause),
    /// `Decided` for a kind whose changes carry no decisions and no verdict.
    Decided(ChangeKind),
    /// A policy's `Ignore` for a kind without a reason, or with a blank one.
    IgnoredWithoutReason(ChangeKind),
    /// A policy's `Ignore` for a cause without a reason, or with a blank one.
    CauseIgnoredWithoutReason(Cause),
    /// A kind's source is neither its default's nor the policy's entry for it.
    Source(ChangeKind),
    /// A cause's source is neither its default's nor the policy's entry for it.
    CauseSource(Cause),
    /// A kind's entry has the default's source, but another action, or a reason.
    NotDefault(ChangeKind),
    /// A cause's entry has the default's source, but another treatment, or a reason.
    CauseNotDefault(Cause),
    /// A policy's entry for a kind with a reason that is blank: the loader drops one.
    BlankReason(ChangeKind),
    /// A policy's entry for a cause with a reason that is blank: the loader drops one.
    CauseBlankReason(Cause),
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::MissingKind(k) => write!(f, "no action for {}", k.name()),
            RulesError::MissingCause(c) => write!(f, "no treatment for {}", c.name()),
            RulesError::Decided(k) => write!(
                f,
                "{} carries no decisions and no verdict, so it cannot be decided",
                k.name()
            ),
            RulesError::IgnoredWithoutReason(k) => {
                write!(f, "{} is ignored without a reason", k.name())
            }
            RulesError::CauseIgnoredWithoutReason(c) => {
                write!(f, "{} is ignored without a reason", c.name())
            }
            RulesError::Source(k) => write!(
                f,
                "the source of {k} is neither {DEFAULT_KIND}{k} nor {POLICY_KIND}{k}",
                k = k.name()
            ),
            RulesError::CauseSource(c) => write!(
                f,
                "the source of {c} is neither {DEFAULT_CAUSE}{c} nor {POLICY_CAUSE}{c}",
                c = c.name()
            ),
            RulesError::NotDefault(k) => write!(
                f,
                "{} has the default's source but is not the default as SIGIL writes it ({:?}, \
                 without a reason)",
                k.name(),
                k.default_action()
            ),
            RulesError::CauseNotDefault(c) => write!(
                f,
                "{} has the default's source but is not the default as SIGIL writes it ({:?}, \
                 without a reason)",
                c.name(),
                c.default_treatment()
            ),
            RulesError::BlankReason(k) => write!(f, "{} has a blank reason", k.name()),
            RulesError::CauseBlankReason(c) => write!(f, "{} has a blank reason", c.name()),
        }
    }
}

impl std::error::Error for RulesError {}

impl ChangeKind {
    /// The action of the kind when the policy does not name it. Drift that a single session's
    /// verdict cannot see fails; a change that weakens the baseline warns; improvements, and
    /// changes that follow from others, are ignored; a new finding or violation, and a changed
    /// decision, weigh what the current session decides (a changed decision only when that got
    /// heavier, and at least `Warn`), so an override that expires fails as a new `fail` finding
    /// does; a verdict that got worse weighs what it now is, and a new or changed open question
    /// weighs its treatment (#138).
    pub fn default_action(self) -> CompareAction {
        use ChangeKind as K;
        match self {
            K::LayerChanged | K::FileContentChanged | K::BindWidened => CompareAction::Fail,
            K::VerdictChanged
            | K::FindingNew
            | K::FindingDecisionChanged
            | K::ViolationNew
            | K::ViolationDecisionChanged
            | K::OpenQuestionNew
            | K::OpenQuestionTreatmentChanged => CompareAction::Decided,
            K::PolicyChanged
            | K::CheckOpened
            | K::ModelAdded
            | K::ModelRemoved
            | K::LicenseChanged
            | K::FileAdded
            | K::FileRemoved
            | K::ReleaseChanged
            | K::ComponentChanged
            | K::ListenerAdded => CompareAction::Warn,
            K::CompletenessChanged
            | K::CheckClosed
            | K::FindingResolved
            | K::ViolationResolved
            | K::OpenQuestionResolved
            | K::ListenerRemoved
            | K::BindNarrowed => CompareAction::Ignore,
        }
    }

    /// Whether `Decided` applies to the kind: its changes carry the current session's decisions
    /// ([`Change::decisions`]: a new finding, violation or open question, a changed decision or
    /// treatment), or the verdict they gave (`VerdictChanged`).
    pub fn takes_decided(self) -> bool {
        matches!(
            self,
            ChangeKind::VerdictChanged
                | ChangeKind::FindingNew
                | ChangeKind::FindingDecisionChanged
                | ChangeKind::ViolationNew
                | ChangeKind::ViolationDecisionChanged
                | ChangeKind::OpenQuestionNew
                | ChangeKind::OpenQuestionTreatmentChanged
        )
    }
}

impl Cause {
    /// The treatment of the cause when the policy does not name it: a gap.
    pub fn default_treatment(self) -> OqTreatment {
        OqTreatment::CountAsGap
    }
}

/// The source of a kind's default action, before the kind's name.
const DEFAULT_KIND: &str = "default:compare.";
/// The source of a policy's action for a kind, before the kind's name.
const POLICY_KIND: &str = "policy:compare.changes.";
/// The source of a cause's default treatment, before the cause's name.
const DEFAULT_CAUSE: &str = "default:compare.not_comparable.";
/// The source of a policy's treatment of a cause, before the cause's name.
const POLICY_CAUSE: &str = "policy:compare.not_comparable.";

impl CompareRules {
    /// A table, if it is complete and as SIGIL writes it: every kind and every cause; `Decided`
    /// only where it applies; each entry the default (its source, the default action or
    /// treatment, no reason) or the policy's (its source, and a reason that is never blank, and
    /// given for `Ignore`). It says nothing of which policy file made the table: only loading
    /// that file again does.
    pub fn new(
        policy: KnowledgeRef,
        changes: BTreeMap<ChangeKind, ChangeTreatment>,
        not_comparable: BTreeMap<Cause, NotComparableTreatment>,
    ) -> Result<CompareRules, RulesError> {
        for kind in ChangeKind::ALL {
            let Some(t) = changes.get(&kind) else {
                return Err(RulesError::MissingKind(kind));
            };
            if t.action == CompareAction::Decided && !kind.takes_decided() {
                return Err(RulesError::Decided(kind));
            }
            let source = t.source.as_str();
            if named(source, DEFAULT_KIND, kind.name()) {
                if t.action != kind.default_action() || t.reason.is_some() {
                    return Err(RulesError::NotDefault(kind));
                }
            } else if !named(source, POLICY_KIND, kind.name()) {
                return Err(RulesError::Source(kind));
            } else if t.action == CompareAction::Ignore && !given(t.reason.as_deref()) {
                return Err(RulesError::IgnoredWithoutReason(kind));
            } else if blank(t.reason.as_deref()) {
                return Err(RulesError::BlankReason(kind));
            }
        }
        for cause in Cause::ALL {
            let Some(t) = not_comparable.get(&cause) else {
                return Err(RulesError::MissingCause(cause));
            };
            let source = t.source.as_str();
            if named(source, DEFAULT_CAUSE, cause.name()) {
                if t.treatment != cause.default_treatment() || t.reason.is_some() {
                    return Err(RulesError::CauseNotDefault(cause));
                }
            } else if !named(source, POLICY_CAUSE, cause.name()) {
                return Err(RulesError::CauseSource(cause));
            } else if t.treatment == OqTreatment::Ignore && !given(t.reason.as_deref()) {
                return Err(RulesError::CauseIgnoredWithoutReason(cause));
            } else if blank(t.reason.as_deref()) {
                return Err(RulesError::CauseBlankReason(cause));
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
                    source: PolicyRuleRef::from_static(DEFAULT_KIND, kind.name()),
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
                    source: PolicyRuleRef::from_static(DEFAULT_CAUSE, cause.name()),
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
    /// decisions, the current session's (`Fail` without any: an item whose decisions are unknown
    /// is never lighter than it could be); and whether its decisions gave it. A changed decision
    /// weighs that action, at least `Warn`, only when it is heavier than the baseline's (by the
    /// same rule); otherwise `Warn`: another reason, source or expiry, or a weakening, warns. A
    /// changed verdict weighs the current verdict when it is worse than the baseline's (`Fail`
    /// or `Warn`), and nothing when it is the same or better. An open question weighs its
    /// treatment ([`CompareAction::Decided`]).
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
            CompareAction::Decided => (decided_weight(change), true),
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

/// Whether `reason` is given and not blank (as a session's `Ignore` needs one).
fn given(reason: Option<&str>) -> bool {
    reason.is_some_and(|r| !r.trim().is_empty())
}

/// Whether `reason` is given but blank: the loader never writes one.
fn blank(reason: Option<&str>) -> bool {
    reason.is_some_and(|r| r.trim().is_empty())
}

/// Whether `source` is `prefix` followed by `name`.
fn named(source: &str, prefix: &str, name: &str) -> bool {
    source.strip_prefix(prefix) == Some(name)
}

fn is_incomplete(c: &Completeness) -> bool {
    matches!(c, Completeness::Incomplete { .. })
}

/// What `change` weighs under `Decided` ([`CompareRules::weigh`]).
fn decided_weight(change: &Change) -> Action {
    if let Change::VerdictChanged { baseline, current } = change {
        return if current > baseline {
            action_of(*current)
        } else {
            Action::Ignore
        };
    }
    let (now, before) = match change {
        Change::OpenQuestionNew { decisions, .. } => (treated(decisions), None),
        Change::OpenQuestionTreatmentChanged {
            baseline, current, ..
        } => (treated(current), Some(treated(baseline))),
        _ => (
            decided(change.decisions().unwrap_or(&[])),
            baseline_decisions(change).map(decided),
        ),
    };
    match before {
        None => now,
        Some(before) if verdict_of(now) > verdict_of(before) => heavier(now, Action::Warn),
        Some(_) => Action::Warn,
    }
}

/// The baseline's decisions of a changed decision (`FindingDecisionChanged`,
/// `ViolationDecisionChanged`); `None` for every other kind.
fn baseline_decisions(change: &Change) -> Option<&[PolicyDecision]> {
    match change {
        Change::FindingDecisionChanged { baseline, .. }
        | Change::ViolationDecisionChanged { baseline, .. } => Some(baseline),
        _ => None,
    }
}

/// The maximum action of `decisions`, ordered as the verdicts they give (`Ignore < Warn <
/// Fail`). Without any, `Fail`.
fn decided(decisions: &[PolicyDecision]) -> Action {
    strongest(decisions.iter().map(|d| d.action))
}

/// The maximum weight of an open question's decisions (#138): `fail` and `warn` weigh as those
/// actions; `count_as_gap` and `ignore` weigh nothing, since a gap counts toward completeness,
/// not the verdict. Without any, `Fail`.
fn treated(decisions: &[OpenQuestionDecision]) -> Action {
    strongest(decisions.iter().map(|d| match d.treatment {
        OqTreatment::Fail => Action::Fail,
        OqTreatment::Warn => Action::Warn,
        OqTreatment::CountAsGap | OqTreatment::Ignore => Action::Ignore,
    }))
}

/// The heaviest of `actions` (`Ignore < Warn < Fail`); `Fail` without any: an item whose
/// decisions are unknown is never lighter than it could be.
fn strongest(actions: impl Iterator<Item = Action>) -> Action {
    actions
        .max_by_key(|a| verdict_of(*a))
        .unwrap_or(Action::Fail)
}

/// The heavier of two actions (`Ignore < Warn < Fail`).
fn heavier(a: Action, b: Action) -> Action {
    if verdict_of(a) >= verdict_of(b) {
        a
    } else {
        b
    }
}

/// The action a verdict weighs (`Pass` weighs nothing).
fn action_of(verdict: Verdict) -> Action {
    match verdict {
        Verdict::Fail => Action::Fail,
        Verdict::Warn => Action::Warn,
        Verdict::Pass => Action::Ignore,
    }
}

fn verdict_of(action: Action) -> Verdict {
    match action {
        Action::Fail => Verdict::Fail,
        Action::Warn => Verdict::Warn,
        Action::Ignore => Verdict::Pass,
    }
}
