//! [`compare`]: the differences between two validated sessions.

use crate::diff::{
    Cause, Change, CompareRules, Diff, DiffSchema, DiffSide, Item, NotComparable, Side,
};
use crate::finding::Completeness;
use crate::id::{CheckId, Sha256Hex};
use crate::session::{KnowledgeKind, KnowledgeRef, Session, ToolInfo};
use crate::validate::ValidatedSession;

/// What a comparison has found so far.
#[derive(Default)]
pub(super) struct Found {
    pub(super) changes: Vec<Change>,
    pub(super) not_comparable: Vec<NotComparable>,
}

/// The differences between `baseline` and `current`, whose canonical JSON have the SHA-256s
/// given (computed by the caller, as for the AI-BOM), judged under `rules` with both sessions'
/// recorded completeness (#16, PR-16b). Pure and deterministic: both sessions are compared in
/// canonical order, whatever order their lists are in.
pub fn compare(
    baseline: &ValidatedSession,
    baseline_sha256: Sha256Hex,
    current: &ValidatedSession,
    current_sha256: Sha256Hex,
    tool: ToolInfo,
    rules: &CompareRules,
) -> Diff {
    let b = canonical(baseline.as_session());
    let c = canonical(current.as_session());
    let mut found = Found::default();
    super::outcome::compare(&b, &c, &mut found);
    super::judged::compare(&b, &c, &mut found);
    super::models::compare(&b, &c, &mut found);
    super::files::compare(&b, &c, &mut found);
    super::listeners::compare(&b, &c, &mut found);
    let mut diff = Diff {
        schema: DiffSchema::V1,
        tool,
        baseline: side(&b, baseline_sha256),
        current: side(&c, current_sha256),
        changes: found.changes,
        not_comparable: found.not_comparable,
        evaluation: rules.judge(&Completeness::Complete, &Completeness::Complete, &[], &[]),
    };
    diff.canonicalize();
    // Judged on the canonical lists, where each change and each item occurs once.
    diff.evaluation = rules.judge(
        &diff.baseline.completeness,
        &diff.current.completeness,
        &diff.changes,
        &diff.not_comparable,
    );
    diff
}

fn canonical(s: &Session) -> Session {
    let mut s = s.clone();
    s.canonicalize();
    s
}

fn side(s: &Session, sha256: Sha256Hex) -> DiffSide {
    DiffSide {
        sha256,
        tool: s.tool.clone(),
        mode: s.request.mode,
        started_at: s.observation.started_at.clone(),
        policy: policy_of(s).cloned(),
        completeness: s.outcome.completeness.clone(),
    }
}

/// The policy a session applied: its first knowledge entry of kind `Policy`.
pub(super) fn policy_of(s: &Session) -> Option<&KnowledgeRef> {
    s.knowledge.iter().find(|k| k.kind == KnowledgeKind::Policy)
}

impl Found {
    /// A difference that cannot be judged: `checks` are not closed on `open_in`.
    pub(super) fn unjudged(&mut self, item: Item, checks: Vec<CheckId>, open_in: Side) {
        self.record(item, Cause::Coverage, checks, open_in);
    }

    /// A difference that cannot be judged because the two runs asked for different things:
    /// `open_in` did not ask for the item, which `checks` would have recorded.
    pub(super) fn not_asked(&mut self, item: Item, checks: Vec<CheckId>, open_in: Side) {
        self.record(item, Cause::Request, checks, open_in);
    }

    /// A difference that cannot be judged because the two sessions applied different policies.
    pub(super) fn under_other_policies(&mut self, item: Item) {
        self.record(item, Cause::Policy, vec![], Side::Both);
    }

    fn record(&mut self, item: Item, cause: Cause, checks: Vec<CheckId>, open_in: Side) {
        self.not_comparable.push(NotComparable {
            item,
            cause,
            checks,
            open_in,
        });
    }
}

/// Check IDs of names that are valid by construction.
pub(super) fn checks(names: &[&str]) -> Vec<CheckId> {
    names.iter().filter_map(|n| CheckId::new(*n).ok()).collect()
}

/// The side(s) where a check is open.
pub(super) fn open_in(baseline_open: bool, current_open: bool) -> Side {
    match (baseline_open, current_open) {
        (true, true) => Side::Both,
        (true, false) => Side::Baseline,
        (false, _) => Side::Current,
    }
}
