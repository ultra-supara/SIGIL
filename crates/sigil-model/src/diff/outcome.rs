//! The outcome (verdict and completeness, each on its own) and the coverage of each check.

use std::collections::{BTreeMap, BTreeSet};

use super::compare::Found;
use super::scope::closed_everywhere;
use crate::diff::{Change, CheckState};
use crate::finding::Completeness;
use crate::id::CheckId;
use crate::render::aibom::state_name;
use crate::session::Session;

pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    if b.outcome.verdict != c.outcome.verdict {
        found.changes.push(Change::VerdictChanged {
            baseline: b.outcome.verdict,
            current: c.outcome.verdict,
        });
    }
    // Only the kind: gap IDs are content-derived, and which checks are open is the checks' own.
    if is_complete(&b.outcome.completeness) != is_complete(&c.outcome.completeness) {
        found.changes.push(Change::CompletenessChanged {
            baseline: b.outcome.completeness.clone(),
            current: c.outcome.completeness.clone(),
        });
    }
    for check in checks(b).union(&checks(c)) {
        let was = closed_everywhere(b, check.as_str());
        let is = closed_everywhere(c, check.as_str());
        let (baseline, current) = (state(b, check), state(c, check));
        let check = check.clone();
        match (was, is) {
            (true, false) => found.changes.push(Change::CheckOpened {
                check,
                baseline,
                current,
            }),
            (false, true) => found.changes.push(Change::CheckClosed {
                check,
                baseline,
                current,
            }),
            _ => {}
        }
    }
}

fn is_complete(c: &Completeness) -> bool {
    matches!(c, Completeness::Complete)
}

/// The checks a session requires or has coverage for.
fn checks(s: &Session) -> BTreeSet<CheckId> {
    s.request
        .required_checks
        .iter()
        .chain(s.coverage.iter().map(|c| &c.check))
        .cloned()
        .collect()
}

/// Whether `check` is required in `s`, and its entries by coverage state.
fn state(s: &Session, check: &CheckId) -> CheckState {
    let mut states = BTreeMap::new();
    for c in s.coverage.iter().filter(|c| c.check == *check) {
        *states
            .entry(state_name(&c.state).to_string())
            .or_insert(0u32) += 1;
    }
    CheckState {
        required: s.request.required_checks.contains(check),
        states,
    }
}
