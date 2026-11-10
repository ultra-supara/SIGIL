//! Findings and policy violations: new or resolved, by rule and normalized subject.

use std::collections::BTreeMap;

use super::compare::{checks, Found};
use super::key;
use super::scope::{arch_of, closed_everywhere, closed_for, placement, placements_of, scope_of};
use crate::binary::{ARTIFACTS_CODE, ARTIFACTS_IDENTITY};
use crate::binary_input::{BINARY_CODE, BINARY_IDENTITY};
use crate::diff::{Change, Item, Placement, Side, SubjectKey};
use crate::evidence::Ref;
use crate::finding::{Completeness, Finding, CAPABILITY_DENY_PREFIX};
use crate::id::{CheckId, FindingId, PolicyRuleRef, RuleId};
use crate::session::Session;

const MODEL_STORE: [&str; 3] = [
    "model_store.integrity",
    "model_store.inventory",
    "model_store.license",
];
const BINDS: &str = "exposure.binds";
const COMPONENT_DENY_PREFIX: &str = "policy:components.deny.";

/// What a subject is about, as keys that survive a new run. A slice found at several places
/// gives one key per placement.
fn subject_keys(s: &Session, subject: &Ref) -> Vec<SubjectKey> {
    let other = || vec![SubjectKey::Other(subject.clone())];
    match subject {
        Ref::Model(m) => vec![SubjectKey::Model(m.clone())],
        Ref::Root(r) => vec![SubjectKey::Root(r.clone())],
        Ref::Instance(id) => s
            .instances
            .iter()
            .find(|i| i.id == *id)
            .map_or_else(other, |i| vec![SubjectKey::Placement(placement(i))]),
        Ref::Listener(id) => s
            .listeners
            .iter()
            .find(|l| l.id == *id)
            .map_or_else(other, |l| vec![SubjectKey::Port(l.port)]),
        Ref::Component { slice, component } => match arch_of(s, slice) {
            Some(arch) => placements_of(s, &slice.artifact())
                .into_iter()
                .map(|placement| SubjectKey::Component {
                    placement,
                    arch,
                    component: component.clone(),
                })
                .collect(),
            None => other(),
        },
        Ref::Slice(slice) => match arch_of(s, slice) {
            Some(arch) => placements_of(s, &slice.artifact())
                .into_iter()
                .map(|placement| SubjectKey::Slice { placement, arch })
                .collect(),
            None => other(),
        },
        _ => other(),
    }
}

/// What tells apart findings of one rule on one subject (a layer, `#1`): the rest of the ID
/// after `finding:<rule>@<subject>`. An ID of another form is kept whole.
fn at(f: &Finding) -> String {
    let on = match &f.subject {
        Ref::Model(m) => m.as_str(),
        Ref::Instance(i) => i.as_str(),
        Ref::Root(r) => r.as_str(),
        Ref::Listener(l) => l.as_str(),
        _ => return f.id.as_str().to_string(),
    };
    let prefix = format!("finding:{}@{on}", f.rule);
    f.id.as_str()
        .strip_prefix(prefix.as_str())
        .unwrap_or(f.id.as_str())
        .to_string()
}

/// One judged item on one side: what it is, the scope its absence is judged over, and the
/// pointers to it in the session.
struct Judged<P> {
    item: Item,
    scope: Ref,
    pointers: Vec<P>,
}

fn findings(s: &Session) -> BTreeMap<String, Judged<FindingId>> {
    let mut out: BTreeMap<String, Judged<FindingId>> = BTreeMap::new();
    for f in &s.findings {
        let at = at(f);
        for subject in subject_keys(s, &f.subject) {
            let item = Item::Finding {
                rule: f.rule.clone(),
                subject,
                at: at.clone(),
            };
            out.entry(key(&item))
                .or_insert_with(|| Judged {
                    item,
                    scope: f.subject.clone(),
                    pointers: vec![],
                })
                .pointers
                .push(f.id.clone());
        }
    }
    out
}

fn violations(s: &Session) -> BTreeMap<String, Judged<Ref>> {
    let mut out: BTreeMap<String, Judged<Ref>> = BTreeMap::new();
    for v in &s.policy_violations {
        for subject in subject_keys(s, &v.subject) {
            let item = Item::Violation {
                policy_rule: v.policy_rule.clone(),
                subject,
            };
            out.entry(key(&item))
                .or_insert_with(|| Judged {
                    item,
                    scope: v.subject.clone(),
                    pointers: vec![],
                })
                .pointers
                .push(v.subject.clone());
        }
    }
    out
}

/// Any other rule: the absent side is `Complete`, or the checks it left open.
fn complete(s: &Session) -> (bool, Vec<CheckId>) {
    match &s.outcome.completeness {
        Completeness::Complete => (true, vec![]),
        Completeness::Incomplete {
            missing_required, ..
        } => (false, missing_required.clone()),
    }
}

/// Whether `absent` would have recorded a finding of `rule` about `scope`, and the checks
/// that say so. A model-store rule needs the model-store checks taken together closed for the
/// subject's scope (its root's inventory answers for a model that is gone); an exposure rule
/// needs `exposure.binds` closed everywhere.
fn finding_recorded(absent: &Session, rule: &RuleId, scope: &Ref) -> (bool, Vec<CheckId>) {
    if rule.as_str().starts_with("model.") {
        (
            closed_for(absent, &MODEL_STORE, scope),
            checks(&MODEL_STORE),
        )
    } else if rule.as_str().starts_with("exposure.") {
        (closed_everywhere(absent, BINDS), checks(&[BINDS]))
    } else {
        complete(absent)
    }
}

/// The placement a subject key names.
fn placement_of(subject: &SubjectKey) -> Option<&Placement> {
    match subject {
        SubjectKey::Placement(p)
        | SubjectKey::Component { placement: p, .. }
        | SubjectKey::Slice { placement: p, .. } => Some(p),
        _ => None,
    }
}

/// Whether `absent` would have recorded a violation of `rule` about `subject`: a component
/// denial needs the placement's identity check closed, a capability denial its code check.
fn violation_recorded(
    absent: &Session,
    rule: &PolicyRuleRef,
    subject: &SubjectKey,
) -> (bool, Vec<CheckId>) {
    let names: &[&str] = if rule.as_str().starts_with(COMPONENT_DENY_PREFIX) {
        &[ARTIFACTS_IDENTITY, BINARY_IDENTITY]
    } else if rule.as_str().starts_with(CAPABILITY_DENY_PREFIX) {
        &[ARTIFACTS_CODE, BINARY_CODE]
    } else {
        return complete(absent);
    };
    let closed = placement_of(subject)
        .and_then(|p| scope_of(absent, p))
        .is_some_and(|scope| closed_for(absent, names, &scope));
    (closed, checks(names))
}

pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    let (was, is) = (findings(b), findings(c));
    for (k, j) in &was {
        let Item::Finding { rule, subject, at } = &j.item else {
            continue;
        };
        if is.contains_key(k) {
            continue;
        }
        match finding_recorded(c, rule, &j.scope) {
            (true, _) => found.changes.push(Change::FindingResolved {
                rule: rule.clone(),
                subject: subject.clone(),
                at: at.clone(),
                baseline: j.pointers.clone(),
            }),
            (false, open) => found.unjudged(j.item.clone(), open, Side::Current),
        }
    }
    for (k, j) in &is {
        let Item::Finding { rule, subject, at } = &j.item else {
            continue;
        };
        if was.contains_key(k) {
            continue;
        }
        match finding_recorded(b, rule, &j.scope) {
            (true, _) => found.changes.push(Change::FindingNew {
                rule: rule.clone(),
                subject: subject.clone(),
                at: at.clone(),
                current: j.pointers.clone(),
            }),
            (false, open) => found.unjudged(j.item.clone(), open, Side::Baseline),
        }
    }
    let (was, is) = (violations(b), violations(c));
    for (k, j) in &was {
        let Item::Violation {
            policy_rule,
            subject,
        } = &j.item
        else {
            continue;
        };
        if is.contains_key(k) {
            continue;
        }
        match violation_recorded(c, policy_rule, subject) {
            (true, _) => found.changes.push(Change::ViolationResolved {
                policy_rule: policy_rule.clone(),
                subject: subject.clone(),
                baseline: j.pointers.clone(),
            }),
            (false, open) => found.unjudged(j.item.clone(), open, Side::Current),
        }
    }
    for (k, j) in &is {
        let Item::Violation {
            policy_rule,
            subject,
        } = &j.item
        else {
            continue;
        };
        if was.contains_key(k) {
            continue;
        }
        match violation_recorded(b, policy_rule, subject) {
            (true, _) => found.changes.push(Change::ViolationNew {
                policy_rule: policy_rule.clone(),
                subject: subject.clone(),
                current: j.pointers.clone(),
            }),
            (false, open) => found.unjudged(j.item.clone(), open, Side::Baseline),
        }
    }
}
