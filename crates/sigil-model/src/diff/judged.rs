//! Findings and policy violations: new, resolved, or decided otherwise, by rule and normalized
//! subject.

use std::collections::BTreeMap;

use super::compare::{checks, policy_of, Found};
use super::scope::{
    arch_of, checks_at, closed_everywhere, closed_for_under, placement, placements_of, root_at,
    root_of, same_model_filter, scope_of, CODE, IDENTITY, INVENTORY,
};
use super::{key, sort_decisions};
use crate::diff::{Change, Item, Placement, Side, SubjectKey};
use crate::evidence::Ref;
use crate::finding::{Completeness, Finding, PolicyDecision, CAPABILITY_DENY_PREFIX};
use crate::id::{CheckId, FindingId, PolicyRuleRef, RootId, RuleId};
use crate::session::Session;

const INTEGRITY: &str = "model_store.integrity";
const LICENSE: &str = "model_store.license";
const MODEL_STORE: [&str; 3] = [INTEGRITY, INVENTORY, LICENSE];
const BINDS: &str = "exposure.binds";
const COMPONENT_DENY_PREFIX: &str = "policy:components.deny.";

/// The checks that would record a finding of the model-store rule `rule`, each on its own. A
/// rule without a check of its own needs all three.
fn model_checks(rule: &str) -> &'static [&'static str] {
    match rule {
        "model.blob_missing" | "model.blob_digest_mismatch" => &[INTEGRITY],
        "model.license_missing" => &[LICENSE],
        "model.manifest_digest_malformed"
        | "model.manifest_unparseable"
        | "model.provenance_unknown"
        | "model.not_found" => &[INVENTORY],
        _ => &MODEL_STORE,
    }
}

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

/// One judged item on one side: what it is, the scope its absence is judged over and the root
/// this side recorded for that scope (the other side may not hold it), the pointers to it in the
/// session, and its distinct decisions in canonical order.
struct Judged<P> {
    item: Item,
    scope: Ref,
    root: Option<RootId>,
    pointers: Vec<P>,
    decisions: Vec<PolicyDecision>,
}

/// One finding or violation of an item, as [`add`] adds it.
struct Entry<'s, P> {
    scope: &'s Ref,
    root: Option<RootId>,
    pointer: P,
    decision: &'s PolicyDecision,
}

/// Adds one finding or violation to the item `item` of `out`.
fn add<P>(out: &mut BTreeMap<String, Judged<P>>, item: Item, entry: Entry<'_, P>) {
    let judged = out.entry(key(&item)).or_insert_with(|| Judged {
        item,
        scope: entry.scope.clone(),
        root: entry.root,
        pointers: vec![],
        decisions: vec![],
    });
    judged.pointers.push(entry.pointer);
    judged.decisions.push(entry.decision.clone());
    sort_decisions(&mut judged.decisions);
}

fn findings(s: &Session) -> BTreeMap<String, Judged<FindingId>> {
    let mut out = BTreeMap::new();
    for f in &s.findings {
        let at = at(f);
        for subject in subject_keys(s, &f.subject) {
            let item = Item::Finding {
                rule: f.rule.clone(),
                subject,
                at: at.clone(),
            };
            let entry = Entry {
                scope: &f.subject,
                root: root_of(s, &f.subject, None),
                pointer: f.id.clone(),
                decision: &f.decision,
            };
            add(&mut out, item, entry);
        }
    }
    out
}

fn violations(s: &Session) -> BTreeMap<String, Judged<Ref>> {
    let mut out = BTreeMap::new();
    for v in &s.policy_violations {
        for subject in subject_keys(s, &v.subject) {
            let root = placement_of(&subject).and_then(|p| root_at(s, p));
            let item = Item::Violation {
                policy_rule: v.policy_rule.clone(),
                subject,
            };
            let entry = Entry {
                scope: &v.subject,
                root,
                pointer: v.subject.clone(),
                decision: &v.decision,
            };
            add(&mut out, item, entry);
        }
    }
    out
}

/// Whether the side an item is absent from would have recorded it.
enum Absence {
    /// It would have: the item is gone from it (or new on the other).
    Recorded,
    /// These checks are not closed on it.
    Open(Vec<CheckId>),
    /// It did not ask for the item, which these checks would have recorded.
    NotAsked(Vec<CheckId>),
    /// The two sessions applied different policies.
    OtherPolicy,
}

impl Absence {
    fn closed(closed: bool, checks: Vec<CheckId>) -> Absence {
        if closed {
            Absence::Recorded
        } else {
            Absence::Open(checks)
        }
    }
}

/// Any other rule: the absent side is `Complete`, or the checks it left open.
fn complete(s: &Session) -> Absence {
    match &s.outcome.completeness {
        Completeness::Complete => Absence::Recorded,
        Completeness::Incomplete {
            missing_required, ..
        } => Absence::Open(missing_required.clone()),
    }
}

/// Whether `absent` would have recorded the finding `j` of `rule`, which `present` holds.
///
/// A model-store rule needs each of its checks ([`model_checks`]) closed on its own for the
/// subject's scope, under the root `present` recorded for it. Under another model filter than the
/// present side's (`same_filter` false), it first needs the subject's model on the absent side:
/// the filter may have left it out. Under the same filter, a model that is gone from the absent
/// side has none of its findings, so that side's inventory closed for it is enough. An exposure
/// rule needs `exposure.binds` closed everywhere; any other rule a `Complete` absent side.
fn finding_recorded(
    present: &Session,
    absent: &Session,
    same_filter: bool,
    rule: &RuleId,
    j: &Judged<FindingId>,
) -> Absence {
    let (scope, root) = (&j.scope, j.root.as_ref());
    if rule.as_str().starts_with("model.") {
        let held = holds_model(absent, scope);
        if !same_filter && !held {
            return Absence::NotAsked(checks(&[INVENTORY]));
        }
        if !held && holds_model(present, scope) {
            let closed = closed_for_under(absent, &[INVENTORY], scope, root);
            return Absence::closed(closed, checks(&[INVENTORY]));
        }
        let required = model_checks(rule.as_str());
        let closed = required
            .iter()
            .all(|check| closed_for_under(absent, &[*check], scope, root));
        Absence::closed(closed, checks(required))
    } else if rule.as_str().starts_with("exposure.") {
        Absence::closed(closed_everywhere(absent, BINDS), checks(&[BINDS]))
    } else {
        complete(absent)
    }
}

/// Whether `s` holds the model a finding's subject is about: that model, or the model of that
/// manifest. Any other subject names no model.
fn holds_model(s: &Session, subject: &Ref) -> bool {
    match subject {
        Ref::Model(id) => s.models.iter().any(|m| m.id == *id),
        Ref::Instance(manifest) => s.models.iter().any(|m| m.manifest == *manifest),
        _ => false,
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

/// Whether `absent` would have recorded a violation of `rule` about `subject`. Only under the
/// policy the present side applied (`same_policy`): another may not have the rule at all. Then a
/// component denial needs the placement's identity check closed, a capability denial its code
/// check, under the root the present side recorded there (`root`: the file may be gone from the
/// absent side). A subject with no placement cannot be judged; both checks are named.
fn violation_recorded(
    absent: &Session,
    same_policy: bool,
    rule: &PolicyRuleRef,
    subject: &SubjectKey,
    root: Option<&RootId>,
) -> Absence {
    if !same_policy {
        return Absence::OtherPolicy;
    }
    let pair = if rule.as_str().starts_with(COMPONENT_DENY_PREFIX) {
        &IDENTITY
    } else if rule.as_str().starts_with(CAPABILITY_DENY_PREFIX) {
        &CODE
    } else {
        return complete(absent);
    };
    let Some(p) = placement_of(subject) else {
        return Absence::Open(checks(pair));
    };
    let names = checks_at(p, pair);
    let closed =
        scope_of(absent, p).is_some_and(|scope| closed_for_under(absent, names, &scope, root));
    Absence::closed(closed, checks(names))
}

/// An item on one side only: `change` when the other side would have recorded it, otherwise not
/// comparable for the reason `absence` gives, on `side`.
fn judge(found: &mut Found, absence: Absence, item: &Item, side: Side, change: Change) {
    match absence {
        Absence::Recorded => found.changes.push(change),
        Absence::Open(checks) => found.unjudged(item.clone(), checks, side),
        Absence::NotAsked(checks) => found.not_asked(item.clone(), checks, side),
        Absence::OtherPolicy => found.under_other_policies(item.clone()),
    }
}

pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    let same_filter = same_model_filter(b, c);
    let (was, is) = (findings(b), findings(c));
    for (k, j) in &was {
        let Item::Finding { rule, subject, at } = &j.item else {
            continue;
        };
        match is.get(k) {
            Some(now) if j.decisions != now.decisions => {
                found.changes.push(Change::FindingDecisionChanged {
                    rule: rule.clone(),
                    subject: subject.clone(),
                    at: at.clone(),
                    baseline: j.decisions.clone(),
                    current: now.decisions.clone(),
                });
            }
            Some(_) => {}
            None => {
                let resolved = Change::FindingResolved {
                    rule: rule.clone(),
                    subject: subject.clone(),
                    at: at.clone(),
                    baseline: j.pointers.clone(),
                };
                let absence = finding_recorded(b, c, same_filter, rule, j);
                judge(found, absence, &j.item, Side::Current, resolved);
            }
        }
    }
    for (k, j) in &is {
        let Item::Finding { rule, subject, at } = &j.item else {
            continue;
        };
        if was.contains_key(k) {
            continue;
        }
        let new = Change::FindingNew {
            rule: rule.clone(),
            subject: subject.clone(),
            at: at.clone(),
            current: j.pointers.clone(),
        };
        let absence = finding_recorded(c, b, same_filter, rule, j);
        judge(found, absence, &j.item, Side::Baseline, new);
    }
    let same_policy = policy_of(b) == policy_of(c);
    let (was, is) = (violations(b), violations(c));
    for (k, j) in &was {
        let Item::Violation {
            policy_rule,
            subject,
        } = &j.item
        else {
            continue;
        };
        match is.get(k) {
            Some(now) if j.decisions != now.decisions => {
                found.changes.push(Change::ViolationDecisionChanged {
                    policy_rule: policy_rule.clone(),
                    subject: subject.clone(),
                    baseline: j.decisions.clone(),
                    current: now.decisions.clone(),
                });
            }
            Some(_) => {}
            None => {
                let resolved = Change::ViolationResolved {
                    policy_rule: policy_rule.clone(),
                    subject: subject.clone(),
                    baseline: j.pointers.clone(),
                };
                let root = j.root.as_ref();
                let absence = violation_recorded(c, same_policy, policy_rule, subject, root);
                judge(found, absence, &j.item, Side::Current, resolved);
            }
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
        let new = Change::ViolationNew {
            policy_rule: policy_rule.clone(),
            subject: subject.clone(),
            current: j.pointers.clone(),
        };
        let root = j.root.as_ref();
        let absence = violation_recorded(b, same_policy, policy_rule, subject, root);
        judge(found, absence, &j.item, Side::Baseline, new);
    }
}
