//! Analyses: findings and coverage derived from collected facts. They are pure functions: the
//! same facts always give the same results.

pub mod exposure;
pub mod model_store;
pub mod release;
pub mod runtime_api;

use sigil_model::{
    Action, CondEvidence, CondId, CondState, Condition, EvidenceRef, Finding, FindingId,
    PolicyDecision, PolicyRuleRef, Ref, RuleId, Severity,
};

use crate::policy::catalog;

/// A finding of catalog rule `rule` about `subject`, with one `Observed` condition resting on
/// `facts`. Its ID is `finding:<rule>@<subject><at>`; `at` tells apart findings of one rule on one
/// subject (e.g. `#<layer>`). The decision is the rule's default, until policy evaluation.
///
/// Rules come from the catalog and names are fixed, so these always validate. A failure is a
/// catalog bug, and drops the finding rather than panicking.
pub(crate) fn observed_finding(
    rule: &str,
    subject: Ref,
    at: &str,
    condition: &str,
    facts: Vec<EvidenceRef>,
    evidence: Vec<EvidenceRef>,
) -> Option<Finding> {
    let info = catalog::rule(rule)?;
    let on = match &subject {
        Ref::Model(m) => m.as_str().to_string(),
        Ref::Instance(i) => i.as_str().to_string(),
        Ref::Root(r) => r.as_str().to_string(),
        Ref::Listener(l) => l.as_str().to_string(),
        _ => return None,
    };
    let (Ok(id), Ok(rule_id), Ok(cond_id), Ok(source)) = (
        FindingId::new(format!("finding:{rule}@{on}{at}")),
        RuleId::new(rule),
        CondId::new(condition),
        PolicyRuleRef::new(format!("default:{rule}")),
    ) else {
        return None;
    };
    Some(Finding {
        id,
        rule: rule_id,
        kind: info.kind,
        subject,
        summary: info.summary.to_string(),
        conditions: vec![Condition {
            id: cond_id,
            state: CondState::Met {
                evidence: CondEvidence::Observed { facts },
            },
            unresolved: vec![],
        }],
        evidence,
        limits: vec![],
        default_severity: info.default,
        // Replaced by policy evaluation.
        decision: PolicyDecision {
            action: match info.default {
                Severity::Warn => Action::Warn,
                Severity::Fail => Action::Fail,
            },
            source,
            reason: None,
            expires: None,
        },
    })
}
