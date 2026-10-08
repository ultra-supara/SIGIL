//! Applying a policy to a session (plan §4.7).
//!
//! Evaluation changes only what the policy owns: assumption acceptance, the decision of each
//! finding and open question, the policy violations, and the outcome. Findings, open questions,
//! their conditions and evidence, and `default_severity` are never touched; an ignored finding
//! stays with its reason.

use sigil_model::{
    Action, AssumptionAcceptance, CheckId, Completeness, CoverageState, Date, EvidenceRef,
    IdentityStatus, OpenQuestionDecision, OqTreatment, Outcome, PolicyDecision, PolicyRuleRef,
    PolicyViolation, Ref, RuleId, Session, Severity, Timestamp, Verdict,
};

use super::Policy;

/// Something the operator should know about how the policy applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyWarning {
    /// A rule override expired; the rule's default applied instead.
    OverrideExpired { rule: RuleId, expires: Date },
}

/// Sets assumption acceptance, decisions, policy violations, and the outcome on `session`, with
/// rule expiry judged at `policy_time` (recorded in the outcome so that a re-evaluation reuses it).
pub fn evaluate(
    session: &mut Session,
    policy: &Policy,
    policy_time: Timestamp,
) -> Vec<PolicyWarning> {
    let sources = &policy.sources;
    for assumption in &mut session.assumptions {
        assumption.acceptance = if policy.accept.contains(&assumption.id) {
            AssumptionAcceptance::Accepted {
                source: sources.assumptions.clone(),
            }
        } else {
            AssumptionAcceptance::NotAccepted
        };
    }

    let mut warnings = vec![];
    for finding in &mut session.findings {
        let default = |reason: Option<String>| PolicyDecision {
            action: match finding.default_severity {
                Severity::Warn => Action::Warn,
                Severity::Fail => Action::Fail,
            },
            source: PolicyRuleRef::new(format!("default:{}", finding.rule))
                .unwrap_or_else(|_| sources.default.clone()),
            reason,
            expires: None,
        };
        let applied = policy
            .rules
            .get(&finding.rule)
            .zip(sources.rules.get(&finding.rule));
        finding.decision = match applied {
            None => default(None),
            Some((rule, source)) => match &rule.expires {
                Some(expires) if expired(expires, &policy_time) => {
                    let warning = PolicyWarning::OverrideExpired {
                        rule: finding.rule.clone(),
                        expires: expires.clone(),
                    };
                    if !warnings.contains(&warning) {
                        warnings.push(warning);
                    }
                    default(Some(format!("override expired {expires}")))
                }
                _ => PolicyDecision {
                    action: rule.action,
                    source: source.clone(),
                    reason: rule.reason.clone(),
                    expires: rule.expires.clone(),
                },
            },
        };
    }

    for question in &mut session.open_questions {
        question.decision = OpenQuestionDecision {
            treatment: policy.open_questions.treatment,
            source: sources.open_questions.clone(),
            reason: policy.open_questions.reason.clone(),
        };
    }

    session.policy_violations = policy
        .deny
        .iter()
        .flat_map(|deny| {
            session
                .components
                .iter()
                .filter(move |claim| {
                    claim.component == deny.component
                        && claim.status != IdentityStatus::Unidentified
                })
                .map(move |claim| PolicyViolation {
                    policy_rule: deny.source.clone(),
                    subject: Ref::Component {
                        slice: claim.subject.clone(),
                        component: claim.component.clone(),
                    },
                    evidence: vec![EvidenceRef::Artifact {
                        artifact: claim.subject.artifact(),
                    }],
                    decision: PolicyDecision {
                        action: deny.action,
                        source: deny.source.clone(),
                        reason: Some(deny.reason.clone()),
                        expires: None,
                    },
                })
        })
        .collect();

    session.outcome = outcome(session, policy_time);
    warnings
}

/// Whether an override valid through `expires` (a UTC day) has expired at `time`.
fn expired(expires: &Date, time: &Timestamp) -> bool {
    time.as_str()
        .get(..10)
        .is_some_and(|day| day > expires.as_str())
}

/// The outcome of the decisions and coverage recorded in `session` (plan §4.7):
/// - `verdict`: the maximum action of the findings, policy violations, and open questions treated
///   as `Warn`/`Fail`; `Ignore` and `CountAsGap` do not count. Gaps never change it.
/// - `completeness`: the required checks that are not closed (no coverage, or coverage that does
///   not close them) and the open questions treated as gaps. Findings never change it.
pub fn outcome(session: &Session, policy_time: Timestamp) -> Outcome {
    let from_action = |action: Action| match action {
        Action::Fail => Some(Verdict::Fail),
        Action::Warn => Some(Verdict::Warn),
        Action::Ignore => None,
    };
    let verdict = session
        .findings
        .iter()
        .map(|f| from_action(f.decision.action))
        .chain(
            session
                .policy_violations
                .iter()
                .map(|v| from_action(v.decision.action)),
        )
        .chain(
            session
                .open_questions
                .iter()
                .map(|q| match q.decision.treatment {
                    OqTreatment::Fail => Some(Verdict::Fail),
                    OqTreatment::Warn => Some(Verdict::Warn),
                    OqTreatment::CountAsGap | OqTreatment::Ignore => None,
                }),
        )
        .flatten()
        .max()
        .unwrap_or(Verdict::Pass);
    let count = |action: Action| {
        let n = session
            .findings
            .iter()
            .filter(|f| f.decision.action == action)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    };
    let closed = |check: &CheckId| {
        let mut states = session
            .coverage
            .iter()
            .filter(|c| c.check == *check)
            .map(|c| &c.state)
            .peekable();
        states.peek().is_some() && states.all(CoverageState::can_close)
    };
    let mut missing_required = vec![];
    for check in &session.request.required_checks {
        if !closed(check) && !missing_required.contains(check) {
            missing_required.push(check.clone());
        }
    }
    let gaps: Vec<_> = session
        .open_questions
        .iter()
        .filter(|q| q.decision.treatment == OqTreatment::CountAsGap)
        .map(|q| q.id.clone())
        .collect();
    let completeness = if missing_required.is_empty() && gaps.is_empty() {
        Completeness::Complete
    } else {
        Completeness::Incomplete {
            missing_required,
            gaps,
        }
    };
    Outcome {
        verdict,
        completeness,
        confirmed_failures: count(Action::Fail),
        confirmed_warnings: count(Action::Warn),
        policy_time,
    }
}
