//! Applying a policy to a session (plan §4.7).
//!
//! A policy has two kinds of content.
//! - **Inputs to the analysis:** the required checks (`Policy::scope`) and the accepted
//!   assumptions (`Policy::acceptance`). Collection runs for the required checks, and acceptance
//!   decides which conditions an assumption may settle. The session assembler records both in the
//!   session before the analysis.
//! - **Decisions over its results:** what evaluation sets. That is the decision of each finding
//!   and open question, the policy violations, the outcome, and the record of which policy was
//!   applied.
//!
//! [`evaluate`] refuses a policy whose inputs differ from those the session was analyzed with,
//! because only a new analysis can update the technical conclusions. The same entry point serves
//! the first evaluation and a later re-evaluation. Findings, open questions, their conditions and
//! evidence, and `default_severity` are never touched. An ignored finding stays, with its reason.

use std::collections::BTreeSet;
use std::fmt;

use sigil_model::{
    Action, AssumptionAcceptance, AssumptionId, CheckId, Completeness, CoverageState, Date,
    EvidenceRef, IdentityStatus, KnowledgeKind, OpenQuestionDecision, OqTreatment, Outcome,
    PolicyDecision, PolicyRuleRef, PolicyViolation, Ref, RuleId, Session, Severity, Timestamp,
    Verdict,
};

use super::Policy;

/// Something the operator should know about how the policy applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyWarning {
    /// A rule override expired; the rule's default applied instead.
    OverrideExpired { rule: RuleId, expires: Date },
}

/// Why a session cannot be evaluated with a policy. The policy would change the analysis itself,
/// not only the decisions over it, so the session must be analyzed again with this policy.
/// [`evaluate`] leaves the session unchanged when it returns one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluateError {
    /// The policy accepts, or no longer accepts, these assumptions (in session order). A condition
    /// resting on one of them could become settled or unsettled.
    AssumptionsChanged(Vec<AssumptionId>),
    /// The policy requires another set of checks than the session's request: a check is added or
    /// removed. Coverage was collected for the request's checks. The order of the lists does not
    /// matter (a canonical session sorts them).
    RequiredChecksChanged {
        request: Vec<CheckId>,
        policy: Vec<CheckId>,
    },
}

impl fmt::Display for EvaluateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |items: Vec<&str>| items.join(", ");
        match self {
            EvaluateError::AssumptionsChanged(ids) => write!(
                f,
                "the policy changes the acceptance of {}; analyze again with this policy",
                list(ids.iter().map(AssumptionId::as_str).collect())
            ),
            EvaluateError::RequiredChecksChanged { request, policy } => write!(
                f,
                "the policy requires [{}] but the session was collected for [{}]; analyze again \
                 with this policy",
                list(policy.iter().map(CheckId::as_str).collect()),
                list(request.iter().map(CheckId::as_str).collect())
            ),
        }
    }
}

impl std::error::Error for EvaluateError {}

/// Applies `policy` to `session`. It sets the decisions, the policy violations, the outcome, and
/// the policy's knowledge entry. Rule expiry is judged at `policy_time`, which is recorded in the
/// outcome so that a re-evaluation reuses it.
///
/// Fails, without changing `session`, when the policy's accepted assumptions or required checks
/// differ from those recorded in the session ([`EvaluateError`]). Required checks are compared as
/// sets, so a session saved as canonical JSON and loaded again re-evaluates with the same policy.
pub fn evaluate(
    session: &mut Session,
    policy: &Policy,
    policy_time: Timestamp,
) -> Result<Vec<PolicyWarning>, EvaluateError> {
    let changed: Vec<AssumptionId> = session
        .assumptions
        .iter()
        .filter(|a| {
            let recorded = matches!(a.acceptance, AssumptionAcceptance::Accepted { .. });
            recorded != policy.accept.contains(&a.id)
        })
        .map(|a| a.id.clone())
        .collect();
    if !changed.is_empty() {
        return Err(EvaluateError::AssumptionsChanged(changed));
    }
    let active = !session.request.active.is_empty();
    let (_, required) = policy.scope(session.request.mode, active);
    let set = |checks: &[CheckId]| checks.iter().cloned().collect::<BTreeSet<CheckId>>();
    if set(&required) != set(&session.request.required_checks) {
        return Err(EvaluateError::RequiredChecksChanged {
            request: session.request.required_checks.clone(),
            policy: required,
        });
    }

    // The policy's own entry replaces any earlier one, in place.
    let at = session
        .knowledge
        .iter()
        .position(|k| k.kind == KnowledgeKind::Policy)
        .unwrap_or(session.knowledge.len());
    session
        .knowledge
        .retain(|k| k.kind != KnowledgeKind::Policy);
    session.knowledge.insert(at, policy.knowledge());

    let sources = &policy.sources;
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
    Ok(warnings)
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
