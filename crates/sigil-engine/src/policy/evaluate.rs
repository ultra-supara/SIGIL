//! Applying a policy to a session (plan §4.7).

use sigil_model::{Date, Outcome, RuleId, Session, Timestamp};

use super::Policy;

/// Something the operator should know about how the policy applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyWarning {
    /// A rule override expired; the rule's default applied instead.
    OverrideExpired { rule: RuleId, expires: Date },
}

/// Sets assumption acceptance, decisions, policy violations, and the outcome on `session`.
pub fn evaluate(
    session: &mut Session,
    policy: &Policy,
    policy_time: Timestamp,
) -> Vec<PolicyWarning> {
    let _ = (session, policy, policy_time);
    vec![]
}

/// The outcome of the decisions and coverage recorded in `session`.
pub fn outcome(session: &Session, policy_time: Timestamp) -> Outcome {
    let _ = policy_time;
    session.outcome.clone()
}
