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
//!
//! A deny entry is matched through the embedded component database of the build that evaluates,
//! so a session re-evaluated by a build with other names may gain or lose violations (the same
//! build is deterministic).
//!
//! A capability denial (#51) is matched through the session's own hints and code facts, which its
//! binaries were analyzed with the capability table it records: a build with the same table gives
//! the same results, and a build with another one refuses to judge the session, which must be
//! analyzed again. Its open questions (rule `binary.capability_call`) are evaluation's, as its
//! violations are: each evaluation removes them and makes them again.

use std::collections::BTreeSet;
use std::fmt;

use sigil_model::{
    Action, AssumptionAcceptance, AssumptionId, CallTarget, CheckId, Completeness, ComponentClaim,
    ComponentKey, CondId, CondState, Condition, CoverageState, Date, EvidenceRef,
    IdentityAssertion, IdentityStatus, InstanceContent, KnowledgeKind, Loc, OpenQuestion,
    OpenQuestionDecision, OpenQuestionId, OqTreatment, Outcome, PolicyDecision, PolicyRuleRef,
    PolicyViolation, Ref, RuleId, Session, Severity, Sha256Hex, Signal, SliceId, Timestamp,
    UnknownReason, UntrustedText, Verdict, BINARY_CODE, CAPABILITY_CONDITION_PREFIX,
    CAPABILITY_RULE, CAPABILITY_TABLE_ID,
};

use super::{CapabilityDeny, Policy, ScopeInput};
use crate::analyze::components::{components, ComponentDb};
use crate::analyze::hints;
use crate::code::data::signatures;

/// Something the operator should know about how the policy applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyWarning {
    /// A rule override expired; the rule's default applied instead.
    OverrideExpired { rule: RuleId, expires: Date },
}

/// Why a session cannot be evaluated with a policy. [`evaluate`] leaves the session unchanged when
/// it returns one of these. For `AssumptionsChanged` and `RequiredChecksChanged`, the policy would
/// change the analysis itself, not only the decisions over it, so the session must be analyzed
/// again with this policy; `ComponentDatabase` is an internal error.
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
    /// The embedded component database, which a deny entry is matched through (PR-4c-2b), is
    /// invalid. Its test `the_embedded_database_parses` rules this out.
    ComponentDatabase(String),
    /// An ID of a capability result could not be made (#51): an internal error, since its parts
    /// are IDs the session and policy already hold.
    CapabilityId(String),
    /// The policy denies a capability, and the session's binaries were not analyzed with this
    /// build's capability table (#51, plan review P2-1): `recorded` lists the SHA-256 of each
    /// table the session records (none for a session made before #51). Its hints and call sites
    /// name only that table's imports, so the session must be analyzed again with this build.
    CapabilityTable {
        recorded: Vec<Sha256Hex>,
        embedded: Sha256Hex,
    },
    /// The policy denies a capability, and the session's `Import` hints are not the ones its
    /// capability table gives its import facts (#51): how many are missing, and how many the
    /// table does not give. `validate` checks that a hint names a real import, not that every
    /// import has its hint, so evaluation does.
    CapabilityHints { missing: usize, extra: usize },
    /// The embedded capability table is invalid: an internal error that its tests rule out.
    Signatures(String),
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
            EvaluateError::ComponentDatabase(m) => {
                write!(f, "the embedded component database is invalid: {m}")
            }
            EvaluateError::CapabilityId(m) => {
                write!(f, "a capability result's ID could not be made: {m}")
            }
            EvaluateError::CapabilityTable { recorded, embedded } => {
                let recorded = if recorded.is_empty() {
                    "no recorded capability table".to_string()
                } else {
                    let shown: Vec<&str> = recorded.iter().map(Sha256Hex::as_str).collect();
                    format!("the capability table {}", shown.join(", "))
                };
                write!(
                    f,
                    "the policy denies capabilities, and the session's binaries were analyzed with \
                     {recorded}, not this build's ({embedded}): their hints and call sites name \
                     only that table's imports, so analyze the files again with this build"
                )
            }
            EvaluateError::CapabilityHints { missing, extra } => write!(
                f,
                "the policy denies capabilities, and the session's import hints are not the ones \
                 its capability table gives its imports ({missing} missing, {extra} not given)"
            ),
            EvaluateError::Signatures(m) => {
                write!(f, "the embedded capability table is invalid: {m}")
            }
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
/// It also fails, without changing `session`, when the policy has a deny entry and the embedded
/// component database is invalid (an internal error that the database's tests rule out), and,
/// when the policy denies a capability, for a session with binary facts that does not record this
/// build's capability table or whose `Import` hints are not the ones that table gives (#51).
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
    let (_, required) = policy.scope(&ScopeInput::of(&session.request));
    let set = |checks: &[CheckId]| checks.iter().cloned().collect::<BTreeSet<CheckId>>();
    if set(&required) != set(&session.request.required_checks) {
        return Err(EvaluateError::RequiredChecksChanged {
            request: session.request.required_checks.clone(),
            policy: required,
        });
    }
    let db: Option<&ComponentDb> = if policy.deny.is_empty() {
        None
    } else {
        Some(components().map_err(EvaluateError::ComponentDatabase)?)
    };
    let (capability_violations, capability_questions) = capabilities(session, policy)?;

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

    // The capability questions of an earlier evaluation are replaced (#51); the analysis's own
    // questions stay.
    session
        .open_questions
        .retain(|q| q.rule.as_str() != CAPABILITY_RULE);
    session.open_questions.extend(capability_questions);
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
                    claim.status != IdentityStatus::Unidentified
                        && db.is_some_and(|db| names(db, claim).contains(&&deny.component))
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
    session.policy_violations.extend(capability_violations);

    session.outcome = outcome(session, policy_time);
    Ok(warnings)
}

/// What `policy`'s capability denials give on `session` (#51 spec §3), for each slice of its
/// binaries and each denial in file order: nothing when the slice's `Import` hints give the
/// feature no import; a violation citing every direct call site of those imports, by ID, when
/// there is one; otherwise an open question, whatever `binary.code` says (a call that is not
/// direct is not followed). The questions' decisions are set with the others'. Refused for a
/// session that does not record this build's table, or whose hints are not the table's
/// ([`pinned`]).
fn capabilities(
    session: &Session,
    policy: &Policy,
) -> Result<(Vec<PolicyViolation>, Vec<OpenQuestion>), EvaluateError> {
    let id_error = |e: sigil_model::IdError| EvaluateError::CapabilityId(e.to_string());
    let mut violations = vec![];
    let mut questions = vec![];
    if policy.capabilities.is_empty() || session.binaries.is_empty() {
        return Ok((violations, questions));
    }
    pinned(session)?;
    let rule = RuleId::new(CAPABILITY_RULE).map_err(id_error)?;
    for slice in session.binaries.iter().map(|b| &b.slice) {
        for deny in &policy.capabilities {
            let imports: BTreeSet<&UntrustedText> = session
                .hints
                .iter()
                .filter(|h| {
                    h.subject == *slice && h.signal == Signal::Import && h.feature == deny.feature
                })
                .map(|h| &h.value)
                .collect();
            if imports.is_empty() {
                continue;
            }
            // By ID, so a canonical session re-evaluates to the same bytes.
            let sites: Vec<EvidenceRef> = session
                .code
                .iter()
                .filter(|c| c.slice == *slice)
                .flat_map(|c| &c.call_sites)
                .filter(|c| {
                    matches!(&c.target, CallTarget::Import { symbol, .. } if imports.contains(symbol))
                })
                .map(|c| &c.id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|id| EvidenceRef::Code {
                    slice: slice.clone(),
                    loc: Loc::CallSite(id.clone()),
                })
                .collect();
            if !sites.is_empty() {
                violations.push(violation(deny, slice, sites));
                continue;
            }
            questions.push(OpenQuestion {
                id: OpenQuestionId::new(format!("capability:{}@{slice}", deny.feature))
                    .map_err(id_error)?,
                rule: rule.clone(),
                subject: Ref::Slice(slice.clone()),
                conditions: vec![Condition {
                    id: CondId::new(format!("{CAPABILITY_CONDITION_PREFIX}{}", deny.feature))
                        .map_err(id_error)?,
                    state: CondState::Unknown {
                        reason: unknown_call(session, slice).map_err(id_error)?,
                        evidence: None,
                    },
                    unresolved: vec![],
                }],
                evidence: imports
                    .iter()
                    .map(|name| EvidenceRef::Code {
                        slice: slice.clone(),
                        loc: Loc::Symbol((*name).clone()),
                    })
                    .collect(),
                decision: OpenQuestionDecision {
                    treatment: policy.open_questions.treatment,
                    source: policy.sources.open_questions.clone(),
                    reason: policy.open_questions.reason.clone(),
                },
            });
        }
    }
    Ok((violations, questions))
}

/// Whether `session`, which has binary facts, was analyzed with this build's capability table
/// (#51, plan review P2-1): it records exactly one entry of it, with the embedded table's SHA-256,
/// and its `Import` hints are the ones the table gives its import facts. A session saved before
/// a table change lacks the hints of names added since, and its code facts their call sites, so
/// a denial judged on it would miss them.
fn pinned(session: &Session) -> Result<(), EvaluateError> {
    let sig = signatures().map_err(EvaluateError::Signatures)?;
    let embedded = &sig.knowledge().sha256;
    let recorded: Vec<Sha256Hex> = session
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::SignatureDb && k.id == CAPABILITY_TABLE_ID)
        .map(|k| k.sha256.clone())
        .collect();
    if recorded.as_slice() != std::slice::from_ref(embedded) {
        return Err(EvaluateError::CapabilityTable {
            recorded,
            embedded: embedded.clone(),
        });
    }
    let derived = hints::derive(&session.binaries).map_err(EvaluateError::Signatures)?;
    let derived: Vec<_> = derived
        .iter()
        .filter(|h| h.signal == Signal::Import)
        .collect();
    let recorded: Vec<_> = session
        .hints
        .iter()
        .filter(|h| h.signal == Signal::Import)
        .collect();
    let missing = derived.iter().filter(|h| !recorded.contains(h)).count();
    let extra = recorded.iter().filter(|h| !derived.contains(h)).count();
    if missing + extra > 0 {
        return Err(EvaluateError::CapabilityHints { missing, extra });
    }
    Ok(())
}

fn violation(deny: &CapabilityDeny, slice: &SliceId, sites: Vec<EvidenceRef>) -> PolicyViolation {
    PolicyViolation {
        policy_rule: deny.source.clone(),
        subject: Ref::Slice(slice.clone()),
        evidence: sites,
        decision: PolicyDecision {
            action: deny.action,
            source: deny.source.clone(),
            reason: Some(deny.reason.clone()),
            expires: None,
        },
    }
}

/// Why a call of a slice's import is not known (#51 spec §3), by the `binary.code` entries of the
/// instances whose content is the slice's artifact: none (no code analysis), one that is not
/// `Complete`, or every one `Complete` (a call that is not direct is not followed).
fn unknown_call(session: &Session, slice: &SliceId) -> Result<UnknownReason, sigil_model::IdError> {
    let artifact = slice.artifact();
    let placed: BTreeSet<_> = session
        .instances
        .iter()
        .filter(|i| matches!(&i.content, InstanceContent::Read { artifact: a } if *a == artifact))
        .map(|i| &i.id)
        .collect();
    let states: Vec<&CoverageState> = session
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == BINARY_CODE)
        .filter(|c| matches!(&c.scope, Ref::Instance(i) if placed.contains(i)))
        .map(|c| &c.state)
        .collect();
    Ok(if states.is_empty() {
        UnknownReason::NotModeled {
            what: "calls in code that was not analyzed".into(),
        }
    } else if states.iter().all(|s| matches!(s, CoverageState::Complete)) {
        UnknownReason::NotModeled {
            what: "calls that are not direct (through a function pointer, or from data)".into(),
        }
    } else {
        UnknownReason::CheckIncomplete {
            check: CheckId::new(BINARY_CODE)?,
        }
    })
}

/// The components a claim is named as (PR-4c-2b spec §6): its own, and the one each of its
/// self-names names in `db`. More than one only for a derived `Conflicting` claim, which a deny
/// entry of any of them matches; its violation's subject is still the claim, of its own component.
fn names<'c>(db: &'c ComponentDb, claim: &'c ComponentClaim) -> BTreeSet<&'c ComponentKey> {
    let mut keys = BTreeSet::from([&claim.component]);
    for a in &claim.assertions {
        if let IdentityAssertion::SelfName { value, .. } = a {
            keys.extend(db.component(value.as_bytes()));
        }
    }
    keys
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
