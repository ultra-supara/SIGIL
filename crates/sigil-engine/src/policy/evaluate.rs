//! Applying a policy to a session (plan §4.7).
//!
//! A policy has two kinds of content.
//! - **Inputs to the analysis:** the required checks (`Policy::scope`) and the accepted
//!   assumptions (`Policy::acceptance`). Collection runs for the required checks, and acceptance
//!   decides which conditions an assumption may settle. The session assembler records both in the
//!   session before the analysis.
//! - **Decisions over its results:** what evaluation sets. That is the decision of each finding
//!   and open question, the policy violations, the capability open questions (#51), the outcome,
//!   and the record of which policy was applied.
//!
//! [`evaluate`] refuses a policy whose inputs differ from those the session was analyzed with,
//! because only a new analysis can update the technical conclusions. The same entry point serves
//! the first evaluation and a later re-evaluation. The analysis's findings and open questions,
//! their conditions and evidence, and `default_severity` are never touched. An ignored finding
//! stays, with its reason.
//!
//! A component deny entry (`[[components.deny]]`) is matched through the embedded component
//! database of the build that evaluates, so a session re-evaluated by a build with other names may
//! gain or lose violations (the same build is deterministic).
//!
//! A capability denial (`[[capabilities.deny]]`, #51) is matched through the session's own hints
//! and code facts, made with the capability table the session records: a build with the same
//! table gives the same results, and a build with another one refuses to judge the session, which
//! must be analyzed again. Its open questions (rule `binary.capability_call`) are evaluation's, as
//! its violations are: each evaluation removes them and makes them again, with their conditions
//! and evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sigil_model::{
    Action, ArtifactId, AssumptionAcceptance, AssumptionId, CallId, CallTarget, CheckId,
    Completeness, ComponentClaim, ComponentKey, CondId, CondState, Condition, CoverageState, Date,
    EvidenceRef, FeatureHint, FeatureKey, IdentityAssertion, IdentityStatus, InstanceContent,
    InstanceId, KnowledgeKind, Loc, OpenQuestion, OpenQuestionDecision, OpenQuestionId,
    OqTreatment, Outcome, PolicyDecision, PolicyRuleRef, PolicyViolation, Ref, RuleId, Session,
    Severity, Sha256Hex, Signal, SliceId, Timestamp, UnknownReason, UntrustedText, Verdict,
    BINARY_CODE, CAPABILITY_CONDITION_PREFIX, CAPABILITY_RULE, CAPABILITY_TABLE_ID,
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
/// again with this policy. For `CapabilityTable` and `CapabilityHints` (#51), the session's
/// binaries were not analyzed with this build's capability table, so they must be analyzed again
/// with this build. `ComponentDatabase`, `CapabilityId`, and `Signatures` are internal errors.
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
                let shown: Vec<&str> = recorded.iter().map(Sha256Hex::as_str).collect();
                let recorded = match shown.as_slice() {
                    [] => "no recorded capability table".to_string(),
                    [one] => format!("the capability table {one}"),
                    many => format!("{} capability tables ({})", many.len(), many.join(", ")),
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
                 its capability table gives its imports ({missing} missing, {extra} not given): \
                 analyze the files again with this build"
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
    // Each slice's imports of each feature, its call sites of an import, and its inputs'
    // `binary.code` states, gathered once: walking the whole session for each slice and denial
    // would grow with the square of the slices (PR review).
    let mut imported: BTreeMap<(&SliceId, &FeatureKey), BTreeSet<&UntrustedText>> = BTreeMap::new();
    for h in session.hints.iter().filter(|h| h.signal == Signal::Import) {
        imported
            .entry((&h.subject, &h.feature))
            .or_default()
            .insert(&h.value);
    }
    let mut calls: BTreeMap<&SliceId, Vec<(&CallId, &UntrustedText)>> = BTreeMap::new();
    for facts in &session.code {
        for c in &facts.call_sites {
            if let CallTarget::Import { symbol, .. } = &c.target {
                calls.entry(&facts.slice).or_default().push((&c.id, symbol));
            }
        }
    }
    let states = code_states(session);
    for slice in session.binaries.iter().map(|b| &b.slice) {
        for deny in &policy.capabilities {
            let Some(imports) = imported.get(&(slice, &deny.feature)) else {
                continue;
            };
            // By ID, so a canonical session re-evaluates to the same bytes.
            let sites: Vec<EvidenceRef> = calls
                .get(slice)
                .into_iter()
                .flatten()
                .filter(|(_, symbol)| imports.contains(symbol))
                .map(|(id, _)| *id)
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
                        reason: unknown_call(
                            states.get(&slice.artifact()).map_or(&[], Vec::as_slice),
                        )
                        .map_err(id_error)?,
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
    // Compared as sorted lists, each hint as often as it is recorded: a duplicate is a difference,
    // and the comparison grows with the hints, not their square (PR review).
    let derived = hints::derive(&session.binaries).map_err(EvaluateError::Signatures)?;
    let derived = import_keys(&derived);
    let recorded = import_keys(&session.hints);
    let (missing, extra) = surplus(&derived, &recorded);
    if missing + extra > 0 {
        return Err(EvaluateError::CapabilityHints { missing, extra });
    }
    Ok(())
}

/// The `Import` hints of `hints`, each as the fields that make it, sorted.
fn import_keys(hints: &[FeatureHint]) -> Vec<(&str, &str, &[u8], String)> {
    let mut keys: Vec<_> = hints
        .iter()
        .filter(|h| h.signal == Signal::Import)
        .map(|h| {
            (
                h.subject.as_str(),
                h.feature.as_str(),
                h.value.as_bytes(),
                format!("{:?}", h.at),
            )
        })
        .collect();
    keys.sort();
    keys
}

/// How many items of the sorted lists `a` and `b` the other lacks, each counted as often as it
/// occurs: `(in a only, in b only)`.
fn surplus<T: Ord>(a: &[T], b: &[T]) -> (usize, usize) {
    let (mut i, mut j, mut only_a, mut only_b) = (0, 0, 0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                only_a += 1;
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                only_b += 1;
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    (only_a + a.len() - i, only_b + b.len() - j)
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

/// The `binary.code` states of each artifact's inputs (#51 spec §3): of the coverage entries of
/// the instances whose content is that artifact.
fn code_states(session: &Session) -> BTreeMap<&ArtifactId, Vec<&CoverageState>> {
    let artifact_of: BTreeMap<&InstanceId, &ArtifactId> = session
        .instances
        .iter()
        .filter_map(|i| match &i.content {
            InstanceContent::Read { artifact } => Some((&i.id, artifact)),
            _ => None,
        })
        .collect();
    let mut states: BTreeMap<&ArtifactId, Vec<&CoverageState>> = BTreeMap::new();
    for c in session
        .coverage
        .iter()
        .filter(|c| c.check.as_str() == BINARY_CODE)
    {
        if let Ref::Instance(i) = &c.scope {
            if let Some(artifact) = artifact_of.get(i) {
                states.entry(artifact).or_default().push(&c.state);
            }
        }
    }
    states
}

/// Why a call of a slice's import is not known (#51 spec §3), by the `binary.code` states of the
/// slice's inputs: none (no code analysis), one that is not `Complete`, or every one `Complete`
/// (a call that is not direct is not followed).
fn unknown_call(states: &[&CoverageState]) -> Result<UnknownReason, sigil_model::IdError> {
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
