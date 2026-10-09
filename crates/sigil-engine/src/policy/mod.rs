//! `sigil-policy/1`: what the organization requires and how it treats what was found (plan §4.7).
//!
//! A policy says which audit scopes are required (and so which checks must be closed), how open
//! questions count, which assumptions a finding may rest on, how individual rules are treated, who
//! is trusted, and which components are denied. Loading is strict: an unknown key, rule, scope,
//! check, or assumption, a malformed date, and `ignore` without a reason are all fatal, so a typo
//! never silently weakens a policy.
//!
//! The session assembler records the policy's inputs to the analysis ([`Policy::scope`],
//! [`Policy::acceptance`]). [`evaluate`] then applies the policy's decisions, and refuses a policy
//! whose inputs differ from those recorded.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};
use sigil_model::{
    Action, AssumptionAcceptance, AssumptionId, AuditScope, CheckId, ComponentKey, Date,
    KnowledgeKind, KnowledgeRef, Mode, OqTreatment, PolicyRuleRef, RuleId, Sha256Hex,
};

pub mod catalog;
mod evaluate;
mod raw;

pub use evaluate::{evaluate, outcome, EvaluateError, PolicyWarning};

/// The schema line every policy starts with.
pub const SCHEMA: &str = "sigil-policy/1";

const DEFAULT_POLICY: &str = include_str!("../../policies/default.toml");

/// What decides the audit scope: the mode, whether an active feature was requested, and whether
/// an installation is inspected (an `install` root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeInput {
    pub mode: Mode,
    pub active: bool,
    pub install: bool,
}

impl ScopeInput {
    /// What a recorded request implies: an active feature if it lists one, an installation if it
    /// has an [`INSTALL_ROOT`](sigil_model::INSTALL_ROOT) root.
    pub fn of(request: &sigil_model::RunRequest) -> ScopeInput {
        ScopeInput {
            mode: request.mode,
            active: !request.active.is_empty(),
            install: request
                .roots
                .iter()
                .any(|r| r.id.as_str() == sigil_model::INSTALL_ROOT),
        }
    }
}

/// A loaded, validated policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    /// SHA-256 of the policy text, recorded in the session's knowledge.
    pub sha256: Sha256Hex,
    /// Scopes audited in every mode.
    pub audit: Vec<AuditScope>,
    /// Scopes added in observe mode.
    pub observe_audit: Vec<AuditScope>,
    /// Scopes added when an active feature is requested (`--active`).
    pub active_audit: Vec<AuditScope>,
    /// Scopes added when an installation is inspected (`--install-dir`).
    pub install_audit: Vec<AuditScope>,
    /// Checks required beyond those of the scopes.
    pub extra_required: Vec<CheckId>,
    pub open_questions: OqPolicy,
    /// Assumptions a finding condition may rest on.
    pub accept: Vec<AssumptionId>,
    pub rules: BTreeMap<RuleId, RuleOverride>,
    pub trust: Trust,
    pub deny: Vec<ComponentDeny>,
    /// The decision sources, validated when the policy is loaded so that evaluation cannot fail.
    pub(crate) sources: Sources,
}

/// The `source` of each decision the policy can make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sources {
    /// `policy:assumptions.accept`
    pub assumptions: PolicyRuleRef,
    /// `policy:open_questions.default`
    pub open_questions: PolicyRuleRef,
    /// `default`: used when `default:<rule>` would not be a valid reference.
    pub default: PolicyRuleRef,
    /// `policy:rules.<rule>` for each override.
    pub rules: BTreeMap<RuleId, PolicyRuleRef>,
}

/// How open questions are treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OqPolicy {
    pub treatment: OqTreatment,
    /// Required for `Ignore`.
    pub reason: Option<String>,
}

/// What the policy does with the findings of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOverride {
    pub action: Action,
    /// Required for `Ignore`.
    pub reason: Option<String>,
    /// Valid through this UTC day; afterwards the rule's default applies again.
    pub expires: Option<Date>,
}

/// Who is trusted to write where the runtime reads (used by access analysis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub principals: Vec<TrustedPrincipal>,
    /// Additional trusted groups, by GID.
    pub extra_groups: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedPrincipal {
    Root,
    /// The user the runtime process runs as.
    Runtime,
    Uid(u32),
}

/// An organizational ban on a component; a match is a `PolicyViolation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentDeny {
    pub component: ComponentKey,
    /// `Warn` or `Fail`.
    pub action: Action,
    pub reason: String,
    /// `policy:components.deny.<component>`
    pub(crate) source: PolicyRuleRef,
}

/// Why a policy did not load. Every variant is fatal (exit code 1 in the CLI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Not TOML, an unknown key, or a value of the wrong type.
    Syntax(String),
    /// The `schema` line is not `sigil-policy/1`.
    Schema(String),
    BadName(String),
    UnknownRule(String),
    UnknownScope(String),
    UnknownCheck(String),
    UnknownAssumption(String),
    BadDate {
        at: String,
        value: String,
    },
    IgnoreWithoutReason {
        at: String,
    },
    BadPrincipal(String),
    BadGroup(String),
    BadDenyAction {
        component: String,
    },
    DenyWithoutReason {
        component: String,
    },
    DuplicateDeny(String),
    BadId(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PolicyError::*;
        match self {
            Syntax(m) => write!(f, "policy is not valid sigil-policy/1 TOML: {m}"),
            Schema(s) => write!(f, "policy schema is {s:?}; expected {SCHEMA:?}"),
            BadName(n) => write!(f, "policy name {n:?} is empty or has control characters"),
            UnknownRule(r) => write!(f, "policy names unknown rule {r:?}"),
            UnknownScope(s) => write!(f, "policy names unknown audit scope {s:?}"),
            UnknownCheck(c) => write!(f, "policy names unknown check {c:?}"),
            UnknownAssumption(a) => write!(f, "policy accepts unknown assumption {a:?}"),
            BadDate { at, value } => write!(f, "{at}: {value:?} is not a YYYY-MM-DD date"),
            IgnoreWithoutReason { at } => write!(f, "{at}: \"ignore\" needs a reason"),
            BadPrincipal(p) => write!(
                f,
                "trust.principals: {p:?} is not root, runtime, or uid:<n>"
            ),
            BadGroup(g) => write!(f, "trust.extra_groups: {g:?} is not gid:<n>"),
            BadDenyAction { component } => {
                write!(
                    f,
                    "components.deny {component:?}: action must be \"warn\" or \"fail\""
                )
            }
            DenyWithoutReason { component } => {
                write!(f, "components.deny {component:?}: needs a reason")
            }
            DuplicateDeny(c) => write!(f, "components.deny names {c:?} twice"),
            BadId(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Parses and validates a policy.
    pub fn load(text: &str) -> Result<Policy, PolicyError> {
        let raw: raw::RawPolicy =
            toml::from_str(text).map_err(|e| PolicyError::Syntax(e.message().to_string()))?;
        if raw.schema != SCHEMA {
            return Err(PolicyError::Schema(raw.schema));
        }
        if raw.name.trim().is_empty() || raw.name.chars().any(char::is_control) {
            return Err(PolicyError::BadName(raw.name));
        }
        let scopes = |list: &[String]| -> Result<Vec<AuditScope>, PolicyError> {
            list.iter()
                .map(|s| {
                    catalog::scope(s).ok_or_else(|| PolicyError::UnknownScope(s.clone()))?;
                    id(AuditScope::new(s.as_str()))
                })
                .collect()
        };
        let audit = scopes(&raw.scope.audit)?;
        let observe_audit = scopes(&raw.scope.observe_audit)?;
        let active_audit = scopes(&raw.scope.active_audit)?;
        let install_audit = scopes(&raw.scope.install_audit)?;
        let extra_required = raw
            .scope
            .extra_required
            .iter()
            .map(|c| {
                if !catalog::is_check(c) {
                    return Err(PolicyError::UnknownCheck(c.clone()));
                }
                id(CheckId::new(c.as_str()))
            })
            .collect::<Result<_, _>>()?;
        let oq = raw.open_questions;
        let treatment = match oq.default {
            raw::RawTreatment::CountAsGap => OqTreatment::CountAsGap,
            raw::RawTreatment::Warn => OqTreatment::Warn,
            raw::RawTreatment::Fail => OqTreatment::Fail,
            raw::RawTreatment::Ignore => OqTreatment::Ignore,
        };
        let open_questions = OqPolicy {
            treatment,
            reason: reason(
                oq.reason,
                treatment == OqTreatment::Ignore,
                "open_questions",
            )?,
        };
        let accept = raw
            .assumptions
            .accept
            .iter()
            .map(|a| {
                catalog::assumption(a).ok_or_else(|| PolicyError::UnknownAssumption(a.clone()))?;
                id(AssumptionId::new(a.as_str()))
            })
            .collect::<Result<_, _>>()?;
        let mut rules = BTreeMap::new();
        for (rule, entry) in raw.rules {
            if catalog::rule(&rule).is_none() {
                return Err(PolicyError::UnknownRule(rule));
            }
            let at = format!("rules.{rule:?}");
            let action = action(entry.action);
            let expires = match entry.expires {
                None => None,
                Some(date) => {
                    let value = date.text();
                    Some(Date::new(value.as_str()).map_err(|_| PolicyError::BadDate {
                        at: at.clone(),
                        value,
                    })?)
                }
            };
            let reason = reason(entry.reason, action == Action::Ignore, &at)?;
            rules.insert(
                id(RuleId::new(rule.as_str()))?,
                RuleOverride {
                    action,
                    reason,
                    expires,
                },
            );
        }
        let principals = raw
            .trust
            .principals
            .iter()
            .map(|p| match p.as_str() {
                "root" => Ok(TrustedPrincipal::Root),
                "runtime" => Ok(TrustedPrincipal::Runtime),
                other => numbered(other, "uid:")
                    .map(TrustedPrincipal::Uid)
                    .ok_or_else(|| PolicyError::BadPrincipal(p.clone())),
            })
            .collect::<Result<_, _>>()?;
        let extra_groups = raw
            .trust
            .extra_groups
            .iter()
            .map(|g| numbered(g, "gid:").ok_or_else(|| PolicyError::BadGroup(g.clone())))
            .collect::<Result<_, _>>()?;
        let mut deny: Vec<ComponentDeny> = vec![];
        for entry in raw.components.deny {
            let component = id(ComponentKey::new(entry.component.as_str()))?;
            if deny.iter().any(|d| d.component == component) {
                return Err(PolicyError::DuplicateDeny(entry.component));
            }
            let action = match entry.action {
                raw::RawAction::Fail => Action::Fail,
                raw::RawAction::Warn => Action::Warn,
                raw::RawAction::Ignore => {
                    return Err(PolicyError::BadDenyAction {
                        component: entry.component,
                    })
                }
            };
            if entry.reason.trim().is_empty() {
                return Err(PolicyError::DenyWithoutReason {
                    component: entry.component,
                });
            }
            let source = id(PolicyRuleRef::new(format!(
                "policy:components.deny.{component}"
            )))?;
            deny.push(ComponentDeny {
                component,
                action,
                reason: entry.reason,
                source,
            });
        }
        let sources = Sources {
            assumptions: id(PolicyRuleRef::new("policy:assumptions.accept"))?,
            open_questions: id(PolicyRuleRef::new("policy:open_questions.default"))?,
            default: id(PolicyRuleRef::new("default"))?,
            rules: rules
                .keys()
                .map(|rule| {
                    Ok((
                        rule.clone(),
                        id(PolicyRuleRef::new(format!("policy:rules.{rule}")))?,
                    ))
                })
                .collect::<Result<_, PolicyError>>()?,
        };
        Ok(Policy {
            name: raw.name,
            sha256: sha256_hex(text)?,
            audit,
            observe_audit,
            active_audit,
            install_audit,
            extra_required,
            open_questions,
            accept,
            rules,
            trust: Trust {
                principals,
                extra_groups,
            },
            deny,
            sources,
        })
    }

    /// The built-in policy (`policies/default.toml`).
    pub fn builtin_default() -> Result<Policy, PolicyError> {
        Policy::load(DEFAULT_POLICY)
    }

    /// The audit scope requested for `input`, and the checks it requires (in catalog order, then
    /// `extra_required`, without repeats). The assembler and `evaluate` both compute it, so a
    /// session's required checks are what its own request implies.
    pub fn scope(&self, input: &ScopeInput) -> (Vec<AuditScope>, Vec<CheckId>) {
        let mode = input.mode;
        let mut audit: Vec<AuditScope> = vec![];
        let observe = match mode {
            Mode::Observe => self.observe_audit.as_slice(),
            Mode::Static => &[],
        };
        let active = if input.active {
            self.active_audit.as_slice()
        } else {
            &[]
        };
        let install = if input.install {
            self.install_audit.as_slice()
        } else {
            &[]
        };
        for scope in self
            .audit
            .iter()
            .chain(observe)
            .chain(active)
            .chain(install)
        {
            if !audit.contains(scope) {
                audit.push(scope.clone());
            }
        }
        let mut required: Vec<CheckId> = vec![];
        let from_scopes = audit
            .iter()
            .filter_map(|s| catalog::scope(s.as_str()))
            .flat_map(|s| s.checks.iter().filter_map(|c| CheckId::new(*c).ok()));
        for check in from_scopes.chain(self.extra_required.iter().cloned()) {
            if !required.contains(&check) {
                required.push(check);
            }
        }
        (audit, required)
    }

    /// Whether a condition may rest on `assumption`. The session assembler records this for every
    /// assumption before the analysis, because acceptance decides which conditions are settled.
    pub fn acceptance(&self, assumption: &AssumptionId) -> AssumptionAcceptance {
        if self.accept.contains(assumption) {
            AssumptionAcceptance::Accepted {
                source: self.sources.assumptions.clone(),
            }
        } else {
            AssumptionAcceptance::NotAccepted
        }
    }

    /// The knowledge entry that records which policy was applied.
    pub fn knowledge(&self) -> KnowledgeRef {
        KnowledgeRef {
            kind: KnowledgeKind::Policy,
            id: self.name.clone(),
            version: SCHEMA.to_string(),
            sha256: self.sha256.clone(),
        }
    }
}

/// A catalog ID that failed the model's ID rules (a catalog bug, reported rather than panicking).
fn id<T>(result: Result<T, sigil_model::IdError>) -> Result<T, PolicyError> {
    result.map_err(|e| PolicyError::BadId(e.to_string()))
}

fn action(raw: raw::RawAction) -> Action {
    match raw {
        raw::RawAction::Fail => Action::Fail,
        raw::RawAction::Warn => Action::Warn,
        raw::RawAction::Ignore => Action::Ignore,
    }
}

/// The trimmed reason; required (non-blank) when `required`.
fn reason(reason: Option<String>, required: bool, at: &str) -> Result<Option<String>, PolicyError> {
    let reason = reason.filter(|r| !r.trim().is_empty());
    if required && reason.is_none() {
        return Err(PolicyError::IgnoreWithoutReason { at: at.to_string() });
    }
    Ok(reason)
}

/// `<prefix><decimal>`, e.g. `uid:1000`.
fn numbered(text: &str, prefix: &str) -> Option<u32> {
    let digits = text.strip_prefix(prefix)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn sha256_hex(text: &str) -> Result<Sha256Hex, PolicyError> {
    Sha256Hex::new(format!("{:x}", Sha256::digest(text.as_bytes())))
        .map_err(|e| PolicyError::BadId(e.to_string()))
}
