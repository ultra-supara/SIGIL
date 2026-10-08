//! What a policy may name: the detection rules, the audit scopes with the checks they require, and
//! the assumptions (plan §4.7, §6.3, §8). Each later PR adds the rules and scopes its collectors
//! produce.

use sigil_model::{FindingKind, Severity};

/// A detection rule and its technical defaults. Policy can change what is done with a finding,
/// never these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: &'static str,
    pub kind: FindingKind,
    pub default: Severity,
    pub summary: &'static str,
}

/// The rules of the model store and exposure (the migration table, plan §6.3).
pub const RULES: &[RuleInfo] = &[
    RuleInfo {
        id: "model.blob_missing",
        kind: FindingKind::Integrity,
        default: Severity::Warn,
        summary: "A manifest references a blob that is not in the store",
    },
    RuleInfo {
        id: "model.blob_digest_mismatch",
        kind: FindingKind::Integrity,
        default: Severity::Fail,
        summary: "A blob's SHA-256 differs from the digest its manifest names",
    },
    RuleInfo {
        id: "model.manifest_digest_malformed",
        kind: FindingKind::Integrity,
        default: Severity::Fail,
        summary: "A manifest names a digest that is not sha256 with 64 lowercase hex digits",
    },
    RuleInfo {
        id: "model.manifest_unparseable",
        kind: FindingKind::Integrity,
        default: Severity::Warn,
        summary: "A manifest is not valid JSON of the expected shape",
    },
    RuleInfo {
        id: "model.license_missing",
        kind: FindingKind::Integrity,
        default: Severity::Warn,
        summary: "A manifest has no license layer",
    },
    RuleInfo {
        id: "model.provenance_unknown",
        kind: FindingKind::Integrity,
        default: Severity::Warn,
        summary: "A manifest path is too shallow to name registry, model, and tag",
    },
    RuleInfo {
        id: "model.not_found",
        kind: FindingKind::Integrity,
        default: Severity::Warn,
        summary: "The requested model is not in the store",
    },
    RuleInfo {
        id: "exposure.bind_public",
        kind: FindingKind::Exposure,
        default: Severity::Warn,
        summary: "The runtime listens on a wildcard or globally routable address",
    },
    RuleInfo {
        id: "exposure.bind_lan",
        kind: FindingKind::Exposure,
        default: Severity::Warn,
        summary: "The runtime listens on a private or link-local address",
    },
];

/// An audit scope and the checks it requires, whether or not anything was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeInfo {
    pub id: &'static str,
    pub checks: &'static [&'static str],
}

pub const SCOPES: &[ScopeInfo] = &[
    ScopeInfo {
        id: "model_store",
        checks: &[
            "model_store.inventory",
            "model_store.integrity",
            "model_store.license",
        ],
    },
    ScopeInfo {
        id: "exposure",
        checks: &["exposure.binds"],
    },
    ScopeInfo {
        id: "runtime_artifacts",
        checks: &["artifacts.discovery"],
    },
    ScopeInfo {
        id: "backend_loader",
        checks: &[
            "artifacts.discovery",
            "loader.identify",
            "loader.search_paths",
        ],
    },
];

/// An assumption a finding condition may rest on, if the policy accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssumptionInfo {
    pub id: &'static str,
    pub statement: &'static str,
}

pub const ASSUMPTIONS: &[AssumptionInfo] = &[
    AssumptionInfo {
        id: "A-1",
        statement: "/etc/passwd and /etc/group reflect the environment (not true with NSS/LDAP)",
    },
    AssumptionInfo {
        id: "A-2",
        statement: "The service unit found, with its drop-ins, is the one in effect",
    },
    AssumptionInfo {
        id: "A-3",
        statement: "The runtime was launched by this system-instance unit, so an unset WorkingDirectory= means cwd \"/\"",
    },
    AssumptionInfo {
        id: "A-4",
        statement: "No symbol interposition in the role: each loader PLT call binds to the analyzed definer",
    },
];

pub fn rule(id: &str) -> Option<&'static RuleInfo> {
    RULES.iter().find(|r| r.id == id)
}

pub fn scope(id: &str) -> Option<&'static ScopeInfo> {
    SCOPES.iter().find(|s| s.id == id)
}

/// Whether some scope requires `check`.
pub fn is_check(check: &str) -> bool {
    SCOPES.iter().any(|s| s.checks.contains(&check))
}

pub fn assumption(id: &str) -> Option<&'static AssumptionInfo> {
    ASSUMPTIONS.iter().find(|a| a.id == id)
}
