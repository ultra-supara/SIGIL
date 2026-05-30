use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub allowed_capabilities: BTreeSet<String>,
    pub forbidden_capabilities: BTreeSet<String>,
    pub verdict_rules: BTreeMap<String, String>,
}

impl Policy {
    pub fn new<const A: usize, const F: usize, const R: usize>(
        name: &str,
        allowed_capabilities: [&str; A],
        forbidden_capabilities: [&str; F],
        verdict_rules: [(&str, &str); R],
    ) -> Self {
        Self {
            name: name.to_string(),
            allowed_capabilities: allowed_capabilities
                .into_iter()
                .map(str::to_string)
                .collect(),
            forbidden_capabilities: forbidden_capabilities
                .into_iter()
                .map(str::to_string)
                .collect(),
            verdict_rules: verdict_rules
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub rule: String,
    pub capability: String,
    #[serde(default = "default_violation_severity")]
    pub severity: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_address: Option<String>,
}

fn default_violation_severity() -> Verdict {
    Verdict::Fail
}

impl PolicyViolation {
    pub fn new(rule: impl Into<String>, capability: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            capability: capability.into(),
            severity: Verdict::Fail,
            evidence_address: None,
        }
    }

    pub fn with_address(
        rule: impl Into<String>,
        capability: impl Into<String>,
        evidence_address: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            capability: capability.into(),
            severity: Verdict::Fail,
            evidence_address: Some(evidence_address.into()),
        }
    }

    pub fn with_severity(mut self, severity: Verdict) -> Self {
        self.severity = severity;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub verdict: Verdict,
    pub violations: Vec<PolicyViolation>,
}

#[derive(Debug, Deserialize)]
struct PolicyYaml {
    name: String,
    #[serde(default)]
    allowed: CapabilityList,
    #[serde(default)]
    forbidden: CapabilityList,
    #[serde(default)]
    verdict_rules: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct CapabilityList {
    #[serde(default)]
    capabilities: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AssessError {
    #[error("failed to read policy {path}: {source}")]
    ReadPolicy {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse policy {path}: {source}")]
    ParsePolicy {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("policy missing required field: name")]
    MissingName,
}

pub fn load_policy(path: impl AsRef<Path>) -> Result<Policy, AssessError> {
    let path_ref = path.as_ref();
    let path_display = path_ref.display().to_string();
    let raw = fs::read_to_string(path_ref).map_err(|source| AssessError::ReadPolicy {
        path: path_display.clone(),
        source,
    })?;
    let parsed: PolicyYaml =
        serde_yaml::from_str(&raw).map_err(|source| AssessError::ParsePolicy {
            path: path_display,
            source,
        })?;
    if parsed.name.trim().is_empty() {
        return Err(AssessError::MissingName);
    }
    Ok(Policy {
        name: parsed.name,
        allowed_capabilities: parsed.allowed.capabilities.into_iter().collect(),
        forbidden_capabilities: parsed.forbidden.capabilities.into_iter().collect(),
        verdict_rules: parsed.verdict_rules,
    })
}

/// Resolve the severity that a named policy rule should produce, defaulting
/// when the policy does not configure the rule explicitly.
pub fn severity_for_rule(policy: &Policy, rule_key: &str, default: Verdict) -> Verdict {
    match policy
        .verdict_rules
        .get(rule_key)
        .map(String::as_str)
        .unwrap_or(default.as_str())
    {
        "FAIL" => Verdict::Fail,
        "WARN" => Verdict::Warn,
        "PASS" => Verdict::Pass,
        _ => default,
    }
}

fn escalate(current: Verdict, candidate: Verdict) -> Verdict {
    match (current, candidate) {
        (Verdict::Fail, _) | (_, Verdict::Fail) => Verdict::Fail,
        (Verdict::Warn, _) | (_, Verdict::Warn) => Verdict::Warn,
        _ => Verdict::Pass,
    }
}

pub fn evaluate_policy<'a, I, S>(policy: &Policy, capabilities: I) -> PolicyResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut verdict = Verdict::Pass;
    let mut violations = Vec::new();
    let unique_capabilities: BTreeSet<String> = capabilities
        .into_iter()
        .map(|capability| capability.as_ref().to_string())
        .collect();

    for capability in unique_capabilities {
        if policy.forbidden_capabilities.contains(&capability) {
            let rule_severity = severity_for_rule(policy, "forbidden_capability", Verdict::Fail);
            violations.push(
                PolicyViolation::new(
                    format!("forbidden.capabilities.{capability}"),
                    capability.clone(),
                )
                .with_severity(rule_severity),
            );
            verdict = escalate(verdict, rule_severity);
        }

        if !policy.allowed_capabilities.is_empty()
            && !policy.allowed_capabilities.contains(&capability)
        {
            let rule_severity = severity_for_rule(policy, "allowlist_violation", Verdict::Fail);
            violations.push(
                PolicyViolation::new(
                    format!("allowed.capabilities.{capability}"),
                    capability.clone(),
                )
                .with_severity(rule_severity),
            );
            verdict = escalate(verdict, rule_severity);
        }

        if capability == "unsupported_instruction" {
            let rule_severity = severity_for_rule(policy, "unsupported_instruction", Verdict::Warn);
            verdict = escalate(verdict, rule_severity);
        }
    }

    PolicyResult {
        verdict,
        violations,
    }
}

pub fn capability_for_symbol(symbol: &str) -> Option<&'static str> {
    let name = symbol.split('@').next().unwrap_or(symbol);
    match name {
        "connect" | "getaddrinfo" | "send" | "sendto" | "recv" | "recvfrom" | "socket" => {
            Some("network")
        }
        "open" | "openat" | "fopen" | "read" | "pread" => Some("file_read"),
        "write" | "pwrite" | "fwrite" | "creat" | "rename" | "unlink" => Some("file_write"),
        "execve" | "fork" | "posix_spawn" | "system" => Some("process_spawn"),
        "dlopen" | "dlsym" => Some("dynamic_loading"),
        "getenv" | "setenv" | "putenv" => Some("environment_access"),
        "ptrace" => Some("anti_debug"),
        _ => None,
    }
}
