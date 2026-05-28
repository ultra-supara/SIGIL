use serde::{Deserialize, Serialize};

use crate::assess::{PolicyViolation, Verdict};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub name: String,
    pub evidence: Vec<EvidenceItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub address: String,
    pub instruction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCall {
    pub symbol: String,
    pub capability: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedInstruction {
    pub address: String,
    pub instruction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub binary: String,
    pub entry: String,
    pub verdict: Verdict,
    pub capabilities: Vec<CapabilityEvidence>,
    pub external_calls: Vec<ExternalCall>,
    pub unsupported_instructions: Vec<UnsupportedInstruction>,
    pub policy_violations: Vec<PolicyViolation>,
}

impl Evidence {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
