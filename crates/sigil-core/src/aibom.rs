use serde::{Deserialize, Serialize};

use crate::assess::Verdict;
use crate::ollama::{ApiExposure, LicenseInfo, ModelProvenance, OllamaReport, RuntimeStatus};
use crate::runtime::RuntimeExposure;

/// Stable AI-BOM schema version. Bump minor for additive changes, major for
/// breaking changes.
pub const SCHEMA_VERSION: &str = "1.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBom {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub runtime: RuntimeInfo,
    pub models: Vec<ModelEntry>,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub name: String,
    pub host: String,
    // None is reserved for future runtimes without an on-disk model store; always Some for Ollama.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models_dir: Option<String>,
    pub api_exposure: ApiExposure,
    pub status: RuntimeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub exposure: ExposureInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureInfo {
    pub class: RuntimeExposure,
    pub source: String,
    pub observed: Vec<BindEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindEntry {
    pub addr: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    // None is reserved for runtimes without per-model manifests; always Some for Ollama.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    pub files: Vec<FileEntry>,
    pub provenance: ProvenanceEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub digest: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub layer_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseEntry {
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_id: Option<String>,
    pub text_excerpt: String,
}

impl From<&ModelProvenance> for ProvenanceEntry {
    fn from(value: &ModelProvenance) -> Self {
        Self {
            registry: value.registry.clone(),
            namespace: value.namespace.clone(),
            model: value.model.clone(),
            tag: value.tag.clone(),
            config_digest: value.config_digest.clone(),
            layer_digests: value.layer_digests.clone(),
        }
    }
}

impl From<&LicenseInfo> for LicenseEntry {
    fn from(value: &LicenseInfo) -> Self {
        Self {
            digest: value.digest.clone(),
            size: value.size,
            spdx_id: value.spdx_id.clone(),
            text_excerpt: value.text_excerpt.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Runtime,
    Model,
    // Reserved for native-binary findings; not produced by the Ollama path yet.
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

impl AiBom {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl From<&OllamaReport> for AiBom {
    fn from(report: &OllamaReport) -> Self {
        let observed = report
            .runtime_exposure
            .observed
            .iter()
            .map(|bind| BindEntry {
                addr: bind.addr.clone(),
                port: bind.port,
                process: bind.process.clone(),
            })
            .collect();
        let models = report
            .models
            .iter()
            .map(|model| ModelEntry {
                name: model.name.clone(),
                manifest_path: Some(model.manifest_path.display().to_string()),
                files: model
                    .files
                    .iter()
                    .map(|file| FileEntry {
                        digest: file.digest.clone(),
                        path: file.path.display().to_string(),
                        size: file.size,
                        sha256: file.sha256.clone(),
                        kind: file.kind.clone(),
                    })
                    .collect(),
                provenance: ProvenanceEntry::from(&model.provenance),
                license: model.license.as_ref().map(LicenseEntry::from),
            })
            .collect();
        let findings = report
            .findings
            .iter()
            .map(|finding| Finding {
                id: finding.id.clone(),
                category: finding_category(&finding.id),
                severity: severity_from_str(&finding.severity),
                message: finding.message.clone(),
                evidence: finding.evidence.clone(),
            })
            .collect();
        AiBom {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: ToolInfo {
                name: "sigil".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            runtime: RuntimeInfo {
                name: report.runtime.clone(),
                host: report.host.clone(),
                models_dir: Some(report.models_dir.display().to_string()),
                api_exposure: report.api.clone(),
                status: report.runtime_status.clone(),
                version: report.version.clone(),
                exposure: ExposureInfo {
                    class: report.runtime_exposure.class,
                    source: report.runtime_exposure.source.clone(),
                    observed,
                },
            },
            models,
            findings,
            verdict: verdict_from_str(&report.verdict),
        }
    }
}

pub fn render_ai_bom(bom: &AiBom) -> String {
    let mut lines = Vec::new();
    lines.push(format!("# SIGIL AI-BOM: [{}]", bom.verdict.as_str()));
    lines.push(String::new());
    lines.push(format!("- Schema: `{}`", bom.schema_version));
    lines.push(format!("- Tool: `{} {}`", bom.tool.name, bom.tool.version));
    lines.push(String::new());

    push_runtime_section(&mut lines, bom);
    push_models_section(&mut lines, bom);
    push_findings_section(&mut lines, bom);

    lines.join("\n") + "\n"
}

fn push_runtime_section(lines: &mut Vec<String>, bom: &AiBom) {
    lines.push("## Runtime".to_string());
    lines.push("| Property | Value |".to_string());
    lines.push("|----------|-------|".to_string());
    lines.push(format!("| Name | `{}` |", bom.runtime.name));
    lines.push(format!("| Host | `{}` |", bom.runtime.host));
    if let Some(version) = &bom.runtime.version {
        lines.push(format!("| Version | `{version}` |"));
    }
    if let Some(models_dir) = &bom.runtime.models_dir {
        lines.push(format!("| Models dir | `{models_dir}` |"));
    }
    lines.push(format!(
        "| API exposure | `{}` |",
        bom.runtime.api_exposure.as_str()
    ));
    lines.push(format!(
        "| Runtime exposure | `{}` (source: `{}`) |",
        bom.runtime.exposure.class.as_str(),
        bom.runtime.exposure.source
    ));
    lines.push(format!("| Status | `{}` |", bom.runtime.status.as_str()));
    lines.push(String::new());

    if !bom.runtime.exposure.observed.is_empty() {
        lines.push("### Observed binds".to_string());
        lines.push("| Address | Process |".to_string());
        lines.push("|---------|---------|".to_string());
        for bind in &bom.runtime.exposure.observed {
            let process = bind.process.as_deref().unwrap_or("");
            let process_cell = if process.is_empty() {
                String::new()
            } else {
                format!("`{process}`")
            };
            lines.push(format!(
                "| `{}:{}` | {} |",
                bind.addr, bind.port, process_cell
            ));
        }
        lines.push(String::new());
    }
}

fn push_models_section(lines: &mut Vec<String>, bom: &AiBom) {
    lines.push("## Models".to_string());
    if bom.models.is_empty() {
        lines.push("_No matching models found._".to_string());
        lines.push(String::new());
        return;
    }
    for model in &bom.models {
        lines.push(String::new());
        lines.push(format!("### `{}`", model.name));
        match &model.license {
            Some(license) => lines.push(format!(
                "- **License:** `{}` (digest `{}`, {} B)",
                license.spdx_id.as_deref().unwrap_or("unknown"),
                license.digest,
                license.size,
            )),
            None => lines.push("- **License:** _missing_".to_string()),
        }
        let provenance = format!(
            "{} / {} / {} / {}",
            model.provenance.registry.as_deref().unwrap_or("unknown"),
            model.provenance.namespace.as_deref().unwrap_or("-"),
            model.provenance.model.as_deref().unwrap_or("unknown"),
            model.provenance.tag.as_deref().unwrap_or("unknown"),
        );
        lines.push(format!("- **Provenance:** `{provenance}`"));
        if let Some(manifest) = &model.manifest_path {
            lines.push(format!("- **Manifest:** `{manifest}`"));
        }
        if !model.files.is_empty() {
            lines.push(String::new());
            lines.push("| Kind | Size | Digest |".to_string());
            lines.push("|------|------|--------|".to_string());
            for file in &model.files {
                lines.push(format!(
                    "| {} | {} B | `{}` |",
                    file.kind, file.size, file.digest
                ));
            }
        }
    }
    lines.push(String::new());
}

fn push_findings_section(lines: &mut Vec<String>, bom: &AiBom) {
    lines.push("## Findings".to_string());
    if bom.findings.is_empty() {
        lines.push("_No findings._".to_string());
        return;
    }
    lines.push("| Severity | Category | ID | Message | Evidence |".to_string());
    lines.push("|----------|----------|----|---------|----------|".to_string());
    for finding in &bom.findings {
        lines.push(format!(
            "| {} | {} | `{}` | {} | `{}` |",
            finding.severity.as_str(),
            finding_category_str(finding.category),
            finding.id,
            finding.message,
            finding.evidence,
        ));
    }
}

fn finding_category_str(category: FindingCategory) -> &'static str {
    match category {
        FindingCategory::Runtime => "runtime",
        FindingCategory::Model => "model",
        FindingCategory::Binary => "binary",
    }
}

fn finding_category(id: &str) -> FindingCategory {
    match id {
        "ollama.invalid_blob_digest"
        | "ollama.blob_digest_mismatch"
        | "ollama.blob_missing"
        | "ollama.model_not_found"
        | "ollama.license_missing"
        | "ollama.provenance_unknown" => FindingCategory::Model,
        _ => FindingCategory::Runtime,
    }
}

fn severity_from_str(value: &str) -> Severity {
    match value {
        "FAIL" => Severity::Fail,
        _ => Severity::Warn,
    }
}

fn verdict_from_str(value: &str) -> Verdict {
    match value {
        "FAIL" => Verdict::Fail,
        "WARN" => Verdict::Warn,
        _ => Verdict::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serializes_screaming() {
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"WARN\"");
        assert_eq!(serde_json::to_string(&Severity::Fail).unwrap(), "\"FAIL\"");
    }

    #[test]
    fn finding_category_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&FindingCategory::Runtime).unwrap(),
            "\"runtime\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::Model).unwrap(),
            "\"model\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::Binary).unwrap(),
            "\"binary\""
        );
    }

    #[test]
    fn runtime_finding_ids_map_to_runtime_category() {
        for id in [
            "ollama.public_bind",
            "ollama.network_endpoint",
            "ollama.runtime_lan_exposure",
            "ollama.runtime_public_bind",
            "ollama.runtime_docker_published",
            "ollama.runtime_proxy",
        ] {
            assert_eq!(finding_category(id), FindingCategory::Runtime, "{id}");
        }
    }

    #[test]
    fn model_finding_ids_map_to_model_category() {
        for id in [
            "ollama.invalid_blob_digest",
            "ollama.blob_digest_mismatch",
            "ollama.blob_missing",
            "ollama.model_not_found",
            "ollama.license_missing",
            "ollama.provenance_unknown",
        ] {
            assert_eq!(finding_category(id), FindingCategory::Model, "{id}");
        }
    }

    #[test]
    fn unknown_finding_id_defaults_to_runtime() {
        assert_eq!(
            finding_category("ollama.future_thing"),
            FindingCategory::Runtime
        );
    }

    #[test]
    fn severity_and_verdict_map_from_strings() {
        assert_eq!(severity_from_str("FAIL"), Severity::Fail);
        assert_eq!(severity_from_str("WARN"), Severity::Warn);
        assert_eq!(severity_from_str("anything"), Severity::Warn);
        assert_eq!(verdict_from_str("FAIL"), Verdict::Fail);
        assert_eq!(verdict_from_str("WARN"), Verdict::Warn);
        assert_eq!(verdict_from_str("PASS"), Verdict::Pass);
    }
}
