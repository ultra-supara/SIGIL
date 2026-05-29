use serde::{Deserialize, Serialize};

use crate::assess::Verdict;
use crate::ollama::{ApiExposure, OllamaReport, RuntimeStatus};
use crate::runtime::RuntimeExposure;

/// Stable AI-BOM schema version. Bump minor for additive changes, major for
/// breaking changes.
pub const SCHEMA_VERSION: &str = "1.0";

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
    let mut lines = vec![
        "# SIGIL AI-BOM".to_string(),
        String::new(),
        format!("- Runtime: `{}`", bom.runtime.name),
        format!("- Host: `{}`", bom.runtime.host),
        format!("- API exposure: `{}`", bom.runtime.api_exposure.as_str()),
        format!(
            "- Runtime exposure: `{}`",
            bom.runtime.exposure.class.as_str()
        ),
        format!("- Runtime status: `{}`", bom.runtime.status.as_str()),
        format!("- Verdict: `{}`", bom.verdict.as_str()),
    ];
    if let Some(version) = &bom.runtime.version {
        lines.push(format!("- Version: `{version}`"));
    }
    for bind in &bom.runtime.exposure.observed {
        match &bind.process {
            Some(process) => lines.push(format!(
                "- Runtime bind: `{}:{}` process=`{process}`",
                bind.addr, bind.port
            )),
            None => lines.push(format!("- Runtime bind: `{}:{}`", bind.addr, bind.port)),
        }
    }
    lines.push(String::new());
    lines.push("## Models".to_string());
    if bom.models.is_empty() {
        lines.push("- No matching Ollama models found.".to_string());
    }
    for model in &bom.models {
        lines.push(format!("- `{}`", model.name));
        if let Some(manifest) = &model.manifest_path {
            lines.push(format!("  - Manifest: `{manifest}`"));
        }
        for file in &model.files {
            lines.push(format!(
                "  - `{}` size={} sha256=`{}` path=`{}`",
                file.digest, file.size, file.sha256, file.path
            ));
        }
    }
    if !bom.findings.is_empty() {
        lines.push(String::new());
        lines.push("## Findings".to_string());
        for finding in &bom.findings {
            lines.push(format!(
                "- `{}` {}: {} ({})",
                finding.id,
                finding.severity.as_str(),
                finding.message,
                finding.evidence
            ));
        }
    }
    lines.join("\n") + "\n"
}

fn finding_category(id: &str) -> FindingCategory {
    match id {
        "ollama.invalid_blob_digest"
        | "ollama.blob_digest_mismatch"
        | "ollama.blob_missing"
        | "ollama.model_not_found" => FindingCategory::Model,
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
        ] {
            assert_eq!(finding_category(id), FindingCategory::Model, "{id}");
        }
    }

    #[test]
    fn unknown_finding_id_defaults_to_runtime() {
        assert_eq!(finding_category("ollama.future_thing"), FindingCategory::Runtime);
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
