use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OllamaInspectOptions {
    pub model: Option<String>,
    pub models_dir: PathBuf,
    pub host: String,
    pub probe_api: bool,
}

impl OllamaInspectOptions {
    pub fn default_models_dir() -> PathBuf {
        if let Ok(value) = std::env::var("OLLAMA_MODELS") {
            return PathBuf::from(value);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".ollama/models")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiExposure {
    NotProbed,
    Localhost,
    Network,
    PublicBind,
    Unavailable,
}

impl ApiExposure {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotProbed => "not_probed",
            Self::Localhost => "localhost",
            Self::Network => "network",
            Self::PublicBind => "public_bind",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    NotProbed,
    Reachable,
    Unreachable,
}

impl RuntimeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotProbed => "not_probed",
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFile {
    pub digest: String,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaModel {
    pub name: String,
    pub manifest_path: PathBuf,
    pub files: Vec<ModelFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFinding {
    pub id: String,
    pub severity: String,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaReport {
    pub runtime: String,
    pub model: Option<String>,
    pub models_dir: PathBuf,
    pub host: String,
    pub api: ApiExposure,
    pub runtime_status: RuntimeStatus,
    pub version: Option<String>,
    pub models: Vec<OllamaModel>,
    pub findings: Vec<RuntimeFinding>,
    pub verdict: String,
}

impl OllamaReport {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OllamaError {
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse manifest {path}: {source}")]
    ParseManifest {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    config: Option<ManifestDescriptor>,
    #[serde(default)]
    layers: Vec<ManifestDescriptor>,
}

#[derive(Debug, Deserialize)]
struct ManifestDescriptor {
    digest: String,
    #[serde(default, rename = "mediaType")]
    media_type: Option<String>,
}

pub fn inspect_ollama(options: OllamaInspectOptions) -> Result<OllamaReport, OllamaError> {
    let manifests_dir = options.models_dir.join("manifests");
    let manifest_paths = collect_files(&manifests_dir)?;
    let mut findings = Vec::new();
    let mut models = Vec::new();
    for manifest_path in manifest_paths {
        let Some(name) = model_name_from_manifest(&options.models_dir, &manifest_path) else {
            continue;
        };
        if let Some(filter) = &options.model {
            if &name != filter {
                continue;
            }
        }
        let raw = read_to_string(&manifest_path)?;
        let manifest: Manifest =
            serde_json::from_str(&raw).map_err(|source| OllamaError::ParseManifest {
                path: manifest_path.display().to_string(),
                source,
            })?;
        let mut files = Vec::new();
        if let Some(config) = manifest.config {
            push_model_file_or_finding(
                &options.models_dir,
                &config.digest,
                "config",
                &manifest_path,
                &mut files,
                &mut findings,
            )?;
        }
        for layer in manifest.layers {
            let kind = layer
                .media_type
                .as_deref()
                .and_then(|media_type| media_type.rsplit('.').next())
                .unwrap_or("blob");
            push_model_file_or_finding(
                &options.models_dir,
                &layer.digest,
                kind,
                &manifest_path,
                &mut files,
                &mut findings,
            )?;
        }
        files.sort_by(|left, right| left.digest.cmp(&right.digest));
        files.dedup_by(|left, right| left.digest == right.digest);
        models.push(OllamaModel {
            name,
            manifest_path,
            files,
        });
    }
    models.sort_by(|left, right| left.name.cmp(&right.name));

    let static_host_classification = classify_host(&options.host);
    let mut api = if static_host_classification == ApiExposure::PublicBind {
        ApiExposure::PublicBind
    } else if static_host_classification == ApiExposure::Network {
        ApiExposure::Network
    } else {
        ApiExposure::NotProbed
    };
    if static_host_classification == ApiExposure::PublicBind {
        findings.push(RuntimeFinding {
            id: "ollama.public_bind".to_string(),
            severity: "WARN".to_string(),
            message: "Ollama host is configured as a public bind address".to_string(),
            evidence: options.host.clone(),
        });
    }
    if static_host_classification == ApiExposure::Network {
        findings.push(RuntimeFinding {
            id: "ollama.network_endpoint".to_string(),
            severity: "WARN".to_string(),
            message: "Ollama host is configured as a non-local network endpoint".to_string(),
            evidence: options.host.clone(),
        });
    }

    let mut version = None;
    let runtime_status = if options.probe_api {
        match probe_ollama_version(&options.host) {
            Ok(value) => {
                version = value;
                if api != ApiExposure::PublicBind && api != ApiExposure::Network {
                    api = ApiExposure::Localhost;
                }
                RuntimeStatus::Reachable
            }
            Err(_) => {
                if api == ApiExposure::NotProbed {
                    api = ApiExposure::Unavailable;
                }
                RuntimeStatus::Unreachable
            }
        }
    } else {
        RuntimeStatus::NotProbed
    };

    if options.model.is_some() && models.is_empty() {
        findings.push(RuntimeFinding {
            id: "ollama.model_not_found".to_string(),
            severity: "WARN".to_string(),
            message: "Requested model was not found in the Ollama model store".to_string(),
            evidence: options.model.clone().unwrap_or_default(),
        });
    }

    let verdict = if findings.iter().any(|finding| finding.severity == "FAIL") {
        "FAIL"
    } else if findings.iter().any(|finding| finding.severity == "WARN") {
        "WARN"
    } else {
        "PASS"
    }
    .to_string();

    Ok(OllamaReport {
        runtime: "ollama".to_string(),
        model: options.model,
        models_dir: options.models_dir,
        host: options.host,
        api,
        runtime_status,
        version,
        models,
        findings,
        verdict,
    })
}

pub fn render_ai_bom(report: &OllamaReport) -> String {
    let mut lines = vec![
        "# SIGIL AI-BOM".to_string(),
        String::new(),
        format!("- Runtime: `{}`", report.runtime),
        format!("- Host: `{}`", report.host),
        format!("- API exposure: `{}`", report.api.as_str()),
        format!("- Runtime status: `{}`", report.runtime_status.as_str()),
        format!("- Verdict: `{}`", report.verdict),
    ];
    if let Some(version) = &report.version {
        lines.push(format!("- Version: `{version}`"));
    }
    lines.push(String::new());
    lines.push("## Models".to_string());
    if report.models.is_empty() {
        lines.push("- No matching Ollama models found.".to_string());
    }
    for model in &report.models {
        lines.push(format!("- `{}`", model.name));
        lines.push(format!("  - Manifest: `{}`", model.manifest_path.display()));
        for file in &model.files {
            lines.push(format!(
                "  - `{}` size={} sha256=`{}` path=`{}`",
                file.digest,
                file.size,
                file.sha256,
                file.path.display()
            ));
        }
    }
    if !report.findings.is_empty() {
        lines.push(String::new());
        lines.push("## Findings".to_string());
        for finding in &report.findings {
            lines.push(format!(
                "- `{}` {}: {} ({})",
                finding.id, finding.severity, finding.message, finding.evidence
            ));
        }
    }
    lines.join("\n") + "\n"
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, OllamaError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_files_inner(root, &mut files)?;
    Ok(files)
}

fn collect_files_inner(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), OllamaError> {
    for entry in fs::read_dir(path).map_err(|source| OllamaError::ReadDir {
        path: path.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| OllamaError::ReadDir {
            path: path.display().to_string(),
            source,
        })?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_files_inner(&entry_path, files)?;
        } else {
            files.push(entry_path);
        }
    }
    Ok(())
}

fn read_to_string(path: &Path) -> Result<String, OllamaError> {
    fs::read_to_string(path).map_err(|source| OllamaError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn push_model_file_or_finding(
    models_dir: &Path,
    digest: &str,
    kind: &str,
    manifest_path: &Path,
    files: &mut Vec<ModelFile>,
    findings: &mut Vec<RuntimeFinding>,
) -> Result<(), OllamaError> {
    match model_file_for_digest(models_dir, digest, kind)? {
        Some(file) => {
            if let Some(expected) = digest.strip_prefix("sha256:") {
                if file.sha256 != expected {
                    findings.push(RuntimeFinding {
                        id: "ollama.blob_digest_mismatch".to_string(),
                        severity: "FAIL".to_string(),
                        message: "Ollama blob content does not match the manifest digest"
                            .to_string(),
                        evidence: format!(
                            "{} expected={} actual={}",
                            file.path.display(),
                            expected,
                            file.sha256
                        ),
                    });
                }
            }
            files.push(file);
        }
        None => findings.push(RuntimeFinding {
            id: "ollama.blob_missing".to_string(),
            severity: "WARN".to_string(),
            message: "Ollama manifest references a missing blob".to_string(),
            evidence: format!("{} digest={digest}", manifest_path.display()),
        }),
    }
    Ok(())
}

fn model_name_from_manifest(models_dir: &Path, manifest_path: &Path) -> Option<String> {
    let relative = manifest_path
        .strip_prefix(models_dir.join("manifests"))
        .ok()?;
    let parts: Vec<_> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    let tag = parts.last()?.clone();
    let name = parts.get(parts.len() - 2)?.clone();
    Some(format!("{name}:{tag}"))
}

fn model_file_for_digest(
    models_dir: &Path,
    digest: &str,
    kind: &str,
) -> Result<Option<ModelFile>, OllamaError> {
    let blob_path = models_dir.join("blobs").join(digest.replace(':', "-"));
    if !blob_path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&blob_path).map_err(|source| OllamaError::ReadFile {
        path: blob_path.display().to_string(),
        source,
    })?;
    let file = File::open(&blob_path).map_err(|source| OllamaError::ReadFile {
        path: blob_path.display().to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| OllamaError::ReadFile {
                path: blob_path.display().to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let sha256 = hex_lower(&hasher.finalize());
    Ok(Some(ModelFile {
        digest: digest.to_string(),
        path: blob_path,
        size: metadata.len(),
        sha256,
        kind: kind.to_string(),
    }))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn classify_host(host: &str) -> ApiExposure {
    let hostname = host_name_for_classification(host);
    if hostname == "0.0.0.0" || hostname == "::" {
        ApiExposure::PublicBind
    } else if hostname == "localhost" || hostname.starts_with("127.") || hostname == "::1" {
        ApiExposure::Localhost
    } else {
        ApiExposure::Network
    }
}

fn host_name_for_classification(host: &str) -> String {
    let without_scheme = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(host);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_ascii_lowercase();
    }
    authority
        .split(':')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

fn probe_ollama_version(host: &str) -> std::io::Result<Option<String>> {
    let (hostname, port) = parse_http_host(host).unwrap_or(("127.0.0.1".to_string(), 11434));
    let mut stream = TcpStream::connect((hostname.as_str(), port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request = format!(
        "GET /api/version HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        hostname, port
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(extract_json_string_field(&response, "version"))
}

fn parse_http_host(host: &str) -> Option<(String, u16)> {
    let without_scheme = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(host);
    let authority = without_scheme.split('/').next()?;
    let (hostname, port) = if authority.starts_with('[') {
        let (hostname, rest) = authority.split_once(']')?;
        let port = rest.strip_prefix(':').unwrap_or("11434");
        (hostname.trim_start_matches('[').to_string(), port)
    } else if let Some((hostname, port)) = authority.rsplit_once(':') {
        (hostname.to_string(), port)
    } else {
        (authority.to_string(), "11434")
    };
    let port = port.parse().ok()?;
    Some((hostname, port))
}

fn extract_json_string_field(response: &str, field: &str) -> Option<String> {
    let body = response.split("\r\n\r\n").nth(1)?;
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}
