use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::{classify_runtime_exposure, RuntimeExposureReport, RuntimeListeners};

const LICENSE_MEDIA_TYPE: &str = "application/vnd.ollama.image.license";
const LICENSE_EXCERPT_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OllamaInspectOptions {
    pub model: Option<String>,
    pub models_dir: PathBuf,
    pub host: String,
    pub probe_api: bool,
    pub runtime_listeners: RuntimeListeners,
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
pub struct ModelProvenance {
    pub registry: Option<String>,
    pub namespace: Option<String>,
    pub model: Option<String>,
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub layer_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_id: Option<String>,
    pub text_excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaModel {
    pub name: String,
    pub manifest_path: PathBuf,
    pub files: Vec<ModelFile>,
    pub provenance: ModelProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseInfo>,
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
    pub runtime_exposure: RuntimeExposureReport,
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
        let Some((name, mut provenance)) = parse_manifest_path(&options.models_dir, &manifest_path)
        else {
            findings.push(RuntimeFinding {
                id: "ollama.provenance_unknown".to_string(),
                severity: "WARN".to_string(),
                message: "Ollama manifest path is too shallow to determine provenance".to_string(),
                evidence: manifest_path.display().to_string(),
            });
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
        let mut license = None;
        if let Some(config) = manifest.config {
            provenance.config_digest = Some(config.digest.clone());
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
            provenance.layer_digests.push(layer.digest.clone());
            let is_license = layer
                .media_type
                .as_deref()
                .map(|media_type| media_type == LICENSE_MEDIA_TYPE)
                .unwrap_or(false);
            let kind = layer
                .media_type
                .as_deref()
                .and_then(|media_type| media_type.rsplit('.').next())
                .unwrap_or("blob");
            let before_len = files.len();
            push_model_file_or_finding(
                &options.models_dir,
                &layer.digest,
                kind,
                &manifest_path,
                &mut files,
                &mut findings,
            )?;
            if is_license && license.is_none() {
                if let Some(file) = files.get(before_len) {
                    let text = read_license_excerpt(&file.path)?;
                    let spdx_id = detect_spdx_id(&text);
                    license = Some(LicenseInfo {
                        digest: file.digest.clone(),
                        size: file.size,
                        spdx_id,
                        text_excerpt: text,
                    });
                }
            }
        }
        files.sort_by(|left, right| left.digest.cmp(&right.digest));
        files.dedup_by(|left, right| left.digest == right.digest);
        if license.is_none() {
            findings.push(RuntimeFinding {
                id: "ollama.license_missing".to_string(),
                severity: "WARN".to_string(),
                message: "Ollama manifest does not reference a license layer".to_string(),
                evidence: manifest_path.display().to_string(),
            });
        }
        models.push(OllamaModel {
            name,
            manifest_path,
            files,
            provenance,
            license,
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

    let ollama_port = resolve_ollama_port(&options.host);
    let runtime_exposure =
        classify_runtime_exposure(&options.runtime_listeners.snapshot(), ollama_port);
    push_runtime_exposure_finding(&runtime_exposure, ollama_port, &mut findings);

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
        runtime_exposure,
        runtime_status,
        version,
        models,
        findings,
        verdict,
    })
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
    if !is_valid_ollama_digest(digest) {
        findings.push(RuntimeFinding {
            id: "ollama.invalid_blob_digest".to_string(),
            severity: "WARN".to_string(),
            message: "Ollama manifest references an invalid blob digest".to_string(),
            evidence: format!("{} digest={digest}", manifest_path.display()),
        });
        return Ok(());
    }

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

/// Returns `(display_name, ModelProvenance)` parsed from the manifest path.
///
/// Ollama lays manifests at `<models_dir>/manifests/<registry>/<namespace...>/<model>/<tag>`.
/// We treat the last component as the tag, the second-to-last as the model name,
/// the first as the registry, and everything in between as the namespace
/// (joined with `/`). Anything shallower than 3 components is treated as
/// unknown provenance and surfaces as a finding upstream.
fn parse_manifest_path(
    models_dir: &Path,
    manifest_path: &Path,
) -> Option<(String, ModelProvenance)> {
    let relative = manifest_path
        .strip_prefix(models_dir.join("manifests"))
        .ok()?;
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    let tag = parts.last()?.clone();
    let model = parts.get(parts.len() - 2)?.clone();
    let registry = parts.first()?.clone();
    let namespace = if parts.len() > 3 {
        Some(parts[1..parts.len() - 2].join("/"))
    } else {
        None
    };
    let display = format!("{model}:{tag}");
    let provenance = ModelProvenance {
        registry: Some(registry),
        namespace,
        model: Some(model),
        tag: Some(tag),
        config_digest: None,
        layer_digests: Vec::new(),
    };
    Some((display, provenance))
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

fn is_valid_ollama_digest(digest: &str) -> bool {
    let Some(value) = digest.strip_prefix("sha256:") else {
        return false;
    };
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn resolve_ollama_port(host: &str) -> u16 {
    parse_http_host(host).map(|(_, port)| port).unwrap_or(11434)
}

fn push_runtime_exposure_finding(
    exposure: &RuntimeExposureReport,
    port: u16,
    findings: &mut Vec<RuntimeFinding>,
) {
    use crate::runtime::RuntimeExposure;

    let (id, message) = match exposure.class {
        RuntimeExposure::Lan => (
            "ollama.runtime_lan_exposure",
            "Ollama is bound to a LAN-reachable address",
        ),
        RuntimeExposure::PublicBind => (
            "ollama.runtime_public_bind",
            "Ollama is bound to a public/wildcard address",
        ),
        RuntimeExposure::DockerPublished => (
            "ollama.runtime_docker_published",
            "Ollama appears published through a Docker port mapping",
        ),
        RuntimeExposure::Proxy => (
            "ollama.runtime_proxy",
            "Ollama port appears fronted by a reverse proxy",
        ),
        RuntimeExposure::Localhost | RuntimeExposure::Unknown => return,
    };

    let observed = if exposure.observed.is_empty() {
        format!("port={port}")
    } else {
        exposure
            .observed
            .iter()
            .map(|bind| match &bind.process {
                Some(process) => format!("{}:{} ({process})", bind.addr, bind.port),
                None => format!("{}:{}", bind.addr, bind.port),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    findings.push(RuntimeFinding {
        id: id.to_string(),
        severity: "WARN".to_string(),
        message: message.to_string(),
        evidence: observed,
    });
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

fn read_license_excerpt(path: &Path) -> Result<String, OllamaError> {
    let file = File::open(path).map_err(|source| OllamaError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0_u8; LICENSE_EXCERPT_BYTES];
    let mut total = 0;
    loop {
        let read = reader
            .read(&mut buffer[total..])
            .map_err(|source| OllamaError::ReadFile {
                path: path.display().to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        total += read;
        if total == buffer.len() {
            break;
        }
    }
    buffer.truncate(total);
    Ok(String::from_utf8_lossy(&buffer).trim().to_string())
}

fn detect_spdx_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let first_line = trimmed.lines().next().unwrap_or(trimmed).trim();
    // Fast path: the blob is already an SPDX short identifier (e.g. "MIT",
    // "Apache-2.0", "GPL-3.0-only"). Reject prose so we never claim an SPDX id
    // we did not actually identify.
    if !first_line.is_empty()
        && first_line.len() <= 32
        && !first_line.contains(' ')
        && first_line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Some(first_line.to_string());
    }
    detect_spdx_from_body(trimmed)
}

/// Match well-known license preambles in the first ~256 bytes of a license
/// blob. Each pattern is required to be unambiguous so we never confuse two
/// similar licenses. Ordering matters — the most-specific variant must be
/// checked first (LGPL before GPL, version 3 before version 2).
fn detect_spdx_from_body(text: &str) -> Option<String> {
    let condensed = condense_whitespace(text);
    let lc = condensed.as_str();

    if lc.contains("gnu lesser general public license") {
        if lc.contains("version 3") {
            return Some("LGPL-3.0".to_string());
        }
        if lc.contains("version 2.1") {
            return Some("LGPL-2.1".to_string());
        }
    }
    if lc.contains("gnu general public license") {
        if lc.contains("version 3") {
            return Some("GPL-3.0".to_string());
        }
        if lc.contains("version 2") {
            return Some("GPL-2.0".to_string());
        }
    }
    if lc.contains("mozilla public license") && lc.contains("version 2.0") {
        return Some("MPL-2.0".to_string());
    }
    if lc.contains("apache license") && lc.contains("version 2.0") {
        return Some("Apache-2.0".to_string());
    }
    if lc.contains("redistribution and use in source and binary forms") {
        if lc.contains("neither the name") {
            return Some("BSD-3-Clause".to_string());
        }
        return Some("BSD-2-Clause".to_string());
    }
    if lc.starts_with("isc license")
        || (lc.contains("permission to use, copy, modify")
            && lc.contains("with or without fee is hereby granted"))
    {
        return Some("ISC".to_string());
    }
    if lc.starts_with("mit license") || lc.contains("permission is hereby granted, free of charge")
    {
        return Some("MIT".to_string());
    }
    None
}

fn condense_whitespace(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::detect_spdx_id;

    #[test]
    fn fast_path_accepts_short_spdx_token() {
        assert_eq!(detect_spdx_id("MIT"), Some("MIT".to_string()));
        assert_eq!(detect_spdx_id("Apache-2.0"), Some("Apache-2.0".to_string()));
        assert_eq!(
            detect_spdx_id("BSD-3-Clause"),
            Some("BSD-3-Clause".to_string())
        );
    }

    #[test]
    fn fast_path_rejects_empty_or_prose() {
        assert_eq!(detect_spdx_id(""), None);
        assert_eq!(detect_spdx_id("   "), None);
    }

    #[test]
    fn detects_apache_2_0_from_body() {
        let body = "                                 Apache License\n\
                    \n                           Version 2.0, January 2004\n\
                    \n                        http://www.apache.org/licenses/\n\
                    \n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION";
        assert_eq!(detect_spdx_id(body), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn detects_mit_from_permission_clause() {
        let body = "MIT License\n\
                    \n\
                    Copyright (c) 2024 Example\n\
                    \n\
                    Permission is hereby granted, free of charge, to any person obtaining a copy\
                    of this software and associated documentation files (the \"Software\"), ...";
        assert_eq!(detect_spdx_id(body), Some("MIT".to_string()));
    }

    #[test]
    fn detects_mit_from_bare_permission_text() {
        let body = "Permission is hereby granted, free of charge, to any person obtaining a copy\
                    of this software and associated documentation files...";
        assert_eq!(detect_spdx_id(body), Some("MIT".to_string()));
    }

    #[test]
    fn detects_mpl_2_0_from_body() {
        let body = "Mozilla Public License Version 2.0\n\
                    ==================================\n\
                    \n1. Definitions";
        assert_eq!(detect_spdx_id(body), Some("MPL-2.0".to_string()));
    }

    #[test]
    fn detects_gpl_3_0_from_body() {
        let body = "                    GNU GENERAL PUBLIC LICENSE\n\
                    \n                       Version 3, 29 June 2007\n\
                    \n Copyright (C) 2007 Free Software Foundation, Inc.";
        assert_eq!(detect_spdx_id(body), Some("GPL-3.0".to_string()));
    }

    #[test]
    fn detects_gpl_2_0_from_body() {
        let body = "                    GNU GENERAL PUBLIC LICENSE\n\
                    \n                       Version 2, June 1991\n\
                    \n Copyright (C) 1989, 1991 Free Software Foundation, Inc.";
        assert_eq!(detect_spdx_id(body), Some("GPL-2.0".to_string()));
    }

    #[test]
    fn detects_lgpl_3_0_from_body() {
        let body = "                   GNU LESSER GENERAL PUBLIC LICENSE\n\
                    \n                       Version 3, 29 June 2007\n";
        assert_eq!(detect_spdx_id(body), Some("LGPL-3.0".to_string()));
    }

    #[test]
    fn detects_lgpl_2_1_from_body() {
        let body = "                  GNU LESSER GENERAL PUBLIC LICENSE\n\
                    \n                       Version 2.1, February 1999\n";
        assert_eq!(detect_spdx_id(body), Some("LGPL-2.1".to_string()));
    }

    #[test]
    fn detects_bsd_3_clause_from_body() {
        let body = "Copyright (c) 2024, Example\n\
                    All rights reserved.\n\
                    \n\
                    Redistribution and use in source and binary forms, with or without\
                    modification, are permitted provided that the following conditions are met:\n\
                    \n\
                    1. Redistributions of source code must retain the above copyright notice,\n\
                    2. Redistributions in binary form must reproduce the above copyright notice,\n\
                    3. Neither the name of the copyright holder nor the names of its contributors\
                    may be used to endorse or promote products derived from this software\
                    without specific prior written permission.";
        assert_eq!(detect_spdx_id(body), Some("BSD-3-Clause".to_string()));
    }

    #[test]
    fn detects_bsd_2_clause_from_body() {
        let body = "Copyright (c) 2024, Example\n\
                    All rights reserved.\n\
                    \n\
                    Redistribution and use in source and binary forms, with or without\
                    modification, are permitted provided that the following conditions are met:\n\
                    \n\
                    1. Redistributions of source code must retain the above copyright notice,\n\
                    2. Redistributions in binary form must reproduce the above copyright notice,\n\
                    \n\
                    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS";
        assert_eq!(detect_spdx_id(body), Some("BSD-2-Clause".to_string()));
    }

    #[test]
    fn detects_isc_from_body() {
        let body = "ISC License\n\
                    \n\
                    Copyright (c) 2024 Example\n\
                    \n\
                    Permission to use, copy, modify, and/or distribute this software for any\
                    purpose with or without fee is hereby granted.";
        assert_eq!(detect_spdx_id(body), Some("ISC".to_string()));
    }

    #[test]
    fn unknown_license_body_returns_none() {
        let body = "Some random text that is not a known license preamble.\n\
                    Just prose without any well-known signature.";
        assert_eq!(detect_spdx_id(body), None);
    }
}
