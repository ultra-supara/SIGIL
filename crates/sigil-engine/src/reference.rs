//! Reference manifests: the per-member contents of official release archives (plan §0.5.1,
//! §4.4.2; PR-4a). Embedded unchanged as produced in PR-0 (`scripts/refmanifest/`). A match is a
//! comparison with those archives' contents, not a signature check.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use sigil_model::{KnowledgeKind, KnowledgeRef, MemberKind, RefSetId, Sha256Hex};

/// The release archives of one reference set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSet {
    pub id: RefSetId,
    pub version: String,
    /// SHA-256 over the embedded files: each file's name, a NUL, its length in decimal, a NUL,
    /// then its bytes, in name order.
    pub sha256: Sha256Hex,
    /// In name order of their files.
    pub releases: Vec<RefRelease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRelease {
    pub tag: String,
    /// By archive path.
    pub members: BTreeMap<String, RefMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefMember {
    File { sha256: Sha256Hex, size: u64 },
    Symlink { target: String },
    Directory,
}

impl RefMember {
    pub fn kind(&self) -> MemberKind {
        match self {
            RefMember::File { .. } => MemberKind::File,
            RefMember::Symlink { .. } => MemberKind::Symlink,
            RefMember::Directory => MemberKind::Directory,
        }
    }
}

impl RefSet {
    /// The session's knowledge entry for this set.
    pub fn knowledge(&self) -> KnowledgeRef {
        KnowledgeRef {
            kind: KnowledgeKind::ReferenceManifest,
            id: self.id.as_str().to_string(),
            version: self.version.clone(),
            sha256: self.sha256.clone(),
        }
    }
}

const OFFICIAL: &[(&str, &str)] = &[
    (
        "ollama-v0.30.5-linux-amd64.json",
        include_str!("../refs/ollama-official/ollama-v0.30.5-linux-amd64.json"),
    ),
    (
        "ollama-v0.30.6-linux-amd64.json",
        include_str!("../refs/ollama-official/ollama-v0.30.6-linux-amd64.json"),
    ),
    (
        "ollama-v0.30.7-linux-amd64.json",
        include_str!("../refs/ollama-official/ollama-v0.30.7-linux-amd64.json"),
    ),
];

/// The official Ollama release manifests embedded in this build. An error only if the embedded
/// files are malformed, which `tests/refset.rs` rules out.
pub fn official() -> Result<&'static RefSet, String> {
    static SET: OnceLock<Result<RefSet, String>> = OnceLock::new();
    SET.get_or_init(|| parse_set("ollama-official", "2026-10-07", OFFICIAL))
        .as_ref()
        .map_err(Clone::clone)
}

#[derive(Deserialize)]
struct RawManifest {
    tag: String,
    entries: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[allow(dead_code)]
    mode: String,
    sha256: Option<String>,
    size: Option<u64>,
    link: Option<String>,
}

/// Parses manifest files into a set. Every entry must be a well-formed file, symlink, or
/// directory with a relative, normalized name, listed once.
pub fn parse_set(id: &str, version: &str, files: &[(&str, &str)]) -> Result<RefSet, String> {
    let mut sorted: Vec<&(&str, &str)> = files.iter().collect();
    sorted.sort_by_key(|(name, _)| *name);
    let mut hasher = Sha256::new();
    let mut releases = vec![];
    for (name, text) in sorted {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(text.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(text.as_bytes());
        let raw: RawManifest = serde_json::from_str(text).map_err(|e| format!("{name}: {e}"))?;
        let mut members = BTreeMap::new();
        for e in raw.entries {
            let path = e.name.trim_end_matches('/');
            if path.is_empty()
                || path.starts_with('/')
                || path
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(format!(
                    "{name}: member {:?} is not a relative path",
                    e.name
                ));
            }
            let member = match (e.kind.as_str(), e.sha256, e.size, e.link) {
                ("0", Some(sha), Some(size), None) => RefMember::File {
                    sha256: Sha256Hex::new(sha).map_err(|err| format!("{name}: {err}"))?,
                    size,
                },
                ("2", None, None, Some(target)) if !target.is_empty() => {
                    RefMember::Symlink { target }
                }
                ("5", None, None, None) => RefMember::Directory,
                (kind, ..) => {
                    return Err(format!(
                        "{name}: member {path}: type {kind:?} is not a file, symlink, or \
                         directory with its fields"
                    ))
                }
            };
            if members.insert(path.to_string(), member).is_some() {
                return Err(format!("{name}: member {path} appears twice"));
            }
        }
        releases.push(RefRelease {
            tag: raw.tag,
            members,
        });
    }
    Ok(RefSet {
        id: RefSetId::new(id).map_err(|e| e.to_string())?,
        version: version.to_string(),
        sha256: Sha256Hex::new(format!("{:x}", hasher.finalize())).map_err(|e| e.to_string())?,
        releases,
    })
}
