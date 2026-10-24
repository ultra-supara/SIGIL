//! Reference manifests: the per-member contents of official release archives (plan §0.5.1,
//! §4.4.2; PR-4a). Embedded unchanged as produced in PR-0 (`scripts/refmanifest/`). A match is a
//! comparison with those archives' contents, not a signature check. With them, `commits.toml`:
//! what each release's own files report (PR-4c-2c).

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
    /// What the release's own files report, from `commits.toml` (PR-4c-2c). Empty without an
    /// entry: such a release is never a candidate of an open claim.
    pub commits: Vec<RefCommit>,
}

/// The value one of a release's files reports for an embedded field (PR-4c-2c): SIGIL reads
/// `value` for `field` from the release's member `member`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefCommit {
    pub field: String,
    pub member: String,
    pub value: String,
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
    (
        COMMITS,
        include_str!("../refs/ollama-official/commits.toml"),
    ),
];

/// The official Ollama release manifests and their `commits.toml` embedded in this build. An
/// error only if the embedded files are malformed, which `tests/refset.rs` rules out.
pub fn official() -> Result<&'static RefSet, String> {
    static SET: OnceLock<Result<RefSet, String>> = OnceLock::new();
    SET.get_or_init(|| parse_set("ollama-official", "2026-10-24", OFFICIAL))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommits {
    release: Vec<RawReleaseCommits>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReleaseCommits {
    tag: String,
    commits: Vec<RawCommit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommit {
    field: String,
    member: String,
    value: String,
}

/// The name of the commit data among a set's files (PR-4c-2c).
pub const COMMITS: &str = "commits.toml";

/// Parses a set's files: manifests (`*.json`) and, optionally, one [`COMMITS`]. Any other file
/// name is an error. Every manifest entry must be a well-formed file, symlink, or directory with
/// a relative, normalized name, listed once, and every manifest has its own tag. In [`COMMITS`],
/// each release of the set has at most one entry, with at least one commit. A commit's field is
/// non-empty ASCII graphic text, once per release; its member is a file of that release; its
/// value is 7 to 40 lowercase hex digits.
pub fn parse_set(id: &str, version: &str, files: &[(&str, &str)]) -> Result<RefSet, String> {
    let mut sorted: Vec<&(&str, &str)> = files.iter().collect();
    sorted.sort_by_key(|(name, _)| *name);
    let mut hasher = Sha256::new();
    let mut releases = vec![];
    let mut commits = None;
    for (name, text) in sorted {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(text.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(text.as_bytes());
        if *name == COMMITS {
            if commits.replace(*text).is_some() {
                return Err(format!("{COMMITS}: listed twice"));
            }
            continue;
        }
        if !name.ends_with(".json") {
            return Err(format!("{name}: neither a manifest (.json) nor {COMMITS}"));
        }
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
        if releases.iter().any(|r: &RefRelease| r.tag == raw.tag) {
            return Err(format!("{name}: release {} is listed twice", raw.tag));
        }
        releases.push(RefRelease {
            tag: raw.tag,
            members,
            commits: vec![],
        });
    }
    if let Some(text) = commits {
        add_commits(&mut releases, text)?;
    }
    Ok(RefSet {
        id: RefSetId::new(id).map_err(|e| e.to_string())?,
        version: version.to_string(),
        sha256: Sha256Hex::new(format!("{:x}", hasher.finalize())).map_err(|e| e.to_string())?,
        releases,
    })
}

/// Adds [`COMMITS`] to the releases it names.
fn add_commits(releases: &mut [RefRelease], text: &str) -> Result<(), String> {
    let raw: RawCommits = toml::from_str(text).map_err(|e| format!("{COMMITS}: {e}"))?;
    for entry in raw.release {
        let tag = entry.tag;
        let release = releases
            .iter_mut()
            .find(|r| r.tag == tag)
            .ok_or_else(|| format!("{COMMITS}: release {tag} is not in the set"))?;
        if !release.commits.is_empty() {
            return Err(format!("{COMMITS}: release {tag} is listed twice"));
        }
        if entry.commits.is_empty() {
            return Err(format!("{COMMITS}: release {tag} lists no commit"));
        }
        for c in entry.commits {
            let at = format!("{COMMITS}: {tag} {:?}", c.field);
            if c.field.is_empty() || !c.field.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(format!("{at}: the field is not ASCII graphic text"));
            }
            if release.commits.iter().any(|x| x.field == c.field) {
                return Err(format!("{at}: the field is listed twice"));
            }
            if !matches!(release.members.get(&c.member), Some(RefMember::File { .. })) {
                return Err(format!("{at}: {:?} is not a file of the release", c.member));
            }
            if !sigil_model::is_commit(c.value.as_bytes()) {
                return Err(format!(
                    "{at}: {:?} is not 7 to 40 lowercase hex digits",
                    c.value
                ));
            }
            release.commits.push(RefCommit {
                field: c.field,
                member: c.member,
                value: c.value,
            });
        }
    }
    Ok(())
}

/// Whether `s`'s reference rows are exactly what `set` gives for its placements (PR-4a §3.3).
///
/// - The session names this set ([`names`]: its `KnowledgeRef` id and SHA-256).
/// - For **every release of the set**, whether or not the session has rows for it, every file,
///   symlink, and directory member has exactly one row when a placement is at its path, an
///   `Absent` row when there is none and discovery is complete, and no row otherwise.
/// - Every row's expected value is the set's, and every row names a release and member of it.
/// - A session that names the set has no row of another reference (PR-4c-2c: a closed claim
///   against another set then has no rows, and `validate` refuses its candidates).
///
/// `Session::validate` checks the rest (observed values against placements, the claim against
/// the rows, and coverage). A session that neither names the set nor has rows for it passes.
/// The set's SHA-256 under another id is an error ([`names`]).
pub fn verify_reference_matches(s: &sigil_model::Session, set: &RefSet) -> Result<(), Vec<String>> {
    use sigil_model::{CoverageState, MemberResult, ARTIFACTS_DISCOVERY, INSTALL_ROOT};
    let named = names(s, set).map_err(|e| vec![e])?;
    let mine = |r: &&sigil_model::ReferenceMatch| r.reference == set.id;
    if !named && !s.reference_matches.iter().any(|r| mine(&r)) {
        return Ok(());
    }
    let mut errors = vec![];
    if named {
        let mut others: Vec<String> = vec![];
        for r in s.reference_matches.iter().filter(|r| r.reference != set.id) {
            let other = r.reference.to_string();
            if !others.contains(&other) {
                others.push(other);
            }
        }
        for other in others {
            errors.push(format!("a row names reference set {other}, not {}", set.id));
        }
    }
    if !named {
        errors.push(format!(
            "the session does not name reference set {} with SHA-256 {}",
            set.id, set.sha256
        ));
    }
    let Some(root) = s
        .request
        .roots
        .iter()
        .find(|r| r.id.as_str() == INSTALL_ROOT)
    else {
        errors.push("reference rows without an install root".to_string());
        return Err(errors);
    };
    let root_text = sigil_model::UntrustedText::from_bytes(root.path.as_bytes().to_vec());
    let placed: BTreeMap<String, &sigil_model::FileInstance> = s
        .instances
        .iter()
        .filter(|i| i.root == root.id)
        .filter_map(|i| crate::analyze::release::member_of(&root_text, i).map(|m| (m, i)))
        .collect();
    let complete = s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == ARTIFACTS_DISCOVERY && c.state == CoverageState::Complete);
    for release in &set.releases {
        for (member, expected) in &release.members {
            let rows: Vec<&sigil_model::ReferenceMatch> = s
                .reference_matches
                .iter()
                .filter(mine)
                .filter(|r| r.release == release.tag && r.member == *member)
                .collect();
            let placement = placed.get(member);
            let want = usize::from(placement.is_some() || complete);
            if rows.len() != want {
                errors.push(format!(
                    "{} {member}: {} rows, expected {want}",
                    release.tag,
                    rows.len()
                ));
                continue;
            }
            let Some(row) = rows.first() else { continue };
            let agrees = match (&row.result, expected) {
                (MemberResult::File { expected: e, .. }, RefMember::File { sha256, .. }) => {
                    e == sha256
                }
                (MemberResult::Symlink { expected: e, .. }, RefMember::Symlink { target }) => {
                    e.as_bytes() == target.as_bytes()
                }
                (MemberResult::Directory, RefMember::Directory) => true,
                (MemberResult::KindDiffers { expected: k, .. }, m) => *k == m.kind(),
                (MemberResult::Absent { kind }, m) => placement.is_none() && *kind == m.kind(),
                (MemberResult::NotCompared, _) => placement.is_some(),
                _ => false,
            };
            let instance_ok = match placement {
                Some(i) => row.instance.as_ref() == Some(&i.id),
                None => row.instance.is_none(),
            };
            if !agrees || !instance_ok {
                errors.push(format!(
                    "{} {member}: the row disagrees with the set",
                    release.tag
                ));
            }
        }
        for row in s
            .reference_matches
            .iter()
            .filter(mine)
            .filter(|r| r.release == release.tag)
        {
            if !release.members.contains_key(&row.member) {
                errors.push(format!(
                    "{} {}: not a member of the release",
                    release.tag, row.member
                ));
            }
        }
    }
    if s.reference_matches
        .iter()
        .filter(mine)
        .any(|r| !set.releases.iter().any(|x| x.tag == r.release))
    {
        errors.push("a row names a release the set does not have".to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Whether `s` names `set` as a reference set it was made with (PR-4c-2c).
///
/// - `Ok(true)`: some `ReferenceManifest` knowledge entry has the set's id and SHA-256.
/// - `Err`: some entry has the set's SHA-256 under another id. An honest SIGIL never writes
///   this, so the verifiers fail closed instead of skipping the session.
/// - `Ok(false)`: otherwise, including the set's id with another SHA-256, which is a session
///   made with an older version of the set.
pub fn names(s: &sigil_model::Session, set: &RefSet) -> Result<bool, String> {
    let mut named = false;
    for k in s
        .knowledge
        .iter()
        .filter(|k| k.kind == KnowledgeKind::ReferenceManifest && k.sha256 == set.sha256)
    {
        if k.id != set.id.as_str() {
            return Err(format!(
                "the session names the embedded reference set's SHA-256 {} under the id {}, not {}",
                set.sha256, k.id, set.id
            ));
        }
        named = true;
    }
    Ok(named)
}

/// Whether `s`'s release claims are exactly the ones the engine derives (PR-4c-2c).
///
/// This runs only for a session that names `set` ([`names`]; one that does not is made with
/// another set or another version of it, and is noted by the CLI instead). The closed claim is
/// recomputed from the session's rows of this set and its placements under the install root
/// ([`crate::analyze::release::by_rows`]; `validate` (V10) and [`verify_reference_matches`] pin
/// the rows), with no install root, no closed claim. The component claims are derived from the
/// session's binary facts (not from `s.components`, which `validate` does not tie to them), and
/// [`crate::analyze::release::claims`] gives the closed claim, else the open one. The session's
/// claims, of any product (plan review P2), must be exactly these: so none is open beside a
/// closed one, and a closed claim cannot be relabelled or dropped to make room for an open one.
/// Both sides are compared in canonical order. `validate` cannot check this: the commit data and
/// the fields' roles are the engine's. V12 requires some `ReferenceManifest` in a session with
/// an open claim.
pub fn verify_release_claims(s: &sigil_model::Session, set: &RefSet) -> Result<(), Vec<String>> {
    use sigil_model::{
        CoverageState, ReleaseBasis, ReleaseClaim, ARTIFACTS_DISCOVERY, INSTALL_ROOT,
    };
    if !names(s, set).map_err(|e| vec![e])? {
        return Ok(());
    }
    let root = s
        .request
        .roots
        .iter()
        .find(|r| r.id.as_str() == INSTALL_ROOT);
    let complete = s
        .coverage
        .iter()
        .any(|c| c.check.as_str() == ARTIFACTS_DISCOVERY && c.state == CoverageState::Complete);
    let closed = match root {
        Some(root) => {
            let placements: Vec<&sigil_model::FileInstance> =
                s.instances.iter().filter(|i| i.root == root.id).collect();
            let rows: Vec<sigil_model::ReferenceMatch> = s
                .reference_matches
                .iter()
                .filter(|r| r.reference == set.id)
                .cloned()
                .collect();
            crate::analyze::release::by_rows(set, &rows, &placements, complete)
                .map_err(|e| vec![e])?
                .1
        }
        None => None,
    };
    let components =
        crate::analyze::identity::derive(&s.instances, &s.binaries, &s.reference_matches)
            .map_err(|e| vec![e])?;
    let mut derived =
        crate::analyze::release::claims(closed, &components, set).map_err(|e| vec![e])?;
    let mut recorded = s.releases.clone();
    let order = |list: &mut Vec<ReleaseClaim>| {
        for c in list.iter_mut() {
            c.canonicalize();
            if let ReleaseBasis::ReferenceMatches { files, .. } = &mut c.basis {
                files.sort();
            }
        }
        list.sort_by_cached_key(|c| {
            (
                c.product.clone(),
                serde_json::to_string(c).unwrap_or_default(),
            )
        });
    };
    order(&mut derived);
    order(&mut recorded);
    if recorded == derived {
        return Ok(());
    }
    let shown = |claims: &[ReleaseClaim]| -> String {
        if claims.is_empty() {
            return "none".to_string();
        }
        let each: Vec<String> = claims
            .iter()
            .map(|c| match &c.basis {
                ReleaseBasis::ReferenceMatches { .. } => {
                    format!("{} {:?} by reference matches", c.product, c.candidates)
                }
                ReleaseBasis::SelfReportedCommit { commits } => {
                    let commits: Vec<String> = commits
                        .iter()
                        .map(|x| format!("{} {}", x.field, x.value.terminal_line()))
                        .collect();
                    format!(
                        "{} {:?} from {}",
                        c.product,
                        c.candidates,
                        commits.join(", ")
                    )
                }
            })
            .collect();
        each.join("; ")
    };
    Err(vec![format!(
        "the release claims are {}, but the session's reference rows, binary facts and the set give {}",
        shown(&recorded),
        shown(&derived)
    )])
}
