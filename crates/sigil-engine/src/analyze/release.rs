//! Release identity of an installation by reference manifests (PR-4a design §6).
//!
//! - One row per placement per release that lists its path.
//! - `Absent` rows only after a complete discovery: not observed is not absent.
//! - The releases every placement matches are the candidates (attribution); a claim is made only
//!   after a complete discovery.
//! - `artifacts.release` is Complete only when no candidate has an absent member (completeness).
//! - Without a claim, the install's self-reported commits may give an **open** one (PR-4c-2c):
//!   the releases whose own files report the same. It never closes `artifacts.release`.

use std::collections::BTreeSet;

use sigil_model::{
    is_commit, CheckId, ComponentClaim, ComponentKey, Coverage, CoverageState, EntryKind,
    FileInstance, IdentityAssertion, InstanceContent, MemberKind, MemberResult, ReferenceMatch,
    ReleaseBasis, ReleaseClaim, ReportedCommit, Sha256Hex, Stability, UntrustedText,
    ARTIFACTS_RELEASE,
};

use crate::analyze::components::{components, Role};
use crate::collect::install::InstallFacts;
use crate::reference::{RefMember, RefSet};

/// The rows, the claim (if any), and the coverage of `artifacts.release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseResult {
    pub rows: Vec<ReferenceMatch>,
    pub claim: Option<ReleaseClaim>,
    pub coverage: Coverage,
}

/// A placement's path under the install root, if it is text.
pub(crate) fn member_of(root: &UntrustedText, i: &FileInstance) -> Option<String> {
    let mut prefix = root.as_bytes().to_vec();
    prefix.push(b'/');
    let rest = i.path.as_bytes().strip_prefix(prefix.as_slice())?;
    String::from_utf8(rest.to_vec()).ok()
}

/// Compares the install with `set`. An error only for an invalid built-in identifier.
pub fn analyze(facts: &InstallFacts, set: &RefSet) -> Result<ReleaseResult, String> {
    let check = CheckId::new(ARTIFACTS_RELEASE).map_err(|e| e.to_string())?;
    let complete = matches!(facts.discovery.state, CoverageState::Complete);
    let members: Vec<(Option<String>, &FileInstance)> = facts
        .instances
        .iter()
        .map(|i| (member_of(&facts.root_path, i), i))
        .collect();
    let mut rows = vec![];
    for release in &set.releases {
        let mut present = BTreeSet::new();
        for (member, i) in &members {
            let Some(m) = member else { continue };
            present.insert(m.clone());
            let Some(expected) = release.members.get(m) else {
                continue;
            };
            rows.push(ReferenceMatch {
                reference: set.id.clone(),
                release: release.tag.clone(),
                member: m.clone(),
                instance: Some(i.id.clone()),
                result: compare(expected, i)?,
            });
        }
        if complete {
            for (m, expected) in &release.members {
                if !present.contains(m) {
                    rows.push(ReferenceMatch {
                        reference: set.id.clone(),
                        release: release.tag.clone(),
                        member: m.clone(),
                        instance: None,
                        result: MemberResult::Absent {
                            kind: expected.kind(),
                        },
                    });
                }
            }
        }
    }
    let placements: Vec<&FileInstance> = facts.instances.iter().collect();
    let (candidates, claim) = by_rows(set, &rows, &placements, complete)?;
    let state = match &facts.discovery.state {
        s @ (CoverageState::Unavailable { .. }
        | CoverageState::BudgetExceeded { .. }
        | CoverageState::Error { .. }) => s.clone(),
        _ => {
            let reasons = reasons(&rows, &candidates, &members, set, complete);
            if claim.is_some() && reasons.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial { missing: reasons }
            }
        }
    };
    Ok(ReleaseResult {
        rows,
        claim,
        coverage: Coverage {
            check,
            scope: facts.discovery.scope.clone(),
            state,
            budget: None,
        },
    })
}

/// The candidates and the claim by reference matches (PR-4c-2c: also what the verifier
/// recomputes from a session's rows): the releases whose rows every placement matches, and, after
/// a complete discovery with a candidate, the claim for `ollama` over the placements. `rows` are
/// the set's.
pub(crate) fn by_rows(
    set: &RefSet,
    rows: &[ReferenceMatch],
    instances: &[&FileInstance],
    complete: bool,
) -> Result<(Vec<String>, Option<ReleaseClaim>), String> {
    let matched = |tag: &str, i: &FileInstance| {
        rows.iter()
            .any(|r| r.release == tag && r.instance.as_ref() == Some(&i.id) && r.result.matches())
    };
    let candidates: Vec<String> = set
        .releases
        .iter()
        .map(|r| r.tag.clone())
        .filter(|tag| !instances.is_empty() && instances.iter().all(|i| matched(tag, i)))
        .collect();
    let claim = if complete && !candidates.is_empty() {
        let mut files: Vec<_> = instances.iter().map(|i| i.id.clone()).collect();
        files.sort();
        Some(ReleaseClaim {
            product: ComponentKey::new("ollama").map_err(|e| e.to_string())?,
            candidates: candidates.clone(),
            basis: ReleaseBasis::ReferenceMatches {
                reference: set.id.clone(),
                files,
            },
        })
    } else {
        None
    };
    Ok((candidates, claim))
}

/// The install's release claims (PR-4c-2c): the claim by reference matches when [`analyze`] made
/// one, otherwise the open claim of the install's self-reported commits ([`open`]), if any.
pub fn claims(
    closed: Option<ReleaseClaim>,
    components: &[ComponentClaim],
    set: &RefSet,
) -> Result<Vec<ReleaseClaim>, String> {
    match closed {
        Some(claim) => Ok(vec![claim]),
        None => Ok(open(components, set)?.into_iter().collect()),
    }
}

/// The open release claim of `claims`, the install's component claims (PR-4c-2c; plan §4.4.3).
///
/// - The commits: each `Embedded` assertion whose field the component database gives the role
///   `commit` and whose value reads as a commit ([`is_commit`]), once.
/// - The candidates: the releases of `set` that list every field collected, each with a value
///   that agrees with the install's (one is a prefix of the other: a commit is abbreviated to a
///   prefix, here of at least 7 digits).
///
/// The commits and the candidates are in canonical order ([`ReleaseClaim::canonicalize`]), so the
/// claim equals the one a saved session holds.
///
/// `None` without a commit, or without a candidate. `Err` only for an invalid database.
pub fn open(claims: &[ComponentClaim], set: &RefSet) -> Result<Option<ReleaseClaim>, String> {
    let db = components()?;
    let mut commits: Vec<ReportedCommit> = vec![];
    for a in claims.iter().flat_map(|c| &c.assertions) {
        let IdentityAssertion::Embedded {
            field, value, at, ..
        } = a
        else {
            continue;
        };
        if !db.field(field).is_some_and(|f| f.role == Role::Commit) || !is_commit(value.as_bytes())
        {
            continue;
        }
        let commit = ReportedCommit {
            field: field.clone(),
            value: value.clone(),
            at: at.clone(),
        };
        if !commits.contains(&commit) {
            commits.push(commit);
        }
    }
    if commits.is_empty() {
        return Ok(None);
    }
    let agrees = |a: &[u8], b: &[u8]| a.starts_with(b) || b.starts_with(a);
    let candidates: Vec<String> = set
        .releases
        .iter()
        .filter(|r| {
            commits.iter().all(|c| {
                r.commits
                    .iter()
                    .any(|x| x.field == c.field && agrees(c.value.as_bytes(), x.value.as_bytes()))
            })
        })
        .map(|r| r.tag.clone())
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    let mut claim = ReleaseClaim {
        product: ComponentKey::new("ollama").map_err(|e| e.to_string())?,
        candidates,
        basis: ReleaseBasis::SelfReportedCommit { commits },
    };
    claim.canonicalize();
    Ok(Some(claim))
}

/// One placement against one member (§6 step 1).
fn compare(expected: &RefMember, i: &FileInstance) -> Result<MemberResult, String> {
    let kind = i.entry_kind();
    let unread_file =
        kind == EntryKind::File && matches!(i.content, InstanceContent::NotRead { .. });
    if i.stability != Stability::NoChangeDetected || unread_file {
        return Ok(MemberResult::NotCompared);
    }
    Ok(match (expected, kind) {
        (RefMember::File { sha256, .. }, EntryKind::File) => {
            let InstanceContent::Read { artifact } = &i.content else {
                return Ok(MemberResult::NotCompared);
            };
            let observed = artifact.as_str().trim_start_matches("sha256:");
            MemberResult::File {
                expected: sha256.clone(),
                observed: Sha256Hex::new(observed).map_err(|e| e.to_string())?,
            }
        }
        (RefMember::Symlink { target }, EntryKind::Symlink) => match i.link_chain.first() {
            Some(hop) => MemberResult::Symlink {
                expected: UntrustedText::new(target.clone()),
                observed: hop.target.clone(),
            },
            None => MemberResult::NotCompared,
        },
        (RefMember::Directory, EntryKind::Directory) => MemberResult::Directory,
        (m, observed) => MemberResult::KindDiffers {
            expected: m.kind(),
            observed,
        },
    })
}

/// The `Partial` entries (§6), sorted.
fn reasons(
    rows: &[ReferenceMatch],
    candidates: &[String],
    members: &[(Option<String>, &FileInstance)],
    set: &RefSet,
    complete: bool,
) -> Vec<String> {
    let mut out = vec![];
    if !complete {
        out.push("discovery incomplete".to_string());
    }
    for tag in candidates {
        let count = |k: MemberKind| {
            rows.iter()
                .filter(|r| r.release == *tag && r.result == MemberResult::Absent { kind: k })
                .count()
        };
        let (f, s, d) = (
            count(MemberKind::File),
            count(MemberKind::Symlink),
            count(MemberKind::Directory),
        );
        if f + s + d > 0 {
            out.push(format!(
                "{tag}: {f} files, {s} symlinks, and {d} directories absent from the install"
            ));
        }
    }
    let mut every_placement_matches_some = true;
    let mut differing = vec![];
    for (member, i) in members {
        let shown = member.clone().unwrap_or_else(|| i.path.terminal_line());
        let mine: Vec<&ReferenceMatch> = rows
            .iter()
            .filter(|r| r.instance.as_ref() == Some(&i.id))
            .collect();
        if mine.is_empty() {
            every_placement_matches_some = false;
            out.push(format!("{shown}: not in any reference"));
            continue;
        }
        let matching: Vec<&str> = mine
            .iter()
            .filter(|r| r.result.matches())
            .map(|r| r.release.as_str())
            .collect();
        if !matching.is_empty() {
            if matching.len() < set.releases.len() {
                differing.push(format!("{shown}: {}", matching.join(", ")));
            }
            continue;
        }
        every_placement_matches_some = false;
        match &mine[0].result {
            MemberResult::Symlink { observed, .. } => {
                let targets: Vec<String> = mine
                    .iter()
                    .filter_map(|r| match &r.result {
                        MemberResult::Symlink { expected, .. } => {
                            Some(format!("{}: {}", r.release, expected.terminal_line()))
                        }
                        _ => None,
                    })
                    .collect();
                out.push(format!(
                    "{shown}: symlink to {}; {}",
                    observed.terminal_line(),
                    targets.join(", ")
                ));
            }
            MemberResult::KindDiffers { expected, observed } => out.push(format!(
                "{shown}: {observed:?} where {} has a {expected:?}",
                mine[0].release
            )),
            MemberResult::NotCompared => out.push(format!("{shown}: not compared")),
            _ => out.push(format!("{shown}: matches no reference")),
        }
    }
    if candidates.is_empty() && every_placement_matches_some && !differing.is_empty() {
        out.push(format!(
            "mixed install: no release matches every placement ({})",
            differing.join("; ")
        ));
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use sigil_model::{
        EvidenceRef, ExtractMethod, IdentityStatus, InstanceId, Loc, RefSetId, SigState, SliceId,
    };

    use super::*;
    use crate::reference::{official, RefCommit, RefRelease};

    const SLICE: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111#x86_64@0";

    /// One claim of the slice numbered `n` with the embedded values `fields` (field, value,
    /// address read at).
    fn claim_of(n: char, fields: &[(&str, &str, u64)]) -> ComponentClaim {
        let slice = SliceId::new(SLICE.replace('1', &n.to_string())).unwrap();
        let mut assertions: Vec<IdentityAssertion> = fields
            .iter()
            .map(|(field, value, addr)| IdentityAssertion::Embedded {
                field: field.to_string(),
                value: UntrustedText::new(*value),
                at: EvidenceRef::Code {
                    slice: slice.clone(),
                    loc: Loc::VAddr(*addr),
                },
                method: ExtractMethod::DataSymbolPointer {
                    symbol: UntrustedText::new(*field),
                },
            })
            .collect();
        assertions.push(IdentityAssertion::Signature {
            state: SigState::NotChecked,
        });
        ComponentClaim {
            subject: slice,
            component: ComponentKey::new("llama.cpp/common").unwrap(),
            assertions,
            status: IdentityStatus::NameOnly,
            versions: vec![],
        }
    }

    /// One claim of the first slice.
    fn claim(fields: &[(&str, &str, u64)]) -> ComponentClaim {
        claim_of('1', fields)
    }

    /// An open claim's candidates, and its commits as (field, value).
    type Open = (Vec<String>, Vec<(String, String)>);

    /// The candidates and the commits (field, value) of the open claim of `claims`.
    fn open_of(claims: &[ComponentClaim], set: &RefSet) -> Option<Open> {
        let claim = open(claims, set).unwrap()?;
        assert_eq!(claim.product.as_str(), "ollama");
        let ReleaseBasis::SelfReportedCommit { commits } = claim.basis else {
            panic!("an open claim: {:?}", claim.basis);
        };
        let commits = commits
            .iter()
            .map(|c| (c.field.clone(), c.value.as_str().unwrap().to_string()))
            .collect();
        Some((claim.candidates, commits))
    }

    fn all() -> Vec<String> {
        ["v0.30.5", "v0.30.6", "v0.30.7"].map(String::from).to_vec()
    }

    fn pair(field: &str, value: &str) -> (String, String) {
        (field.to_string(), value.to_string())
    }

    /// A set of two releases that report `LLAMA_COMMIT` only: `v1` reports `1111111`, `v2`
    /// `6f3a9f3de`.
    fn llama_only() -> RefSet {
        let mut set = official().unwrap().clone();
        set.id = RefSetId::new("test").unwrap();
        set.releases = [("v1", "1111111"), ("v2", "6f3a9f3de")]
            .map(|(tag, value)| RefRelease {
                tag: tag.to_string(),
                members: Default::default(),
                commits: vec![RefCommit {
                    field: "LLAMA_COMMIT".to_string(),
                    member: "lib/ollama/libllama-common.so.0.0.1".to_string(),
                    value: value.to_string(),
                }],
            })
            .to_vec();
        set
    }

    #[test]
    fn a_reported_commit_gives_the_releases_whose_files_report_it() {
        let set = official().unwrap();
        let commit = claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]);
        assert_eq!(
            open_of(&[commit], set),
            Some((all(), vec![pair("LLAMA_COMMIT", "6f3a9f3de")]))
        );
        // One value of each field of the official data, from two claims.
        let both = [
            claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]),
            claim(&[("ggml_commit", "6f3a9f3de", 0x20)]),
        ];
        assert_eq!(
            open_of(&both, set),
            Some((
                all(),
                vec![
                    pair("LLAMA_COMMIT", "6f3a9f3de"),
                    pair("ggml_commit", "6f3a9f3de")
                ]
            ))
        );
        // A release reporting another value is no candidate.
        let commit = claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]);
        assert_eq!(
            open_of(&[commit], &llama_only()).map(|(c, _)| c),
            Some(vec!["v2".to_string()])
        );
    }

    #[test]
    fn values_agree_when_one_abbreviates_the_other() {
        let set = official().unwrap();
        for value in ["6f3a9f3", "6f3a9f3de", "6f3a9f3dee3c"] {
            let commit = claim(&[("LLAMA_COMMIT", value, 0x10)]);
            assert_eq!(
                open_of(&[commit], set).map(|(c, _)| c),
                Some(all()),
                "{value}"
            );
        }
        for value in ["6f3a9f4", "6f3a9f3df", "7f3a9f3de"] {
            let commit = claim(&[("LLAMA_COMMIT", value, 0x10)]);
            assert_eq!(open_of(&[commit], set), None, "{value}");
        }
    }

    #[test]
    fn every_commit_must_agree() {
        let set = official().unwrap();
        // The two fields of one install disagree with each other's releases.
        let mixed = claim(&[
            ("LLAMA_COMMIT", "6f3a9f3de", 0x10),
            ("ggml_commit", "abcdef0", 0x20),
        ]);
        assert_eq!(open_of(&[mixed], set), None);
        // Two contents report different values of one field.
        let two = [
            claim_of('1', &[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]),
            claim_of('2', &[("LLAMA_COMMIT", "1111111", 0x10)]),
        ];
        assert_eq!(open_of(&two, &llama_only()), None);
        // A field no release lists.
        let more = claim(&[
            ("LLAMA_COMMIT", "6f3a9f3de", 0x10),
            ("ggml_commit", "6f3a9f3de", 0x20),
        ]);
        assert_eq!(open_of(&[more], &llama_only()), None);
    }

    #[test]
    fn only_commit_fields_with_a_commit_value_count() {
        let set = official().unwrap();
        for (field, value) in [
            ("LLAMA_COMMIT", "unknown"),
            ("LLAMA_COMMIT", "6F3A9F3DE"),
            ("LLAMA_COMMIT", "6f3a9f"),
            ("LLAMA_BUILD_NUMBER", "6f3a9f3de"),
            ("LLAMA_COMPILER", "6f3a9f3de"),
            ("go.version", "6f3a9f3de"),
        ] {
            assert_eq!(
                open_of(&[claim(&[(field, value, 0x10)])], set),
                None,
                "{field}"
            );
        }
        // An ignored value leaves the others: a version field's, even one that reads as a commit,
        // and a commit field's that does not.
        let version = claim(&[
            ("LLAMA_BUILD_NUMBER", "1234567", 0x08),
            ("LLAMA_COMMIT", "6f3a9f3de", 0x10),
        ]);
        assert_eq!(
            open_of(&[version], set),
            Some((all(), vec![pair("LLAMA_COMMIT", "6f3a9f3de")]))
        );
        let some = claim(&[
            ("LLAMA_COMMIT", "unknown", 0x10),
            ("ggml_commit", "6f3a9f3de", 0x20),
        ]);
        assert_eq!(
            open_of(&[some], set),
            Some((all(), vec![pair("ggml_commit", "6f3a9f3de")]))
        );
        assert_eq!(open_of(&[], set), None, "no claim");
    }

    #[test]
    fn a_commit_is_listed_once_per_place_read() {
        let set = official().unwrap();
        // The same assertion twice (one content, two claims) is one commit; the same value read at
        // two places is two.
        let same = [
            claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]),
            claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]),
        ];
        assert_eq!(open_of(&same, set).map(|(_, c)| c.len()), Some(1));
        let two = claim(&[
            ("LLAMA_COMMIT", "6f3a9f3de", 0x10),
            ("LLAMA_COMMIT", "6f3a9f3de", 0x30),
        ]);
        assert_eq!(open_of(&[two], set).map(|(_, c)| c.len()), Some(2));
    }

    #[test]
    fn the_claim_is_in_canonical_order_whatever_the_claim_order() {
        let set = official().unwrap();
        let a = claim_of(
            '1',
            &[
                ("ggml_commit", "6f3a9f3de", 0x20),
                ("LLAMA_COMMIT", "6f3a9f3de", 0x10),
            ],
        );
        let b = claim_of('2', &[("LLAMA_COMMIT", "6f3a9f3de", 0x30)]);
        let forward = open(&[a.clone(), b.clone()], set).unwrap().unwrap();
        let reverse = open(&[b, a], set).unwrap().unwrap();
        assert_eq!(forward, reverse);
        let ReleaseBasis::SelfReportedCommit { commits } = &forward.basis else {
            panic!("an open claim");
        };
        assert_eq!(commits.len(), 3);
        let mut again = forward.clone();
        again.canonicalize();
        assert_eq!(again, forward);
    }

    #[test]
    fn a_set_without_commit_data_gives_no_open_claim() {
        let mut set = official().unwrap().clone();
        for r in &mut set.releases {
            r.commits.clear();
        }
        let commit = claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)]);
        assert_eq!(open_of(&[commit], &set), None);
    }

    #[test]
    fn a_closed_claim_leaves_no_open_one() {
        let set = official().unwrap();
        let commit = [claim(&[("LLAMA_COMMIT", "6f3a9f3de", 0x10)])];
        let closed = ReleaseClaim {
            product: ComponentKey::new("ollama").unwrap(),
            candidates: vec!["v0.30.6".to_string()],
            basis: ReleaseBasis::ReferenceMatches {
                reference: set.id.clone(),
                files: vec![InstanceId::new("inst:install/bin/ollama").unwrap()],
            },
        };
        assert_eq!(claims(Some(closed.clone()), &commit, set), Ok(vec![closed]));
        let open = claims(None, &commit, set).unwrap();
        assert_eq!(open.len(), 1);
        assert!(matches!(
            open[0].basis,
            ReleaseBasis::SelfReportedCommit { .. }
        ));
        assert_eq!(claims(None, &[], set), Ok(vec![]));
    }
}
