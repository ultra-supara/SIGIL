//! Release identity of an installation by reference manifests (PR-4a design §6).
//!
//! - One row per placement per release that lists its path.
//! - `Absent` rows only after a complete discovery: not observed is not absent.
//! - The releases every placement matches are the candidates (attribution); a claim is made only
//!   after a complete discovery.
//! - `artifacts.release` is Complete only when no candidate has an absent member (completeness).

use std::collections::BTreeSet;

use sigil_model::{
    CheckId, ComponentKey, Coverage, CoverageState, EntryKind, FileInstance, InstanceContent,
    MemberKind, MemberResult, ReferenceMatch, ReleaseBasis, ReleaseClaim, Sha256Hex, Stability,
    UntrustedText, ARTIFACTS_RELEASE,
};

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
    let matched = |tag: &str, i: &FileInstance| {
        rows.iter()
            .any(|r| r.release == tag && r.instance.as_ref() == Some(&i.id) && r.result.matches())
    };
    let candidates: Vec<String> = set
        .releases
        .iter()
        .map(|r| r.tag.clone())
        .filter(|tag| {
            !facts.instances.is_empty() && facts.instances.iter().all(|i| matched(tag, i))
        })
        .collect();
    let claim = if complete && !candidates.is_empty() {
        let mut files: Vec<_> = facts.instances.iter().map(|i| i.id.clone()).collect();
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
