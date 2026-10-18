//! Reading one file for its binary facts (PR-4b-1's read, shared by the install scan and
//! `binary inspect`; PR-4b-2a spec §4.2). It:
//! - hashes the file within a byte limit;
//! - identifies ELF and Mach-O containers;
//! - parses each content once, on the fd that hashed it;
//! - keeps the facts, and the code outcomes, only from a read that saw no change.

use std::collections::BTreeMap;

use sigil_model::{
    Artifact, ArtifactId, BinaryFacts, DiscoverySource, RootId, Sha256Hex, Slice, SliceId,
    Stability,
};

use super::fs::{FileRead, ReadSpec, RelPath, SafeFs};
use crate::binary::{self, BinaryBudgets, ParsedArtifact};
use crate::code::CodeOutcome;

/// Reads `rel` under `root` without following any symlink. The file is hashed only if it is at
/// most `limit` bytes (a larger one is `NotRead { BudgetExceeded }`), and a recognized content
/// not in `parsed` yet is parsed. `during` runs while the file is open (the tests' hook).
#[allow(clippy::too_many_arguments)]
pub(crate) fn read(
    fs: &SafeFs,
    root: &RootId,
    rel: &RelPath,
    limit: u64,
    discovered_by: Vec<DiscoverySource>,
    budgets: BinaryBudgets,
    parsed: &mut BTreeMap<ArtifactId, ParsedArtifact>,
    during: &dyn Fn(&RelPath),
) -> FileRead {
    let (mut read, facts) = {
        let before = &*parsed;
        fs.read_entry_with(
            root,
            rel,
            ReadSpec {
                keep: 64,
                limit: Some(limit),
            },
            discovered_by,
            |input| {
                during(rel);
                if before.contains_key(input.artifact) {
                    return None;
                }
                let digest = input
                    .artifact
                    .as_str()
                    .strip_prefix("sha256:")
                    .and_then(|hex| Sha256Hex::new(hex.to_string()).ok())?;
                binary::parse_artifact(input.file, input.size, &digest, input.prefix, budgets)
            },
        )
    };
    let stable = read
        .instance
        .as_ref()
        .is_some_and(|i| i.stability == Stability::NoChangeDetected);
    let fresh = facts.flatten();
    if let (Some(p), Some(a), true) = (fresh.as_ref(), read.artifact.as_ref(), stable) {
        parsed.insert(a.id.clone(), p.clone());
    }
    if let Some(artifact) = read.artifact.as_mut() {
        if let Some(parsed_artifact) = parsed.get(&artifact.id).or(fresh.as_ref()) {
            artifact.format = parsed_artifact.format;
            artifact.slices = parsed_artifact
                .slices
                .iter()
                .map(|slice| Slice {
                    id: SliceId::from_parts(&artifact.id, slice.arch, slice.offset),
                    arch: slice.arch,
                    offset: slice.offset,
                    size: slice.size,
                    sha256: slice.sha256.clone(),
                })
                .collect();
        }
    }
    read
}

/// One `BinaryFacts` per parsed slice with container facts, and the code outcome of each slice
/// that has one (PR-5a; with or without container facts), each sorted by slice. `parsed` holds
/// only the contents of reads that saw no change ([`read`]), so neither part comes from a read
/// that saw one.
pub(crate) fn binaries(
    parsed: BTreeMap<ArtifactId, ParsedArtifact>,
    artifacts: &[Artifact],
) -> (Vec<BinaryFacts>, Vec<(SliceId, CodeOutcome)>) {
    let (mut out, mut code) = (vec![], vec![]);
    for (id, parsed_artifact) in parsed {
        let Some(artifact) = artifacts.iter().find(|a| a.id == id) else {
            continue;
        };
        for parsed_slice in parsed_artifact.slices {
            let slice_id = SliceId::from_parts(&id, parsed_slice.arch, parsed_slice.offset);
            if !artifact.slices.iter().any(|slice| slice.id == slice_id) {
                continue;
            }
            if let Some(outcome) = parsed_slice.code {
                code.push((slice_id.clone(), outcome));
            }
            let Some(container) = parsed_slice.container else {
                continue;
            };
            out.push(BinaryFacts {
                slice: slice_id,
                container,
                go: parsed_slice.go,
                gaps: parsed_slice.gaps,
            });
        }
    }
    out.sort_by(|a, b| a.slice.cmp(&b.slice));
    code.sort_by(|a, b| a.0.cmp(&b.0));
    (out, code)
}
