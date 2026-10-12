//! Reading one file for its binary facts (PR-4b-1's read, shared by the install scan and
//! `binary inspect`; PR-4b-2a spec §4.2). It:
//! - hashes the file within a byte limit;
//! - identifies an ELF by its header;
//! - parses each content once, on the fd that hashed it;
//! - keeps the facts only from a read that saw no change.

use std::collections::BTreeMap;

use sigil_model::{
    Artifact, ArtifactId, BinaryFacts, DiscoverySource, Format, RootId, Sha256Hex, Slice, SliceId,
    Stability,
};

use super::fs::{FileRead, ReadSpec, RelPath, SafeFs};
use crate::binary::{self, header, BinaryBudgets, Parsed};

/// Reads `rel` under `root` without following any symlink. The file is hashed only if it is at
/// most `limit` bytes (a larger one is `NotRead { BudgetExceeded }`), and an ELF content not in
/// `parsed` yet is parsed. `during` runs while the file is open (the tests'
/// hook). The artifact of the read gets its ELF format and slice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read(
    fs: &SafeFs,
    root: &RootId,
    rel: &RelPath,
    limit: u64,
    discovered_by: Vec<DiscoverySource>,
    budgets: BinaryBudgets,
    parsed: &mut BTreeMap<ArtifactId, Parsed>,
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
                // ELF content, each content once.
                if header::read(input.prefix).is_none() || before.contains_key(input.artifact) {
                    return None;
                }
                Some(binary::parse(input.file, input.size, budgets))
            },
        )
    };
    let stable = read
        .instance
        .as_ref()
        .is_some_and(|i| i.stability == Stability::NoChangeDetected);
    if let (Some(Some(p)), Some(a), true) = (facts, read.artifact.as_ref(), stable) {
        parsed.insert(a.id.clone(), p);
    }
    if let Some(artifact) = read.artifact.as_mut() {
        if let Some((kind, arch)) = header::read(&read.prefix) {
            artifact.format = Format::Elf { kind };
            let hex = artifact
                .id
                .as_str()
                .trim_start_matches("sha256:")
                .to_string();
            if let Ok(sha256) = Sha256Hex::new(hex) {
                artifact.slices = vec![Slice {
                    id: SliceId::from_parts(&artifact.id, arch, 0),
                    arch,
                    offset: 0,
                    size: artifact.size,
                    sha256,
                }];
            }
        }
    }
    read
}

/// One `BinaryFacts` per parsed content, for its slice, sorted by slice.
pub(crate) fn binaries(
    parsed: BTreeMap<ArtifactId, Parsed>,
    artifacts: &[Artifact],
) -> Vec<BinaryFacts> {
    let mut out = vec![];
    for (id, p) in parsed {
        let Some(slice) = artifacts
            .iter()
            .find(|a| a.id == id)
            .and_then(|a| a.slices.first())
        else {
            continue;
        };
        out.push(BinaryFacts {
            slice: slice.id.clone(),
            container: p.container,
            go: p.go,
            gaps: p.gaps,
        });
    }
    out.sort_by(|a, b| a.slice.cmp(&b.slice));
    out
}
