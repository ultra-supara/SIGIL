//! Reading one file for its binary facts (PR-4b-1's read, shared by the install scan and
//! `binary inspect`; PR-4b-2a spec §4.2). It:
//! - hashes the file within a byte limit;
//! - identifies ELF and Mach-O containers;
//! - parses each content once, on the fd that hashed it, and scans an ELF content for the
//!   signature needles there (PR-4c-2a), unless its name says it is identified by name and hash
//!   only;
//! - keeps the facts, the code outcomes, and the scans only from a read that saw no change.

use std::collections::BTreeMap;

use sigil_model::{
    Artifact, ArtifactId, BinaryFacts, DiscoverySource, Format, RootId, Sha256Hex, Slice, SliceId,
    Stability,
};

use super::fs::{FileRead, ReadSpec, RelPath, SafeFs};
use crate::analyze::components::{components, ComponentDb};
use crate::binary::needles::{needles, Needles};
use crate::binary::scan::{ScanOutcome, Sought};
use crate::binary::{self, BinaryBudgets, ParsedArtifact};
use crate::code::CodeOutcome;

/// What the signature scan needs (PR-4c-2a): the needles, and the component database, whose
/// `scan = false` entries name the files it never reads (ADR-010) and whose `read = "function"`
/// fields name the functions whose returned strings it reads (PR-4c-2b).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scanning<'d> {
    pub needles: &'d Needles,
    pub components: &'d ComponentDb,
}

impl Scanning<'static> {
    /// The embedded databases. `Err` only if one is invalid, which their tests rule out.
    pub(crate) fn embedded() -> Result<Self, String> {
        Ok(Scanning {
            needles: needles()?,
            components: components()?,
        })
    }
}

/// Reads `rel` under `root` without following any symlink. The file is hashed only if it is at
/// most `limit` bytes (a larger one is `NotRead { BudgetExceeded }`), and a recognized content
/// not in `parsed` yet is parsed. An ELF content is scanned for `scanning.needles`, unless the
/// database names `rel`'s file name as a component with `scan = false`: its slices are then
/// `NameAndHashOnly`. A content read so far only under such names is parsed and scanned again
/// under a name that is scanned, so another name never hides it from the scan. `during` runs
/// while the file is open (the tests' hook).
#[allow(clippy::too_many_arguments)]
pub(crate) fn read(
    fs: &SafeFs,
    root: &RootId,
    rel: &RelPath,
    limit: u64,
    discovered_by: Vec<DiscoverySource>,
    budgets: BinaryBudgets,
    scanning: Scanning<'_>,
    parsed: &mut BTreeMap<ArtifactId, ParsedArtifact>,
    during: &dyn Fn(&RelPath),
) -> FileRead {
    let scanned = rel
        .name()
        .is_none_or(|name| scanning.components.scans(name.as_bytes()));
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
                if before
                    .get(input.artifact)
                    .is_some_and(|p| !scanned || !name_and_hash_only(p))
                {
                    return None;
                }
                let digest = input
                    .artifact
                    .as_str()
                    .strip_prefix("sha256:")
                    .and_then(|hex| Sha256Hex::new(hex.to_string()).ok())?;
                let sought = scanned.then_some(Sought {
                    needles: scanning.needles,
                    functions: scanning.components.functions(),
                });
                let mut p = binary::parse_artifact(
                    input.file,
                    input.size,
                    &digest,
                    input.prefix,
                    budgets,
                    sought,
                )?;
                // Parsed without needles: its ELF slices were not scanned (ADR-010).
                if !scanned && matches!(p.format, Format::Elf { .. }) {
                    for slice in &mut p.slices {
                        slice.scan.get_or_insert(ScanOutcome::NameAndHashOnly);
                    }
                }
                Some(p)
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

/// Whether `p` was read only under names that are not scanned.
fn name_and_hash_only(p: &ParsedArtifact) -> bool {
    p.slices
        .iter()
        .any(|s| s.scan == Some(ScanOutcome::NameAndHashOnly))
}

/// What the parsed slices give: their facts, code outcomes, and scans.
pub(crate) type Slices = (
    Vec<BinaryFacts>,
    Vec<(SliceId, CodeOutcome)>,
    Vec<(SliceId, ScanOutcome)>,
);

/// One `BinaryFacts` per parsed slice with container facts, the code outcome of each slice that
/// has one (PR-5a; with or without container facts), and the scan of each slice that has one
/// (PR-4c-2a), each sorted by slice. `parsed` holds only the contents of reads that saw no change
/// ([`read`]), so no part comes from a read that saw one.
pub(crate) fn binaries(
    parsed: BTreeMap<ArtifactId, ParsedArtifact>,
    artifacts: &[Artifact],
) -> Slices {
    let (mut out, mut code, mut scans) = (vec![], vec![], vec![]);
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
            if let Some(outcome) = parsed_slice.scan {
                scans.push((slice_id.clone(), outcome));
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
    scans.sort_by(|a, b| a.0.cmp(&b.0));
    (out, code, scans)
}
