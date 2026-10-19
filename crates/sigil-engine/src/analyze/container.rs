//! Coverage of `artifacts.container` and the `Declares` relations (spec §4.6, §3.1), and of
//! `artifacts.identity` (PR-4c-2a spec §5).

use std::collections::BTreeSet;

use sigil_model::{
    Artifact, BinaryFacts, CheckId, ContainerFacts, Coverage, CoverageState, DeclKind, Format,
    InstanceContent, Relation, ARTIFACTS_CONTAINER, ARTIFACTS_IDENTITY, BINARY_NOT_PARSED,
    SCAN_ELF_ONLY,
};

use crate::analyze::release::member_of;
use crate::binary::scan::ScanOutcome;
use crate::collect::install::InstallFacts;

/// One `Declares` per distinct NEEDED name of each record (B3).
pub fn declares(binaries: &[BinaryFacts]) -> Vec<Relation> {
    let mut relations = vec![];
    for b in binaries {
        match &b.container {
            ContainerFacts::Elf(elf) => {
                let mut seen = BTreeSet::new();
                for needed in &elf.needed {
                    if seen.insert(needed) {
                        relations.push(Relation::Declares {
                            from: b.slice.clone(),
                            needed: needed.clone(),
                            kind: DeclKind::ElfNeeded,
                        });
                    }
                }
            }
            ContainerFacts::MachO(macho) => {
                let mut seen = BTreeSet::new();
                for needed in &macho.load_dylibs {
                    if seen.insert(needed) {
                        relations.push(Relation::Declares {
                            from: b.slice.clone(),
                            needed: needed.clone(),
                            kind: DeclKind::MachOLoadDylib,
                        });
                    }
                }
            }
        }
    }
    relations
}

pub fn analyze(facts: &InstallFacts) -> Result<(Coverage, Vec<Relation>), String> {
    let check = CheckId::new(ARTIFACTS_CONTAINER).map_err(|e| e.to_string())?;
    let relations = declares(&facts.binaries);
    let state = match &facts.discovery.state {
        s @ (CoverageState::Unavailable { .. }
        | CoverageState::BudgetExceeded { .. }
        | CoverageState::Error { .. }) => s.clone(),
        discovery => {
            let mut missing = vec![];
            if !matches!(discovery, CoverageState::Complete) {
                missing.push("discovery incomplete".to_string());
            }
            for a in binaries(facts) {
                let path = path_of(facts, a);
                if a.slices.is_empty() {
                    missing.push(format!("{path}: not parsed"));
                }
                for slice in &a.slices {
                    match facts.binaries.iter().find(|b| b.slice == slice.id) {
                        None => missing.push(format!("{path}: {}: not parsed", slice.arch.name())),
                        Some(b) => missing.extend(
                            b.gaps
                                .iter()
                                .map(|gap| format!("{path} [{}]: {gap}", slice.arch.name())),
                        ),
                    }
                }
            }
            missing.sort();
            missing.dedup();
            if missing.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial { missing }
            }
        }
    };
    Ok((
        Coverage {
            check,
            scope: facts.discovery.scope.clone(),
            state,
            budget: None,
        },
        relations,
    ))
}

/// The install's ELF and Mach-O artifacts.
fn binaries(facts: &InstallFacts) -> impl Iterator<Item = &Artifact> {
    facts.artifacts.iter().filter(|a| {
        matches!(
            a.format,
            Format::Elf { .. } | Format::MachO | Format::MachOFat
        )
    })
}

/// The member path of an artifact's first placement, as its gaps name it; its ID without one.
fn path_of(facts: &InstallFacts, a: &Artifact) -> String {
    facts
        .instances
        .iter()
        .filter(|i| {
            i.content
                == InstanceContent::Read {
                    artifact: a.id.clone(),
                }
        })
        .filter_map(|i| member_of(&facts.root_path, i))
        .min()
        .unwrap_or_else(|| a.id.as_str().to_string())
}

/// `artifacts.identity` (PR-4c-2a spec §5): whether every scan the signature database asks for
/// was done within its budget, for each ELF of the install. Like `artifacts.container`, it is the
/// discovery's state when discovery could not run or was cut short by an error or a budget, and
/// otherwise `Complete`, or `Partial` with each gap prefixed by its artifact's path: the scan's
/// gaps, `string scan: ELF only` for a Mach-O, and `not parsed` for a slice without a scan. An
/// NVIDIA library (`NameAndHashOnly`) adds none.
pub fn identity(facts: &InstallFacts) -> Result<Coverage, String> {
    let check = CheckId::new(ARTIFACTS_IDENTITY).map_err(|e| e.to_string())?;
    let state = match &facts.discovery.state {
        s @ (CoverageState::Unavailable { .. }
        | CoverageState::BudgetExceeded { .. }
        | CoverageState::Error { .. }) => s.clone(),
        discovery => {
            let mut missing = vec![];
            if !matches!(discovery, CoverageState::Complete) {
                missing.push("discovery incomplete".to_string());
            }
            for a in binaries(facts) {
                let path = path_of(facts, a);
                if !matches!(a.format, Format::Elf { .. }) {
                    missing.push(format!("{path}: {SCAN_ELF_ONLY}"));
                    continue;
                }
                if a.slices.is_empty() {
                    missing.push(format!("{path}: {BINARY_NOT_PARSED}"));
                }
                for slice in &a.slices {
                    match facts.scans.iter().find(|(id, _)| *id == slice.id) {
                        Some((_, ScanOutcome::Scanned { gaps, .. })) => {
                            missing.extend(gaps.iter().map(|gap| format!("{path}: {gap}")))
                        }
                        Some((_, ScanOutcome::NameAndHashOnly)) => {}
                        None => missing.push(format!("{path}: {BINARY_NOT_PARSED}")),
                    }
                }
            }
            missing.sort();
            missing.dedup();
            if missing.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial { missing }
            }
        }
    };
    Ok(Coverage {
        check,
        scope: facts.discovery.scope.clone(),
        state,
        budget: None,
    })
}
