//! Coverage of `artifacts.container` and the `Declares` relations (spec §4.6, §3.1).

use std::collections::BTreeSet;

use sigil_model::{
    BinaryFacts, CheckId, ContainerFacts, Coverage, CoverageState, DeclKind, Format,
    InstanceContent, Relation, ARTIFACTS_CONTAINER,
};

use crate::analyze::release::member_of;
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
            for a in facts.artifacts.iter().filter(|a| {
                matches!(
                    a.format,
                    Format::Elf { .. } | Format::MachO | Format::MachOFat
                )
            }) {
                let path = facts
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
                    .unwrap_or_else(|| a.id.as_str().to_string());
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
