//! Coverage of `artifacts.container` and the `Declares` relations (spec §4.6, §3.1).

use std::collections::BTreeSet;

use sigil_model::{
    CheckId, ContainerFacts, Coverage, CoverageState, DeclKind, Format, InstanceContent, Relation,
    ARTIFACTS_CONTAINER,
};

use crate::analyze::release::member_of;
use crate::collect::install::InstallFacts;

pub fn analyze(facts: &InstallFacts) -> Result<(Coverage, Vec<Relation>), String> {
    let check = CheckId::new(ARTIFACTS_CONTAINER).map_err(|e| e.to_string())?;
    let mut relations = vec![];
    for b in &facts.binaries {
        let ContainerFacts::Elf(elf) = &b.container;
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
    let state = match &facts.discovery.state {
        s @ (CoverageState::Unavailable { .. }
        | CoverageState::BudgetExceeded { .. }
        | CoverageState::Error { .. }) => s.clone(),
        discovery => {
            let mut missing = vec![];
            if !matches!(discovery, CoverageState::Complete) {
                missing.push("discovery incomplete".to_string());
            }
            for a in facts
                .artifacts
                .iter()
                .filter(|a| matches!(a.format, Format::Elf { .. }))
            {
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
                match facts
                    .binaries
                    .iter()
                    .find(|b| a.slices.iter().any(|s| s.id == b.slice))
                {
                    None => missing.push(format!("{path}: not parsed")),
                    Some(b) => missing.extend(b.gaps.iter().map(|g| format!("{path}: {g}"))),
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
