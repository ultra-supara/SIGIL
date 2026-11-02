//! Coverage of modeled dependency possibilities, preserving collection limits independently.

use super::deps::{DependencyState, DepsAnalysis, RequesterDeps};
use sigil_model::{
    is_binary_root, CheckId, Coverage, CoverageState, FileInstance, Ref, RootId, Session,
    ARTIFACTS_DEPENDENCIES, BINARY_CONTAINER, BINARY_DEPENDENCIES, INSTALL_ROOT,
};
use std::collections::BTreeMap;

fn row_state(row: &RequesterDeps) -> CoverageState {
    match row.state {
        DependencyState::OutOfScope(why) => CoverageState::OutOfScope {
            why: why.to_string(),
        },
        DependencyState::Unsupported(what) => CoverageState::Unsupported {
            what: what.to_string(),
        },
        DependencyState::Modeled if row.gaps.is_empty() => CoverageState::Complete,
        DependencyState::Modeled => CoverageState::Partial {
            missing: row.gaps.clone(),
        },
    }
}

fn combine(prerequisite: &CoverageState, derived: CoverageState) -> CoverageState {
    match prerequisite {
        CoverageState::Complete => derived,
        CoverageState::Partial { missing } => {
            let mut missing = missing.clone();
            match derived {
                CoverageState::Partial { missing: more } => missing.extend(more),
                CoverageState::Unsupported { what } => missing.push(what),
                _ => {}
            }
            missing.sort();
            missing.dedup();
            CoverageState::Partial { missing }
        }
        // A byte/discovery failure remains that exact failure. No match is fabricated from it.
        other => other.clone(),
    }
}

pub fn for_install(
    analysis: &DepsAnalysis,
    instances: &[FileInstance],
    discovery: &Coverage,
    container: &Coverage,
) -> Result<Coverage, String> {
    let ids: std::collections::BTreeSet<_> = instances
        .iter()
        .filter(|i| i.root.as_str() == INSTALL_ROOT)
        .map(|i| &i.id)
        .collect();
    let mut missing = vec![];
    for row in analysis
        .requesters
        .iter()
        .filter(|r| ids.contains(&r.requester))
    {
        match row.state {
            DependencyState::Modeled => {
                missing.extend(row.gaps.iter().map(|g| format!("{}: {g}", row.requester)))
            }
            DependencyState::Unsupported(why) => missing.push(format!("{}: {why}", row.requester)),
            DependencyState::OutOfScope(_) => {}
        }
    }
    missing.sort();
    missing.dedup();
    let derived = if missing.is_empty() {
        CoverageState::Complete
    } else {
        CoverageState::Partial { missing }
    };
    Ok(Coverage {
        check: CheckId::new(ARTIFACTS_DEPENDENCIES).map_err(|e| e.to_string())?,
        scope: Ref::Root(RootId::new(INSTALL_ROOT).map_err(|e| e.to_string())?),
        state: combine(&discovery.state, combine(&container.state, derived)),
        budget: None,
    })
}

pub fn for_binary(analysis: &DepsAnalysis, session: &Session) -> Result<Vec<Coverage>, String> {
    let rows: BTreeMap<_, _> = analysis
        .requesters
        .iter()
        .map(|r| (&r.requester, r))
        .collect();
    // The original .find chooses the first matching binary.container, including on invalid
    // duplicate sessions. This helper accounts coverage; model validation diagnoses duplicates.
    let mut containers = std::collections::HashMap::new();
    for coverage in &session.coverage {
        if coverage.check.as_str() == BINARY_CONTAINER {
            if let Ref::Instance(instance) = &coverage.scope {
                containers.entry(instance).or_insert(coverage);
            }
        }
    }
    let check = CheckId::new(BINARY_DEPENDENCIES).map_err(|e| e.to_string())?;
    session
        .instances
        .iter()
        .filter(|i| is_binary_root(&i.root))
        .map(|i| {
            let row = rows
                .get(&i.id)
                .ok_or_else(|| format!("{}: no dependency requester result", i.id))?;
            let scope = Ref::Instance(i.id.clone());
            let container = containers
                .get(&i.id)
                .ok_or_else(|| format!("{}: no binary.container prerequisite", i.id))?;
            Ok(Coverage {
                check: check.clone(),
                scope,
                state: combine(&container.state, row_state(row)),
                budget: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collection_failures_are_preserved_and_derived_gaps_are_combined() {
        let limit = CoverageState::BudgetExceeded {
            budget: "install_bytes".into(),
            used: 7,
            limit: 8,
        };
        assert_eq!(combine(&limit, CoverageState::Complete), limit);
        let partial = CoverageState::Partial {
            missing: vec!["container incomplete".into()],
        };
        assert_eq!(
            combine(
                &partial,
                CoverageState::Partial {
                    missing: vec!["ld.so.cache not read".into()]
                }
            ),
            CoverageState::Partial {
                missing: vec!["container incomplete".into(), "ld.so.cache not read".into()]
            }
        );
        let row = RequesterDeps {
            requester: sigil_model::InstanceId::new("inst:object.o").unwrap(),
            state: DependencyState::OutOfScope("ET_REL has no runtime dependencies"),
            gaps: vec![],
        };
        assert!(matches!(row_state(&row), CoverageState::OutOfScope { .. }));
        let row = RequesterDeps {
            state: DependencyState::Unsupported("Mach-O dependencies: declared only"),
            ..row
        };
        assert!(matches!(row_state(&row), CoverageState::Unsupported { .. }));
    }
}
