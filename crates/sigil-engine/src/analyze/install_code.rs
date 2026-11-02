//! Code coverage for binary contents discovered in an installation.

use std::collections::{BTreeMap, BTreeSet};

use sigil_model::{
    Arch, Artifact, BudgetUse, CheckId, Coverage, CoverageState, Format, Ref, SliceId,
    ARTIFACTS_CODE, BINARY_CODE_BYTES, BINARY_NOT_PARSED, CODE_UNSUPPORTED,
};

use crate::code::CodeOutcome;
use crate::collect::install::InstallFacts;

/// Return a root summary and one entry for each recognized binary content. The root summary
/// keeps an incomplete discovery from being mistaken for a complete empty set. Outcomes are
/// retained only for stable reads by the collector; a missing outcome is an explicit gap.
pub fn coverage(facts: &InstallFacts, limit: u64) -> Result<Vec<Coverage>, String> {
    let check = CheckId::new(ARTIFACTS_CODE).map_err(|e| e.to_string())?;
    let outcomes: BTreeMap<&SliceId, &CodeOutcome> = facts
        .code
        .iter()
        .map(|(id, outcome)| (id, outcome))
        .collect();
    let parsed: BTreeSet<&SliceId> = facts.binaries.iter().map(|binary| &binary.slice).collect();
    let entries: Vec<_> = facts
        .artifacts
        .iter()
        .filter(|a| {
            matches!(
                a.format,
                Format::Elf { .. } | Format::MachO | Format::MachOFat
            )
        })
        .map(|artifact| {
            let (state, budget) = content(artifact, &outcomes, &parsed, limit);
            Coverage {
                check: check.clone(),
                scope: Ref::Artifact(artifact.id.clone()),
                state,
                budget,
            }
        })
        .collect();
    let state = match &facts.discovery.state {
        s @ (CoverageState::Unavailable { .. }
        | CoverageState::BudgetExceeded { .. }
        | CoverageState::Error { .. }) => s.clone(),
        discovery => {
            let mut missing = Vec::new();
            if !matches!(discovery, CoverageState::Complete) {
                missing.push("discovery incomplete".to_string());
            }
            if entries.iter().any(|entry| !entry.state.can_close()) {
                missing
                    .push("one or more binary contents have incomplete code coverage".to_string());
            }
            if missing.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial { missing }
            }
        }
    };
    let mut result = vec![Coverage {
        check,
        scope: facts.discovery.scope.clone(),
        state,
        budget: None,
    }];
    result.extend(entries);
    Ok(result)
}

fn content(
    artifact: &Artifact,
    outcomes: &BTreeMap<&SliceId, &CodeOutcome>,
    parsed: &BTreeSet<&SliceId>,
    limit: u64,
) -> (CoverageState, Option<BudgetUse>) {
    let unsupported = || {
        (
            CoverageState::Unsupported {
                what: CODE_UNSUPPORTED.to_string(),
            },
            None,
        )
    };
    if !matches!(artifact.format, Format::Elf { .. })
        || artifact
            .slices
            .iter()
            .any(|slice| slice.arch != Arch::X86_64)
    {
        return unsupported();
    }
    let outcome = artifact
        .slices
        .first()
        .filter(|slice| parsed.contains(&slice.id))
        .and_then(|slice| outcomes.get(&slice.id));
    match outcome {
        Some(CodeOutcome::Unsupported) => unsupported(),
        Some(CodeOutcome::Analyzed { gaps, budget, .. }) => (
            if gaps.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial {
                    missing: gaps.clone(),
                }
            },
            Some(budget.clone()),
        ),
        None => (
            CoverageState::Partial {
                missing: vec![BINARY_NOT_PARSED.to_string()],
            },
            Some(BudgetUse {
                budget: BINARY_CODE_BYTES.to_string(),
                used: 0,
                limit,
            }),
        ),
    }
}
