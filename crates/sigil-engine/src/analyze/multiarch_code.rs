//! Marked coverage uses the model's exact per-content fold; collection supplies stable inventory.
use crate::code::CodeOutcome;
use sigil_model::*;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn recognized(a: &Artifact) -> bool {
    matches!(
        a.format,
        Format::Elf { .. } | Format::MachO | Format::MachOFat
    )
}

/// Run only on actual binary roots, before their artifacts are merged with unrelated roots.
pub(crate) fn prepare(
    artifacts: &mut [Artifact],
    instances: &[FileInstance],
    code: bool,
    recognized_multiarch: bool,
) -> bool {
    let marked = code
        && (recognized_multiarch
            || artifacts.iter().any(|a| {
                matches!(a.format, Format::MachO | Format::MachOFat)
                    || matches!(a.format, Format::Elf { .. })
                        && a.slices.iter().any(|s| s.arch == Arch::Aarch64)
            }));
    let stable: BTreeSet<_> = instances
        .iter()
        .filter(|i| i.stability == Stability::NoChangeDetected)
        .filter_map(|i| match &i.content {
            InstanceContent::Read { artifact } => Some(artifact),
            _ => None,
        })
        .collect();
    for a in artifacts {
        if !marked || !stable.contains(&a.id) || !recognized(a) {
            a.code_slice_inventory = None;
        } else if a.code_slice_inventory.is_none() {
            // A recognized malformed thin Mach-O has no slices or per-slice outcome.
            a.code_slice_inventory = Some(CodeSliceInventory::Partial {
                missing: vec![code_coverage::CODE_INVENTORY_INCOMPLETE.into()],
            });
        }
    }
    marked
}

pub(crate) fn children(
    artifact: &Artifact,
    binaries: &BTreeMap<&SliceId, &BinaryFacts>,
    outcomes: &BTreeMap<&SliceId, &CodeOutcome>,
    check: &CheckId,
    limit: u64,
) -> Vec<Coverage> {
    artifact
        .slices
        .iter()
        .map(|slice| {
            let zero = || {
                Some(BudgetUse {
                    budget: BINARY_CODE_BYTES.into(),
                    used: 0,
                    limit,
                })
            };
            let (state, budget) = if !binaries.contains_key(&slice.id) {
                (
                    CoverageState::Partial {
                        missing: vec![code_coverage::CODE_SLICE_NOT_PARSED.into()],
                    },
                    zero(),
                )
            } else {
                match outcomes.get(&slice.id) {
                    Some(CodeOutcome::Analyzed { gaps, budget, .. })
                        if !matches!(binaries.get(&slice.id), Some(BinaryFacts {container: ContainerFacts::Elf(e),..}) if e.abi.is_none()) => (
                        if gaps.is_empty() {
                            CoverageState::Complete
                        } else {
                            CoverageState::Partial {
                                missing: gaps.clone(),
                            }
                        },
                        Some(budget.clone()),
                    ),
                    _ => (
                        CoverageState::Unsupported {
                            what: format!(
                                "code: unsupported {:?} {} slice",
                                artifact.format,
                                slice.arch.name()
                            ),
                        },
                        None,
                    ),
                }
            };
            Coverage {
                check: check.clone(),
                scope: Ref::Slice(slice.id.clone()),
                state,
                budget,
            }
        })
        .collect()
}

pub(crate) fn named(
    s: &Session,
    outcomes: &[(SliceId, CodeOutcome)],
) -> Result<Vec<Coverage>, String> {
    let limit = s.request.budgets[BINARY_CODE_BYTES];
    let check = CheckId::new(BINARY_CODE).map_err(|e| e.to_string())?;
    let outcomes = outcomes.iter().map(|(id, o)| (id, o)).collect();
    let binaries = s.binaries.iter().map(|b| (&b.slice, b)).collect();
    let mut result = Vec::new();
    let mut summaries = BTreeMap::new();
    for a in s
        .artifacts
        .iter()
        .filter(|a| a.code_slice_inventory.is_some())
    {
        let child = children(a, &binaries, &outcomes, &check, limit);
        let summary =
            code_coverage::aggregate_code_slices(a, &child.iter().collect::<Vec<_>>(), limit)?;
        summaries.insert(&a.id, summary);
        result.extend(child);
    }
    for i in s.instances.iter().filter(|i| is_binary_root(&i.root)) {
        let summary = if i.stability == Stability::NoChangeDetected {
            match &i.content {
                InstanceContent::Read { artifact } => summaries.get(artifact).cloned(),
                _ => None,
            }
        } else {
            None
        };
        let (state, budget) = match summary {
            Some(s) => s,
            None => {
                let c = s
                    .coverage
                    .iter()
                    .find(|c| {
                        c.check.as_str() == BINARY_CONTAINER
                            && c.scope == Ref::Instance(i.id.clone())
                    })
                    .ok_or("missing container summary")?;
                (c.state.clone(), None)
            }
        };
        result.push(Coverage {
            check: check.clone(),
            scope: Ref::Instance(i.id.clone()),
            state,
            budget,
        });
    }
    Ok(result)
}
