//! Pure MultiarchV1 coverage contracts. Legacy expectations are deliberately separate.
use std::collections::HashMap;

use crate::{
    Artifact, BinaryFacts, BudgetUse, CodeSliceInventory, ContainerFacts, Coverage, CoverageState,
    Ref, BINARY_CODE_BYTES,
};

pub const CODE_SLICE_NOT_PARSED: &str = "code: slice not parsed";
pub const CODE_INVENTORY_INCOMPLETE: &str = "code: slice inventory incomplete";
pub const CODE_NO_SUPPORTED_SLICE: &str = "code: no supported slice";
pub const CODE_SLICE_NOT_STARTED: &str = "code: artifact budget exhausted before slice";
/// The shared reader's descriptor bound, applied independently to each marked artifact.
pub const MAX_CODE_SLICES: usize = 64;

/// Whether recorded parser gaps prevent proving that all capability imports were collected.
pub fn imports_incomplete(binary: &BinaryFacts) -> bool {
    binary.gaps.iter().any(|gap| {
        gap.starts_with("imports:")
            || gap.starts_with("binary_parse_bytes:")
            || match &binary.container {
                ContainerFacts::Elf(_) => [
                    "dynamic:",
                    "symbols:",
                    "malformed: symbols:",
                    "sections:",
                    "malformed: section names:",
                    "malformed: program headers:",
                ]
                .iter()
                .any(|prefix| gap.starts_with(prefix)),
                ContainerFacts::MachO(_) => {
                    ["load commands:", "load dylib:", "LC_DYLD_CHAINED_FIXUPS:"]
                        .iter()
                        .any(|prefix| gap.starts_with(prefix))
                }
            }
    })
}

/// Why a marked slice with capability imports has no confirmed direct call.
/// Only the slice's own applicable code check can establish a complete local search.
pub fn unknown_capability_call(
    state: Option<&CoverageState>,
    check: crate::CheckId,
) -> crate::UnknownReason {
    if matches!(state, Some(CoverageState::Complete)) {
        crate::UnknownReason::NotModeled {
            what: "calls that are not direct (through a function pointer, or from data)".into(),
        }
    } else {
        crate::UnknownReason::CheckIncomplete { check }
    }
}

pub(crate) fn valid_gaps(missing: &[String]) -> bool {
    !missing.is_empty()
        && missing.iter().all(|s| !s.trim().is_empty())
        && missing.windows(2).all(|p| p[0] < p[1])
}

/// Fold exactly one child for every recorded descriptor, in shared-reader traversal order.
/// Input vector order is immaterial. The caller validates check applicability, stable
/// placement and parsed ABI; this helper validates inventory, child states and all charges.
/// No descriptor or SliceId is synthesized from an inventory diagnostic.
pub fn aggregate_code_slices(
    artifact: &Artifact,
    children: &[&Coverage],
    limit: u64,
) -> Result<(CoverageState, Option<BudgetUse>), String> {
    if artifact.slices.len() > MAX_CODE_SLICES {
        return Err("code inventory exceeds 64 recorded slices per artifact".into());
    }
    if children.len() != artifact.slices.len() {
        return Err("missing or extra code slice child".into());
    }
    let partial_inventory = match &artifact.code_slice_inventory {
        Some(CodeSliceInventory::Complete) if !artifact.slices.is_empty() => false,
        Some(CodeSliceInventory::Complete) => return Err("complete inventory has no slices".into()),
        Some(CodeSliceInventory::Partial { missing })
            if valid_gaps(missing) && missing.iter().any(|s| s == CODE_INVENTORY_INCOMPLETE) => true,
        Some(_) => return Err("partial inventory needs sorted unique diagnostics including code: slice inventory incomplete".into()),
        None => return Err("missing code slice inventory".into()),
    };
    let mut indexed = HashMap::with_capacity(children.len());
    for child in children {
        let Ref::Slice(id) = &child.scope else {
            return Err("code child needs slice scope".into());
        };
        if indexed.insert(id, *child).is_some() {
            return Err("duplicate code slice child".into());
        }
    }
    let mut slices: Vec<_> = artifact.slices.iter().collect();
    slices.sort_by_key(|s| (s.offset, s.arch.name(), &s.id));
    let mut previous_end = 0;
    for slice in &slices {
        if slice.offset < previous_end {
            return Err("code inventory retains overlapping slice descriptors".into());
        }
        previous_end = slice
            .offset
            .checked_add(slice.size)
            .ok_or("code slice range overflow")?;
    }
    let mut used = 0u64;
    let mut unsupported = 0;
    let mut exhausted = false;
    let mut missing = Vec::new();
    if partial_inventory {
        missing.push(CODE_INVENTORY_INCOMPLETE.to_string());
    }
    for slice in slices {
        let child = indexed
            .remove(&slice.id)
            .ok_or("missing or duplicate code slice child")?;
        match &child.state {
            CoverageState::Unsupported { what }
                if !what.trim().is_empty() && child.budget.is_none() =>
            {
                unsupported += 1;
            }
            CoverageState::Complete | CoverageState::Partial { .. } => {
                let b = child
                    .budget
                    .as_ref()
                    .ok_or("code child has no byte budget")?;
                if b.budget != BINARY_CODE_BYTES || b.limit != limit || b.used > limit {
                    return Err("invalid code child byte budget".into());
                }
                let unstarted = matches!(&child.state, CoverageState::Partial { missing } if missing.iter().any(|g| g == CODE_SLICE_NOT_STARTED));
                // Unparsed descriptors retain their mandatory gap even after shared code
                // work stops. The validator separately requires the absence of BinaryFacts.
                let unparsed = matches!(&child.state, CoverageState::Partial { missing } if missing == &[CODE_SLICE_NOT_PARSED.to_string()])
                    && b.used == 0;
                if exhausted && !unstarted && !unparsed {
                    return Err(
                        "later supported slice must remain unstarted after shared exhaustion"
                            .into(),
                    );
                }
                if let CoverageState::Partial { missing } = &child.state {
                    if !valid_gaps(missing) {
                        return Err("partial code child needs sorted unique nonempty gaps".into());
                    }
                    if missing.iter().any(|g| g == CODE_SLICE_NOT_STARTED) && b.used != 0 {
                        return Err("unstarted code slice must charge zero bytes".into());
                    }
                }
                exhausted |= unstarted;
                used = used
                    .checked_add(b.used)
                    .ok_or("code slice byte sum overflow")?;
                if used > limit {
                    return Err("code slice byte sum exceeds artifact limit".into());
                }
            }
            _ => return Err("invalid code slice state or unsupported budget".into()),
        }
        if child.state != CoverageState::Complete {
            missing.push(format!("code: incomplete slice {}", slice.id));
        }
    }
    if !partial_inventory && unsupported == artifact.slices.len() {
        return Ok((
            CoverageState::Unsupported {
                what: CODE_NO_SUPPORTED_SLICE.into(),
            },
            None,
        ));
    }
    missing.sort();
    let state = if missing.is_empty() {
        CoverageState::Complete
    } else {
        CoverageState::Partial { missing }
    };
    Ok((
        state,
        Some(BudgetUse {
            budget: BINARY_CODE_BYTES.into(),
            used,
            limit,
        }),
    ))
}
