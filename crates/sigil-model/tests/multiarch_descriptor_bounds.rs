//! Reviewed saved-session descriptor bounds, without enabling any producer.
#[allow(dead_code)]
#[path = "support/multiarch.rs"]
mod support;
use sigil_model::*;
use support::*;

fn valid(s: &Session) {
    s.validate().unwrap();
    let round: Session = serde_json::from_str(&s.to_canonical_json().unwrap()).unwrap();
    round.validate().unwrap();
}

fn code_error(s: &Session, needle: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::Code { .. }) && e.to_string().contains(needle)),
        "{errors:?}"
    );
}

fn counted(n: usize) -> Session {
    let mut s = fat();
    let template = s.clone();
    s.artifacts[0].size = 4096 + n as u64 * 1024;
    s.artifacts[0].slices.clear();
    s.binaries.clear();
    s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
    for i in 0..n {
        let mut slice = template.artifacts[0].slices[0].clone();
        slice.offset = 4096 + i as u64 * 1024;
        slice.id = SliceId::new(format!("{}#x86_64@{}", s.artifacts[0].id, slice.offset)).unwrap();
        let mut binary = template.binaries[0].clone();
        binary.slice = slice.id.clone();
        if let ContainerFacts::MachO(m) = &mut binary.container {
            m.cpu_subtype = i as i32;
            m.fat_cpu_subtype = Some(i as i32);
        }
        s.coverage.push(Coverage {
            check: CheckId::new(BINARY_CODE).unwrap(),
            scope: Ref::Slice(slice.id.clone()),
            state: CoverageState::Complete,
            budget: Some(budget(0)),
        });
        s.artifacts[0].slices.push(slice);
        s.binaries.push(binary);
    }
    parent(&mut s, CoverageState::Complete, Some(0));
    s
}

fn legacy(mut s: Session) -> Session {
    s.request.code_analysis = None;
    for a in &mut s.artifacts {
        a.code_slice_inventory = None;
    }
    for b in &mut s.binaries {
        if let ContainerFacts::MachO(m) = &mut b.container {
            m.little_endian = None;
        }
    }
    s.code.clear();
    s.coverage.retain(|c| !matches!(c.scope, Ref::Slice(_)));
    parent(
        &mut s,
        CoverageState::Unsupported {
            what: CODE_UNSUPPORTED.into(),
        },
        None,
    );
    s
}

#[test]
fn descriptor_limit_is_per_artifact_and_also_applies_to_partial_inventory() {
    let control = counted(64);
    valid(&control);
    valid(&installation(control.clone()));
    let entries: Vec<_> = control
        .coverage
        .iter()
        .filter(|c| matches!(c.scope, Ref::Slice(_)))
        .collect();
    code_coverage::aggregate_code_slices(&control.artifacts[0], &entries, 10).unwrap();
    for count in [65, 1024] {
        let mut bad = counted(count);
        code_error(&bad, "64 recorded slices");
        let entries: Vec<_> = bad
            .coverage
            .iter()
            .filter(|c| matches!(c.scope, Ref::Slice(_)))
            .collect();
        assert!(
            code_coverage::aggregate_code_slices(&bad.artifacts[0], &entries, 10)
                .unwrap_err()
                .contains("64 recorded slices")
        );
        inventory_partial(&mut bad);
        code_error(&bad, "64 recorded slices");
        valid(&legacy(counted(count)));
    }
    // There is no session-wide 64-slice limit: two valid artifacts have independent budgets.
    let raw = serde_json::to_string(&control)
        .unwrap()
        .replace(
            control.artifacts[0]
                .id
                .as_str()
                .strip_prefix("sha256:")
                .unwrap(),
            &"bb".repeat(32),
        )
        .replace("binary-1", "binary-2");
    let other: Session = serde_json::from_str(&raw).unwrap();
    let mut two = control;
    two.request.roots.extend(other.request.roots);
    two.artifacts.extend(other.artifacts);
    two.binaries.extend(other.binaries);
    two.instances.extend(other.instances);
    two.coverage.extend(other.coverage);
    valid(&two);
}

#[test]
fn invalid_marked_descriptor_shapes_fail_before_ordinary_validation() {
    let mut oversized = counted(65);
    let repeated = oversized.artifacts[0].slices[0].clone();
    oversized.artifacts[0].slices.fill(repeated);
    let errors = oversized.validate().unwrap_err();
    assert_eq!(
        errors.len(),
        1,
        "limit must reject before duplicate diagnostics/index work: {errors:?}"
    );
    code_error(&oversized, "64 recorded slices");
    let mut duplicate = counted(2);
    duplicate.artifacts[0].slices[1] = duplicate.artifacts[0].slices[0].clone();
    let errors = duplicate.validate().unwrap_err();
    assert_eq!(
        errors.len(),
        1,
        "duplicate descriptor shape must fail before indexing: {errors:?}"
    );
    code_error(&duplicate, "duplicate recorded code slice");
}

fn move_slice(s: Session, n: usize, offset: u64) -> Session {
    let mut s = s;
    let old = s.artifacts[0].slices[n].id.clone();
    let new = SliceId::new(format!(
        "{}#{}@{offset}",
        s.artifacts[0].id,
        s.artifacts[0].slices[n].arch.name()
    ))
    .unwrap();
    s.artifacts[0].slices[n].offset = offset;
    serde_json::from_str(
        &serde_json::to_string(&s)
            .unwrap()
            .replace(old.as_str(), new.as_str()),
    )
    .unwrap()
}

fn facts_control() -> Session {
    let mut s = move_slice(fat(), 0, 1024);
    let source: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    for slice in &s.artifacts[0].slices {
        let mut facts = source.code[0].clone();
        facts.slice = slice.id.clone();
        facts.call_sites.clear();
        s.code.push(facts);
    }
    s
}

#[test]
fn fat_alignment_is_checked_without_shift_overflow_or_false_completion() {
    let control = facts_control();
    valid(&control);
    for exponent in [0, 1, 10, 11] {
        let mut s = control.clone();
        if let ContainerFacts::MachO(m) = &mut s.binaries[1].container {
            m.fat_alignment = Some(exponent);
        }
        valid(&s);
    }
    for exponent in [12, 64, 65, u32::MAX] {
        let mut bad = control.clone();
        if let ContainerFacts::MachO(m) = &mut bad.binaries[1].container {
            m.fat_alignment = Some(exponent);
        }
        code_error(&bad, "fat descriptor alignment");
        valid(&legacy(bad.clone()));
        // A forged partial summary does not legitimize an internally contradictory descriptor.
        inventory_partial(&mut bad);
        child(&mut bad, 1).state = CoverageState::Partial {
            missing: vec!["alignment not understood".into()],
        };
        let state = incomplete(&bad, &[1], true);
        parent(&mut bad, state, Some(9));
        code_error(&bad, "fat descriptor alignment");
    }
    let mut high = move_slice(control, 1, 1u64 << 63);
    high.artifacts[0].size = (1u64 << 63) + 1024;
    if let ContainerFacts::MachO(m) = &mut high.binaries[1].container {
        m.fat_alignment = Some(63);
    }
    valid(&high);
    let misaligned = move_slice(high, 1, (1u64 << 63) - 1024);
    code_error(&misaligned, "fat descriptor alignment");
}

#[test]
fn discarded_invalid_descriptors_preserve_healthy_sibling_evidence() {
    let mut s = facts_control();
    let removed = s.artifacts[0].slices.pop().unwrap();
    s.binaries.retain(|b| b.slice != removed.id);
    s.code.retain(|c| c.slice != removed.id);
    s.coverage
        .retain(|c| c.scope != Ref::Slice(removed.id.clone()));
    inventory_partial(&mut s);
    // Keep the original container diagnostic; it must not invalidate the healthy local search.
    s.binaries[0]
        .gaps
        .push("fat slice 1: invalid offset, size, or alignment".into());
    let state = expected_binary_container(&s, &s.instances[0])
        .unwrap()
        .into_state(0);
    s.coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = state;
    let state = incomplete(&s, &[], true);
    parent(&mut s, state, Some(4));
    valid(&s);
    valid(&installation(s.clone()));
    assert_eq!(s.code.len(), 1);
    assert!(!s.code[0].functions.is_empty());
    assert_eq!(s.artifacts[0].slices.len(), 1);
    // The parser's over-count representation retains no fabricated descriptors.
    let mut over_count = counted(0);
    inventory_partial(&mut over_count);
    let state = incomplete(&over_count, &[], true);
    parent(&mut over_count, state, Some(0));
    let state = expected_binary_container(&over_count, &over_count.instances[0])
        .unwrap()
        .into_state(0);
    over_count
        .coverage
        .iter_mut()
        .find(|c| c.check.as_str() == BINARY_CONTAINER)
        .unwrap()
        .state = state;
    completeness(&mut over_count);
    valid(&over_count);
}
