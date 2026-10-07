//! Deterministic serialization (plan §4.4.1, §4.4.7; brief §27).

mod common;

use common::*;
use sigil_model::*;

/// Reverses every set-like list, as a different discovery order would produce.
fn reorder(s: &mut Session) {
    s.knowledge.reverse();
    s.request.roots.reverse();
    s.request.required_checks.reverse();
    s.artifacts.reverse();
    s.instances.reverse();
    s.values.reverse();
    s.components.reverse();
    for claim in &mut s.components {
        claim.assertions.reverse();
        claim.versions.reverse();
    }
    s.code.reverse();
    for facts in &mut s.code {
        facts.functions.reverse();
        facts.call_sites.reverse();
    }
    s.relations.reverse();
    s.rule_support.reverse();
    s.loads.reverse();
    s.coverage.reverse();
    s.findings.reverse();
    s.open_questions.reverse();
}

#[test]
fn serializing_the_same_session_twice_gives_identical_bytes() {
    for (name, s) in examples() {
        let a = s.to_canonical_json().unwrap();
        let b = s.clone().to_canonical_json().unwrap();
        assert_eq!(a, b, "{name}");
        assert_eq!(
            serde_json::to_vec(&s).unwrap(),
            serde_json::to_vec(&s).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn discovery_order_does_not_change_the_canonical_bytes() {
    for (name, s) in examples() {
        let mut shuffled = s.clone();
        reorder(&mut shuffled);
        assert_eq!(
            s.to_canonical_json().unwrap(),
            shuffled.to_canonical_json().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn canonicalization_is_idempotent_and_keeps_validity() {
    for (name, s) in examples() {
        let mut once = s.clone();
        once.canonicalize();
        let mut twice = once.clone();
        twice.canonicalize();
        assert_eq!(once, twice, "{name}");
        assert!(once.validate().is_ok(), "{name}");
    }
}

#[test]
fn ordered_lists_are_evidence_and_are_not_sorted() {
    let s = loader_slice_spec_example();
    let mut reversed = s.clone();
    let Relation::ProfileMatch { obligations, .. } = reversed
        .relations
        .iter_mut()
        .find(|r| matches!(r, Relation::ProfileMatch { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    obligations[0].at.reverse();
    assert_ne!(
        s.to_canonical_json().unwrap(),
        reversed.to_canonical_json().unwrap(),
        "obligation locations"
    );

    let mut canonical = s.clone();
    canonical.canonicalize();
    let names: Vec<_> = canonical.code[0]
        .call_sites
        .iter()
        .filter_map(|c| match c.args.first() {
            Some(ArgValue::ConstStr { value, .. }) if c.addr >= 0xecbe && c.addr < 0xed00 => {
                value.as_str().map(str::to_string)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        ["blas", "cuda", "cpu"],
        "the backend-name sequence keeps call order"
    );
    let atoms: Vec<_> = canonical.code[0].predicate_checks[0]
        .atoms
        .iter()
        .map(|a| a.name.as_str().to_string())
        .collect();
    assert_eq!(atoms, ["T", "F", "C"], "atoms keep the profile's order");
}

#[test]
fn canonical_json_ends_with_a_newline() {
    assert!(complete_pass()
        .to_canonical_json()
        .unwrap()
        .ends_with("}\n"));
}
