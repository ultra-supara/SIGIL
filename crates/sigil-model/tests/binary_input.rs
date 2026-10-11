//! A binary inspection's inputs (PR-4b-2a spec §5): `binary-<n>` roots, the state each input
//! implies (`expected_binary_container`), and B9/B10.

mod common;

use common::*;
use sigil_model::*;

#[test]
fn binary_roots_are_numbered_from_one_without_leading_zeros() {
    assert_eq!(binary_root(1).unwrap().as_str(), "binary-1");
    assert_eq!(binary_root(0), None, "binary-0 is not a binary root");
    for (text, n) in [("binary-1", Some(1)), ("binary-10", Some(10))] {
        assert_eq!(binary_root_index(&id(text)), n, "{text}");
        assert!(is_binary_root(&id(text)));
    }
    for text in [
        "binary-0",
        "binary-01",
        "binary-",
        "binary-x",
        "install",
        "models",
    ] {
        assert_eq!(binary_root_index(&id(text)), None, "{text}");
        assert!(!is_binary_root(&id(text)));
    }
}

#[test]
fn argument_is_serialized_as_its_name() {
    assert_eq!(
        serde_json::to_string(&DiscoverySource::Argument).unwrap(),
        "\"Argument\""
    );
}

fn valid() -> Session {
    let mut s = binary_inspect();
    s.canonicalize();
    assert_eq!(s.validate(), Ok(()), "example 15 must be valid");
    s
}

/// Rejected with a `BinaryInput` error whose reason contains `why`.
fn rejected_for(s: &Session, why: &str) {
    let errors = s.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, ValidationError::BinaryInput { why: w, .. } if w.contains(why))),
        "{why}: {errors:?}"
    );
}

fn state_of<'s>(s: &'s mut Session, inst: &str) -> &'s mut CoverageState {
    &mut s
        .coverage
        .iter_mut()
        .find(|c| c.scope == Ref::Instance(id(inst)))
        .unwrap()
        .state
}

#[test]
fn the_expected_state_of_each_input() {
    let s = valid();
    let inst = |i: &str| s.instances.iter().find(|x| x.id.as_str() == i).unwrap();
    assert_eq!(
        expected_binary_container(&s, inst(ELF_INPUT)),
        Ok(ExpectedContainer::Exactly(CoverageState::Complete))
    );
    assert_eq!(
        expected_binary_container(&s, inst(TEXT_INPUT)),
        Ok(ExpectedContainer::Exactly(CoverageState::Unsupported {
            what: BINARY_UNSUPPORTED.to_string()
        }))
    );
    // A read that saw a change: Error, whatever the content.
    let mut changed = inst(ELF_INPUT).clone();
    changed.stability = Stability::ChangedDuringRead;
    assert_eq!(
        expected_binary_container(&s, &changed),
        Ok(ExpectedContainer::Exactly(CoverageState::Error {
            message: t(BINARY_CHANGED)
        }))
    );
}

#[test]
fn b9_a_coverage_is_scoped_to_an_input_instance() {
    let mut s = valid();
    s.coverage[0].scope = Ref::Audit;
    rejected_for(&s, "must be scoped to an input's instance");
    let mut s = valid();
    s.coverage.push(coverage(
        BINARY_CONTAINER,
        Ref::Instance(id("inst:models/blobs/x")),
        CoverageState::Complete,
    ));
    rejected_for(&s, "not a binary input");
}

#[test]
fn b9_each_input_has_exactly_one_coverage() {
    // The review's case: an entry dropped. outcome() reduces a check to "every entry present
    // closes", so the remaining Complete entry would close it; validate refuses the session.
    let mut s = valid();
    s.coverage
        .retain(|c| c.scope != Ref::Instance(id(TEXT_INPUT)));
    rejected_for(&s, "0 binary.container entries; an input has exactly one");
    let mut s = valid();
    let again = s.coverage[0].clone();
    s.coverage.push(again);
    rejected_for(&s, "2 binary.container entries; an input has exactly one");
}

#[test]
fn b9_the_state_is_what_the_input_implies() {
    // The review's case: an ELF with gaps, recorded as OutOfScope or NotPresent.
    let with_gap = || {
        let mut s = valid();
        s.binaries[0].gaps = vec!["comment: over 16 entries of 256 bytes".to_string()];
        *state_of(&mut s, ELF_INPUT) = CoverageState::Partial {
            missing: vec!["comment: over 16 entries of 256 bytes".to_string()],
        };
        assert_eq!(s.validate(), Ok(()));
        s
    };
    for wrong in [
        CoverageState::OutOfScope {
            why: "not asked".to_string(),
        },
        CoverageState::NotPresent {
            evidence: vec![],
            scope: "x".to_string(),
            basis: AbsenceBasis::ConnectionRefused,
        },
        CoverageState::Complete,
        CoverageState::Partial {
            missing: vec!["something else".to_string()],
        },
    ] {
        let mut s = with_gap();
        *state_of(&mut s, ELF_INPUT) = wrong.clone();
        rejected_for(&s, "but the input implies");
    }
    // Complete for the non-ELF; Unsupported for the ELF; Error without a change.
    let mut s = valid();
    *state_of(&mut s, TEXT_INPUT) = CoverageState::Complete;
    rejected_for(&s, "but the input implies");
    let mut s = valid();
    *state_of(&mut s, ELF_INPUT) = CoverageState::Unsupported {
        what: BINARY_UNSUPPORTED.to_string(),
    };
    rejected_for(&s, "but the input implies");
    let mut s = valid();
    *state_of(&mut s, ELF_INPUT) = CoverageState::Error {
        message: t(BINARY_CHANGED),
    };
    rejected_for(&s, "but the input implies");
}

#[test]
fn b9_an_input_over_binary_bytes() {
    // The text input, not read for the budget: its artifact is gone with its read.
    let over = |state: CoverageState| {
        let mut s = valid();
        s.artifacts.retain(|a| a.format != Format::Other);
        let i = s
            .instances
            .iter_mut()
            .find(|i| i.id.as_str() == TEXT_INPUT)
            .unwrap();
        i.content = InstanceContent::NotRead {
            why: NotReadReason::BudgetExceeded,
        };
        *state_of(&mut s, TEXT_INPUT) = state;
        s
    };
    let limit = 64u64 << 30;
    let ok = over(CoverageState::BudgetExceeded {
        budget: BINARY_BYTES.to_string(),
        used: limit - 10,
        limit,
    });
    assert_eq!(ok.validate(), Ok(()));
    for wrong in [
        CoverageState::BudgetExceeded {
            budget: "install_bytes".to_string(),
            used: 1,
            limit,
        },
        CoverageState::BudgetExceeded {
            budget: BINARY_BYTES.to_string(),
            used: 1,
            limit: 7,
        },
        CoverageState::BudgetExceeded {
            budget: BINARY_BYTES.to_string(),
            used: limit + 1,
            limit,
        },
        CoverageState::Complete,
    ] {
        rejected_for(&over(wrong), "but the input is over binary_bytes");
    }
    // Any other unread input is a fatal error, never part of a session.
    let mut s = over(CoverageState::Complete);
    s.instances
        .iter_mut()
        .find(|i| i.id.as_str() == TEXT_INPUT)
        .unwrap()
        .content = InstanceContent::NotRead {
        why: NotReadReason::PermissionDenied,
    };
    rejected_for(&s, "fatal input error");
}

#[test]
fn b10_a_session_with_a_binary_root_is_a_binary_inspection() {
    let mut s = valid();
    s.request.roots.push(ScanRoot {
        id: id("models"),
        path: t("/srv/models"),
    });
    rejected_for(&s, "has only binary roots");
    let mut s = valid();
    s.request.mode = Mode::Observe;
    rejected_for(&s, "is static");
    let mut s = valid();
    s.request.active = vec![ActiveFeature::ApiProbe {
        address: "127.0.0.1".to_string(),
        port: 11434,
        allow_remote: false,
    }];
    rejected_for(&s, "has no active feature");
    let mut s = valid();
    s.request.model_filter = Some("m:latest".to_string());
    rejected_for(&s, "has no model filter");
    let mut s = valid();
    let mut second = s.instances[0].clone();
    second.id = id("inst:binary-1/other");
    s.instances.push(second);
    rejected_for(&s, "2 instances; a binary root has exactly one");
    let mut s = valid();
    s.instances[0].path = t("/somewhere/else");
    rejected_for(&s, "not at its root's path");
    let mut s = valid();
    s.instances[0].discovered_by = vec![DiscoverySource::Walk];
    rejected_for(&s, "discovered by Argument only");
}
