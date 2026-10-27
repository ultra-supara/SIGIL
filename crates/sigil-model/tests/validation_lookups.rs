//! Lookup optimizations must preserve the ordered errors of ambiguous, invalid sessions.
mod common;

use sigil_model::*;

#[test]
fn a_validated_session_must_be_revalidated_after_editing() {
    let s = common::binary_code();
    let original = s.to_canonical_json().unwrap();
    let checked = ValidatedSession::new(s).unwrap();
    assert_eq!(checked.as_session().to_canonical_json().unwrap(), original);
    let mut edited = checked.into_inner();
    edited.outcome.confirmed_failures += 1;
    let errors = common::errors(&edited);
    assert!(!errors.is_empty());
    assert_eq!(ValidatedSession::new(edited).unwrap_err(), errors);
}

#[test]
fn container_uses_the_last_instance_but_code_and_identity_use_the_last_binary_instance() {
    let mut s = common::binary_code();
    let mut root = s.request.roots[0].clone();
    root.id = RootId::new("outside").unwrap();
    let mut later = s.instances[0].clone();
    later.root = root.id.clone();
    later.discovered_by.clear();
    s.request.roots.push(root);
    s.instances.push(later);
    let id = s.instances[0].id.to_string();
    assert_eq!(
        common::errors(&s),
        vec![
            ValidationError::DuplicateId {
                kind: "instance",
                id: id.clone()
            },
            ValidationError::BinaryInput {
                at: id.clone(),
                why: "binary.container on something that is not a binary input".to_string(),
            },
            ValidationError::BinaryInput {
                at: "request".to_string(),
                why: "a binary inspection has only binary roots".to_string(),
            },
            ValidationError::BinaryInput {
                at: id,
                why: "0 binary.container entries; an input has exactly one".to_string(),
            },
        ]
    );
}

#[test]
fn duplicate_binary_facts_do_not_replace_the_first_facts_used_by_hints_and_coverage() {
    let mut s = common::binary_code();
    let mut later = s.binaries[0].clone();
    let ContainerFacts::Elf(elf) = &mut later.container else {
        panic!("the fixture is ELF");
    };
    elf.imports.clear();
    later.gaps.push("a gap in the later record".to_string());
    s.binaries.push(later);
    assert_eq!(
        common::errors(&s),
        vec![ValidationError::Binary {
            slice: s.binaries[0].slice.to_string(),
            why: "one record per slice".to_string(),
        }]
    );
}

#[test]
fn duplicate_artifacts_and_slices_keep_the_first_artifact_for_binary_facts_and_inputs() {
    let mut s = common::binary_code();
    let mut later = s.artifacts[0].clone();
    later.format = Format::Other;
    s.artifacts.push(later);
    assert_eq!(
        common::errors(&s),
        vec![
            ValidationError::DuplicateId {
                kind: "artifact",
                id: s.artifacts[0].id.to_string(),
            },
            ValidationError::DuplicateId {
                kind: "slice",
                id: s.artifacts[0].slices[0].id.to_string(),
            },
        ]
    );
}

#[test]
fn code_coverage_still_considers_all_artifacts_with_the_input_content_id() {
    let mut s = common::binary_code();
    let mut later = s.artifacts[0].clone();
    let slice = &mut later.slices[0];
    slice.offset = 64;
    slice.size -= 64;
    slice.id = SliceId::from_parts(&later.id, slice.arch, slice.offset);
    let mut code = s.code[0].clone();
    code.slice = slice.id.clone();
    s.code.push(code);
    s.artifacts.push(later);
    assert_eq!(
        common::errors(&s),
        vec![ValidationError::DuplicateId {
            kind: "artifact",
            id: s.artifacts[0].id.to_string(),
        }]
    );
}

#[test]
fn model_blobs_and_license_keep_the_first_root_and_instance() {
    let mut s = common::with_model();
    common::assert_valid(&s);
    let mut root = s.request.roots[1].clone();
    root.path = UntrustedText::new("/elsewhere");
    s.request.roots.push(root);
    let mut blob = s.instances.last().unwrap().clone();
    blob.root = s.request.roots[0].id.clone();
    blob.path = UntrustedText::new("/elsewhere/blob");
    blob.content = s.instances[0].content.clone();
    let id = blob.id.to_string();
    s.instances.push(blob);
    assert_eq!(
        common::errors(&s),
        vec![
            ValidationError::DuplicateId {
                kind: "root",
                id: "models".to_string()
            },
            ValidationError::DuplicateId {
                kind: "instance",
                id
            },
        ]
    );
}
