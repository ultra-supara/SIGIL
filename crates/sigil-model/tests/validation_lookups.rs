//! Lookup optimizations must preserve the ordered errors of ambiguous, invalid sessions.
mod common;

use sigil_model::*;

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
