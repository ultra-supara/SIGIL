//! Every golden binary inspection carries exactly the component claims the engine derives from
//! its facts (PR-4c-1 plan P-l), as `example_hints.rs` does for hints. The install examples'
//! claims are specification examples: they have no binary facts to derive them from.

use std::path::Path;

use sigil_engine::analyze::identity::derive;
use sigil_model::{
    is_binary_inspection, BinaryFacts, ContainerFacts, DataValue, ElfFacts, FunctionReturn, Loc,
    Session, UntrustedText,
};

#[test]
fn every_binary_inspection_example_carries_the_claims_the_engine_derives() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples/session-v1");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    let mut checked = vec![];
    for path in names {
        let session: Session =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if !is_binary_inspection(&session.request) {
            continue;
        }
        let mut derived = session.clone();
        derived.components = derive(
            &session.instances,
            &session.binaries,
            &session.reference_matches,
        )
        .unwrap();
        derived.canonicalize();
        assert_eq!(session.components, derived.components, "{}", path.display());
        checked.push(path.file_stem().unwrap().to_string_lossy().into_owned());
    }
    assert_eq!(checked, ["15-binary-inspect", "16-binary-code"]);
}

/// Example 12 is a specification example, without binary facts. With the facts it describes
/// (`ggml_version()` returning `0.12.0` at `0x9d160`), the engine derives its claim exactly:
/// `Conflicting` under the 0.x rule (PR-4c-2b, F-I2).
#[test]
fn example_12_is_the_claim_the_engine_derives_from_its_facts() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/examples/session-v1/12-conflicting-identity.json");
    let session: Session = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let facts = BinaryFacts {
        slice: session.components[0].subject.clone(),
        container: ContainerFacts::Elf(ElfFacts {
            interp: None,
            soname: None,
            needed: vec![],
            rpath: vec![],
            runpath: vec![],
            build_id: None,
            comment: vec![],
            stripped: Some(true),
            exports: 2,
            imports: vec![],
            data: vec![],
            returns: vec![FunctionReturn {
                function: "ggml_version".to_string(),
                value: DataValue::Text(UntrustedText::new("0.12.0")),
                at: vec![
                    Loc::Symbol(UntrustedText::new("ggml_version")),
                    Loc::VAddr(0x9d160),
                ],
            }],
        }),
        go: None,
        gaps: vec![],
    };
    let mut derived = session.clone();
    derived.components = derive(&session.instances, &[facts], &session.reference_matches).unwrap();
    derived.canonicalize();
    assert_eq!(derived.components, session.components);
}
