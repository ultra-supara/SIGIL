//! Native viewer entry points share strict marked coverage validation with actual WASM.
#[allow(dead_code)]
#[path = "../../sigil-model/tests/support/multiarch.rs"]
mod support;
use sigil_model::{code_abi, CodeAnalysis, Ref, Session};
use sigil_wasm::render_session_markdown_inner;

#[test]
fn historical_install_architecture_and_format_remain_readable() {
    let raw = include_str!("../../../schemas/examples/session-v1/10-target-verified.json");
    for arch in ["x86_64", "aarch64"] {
        for macho in [false, true] {
            for omitted in [false, true] {
                let mut value: serde_json::Value =
                    serde_json::from_str(&raw.replace("x86_64", arch)).unwrap();
                if macho {
                    value["artifacts"][0]["format"] = serde_json::json!("MachO");
                }
                if omitted {
                    value["request"].as_object_mut().unwrap().remove("code");
                }
                assert!(render_session_markdown_inner(&value.to_string()).is_ok());
            }
        }
    }
}

#[test]
fn incomplete_marked_saved_sessions_are_rejected_by_native_and_wasm_entrypoints() {
    let mut s: Session = serde_json::from_str(include_str!(
        "../../../schemas/examples/session-v1/16-binary-code.json"
    ))
    .unwrap();
    assert!(s.validate().is_ok());
    assert!(render_session_markdown_inner(&serde_json::to_string(&s).unwrap()).is_ok());
    s.request.code_analysis = Some(CodeAnalysis::MultiarchV1);
    s.knowledge.push(code_abi::V1.knowledge().unwrap());
    let json = serde_json::to_string(&s).unwrap();
    let errors = s.validate().unwrap_err();
    assert!(errors
        .iter()
        .any(|e| e.to_string().contains("missing code slice inventory")));
    assert!(render_session_markdown_inner(&json)
        .unwrap_err()
        .contains("missing code slice inventory"));
    s.knowledge.last_mut().unwrap().version = "unknown".into();
    assert!(
        render_session_markdown_inner(&serde_json::to_string(&s).unwrap())
            .unwrap_err()
            .contains("code-abi-signatures")
    );
}

#[test]
fn canonical_call_ids_are_required_only_in_marked_viewer_sessions() {
    let raw = include_str!("../../../schemas/examples/session-v1/16-binary-code.json");
    for id in ["cs:0x4d: second", "cs:0x4D", "cs:0x04d", "cs:0x50"] {
        let mut s: Session = serde_json::from_str(&raw.replace("cs:0x4d", id)).unwrap();
        assert!(render_session_markdown_inner(&serde_json::to_string(&s).unwrap()).is_ok());
        s.request.code_analysis = Some(CodeAnalysis::MultiarchV1);
        s.knowledge.push(code_abi::V1.knowledge().unwrap());
        let error = render_session_markdown_inner(&serde_json::to_string(&s).unwrap()).unwrap_err();
        assert!(error.contains("call ID must match its canonical address"));
        assert!(error.contains("missing code slice inventory"));
    }
}

#[test]
fn coverage_inventory_matrix_renders_and_rejects_missing_children() {
    for s in support::matrix() {
        for s in [s.clone(), support::installation(s)] {
            let json = s.to_canonical_json().unwrap();
            let markdown = render_session_markdown_inner(&json).unwrap();
            assert!(!markdown.is_empty());
            let round: Session = serde_json::from_str(&json).unwrap();
            assert_eq!(
                render_session_markdown_inner(&round.to_canonical_json().unwrap()).unwrap(),
                markdown
            );
            if s.artifacts[0].slices.is_empty() {
                continue;
            }
            let mut bad = s;
            let id = bad.artifacts[0].slices[0].id.clone();
            bad.coverage.retain(|c| c.scope != Ref::Slice(id.clone()));
            let error =
                render_session_markdown_inner(&serde_json::to_string(&bad).unwrap()).unwrap_err();
            assert!(error.contains("missing or duplicate required code scope"));
        }
    }
}

#[test]
fn marked_viewer_rejects_oversized_inventory_and_invalid_fat_alignment() {
    let control = support::fat();
    assert!(render_session_markdown_inner(&control.to_canonical_json().unwrap()).is_ok());
    for exponent in [12, 64, 65, u32::MAX] {
        let mut s = control.clone();
        if let sigil_model::ContainerFacts::MachO(m) = &mut s.binaries[1].container {
            m.fat_alignment = Some(exponent);
        }
        let error = render_session_markdown_inner(&serde_json::to_string(&s).unwrap()).unwrap_err();
        assert!(error.contains("fat descriptor alignment"), "{error}");
    }
    let mut s = control;
    let repeated = s.artifacts[0].slices[0].clone();
    s.artifacts[0].slices.resize(65, repeated);
    let error = render_session_markdown_inner(&serde_json::to_string(&s).unwrap()).unwrap_err();
    assert!(error.contains("64 recorded slices"), "{error}");
    assert!(
        !error.contains("duplicate"),
        "count must fail before indexing: {error}"
    );
}
