//! The viewer must fail closed until Task 4 installs multiarchitecture coverage validation.
use sigil_model::{code_abi, CodeAnalysis, Session};
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
fn marked_saved_sessions_are_gated_in_both_native_and_wasm_entrypoints() {
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
    assert!(errors.iter().any(|e| e
        .to_string()
        .contains("multiarch coverage validation is not enabled")));
    assert!(render_session_markdown_inner(&json)
        .unwrap_err()
        .contains("multiarch coverage validation is not enabled"));
    s.knowledge.last_mut().unwrap().version = "unknown".into();
    assert!(
        render_session_markdown_inner(&serde_json::to_string(&s).unwrap())
            .unwrap_err()
            .contains("code-abi-signatures")
    );
}
