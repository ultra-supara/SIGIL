//! `sigil-wasm` natively (PR-3b-3b design §4): what the viewer gets is exactly what the CLI's
//! renderers produce, a session is validated before it is shown, and an AI-BOM v1 is named.

use std::fs;
use std::path::PathBuf;

use sigil_model::render::aibom::markdown as aibom_markdown;
use sigil_model::render::html::from_markdown;
use sigil_model::render::markdown::render_session;
use sigil_model::{AiBom, Session};
use sigil_wasm::{
    detect_inner, markdown_html_inner, render_aibom_markdown_inner, render_session_markdown_inner,
};

fn schemas() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas")
}

fn files(dir: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(schemas().join(dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read_to_string(&path).unwrap())
        })
        .collect();
    out.sort();
    out
}

const V1: &str = r#"{"schema_version": "1.1", "tool": {"name": "sigil", "version": "0.1.0"},
  "runtime": {"name": "ollama"}, "models": [], "findings": [], "verdict": "PASS"}"#;

#[test]
fn detect_names_each_kind() {
    let (_, session) = &files("examples/session-v1")[0];
    let (_, bom) = &files("examples/aibom-v2")[0];
    assert_eq!(detect_inner(session), "session");
    assert_eq!(detect_inner(bom), "aibom-v2");
    assert_eq!(detect_inner(V1), "aibom-v1");
    assert_eq!(detect_inner(r#"{"schema": "sigil-session/2"}"#), "unknown");
    assert_eq!(detect_inner("not json"), "unknown");
}

#[test]
fn sessions_render_as_the_cli_renders_them() {
    for (name, text) in files("examples/session-v1") {
        let session: Session = serde_json::from_str(&text).unwrap();
        let md = render_session_markdown_inner(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(md, render_session(&session), "{name}");
        assert_eq!(markdown_html_inner(&md), from_markdown(&md), "{name}");
    }
}

#[test]
fn aiboms_render_as_the_model_renders_them() {
    for (name, text) in files("examples/aibom-v2") {
        let bom: AiBom = serde_json::from_str(&text).unwrap();
        let md = render_aibom_markdown_inner(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(md, aibom_markdown(&bom), "{name}");
    }
}

#[test]
fn a_session_that_fails_validation_is_not_shown() {
    let (_, text) = files("examples/session-v1")
        .into_iter()
        .find(|(n, _)| n == "02-complete-fail.json")
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    // A finding whose subject names an artifact the session does not contain.
    value["findings"][0]["subject"] =
        serde_json::json!({"Artifact": format!("sha256:{}", "e".repeat(64))});
    let err = render_session_markdown_inner(&value.to_string()).unwrap_err();
    assert!(err.contains("fails validation"), "{err}");
    assert!(err.contains("unknown artifact"), "{err}");
}

#[test]
fn an_aibom_v1_is_named_not_rendered() {
    for err in [
        render_aibom_markdown_inner(V1).unwrap_err(),
        render_session_markdown_inner(V1).unwrap_err(),
    ] {
        assert!(err.contains("AI-BOM v1"), "{err}");
        assert!(err.contains("SIGIL 0.1"), "{err}");
        assert!(err.contains("aibom-v1.schema.json"), "{err}");
    }
}

#[test]
fn other_input_is_refused_with_a_reason() {
    let cases = [
        ("not json", "not valid JSON"),
        (r#"{"schema": "sigil-session/2"}"#, "sigil-session/1"),
        (r#"{"hello": 1}"#, "no \"schema\""),
    ];
    for (input, says) in cases {
        let err = render_session_markdown_inner(input).unwrap_err();
        assert!(err.contains(says), "{input}: {err}");
        let err = render_aibom_markdown_inner(input).unwrap_err();
        assert!(
            err.contains(if says == "sigil-session/1" {
                "sigil-aibom/2"
            } else {
                says
            }),
            "{input}: {err}"
        );
    }
    // A session given as an AI-BOM, and the reverse, are named.
    let (_, session) = &files("examples/session-v1")[0];
    let err = render_aibom_markdown_inner(session).unwrap_err();
    assert!(err.contains("a session"), "{err}");
    let (_, bom) = &files("examples/aibom-v2")[0];
    let err = render_session_markdown_inner(bom).unwrap_err();
    assert!(err.contains("an AI-BOM v2"), "{err}");
}

#[test]
fn render_markdown_dispatches_on_the_kind() {
    use sigil_wasm::render_markdown_inner;
    for (name, text) in files("examples/session-v1") {
        assert_eq!(
            render_markdown_inner(&text),
            render_session_markdown_inner(&text),
            "{name}"
        );
    }
    for (name, text) in files("examples/aibom-v2") {
        assert_eq!(
            render_markdown_inner(&text),
            render_aibom_markdown_inner(&text),
            "{name}"
        );
    }
    let cases = [
        (V1, "AI-BOM v1"),
        ("{not json", "not valid JSON"),
        (r#"{"schema": "sigil-session/2"}"#, "\"sigil-session/2\""),
        (r#"{"hello": 1}"#, "no \"schema\""),
    ];
    for (input, says) in cases {
        let err = render_markdown_inner(input).unwrap_err();
        assert!(err.contains(says), "{input}: {err}");
    }
    // An unknown schema names both formats the viewer reads.
    let err = render_markdown_inner(r#"{"schema": "x"}"#).unwrap_err();
    assert!(
        err.contains("sigil-session/1") && err.contains("sigil-aibom/2"),
        "{err}"
    );
}
