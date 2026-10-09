//! `sigil-wasm`: SIGIL's renderers in the browser viewer (wasm32; plan §4.3, PR-3b-3b design §4).
//!
//! The viewer runs the CLI's own renderers on a session (`sigil-session/1`) or an AI-BOM v2
//! (`sigil-aibom/2`). It inserts HTML only from [`markdown_html`], whose escaping contract is
//! `sigil_model::render::html` (U-10). Nothing is uploaded: these are pure functions of the text
//! the visitor gives the page.
//!
//! - A session is validated (`Session::validate`) before it is shown, as `sigil session render`
//!   does.
//! - An AI-BOM v1 (SIGIL 0.1) is named, with where its format is described, instead of being
//!   rendered.
//!
//! Each export wraps an `*_inner` function that returns `Result<String, String>`, so the native
//! tests exercise every path without the JS runtime.
//!
//! The crate depends only on `sigil-model`: no file, `/proc`, or network code enters the bundle.

use serde_json::Value;
use sigil_model::render::aibom::markdown as aibom_markdown;
use sigil_model::render::html::from_markdown;
use sigil_model::render::markdown::render_session;
use sigil_model::{AiBom, Session};
use wasm_bindgen::prelude::*;

const SESSION_SCHEMA: &str = "sigil-session/1";
const AIBOM_SCHEMA: &str = "sigil-aibom/2";

/// What an AI-BOM v1 gets instead of a render.
const V1_MESSAGE: &str = "This is an AI-BOM v1 file (SIGIL 0.1, \"schema_version\": \"1.x\"). \
This viewer reads SIGIL v2 sessions (sigil-session/1) and AI-BOM v2 (sigil-aibom/2). The v1 \
format is described in https://github.com/ultra-supara/SIGIL/blob/main/schemas/aibom-v1.schema.json, \
and the 2026-H1 report used it: https://ultra-supara.github.io/SIGIL/reports/2026-h1/";

/// `session`, `aibom-v2`, `aibom-v1`, or `unknown`.
pub fn detect_inner(json: &str) -> &'static str {
    let Ok(value) = serde_json::from_str::<Value>(json) else {
        return "unknown";
    };
    kind(&value)
}

fn kind(value: &Value) -> &'static str {
    match value.get("schema").and_then(Value::as_str) {
        Some(SESSION_SCHEMA) => "session",
        Some(AIBOM_SCHEMA) => "aibom-v2",
        _ if value.get("schema_version").is_some() => "aibom-v1",
        _ => "unknown",
    }
}

/// Parses `json` and checks that it is the `wanted` kind, or says what it is instead.
fn parse(json: &str, wanted: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("This is not valid JSON: {e}"))?;
    match (kind(&value), wanted) {
        (found, wanted) if found == wanted => Ok(value),
        ("aibom-v1", _) => Err(V1_MESSAGE.to_string()),
        ("session", _) => Err("This is a session (sigil-session/1), not an AI-BOM v2.".to_string()),
        ("aibom-v2", _) => Err("This is an AI-BOM v2 (sigil-aibom/2), not a session.".to_string()),
        _ => {
            let expected = if wanted == "session" {
                SESSION_SCHEMA
            } else {
                AIBOM_SCHEMA
            };
            Err(match value.get("schema").and_then(Value::as_str) {
                Some(other) => {
                    format!("This file has \"schema\": {other:?}; this viewer reads {expected}.")
                }
                None => format!("This file has no \"schema\"; this viewer reads {expected}."),
            })
        }
    }
}

/// The Markdown report of a session, after `Session::validate`.
pub fn render_session_markdown_inner(json: &str) -> Result<String, String> {
    let value = parse(json, "session")?;
    let session: Session =
        serde_json::from_value(value).map_err(|e| format!("This is not a valid session: {e}"))?;
    if let Err(errors) = session.validate() {
        let shown: Vec<String> = errors.iter().take(5).map(ToString::to_string).collect();
        let more = errors.len().saturating_sub(shown.len());
        let tail = if more > 0 {
            format!(" (and {more} more)")
        } else {
            String::new()
        };
        return Err(format!(
            "The session fails validation: {}{tail}",
            shown.join("; ")
        ));
    }
    Ok(render_session(&session))
}

/// The Markdown report of an AI-BOM v2.
pub fn render_aibom_markdown_inner(json: &str) -> Result<String, String> {
    let value = parse(json, "aibom-v2")?;
    let bom: AiBom =
        serde_json::from_value(value).map_err(|e| format!("This is not a valid AI-BOM v2: {e}"))?;
    Ok(aibom_markdown(&bom))
}

/// The HTML of a report's Markdown (`sigil_model::render::html::from_markdown`).
pub fn markdown_html_inner(md: &str) -> String {
    from_markdown(md)
}

/// What the input is: `session`, `aibom-v2`, `aibom-v1`, or `unknown`.
#[wasm_bindgen]
pub fn detect(json: &str) -> String {
    detect_inner(json).to_string()
}

/// The Markdown report of a session (validated first).
#[wasm_bindgen]
pub fn render_session_markdown(json: &str) -> Result<String, JsError> {
    render_session_markdown_inner(json).map_err(|e| JsError::new(&e))
}

/// The Markdown report of an AI-BOM v2.
#[wasm_bindgen]
pub fn render_aibom_markdown(json: &str) -> Result<String, JsError> {
    render_aibom_markdown_inner(json).map_err(|e| JsError::new(&e))
}

/// The HTML of a report's Markdown: only h1 h2 p ul li table thead tbody tr th td strong, no
/// attributes, all text escaped.
#[wasm_bindgen]
pub fn markdown_html(md: &str) -> String {
    markdown_html_inner(md)
}

/// The formats this viewer reads.
#[wasm_bindgen]
pub fn versions() -> String {
    format!("{SESSION_SCHEMA}, {AIBOM_SCHEMA}")
}
