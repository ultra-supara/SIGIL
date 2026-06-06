//! Browser binding for SIGIL's AI-BOM Markdown renderer.
//!
//! The whole point: the same `render_ai_bom` that emits `*.aibom.md` from the
//! CLI runs unmodified in the browser via `wasm32-unknown-unknown`. No I/O, no
//! network. The visitor drops a JSON, the wasm module validates the schema
//! envelope and hands back Markdown bytes that are byte-equal to what
//! `sigil aibom generate --format md` would write to disk for the same input.
//!
//! Two layers of validation run before the render:
//! 1. **Envelope check** (`validate_schema_envelope`) — enforces the
//!    `schema_version == "1.1"` constant and `additionalProperties: false`
//!    constraints from `schemas/aibom-v1.schema.json` that `serde`'s default
//!    derives silently ignore. Without this, a JSON with
//!    `schema_version: "1.2"` or an unexpected top-level field would
//!    deserialize fine and render as if it were valid.
//! 2. **Struct deserialization** — `serde_json::from_value::<AiBom>` enforces
//!    the rest of the schema (required nested fields, enum values).
//!
//! Determinism is enforced by `tests/determinism.rs`, which loads every
//! checked-in sample and asserts that the wasm-exposed render path (via
//! `render_aibom_markdown_inner`, which the `#[wasm_bindgen]` wrapper just
//! re-exports) produces the same bytes as `sigil_core::aibom::render_ai_bom`.
//! CI runs that suite on every PR.

use serde_json::Value;
use sigil_core::aibom::{render_ai_bom, AiBom, SCHEMA_VERSION};
use wasm_bindgen::prelude::*;

/// Top-level keys the AI-BOM schema declares (`additionalProperties: false`
/// on the root in schemas/aibom-v1.schema.json). Kept in sync by
/// `top_level_keys_match_schema` in `tests/determinism.rs` — if the schema
/// gains or drops a top-level field, the test fails until this list is
/// updated.
const REQUIRED_TOP_LEVEL_KEYS: &[&str] = &[
    "schema_version",
    "tool",
    "runtime",
    "models",
    "findings",
    "verdict",
];

/// Pure render: parse JSON, validate it against the AI-BOM schema's hard
/// constraints, render Markdown. On error returns a human-readable message;
/// serde already includes line/column so we just pass it through.
///
/// Kept separate from the `#[wasm_bindgen]` wrapper so the native test suite
/// can exercise the error path without invoking JS-only imports (`JsError`
/// allocates through `wasm-bindgen` runtime calls and panics on non-wasm).
///
/// Schema constraints enforced before render:
/// - `schema_version` is the literal `"1.1"` (the schema declares this as a
///   `const`; the struct just has it as `String`, so without this check a
///   JSON with `schema_version: "1.2"` would deserialize and render).
/// - The set of top-level keys is exactly the schema's required set
///   (`additionalProperties: false` on the root). The struct's
///   `#[derive(Deserialize)]` silently drops unknown fields, so we walk the
///   `Value` first to catch that.
///
/// Anything deeper (per-field enum values, nested `additionalProperties:
/// false` rules) is already enforced by `serde` deserialization plus the
/// `#[serde(rename_all = ...)]` annotations on the enums in `sigil-core`.
pub fn render_aibom_markdown_inner(json: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(json)
        .map_err(|err| format!("invalid AI-BOM JSON (parse error): {err}"))?;
    validate_schema_envelope(&value)?;
    let bom: AiBom = serde_json::from_value(value)
        .map_err(|err| format!("invalid AI-BOM JSON (schema mismatch): {err}"))?;
    Ok(render_ai_bom(&bom))
}

fn validate_schema_envelope(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "invalid AI-BOM JSON: top-level value must be an object".to_string())?;

    match object.get("schema_version") {
        Some(Value::String(version)) if version == SCHEMA_VERSION => {}
        Some(Value::String(version)) => {
            return Err(format!(
                "invalid AI-BOM JSON: schema_version {version:?} is not supported by this viewer (expected {SCHEMA_VERSION:?})"
            ))
        }
        Some(_) => {
            return Err("invalid AI-BOM JSON: schema_version must be a string".to_string())
        }
        None => return Err("invalid AI-BOM JSON: missing required field `schema_version`".to_string()),
    }

    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !REQUIRED_TOP_LEVEL_KEYS.contains(key))
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(format!(
            "invalid AI-BOM JSON: unexpected top-level field(s): {}",
            unknown.join(", ")
        ));
    }

    Ok(())
}

/// Parse an AI-BOM JSON string and return the rendered Markdown report.
///
/// On invalid JSON (or schema mismatch — serde returns the same error for
/// both), the JS-visible `Error` carries the underlying `serde_json` message
/// so the viewer can show it inline instead of crashing.
#[wasm_bindgen]
pub fn render_aibom_markdown(json: &str) -> Result<String, JsError> {
    render_aibom_markdown_inner(json).map_err(|msg| JsError::new(&msg))
}

/// Schema version this wasm build was compiled against. Exposed so the viewer
/// can render a small caption and so a stale wasm artifact in `site/viewer/pkg/`
/// is obvious from the page rather than from byte diffs.
#[wasm_bindgen]
pub fn aibom_schema_version() -> String {
    sigil_core::aibom::SCHEMA_VERSION.to_string()
}
