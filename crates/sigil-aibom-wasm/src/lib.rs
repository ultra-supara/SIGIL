//! Browser binding for SIGIL's AI-BOM Markdown renderer.
//!
//! The whole point: the same `render_ai_bom` that emits `*.aibom.md` from the
//! CLI runs unmodified in the browser via `wasm32-unknown-unknown`. No I/O, no
//! network, no allocations the caller can't see. The visitor drops a JSON, the
//! wasm module deserializes it with serde, and hands back Markdown bytes that
//! are byte-equal to what `sigil aibom generate --format md` would write to
//! disk for the same input.
//!
//! Determinism is enforced by `tests/determinism.rs`, which loads every
//! checked-in sample and asserts wasm-render == native-render. CI runs that
//! suite on every PR.

use sigil_core::aibom::{render_ai_bom, AiBom};
use wasm_bindgen::prelude::*;

/// Pure render: parse JSON, render Markdown. On error returns a human-readable
/// message; serde already includes line/column so we just pass it through.
///
/// Kept separate from the `#[wasm_bindgen]` wrapper so the native test suite
/// can exercise the error path without invoking JS-only imports (`JsError`
/// allocates through `wasm-bindgen` runtime calls and panics on non-wasm).
pub fn render_aibom_markdown_inner(json: &str) -> Result<String, String> {
    let bom: AiBom =
        serde_json::from_str(json).map_err(|err| format!("invalid AI-BOM JSON: {err}"))?;
    Ok(render_ai_bom(&bom))
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
