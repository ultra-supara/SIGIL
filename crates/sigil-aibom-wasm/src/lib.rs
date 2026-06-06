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
///
/// `#[doc(hidden)]` — semantically internal; only `pub` so the integration
/// test can read it without dropping back to indirect error-message
/// parsing. Not part of the wasm public API (no `#[wasm_bindgen]`, no JS
/// export).
#[doc(hidden)]
pub const REQUIRED_TOP_LEVEL_KEYS: &[&str] = &[
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
/// Validation pipeline, top-to-bottom:
/// 1. Envelope check (`validate_schema_envelope`) — `schema_version` must be
///    the literal `"1.1"` (the schema's `const`), and the set of top-level
///    keys must match the schema's root property set (the schema's
///    `additionalProperties: false`).
/// 2. Struct deserialization (`serde_json::from_value::<AiBom>`) — the
///    `#[serde(deny_unknown_fields)]` derives on every AI-BOM struct in
///    `crates/sigil-core/src/aibom.rs` enforce nested
///    `additionalProperties: false` plus serde's type/enum/required-field
///    checks.
/// 3. Scalar-constraint check (`validate_scalar_constraints`) — the
///    schema-declared `minLength`/`maxLength`/`pattern` constraints that
///    serde's `String` deserializer doesn't enforce: non-empty strings
///    on every required string field, `text_excerpt` ≤ 256 chars, sha256
///    hex pattern on `files[*].sha256`, and `sha256:<hex>` digest pattern
///    on every digest/layer_digests/config_digest field.
///
/// A full JSON Schema validator was tried (`jsonschema` crate) but inflated
/// the wasm bundle past 1 MB gzipped — well over the issue #35 ≤ 500 KB
/// budget. The hand-rolled checks below cover every scalar constraint the
/// committed `schemas/aibom-v1.schema.json` declares, and the
/// `scalar_constraints_match_schema` test re-reads the schema at runtime to
/// make sure that stays true.
pub fn render_aibom_markdown_inner(json: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(json)
        .map_err(|err| format!("invalid AI-BOM JSON (parse error): {err}"))?;
    validate_schema_envelope(&value)?;
    let bom: AiBom = serde_json::from_value(value)
        .map_err(|err| format!("invalid AI-BOM JSON (schema mismatch): {err}"))?;
    validate_scalar_constraints(&bom).map_err(|err| format!("invalid AI-BOM JSON ({err})"))?;
    Ok(render_ai_bom(&bom))
}

const SHA256_HEX_LEN: usize = 64;
const SHA256_DIGEST_PREFIX: &str = "sha256:";
/// Schema: `LicenseEntry.text_excerpt { maxLength: 256 }`.
///
/// `#[doc(hidden)] pub` so the schema-drift gate test
/// (`scalar_constraints_match_schema`) can read it. Not part of the wasm
/// public API.
#[doc(hidden)]
pub const TEXT_EXCERPT_MAX_LEN: usize = 256;

/// Enforce the scalar string constraints from
/// `schemas/aibom-v1.schema.json` that `serde`'s `String` deserializer
/// cannot. Returns the first violation in document order so the viewer's
/// error banner names a specific field. Field paths are written in the
/// same JSON-pointer-ish style the schema uses (`tool.name`,
/// `models[0].files[2].sha256`, etc.) so a reviewer can locate the bad
/// field in their JSON immediately.
pub(crate) fn validate_scalar_constraints(bom: &AiBom) -> Result<(), String> {
    non_empty("tool.name", &bom.tool.name)?;
    non_empty("tool.version", &bom.tool.version)?;
    non_empty("runtime.name", &bom.runtime.name)?;
    non_empty("runtime.host", &bom.runtime.host)?;
    if let Some(dir) = &bom.runtime.models_dir {
        non_empty("runtime.models_dir", dir)?;
    }
    if let Some(version) = &bom.runtime.version {
        non_empty("runtime.version", version)?;
    }
    non_empty("runtime.exposure.source", &bom.runtime.exposure.source)?;
    for (i, bind) in bom.runtime.exposure.observed.iter().enumerate() {
        non_empty(&format!("runtime.exposure.observed[{i}].addr"), &bind.addr)?;
        if let Some(process) = &bind.process {
            non_empty(&format!("runtime.exposure.observed[{i}].process"), process)?;
        }
    }
    for (i, model) in bom.models.iter().enumerate() {
        let m = format!("models[{i}]");
        non_empty(&format!("{m}.name"), &model.name)?;
        if let Some(mp) = &model.manifest_path {
            non_empty(&format!("{m}.manifest_path"), mp)?;
        }
        for (j, file) in model.files.iter().enumerate() {
            let f = format!("{m}.files[{j}]");
            sha256_digest(&format!("{f}.digest"), &file.digest)?;
            non_empty(&format!("{f}.path"), &file.path)?;
            sha256_hex(&format!("{f}.sha256"), &file.sha256)?;
            non_empty(&format!("{f}.kind"), &file.kind)?;
        }
        let p = format!("{m}.provenance");
        if let Some(reg) = &model.provenance.registry {
            non_empty(&format!("{p}.registry"), reg)?;
        }
        if let Some(ns) = &model.provenance.namespace {
            non_empty(&format!("{p}.namespace"), ns)?;
        }
        if let Some(m_name) = &model.provenance.model {
            non_empty(&format!("{p}.model"), m_name)?;
        }
        if let Some(tag) = &model.provenance.tag {
            non_empty(&format!("{p}.tag"), tag)?;
        }
        if let Some(cd) = &model.provenance.config_digest {
            sha256_digest(&format!("{p}.config_digest"), cd)?;
        }
        for (k, layer) in model.provenance.layer_digests.iter().enumerate() {
            sha256_digest(&format!("{p}.layer_digests[{k}]"), layer)?;
        }
        if let Some(license) = &model.license {
            let l = format!("{m}.license");
            sha256_digest(&format!("{l}.digest"), &license.digest)?;
            if let Some(spdx) = &license.spdx_id {
                non_empty(&format!("{l}.spdx_id"), spdx)?;
            }
            text_excerpt(&format!("{l}.text_excerpt"), &license.text_excerpt)?;
        }
    }
    for (i, finding) in bom.findings.iter().enumerate() {
        let f = format!("findings[{i}]");
        non_empty(&format!("{f}.id"), &finding.id)?;
        non_empty(&format!("{f}.message"), &finding.message)?;
        non_empty(&format!("{f}.evidence"), &finding.evidence)?;
    }
    Ok(())
}

fn non_empty(path: &str, s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!(
            "schema violation at {path}: string must be non-empty (schema: minLength 1)"
        ));
    }
    Ok(())
}

fn sha256_hex(path: &str, s: &str) -> Result<(), String> {
    if s.len() != SHA256_HEX_LEN || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "schema violation at {path}: must be 64 hex chars (schema pattern: ^[0-9a-fA-F]{{64}}$, got {s:?})"
        ));
    }
    Ok(())
}

fn sha256_digest(path: &str, s: &str) -> Result<(), String> {
    let Some(rest) = s.strip_prefix(SHA256_DIGEST_PREFIX) else {
        return Err(format!(
            "schema violation at {path}: must start with \"sha256:\" (schema pattern: ^sha256:[0-9a-fA-F]{{64}}$, got {s:?})"
        ));
    };
    sha256_hex(path, rest)
}

fn text_excerpt(path: &str, s: &str) -> Result<(), String> {
    if s.chars().count() > TEXT_EXCERPT_MAX_LEN {
        return Err(format!(
            "schema violation at {path}: must be at most {TEXT_EXCERPT_MAX_LEN} chars (schema: maxLength {TEXT_EXCERPT_MAX_LEN}, got {} chars)",
            s.chars().count()
        ));
    }
    Ok(())
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
