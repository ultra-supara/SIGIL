# Stable AI-BOM JSON Schema Design

Tracks GitHub issue #6.

## Goal

Define a stable, versioned, runtime-agnostic AI-BOM JSON schema for SIGIL's
runtime inspection output. The schema becomes the published contract that CI,
downstream tools, and long-term baselines can depend on. The first concrete
producer is the existing Ollama inspection path; the schema must accommodate
future runtimes without reshaping Ollama-specific code.

## Non-Goals

- No new analysis capability. This change reshapes the *serialization contract*,
  not what SIGIL inspects. `inspect_ollama` logic and findings are unchanged.
- No JSON Schema document (`*.schema.json`) or `jsonschema` validator crate in
  this change. Field/enum stability is enforced by Rust tests. A formal JSON
  Schema artifact is deferred as future work.
- No AI-BOM comparison / baseline drift detection (separate planned work).
- No second runtime implementation. The schema is designed to be reusable, but
  only Ollama is wired up here.
- No change to the native-binary `assess` evidence JSON (`Evidence` in
  `evidence.rs`). The `binary` finding category is reserved in the contract but
  not yet produced.

## Background

Current state (`crates/sigil-core/src/ollama.rs`):

- `inspect_ollama` returns an `OllamaReport` and `OllamaReport::to_json()`
  serializes that struct directly. There is no `schema_version`.
- `runtime inspect ollama --out X` writes the raw `OllamaReport` JSON.
- `aibom generate --runtime ollama --out X` writes Markdown via
  `render_ai_bom(&OllamaReport)` only — no JSON path.
- Enum values already serialize as stable snake_case strings: `ApiExposure`,
  `RuntimeStatus` (in `ollama.rs`), `RuntimeExposure` / `BindEvidence` (in
  `runtime/listeners.rs`). `assess::Verdict` serializes as `PASS|WARN|FAIL`.
- `RuntimeFinding` uses plain `String` severity (`"WARN"`/`"FAIL"`) and has no
  category.

`docs/ai-bom-and-comparison.md` already commits to the direction: add explicit
`schema_version`, stabilize enum values, define required vs optional fields,
separate runtime/model/binary findings, and keep Markdown downstream of the
stable JSON model.

## Design Decisions (resolved during brainstorming)

1. **Decoupling**: introduce a dedicated runtime-agnostic `AiBom` model rather
   than stabilizing `OllamaReport` in place. `OllamaReport` stays an internal
   representation; `AiBom` is the public contract. (Satisfies the "future
   runtimes target the same schema" criterion.)
2. **Emission surface**: unify both commands on the stable schema. `runtime
   inspect ollama --out` emits the stable `AiBom` JSON, and `aibom generate`
   gains `--format json|md` (default `json`), both rendered from `AiBom`.
   Pre-1.0, no external consumers, so a single contract avoids two JSON shapes.
3. **`schema_version` format**: string `"1.0"` (semver-style; additive changes
   bump minor, breaking changes bump major).
4. **Findings structure**: a single flat `findings` array with a stable
   `category` field per finding (`runtime|model|binary`), not nested sections.

## Safety Alignment

This change is pure serialization plumbing. It stays read-only, deterministic,
and adds no subprocess execution and no new external dependency. The `AiBom`
model and its `From<&OllamaReport>` conversion are pure data transforms and
unit-testable. Verdicts remain owned by the existing deterministic path.

## Architecture

### New module: `crates/sigil-core/src/aibom.rs`

Holds the stable DTO, its enums, the conversion from `OllamaReport`, the JSON
serializer, and the Markdown renderer (moved here from `ollama.rs`).

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBom {
    pub schema_version: String,        // "1.0"
    pub tool: ToolInfo,
    pub runtime: RuntimeInfo,
    pub models: Vec<ModelEntry>,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,              // reuse assess::Verdict (PASS|WARN|FAIL)
}

#[derive(...Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,                  // "sigil"
    pub version: String,               // env!("CARGO_PKG_VERSION")
}

#[derive(...Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub name: String,                  // "ollama"
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models_dir: Option<String>,
    pub api_exposure: ApiExposure,     // reuse existing enum
    pub status: RuntimeStatus,         // reuse existing enum
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub exposure: ExposureInfo,
}

#[derive(...Serialize, Deserialize)]
pub struct ExposureInfo {
    pub class: RuntimeExposure,        // reuse existing enum
    pub source: String,                // "proc" | "disabled" | "unavailable"
    pub observed: Vec<BindEntry>,
}

#[derive(...Serialize, Deserialize)]
pub struct BindEntry {
    pub addr: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(...Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    pub files: Vec<FileEntry>,
}

#[derive(...Serialize, Deserialize)]
pub struct FileEntry {
    pub digest: String,                // declared, e.g. "sha256:..."
    pub path: String,
    pub size: u64,
    pub sha256: String,                // computed by SIGIL
    pub kind: String,                  // model|config|params|license|blob...
}

#[derive(...Serialize, Deserialize)]
pub struct Finding {
    pub id: String,                    // stable, e.g. "ollama.public_bind"
    pub category: FindingCategory,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
}

#[derive(...Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory { Runtime, Model, Binary }

#[derive(...Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")] // or explicit renames
pub enum Severity { Warn, Fail }       // "WARN" | "FAIL"

impl AiBom {
    pub fn to_json(&self) -> Result<String, serde_json::Error> { /* pretty */ }
}

impl From<&OllamaReport> for AiBom { /* see Conversion */ }
```

Enum reuse: `ApiExposure`, `RuntimeStatus`, `RuntimeExposure`, and
`assess::Verdict` are already stable snake_case / `PASS|WARN|FAIL` serializers
and are semantically runtime-generic. `aibom.rs` imports and reuses them rather
than redefining. Only `Severity` and `FindingCategory` are new (BOM-level
concerns).

### Conversion `From<&OllamaReport> for AiBom`

Pure mapping, no I/O:

- `schema_version = "1.0"`, `tool = { "sigil", CARGO_PKG_VERSION }`.
- `runtime.name = report.runtime` (`"ollama"`), `host`, `models_dir =
  Some(report.models_dir.display())`, `api_exposure = report.api`, `status =
  report.runtime_status`, `version = report.version.clone()`,
  `exposure = { report.runtime_exposure.class, .source, observed mapped to
  BindEntry }`.
- `models`: each `OllamaModel` → `ModelEntry` with `manifest_path =
  Some(display())` and `files` mapped to `FileEntry` (paths `display()`-ed).
- `findings`: each `RuntimeFinding` → `Finding` with
  - `severity`: `"FAIL"` → `Severity::Fail`, else `Severity::Warn`.
  - `category`: `ollama_finding_category(&id)` — explicit match over known ids
    (see table), default `FindingCategory::Runtime`.
- `verdict`: `"FAIL"`→`Fail`, `"WARN"`→`Warn`, else `Pass`.

`RuntimeFinding` is **not** modified; the contract layer owns categorization.

#### Finding id → category map

| id | category |
|----|----------|
| `ollama.public_bind` | runtime |
| `ollama.network_endpoint` | runtime |
| `ollama.runtime_lan_exposure` | runtime |
| `ollama.runtime_public_bind` | runtime |
| `ollama.runtime_docker_published` | runtime |
| `ollama.runtime_proxy` | runtime |
| `ollama.invalid_blob_digest` | model |
| `ollama.blob_digest_mismatch` | model |
| `ollama.blob_missing` | model |
| `ollama.model_not_found` | model |
| (unknown) | runtime (documented default) |

A unit test enumerates this table so new finding ids are caught in review.

### Changes to `ollama.rs`

- Remove `render_ai_bom` (moves to `aibom.rs`, now taking `&AiBom`).
- `OllamaReport` keeps its current shape and `to_json()` (still used by
  `sigil-core` struct-level tests). It is no longer the CLI's serialized output.

### Changes to `lib.rs`

- Add `pub mod aibom;`.

### CLI (`crates/sigil-cli/src/main.rs`)

- `runtime inspect ollama --out X`: write `AiBom::from(&report).to_json()`
  instead of `report.to_json()`.
- `aibom generate`: add `--format <json|md>` (default `json`). Build
  `AiBom::from(&report)`; for `json` write `aibom.to_json()`, for `md` write
  `render_ai_bom(&aibom)`.
- Import `AiBom` and `render_ai_bom` from `sigil_core::aibom`.

## Output

- JSON (both commands): the `AiBom` shape above, with optional fields omitted
  when absent.
- Markdown (`aibom generate --format md`): same content as today, but rendered
  from `AiBom` so JSON and Markdown share one source of truth.

## Data Flow

```
inspect_ollama(options) -> OllamaReport         (internal representation)
        │
        ▼
AiBom::from(&OllamaReport)                       (pure mapping, stable contract)
        │
        ├── to_json()        -> stable AI-BOM JSON  (runtime inspect --out,
        │                                            aibom generate --format json)
        └── render_ai_bom()  -> Markdown            (aibom generate --format md)
```

## Required vs Optional Fields

Required (always serialized): `schema_version`, `tool.name`, `tool.version`,
`runtime.name`, `runtime.host`, `runtime.api_exposure`, `runtime.status`,
`runtime.exposure.class`, `runtime.exposure.source`,
`runtime.exposure.observed`, `models`, each model's `name` and `files`, each
file's `digest`/`path`/`size`/`sha256`/`kind`, `findings`, each finding's
`id`/`category`/`severity`/`message`/`evidence`, `verdict`.

Optional (omitted when absent): `runtime.models_dir`, `runtime.version`,
`model.manifest_path`, `bind.process`.

`models` and `findings` are always present as arrays (possibly empty).

## Enum Value Reference (pinned by tests)

- `verdict`: `PASS` | `WARN` | `FAIL`
- `severity`: `WARN` | `FAIL`
- `category`: `runtime` | `model` | `binary`
- `api_exposure`: `not_probed` | `localhost` | `network` | `public_bind` | `unavailable`
- `status`: `not_probed` | `reachable` | `unreachable`
- `exposure.class`: `localhost` | `lan` | `public_bind` | `docker_published` | `proxy` | `unknown`

## Testing

New tests in `crates/sigil-core/tests/aibom.rs` (or a `#[cfg(test)]` module):

- **Enum stability**: serialize each `Severity`, `FindingCategory`, and assert
  exact strings; assert reused enums (`Verdict`, `ApiExposure`, `RuntimeStatus`,
  `RuntimeExposure`) still emit expected strings.
- **Structural / schema validation**: build an `OllamaReport` from a fake store,
  convert to `AiBom`, serialize, parse as `serde_json::Value`, and assert:
  - top-level keys exactly `{schema_version, tool, runtime, models, findings,
    verdict}`;
  - `schema_version == "1.0"`;
  - `runtime` has required keys and correct types;
  - optional fields omitted when the source is `None` (e.g. `version` absent
    when `probe_api=false`).
- **Finding category map**: assert each known id maps to its category per the
  table; assert an unknown id defaults to `runtime`.
- **Markdown parity**: `render_ai_bom(&AiBom)` still contains runtime, model
  name, exposure, and findings lines.

Updated existing tests:

- `crates/sigil-core/tests/ollama.rs`: the `render_ai_bom` tests now build an
  `AiBom` first (`render_ai_bom(&AiBom::from(&report))`). `OllamaReport`
  field-level assertions are unchanged.
- `crates/sigil-cli/tests/ollama_cli.rs`: update JSON assertions to the new
  shape (`"schema_version": "1.0"`, `runtime.name`, `api_exposure`, `exposure`
  → `"class"`, model under `models[]`, `verdict`); `aibom generate` markdown
  test passes `--format md`; add an `aibom generate --format json` assertion.

All tests remain deterministic (`--no-probe-api`, `--no-inspect-runtime`, fixed
snapshots) and require no real Ollama or `/proc`.

## Documentation

- `README.md`: add an "AI-BOM JSON contract" section — `schema_version`,
  top-level keys, required vs optional fields, the enum value lists, and that
  Markdown is derived from the JSON model. Update the Ollama example to mention
  `--format`.
- `docs/ai-bom-and-comparison.md`: move the "Schema Direction" items from
  planned to implemented; describe the `AiBom` contract and that both commands
  emit it.

## Acceptance Criteria Mapping

- "Generated JSON includes an explicit schema version" → `schema_version: "1.0"`
  on every `AiBom`, emitted by both commands.
- "Tests assert stable field names and enum values" → structural Value test +
  enum stability tests + finding-category map test.
- "README documents the AI-BOM JSON contract at a high level" → new README
  section.
- "Future runtime implementations can target the same schema without reshaping
  Ollama-specific code" → `AiBom` is runtime-agnostic; a new runtime supplies
  its own `From<...> for AiBom` mapping and reuses the same struct/enums.
