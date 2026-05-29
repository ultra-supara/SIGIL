# Stable AI-BOM JSON Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a versioned, runtime-agnostic `AiBom` JSON contract (schema_version "1.0") that both `runtime inspect ollama` and `aibom generate` emit, with Markdown rendered from the same model.

**Architecture:** A new `sigil-core::aibom` module holds a stable DTO (`AiBom` + sub-structs + `Severity`/`FindingCategory` enums), a pure `From<&OllamaReport>` conversion, a JSON serializer, and the Markdown renderer (moved from `ollama.rs`). `OllamaReport` stays the internal inspection result; `AiBom` is the published contract. Reuses existing stable enums (`Verdict`, `ApiExposure`, `RuntimeStatus`, `RuntimeExposure`).

**Tech Stack:** Rust, serde / serde_json, Cargo workspace (`sigil-core`, `sigil-cli`), clap (CLI), tempfile + assert_cmd (tests).

**Spec:** `docs/superpowers/specs/2026-05-30-aibom-json-schema-design.md`

---

## File Structure

- Create: `crates/sigil-core/src/aibom.rs` — the `AiBom` DTO, enums, conversion, `to_json`, `render_ai_bom`, unit tests for enums + category map.
- Modify: `crates/sigil-core/src/lib.rs` — register `pub mod aibom;`.
- Modify: `crates/sigil-core/src/ollama.rs` — remove `render_ai_bom` (moves to `aibom.rs`).
- Create: `crates/sigil-core/tests/aibom.rs` — integration tests: convert a fake-store `OllamaReport` to `AiBom`, serialize, assert structure / required-vs-optional / enum values.
- Modify: `crates/sigil-core/tests/ollama.rs` — update the 3 `render_ai_bom` tests to render from `AiBom`.
- Modify: `crates/sigil-cli/src/main.rs` — `runtime inspect` emits `AiBom` JSON; `aibom generate` gains `--format json|md` (default json), both from `AiBom`.
- Modify: `crates/sigil-cli/tests/ollama_cli.rs` — update JSON-shape assertions, add `--format md` and a JSON-format test.
- Modify: `README.md` and `docs/ai-bom-and-comparison.md` — document the contract.

---

### Task 1: Create the `aibom` module — DTO structs + enums + `to_json`

**Files:**
- Create: `crates/sigil-core/src/aibom.rs`
- Modify: `crates/sigil-core/src/lib.rs`

- [ ] **Step 1: Register the module in `lib.rs`**

Add `pub mod aibom;` as the first module line in `crates/sigil-core/src/lib.rs` so the file begins:

```rust
pub mod aibom;
pub mod assess;
pub mod evidence;
pub mod ir;
pub mod ollama;
pub mod report;
pub mod runtime;
pub mod safeisa;
pub mod x86;
```

- [ ] **Step 2: Write `aibom.rs` with the DTO, enums, `to_json`, and a failing enum-stability unit test**

Create `crates/sigil-core/src/aibom.rs` with exactly this content:

```rust
use serde::{Deserialize, Serialize};

use crate::assess::Verdict;
use crate::ollama::{ApiExposure, RuntimeStatus};
use crate::runtime::RuntimeExposure;

/// Stable AI-BOM schema version. Bump minor for additive changes, major for
/// breaking changes.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBom {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub runtime: RuntimeInfo,
    pub models: Vec<ModelEntry>,
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub name: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models_dir: Option<String>,
    pub api_exposure: ApiExposure,
    pub status: RuntimeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub exposure: ExposureInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureInfo {
    pub class: RuntimeExposure,
    pub source: String,
    pub observed: Vec<BindEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindEntry {
    pub addr: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub digest: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Runtime,
    Model,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "FAIL")]
    Fail,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

impl AiBom {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serializes_screaming() {
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"WARN\"");
        assert_eq!(serde_json::to_string(&Severity::Fail).unwrap(), "\"FAIL\"");
    }

    #[test]
    fn finding_category_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&FindingCategory::Runtime).unwrap(),
            "\"runtime\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::Model).unwrap(),
            "\"model\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::Binary).unwrap(),
            "\"binary\""
        );
    }
}
```

- [ ] **Step 3: Build and run the new unit tests**

Run: `cargo test -p sigil-core --lib aibom`
Expected: PASS (`severity_serializes_screaming`, `finding_category_serializes_snake_case`). Whole workspace still compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/sigil-core/src/aibom.rs crates/sigil-core/src/lib.rs
git commit -m "feat(aibom): add stable AiBom DTO and enums"
```

---

### Task 2: Add pure mapping helpers (severity, verdict, finding category)

**Files:**
- Modify: `crates/sigil-core/src/aibom.rs`

- [ ] **Step 1: Add a failing unit test for the finding-category map**

In `crates/sigil-core/src/aibom.rs`, inside the existing `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn runtime_finding_ids_map_to_runtime_category() {
        for id in [
            "ollama.public_bind",
            "ollama.network_endpoint",
            "ollama.runtime_lan_exposure",
            "ollama.runtime_public_bind",
            "ollama.runtime_docker_published",
            "ollama.runtime_proxy",
        ] {
            assert_eq!(finding_category(id), FindingCategory::Runtime, "{id}");
        }
    }

    #[test]
    fn model_finding_ids_map_to_model_category() {
        for id in [
            "ollama.invalid_blob_digest",
            "ollama.blob_digest_mismatch",
            "ollama.blob_missing",
            "ollama.model_not_found",
        ] {
            assert_eq!(finding_category(id), FindingCategory::Model, "{id}");
        }
    }

    #[test]
    fn unknown_finding_id_defaults_to_runtime() {
        assert_eq!(finding_category("ollama.future_thing"), FindingCategory::Runtime);
    }

    #[test]
    fn severity_and_verdict_map_from_strings() {
        assert_eq!(severity_from_str("FAIL"), Severity::Fail);
        assert_eq!(severity_from_str("WARN"), Severity::Warn);
        assert_eq!(severity_from_str("anything"), Severity::Warn);
        assert_eq!(verdict_from_str("FAIL"), Verdict::Fail);
        assert_eq!(verdict_from_str("WARN"), Verdict::Warn);
        assert_eq!(verdict_from_str("PASS"), Verdict::Pass);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p sigil-core --lib aibom`
Expected: FAIL to compile — `finding_category`, `severity_from_str`, `verdict_from_str` not found.

- [ ] **Step 3: Implement the helper functions**

In `crates/sigil-core/src/aibom.rs`, add these private functions just above the `#[cfg(test)]` module:

```rust
fn finding_category(id: &str) -> FindingCategory {
    match id {
        "ollama.invalid_blob_digest"
        | "ollama.blob_digest_mismatch"
        | "ollama.blob_missing"
        | "ollama.model_not_found" => FindingCategory::Model,
        _ => FindingCategory::Runtime,
    }
}

fn severity_from_str(value: &str) -> Severity {
    match value {
        "FAIL" => Severity::Fail,
        _ => Severity::Warn,
    }
}

fn verdict_from_str(value: &str) -> Verdict {
    match value {
        "FAIL" => Verdict::Fail,
        "WARN" => Verdict::Warn,
        _ => Verdict::Pass,
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --lib aibom`
Expected: PASS (all six aibom unit tests).

- [ ] **Step 5: Commit**

```bash
git add crates/sigil-core/src/aibom.rs
git commit -m "feat(aibom): add severity/verdict/category mapping helpers"
```

---

### Task 3: Implement `From<&OllamaReport> for AiBom` + structural tests

**Files:**
- Modify: `crates/sigil-core/src/aibom.rs`
- Create: `crates/sigil-core/tests/aibom.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/sigil-core/tests/aibom.rs` with this content:

```rust
use std::fs;
use std::path::Path;

use sigil_core::aibom::AiBom;
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
use sigil_core::runtime::RuntimeListeners;
use tempfile::TempDir;

fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    write_blob(tmp.path(), digest, b"hello");
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{digest}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{{"digest":"{digest}","mediaType":"application/vnd.ollama.image.model"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}

fn write_blob(root: &Path, digest: &str, content: &[u8]) {
    let blob_path = root.join("models/blobs").join(digest.replace(':', "-"));
    fs::write(&blob_path, content).unwrap();
}

fn bom_for(host: &str) -> AiBom {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: host.to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();
    AiBom::from(&report)
}

#[test]
fn aibom_has_stable_top_level_shape() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    let object = value.as_object().unwrap();

    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["findings", "models", "runtime", "schema_version", "tool", "verdict"]
    );

    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["tool"]["name"], "sigil");
    assert!(value["tool"]["version"].is_string());
    assert_eq!(value["runtime"]["name"], "ollama");
    assert_eq!(value["runtime"]["api_exposure"], "not_probed");
    assert_eq!(value["runtime"]["status"], "not_probed");
    assert_eq!(value["runtime"]["exposure"]["class"], "unknown");
    assert_eq!(value["runtime"]["exposure"]["source"], "disabled");
    assert_eq!(value["verdict"], "PASS");
    assert_eq!(value["models"][0]["name"], "gemma4:e2b");
    assert_eq!(value["models"][0]["files"][0]["kind"], "model");
    assert!(value["models"][0]["files"][0]["sha256"].is_string());
}

#[test]
fn aibom_omits_absent_optional_fields() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    // probe_api = false -> no runtime version is recorded.
    assert!(value["runtime"].as_object().unwrap().get("version").is_none());
}

#[test]
fn aibom_maps_public_bind_finding_with_runtime_category_and_warn() {
    let bom = bom_for("0.0.0.0:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    assert_eq!(value["verdict"], "WARN");
    let finding = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "ollama.public_bind")
        .expect("public_bind finding present");
    assert_eq!(finding["category"], "runtime");
    assert_eq!(finding["severity"], "WARN");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p sigil-core --test aibom`
Expected: FAIL to compile — `From<&OllamaReport>` for `AiBom` not implemented (`AiBom::from(&report)` unresolved).

- [ ] **Step 3: Implement the conversion**

In `crates/sigil-core/src/aibom.rs`, add `OllamaReport` to the `ollama` import and implement `From`. Change the import line:

```rust
use crate::ollama::{ApiExposure, OllamaReport, RuntimeStatus};
```

Then add this `impl` just below the `impl AiBom { ... }` block:

```rust
impl From<&OllamaReport> for AiBom {
    fn from(report: &OllamaReport) -> Self {
        let observed = report
            .runtime_exposure
            .observed
            .iter()
            .map(|bind| BindEntry {
                addr: bind.addr.clone(),
                port: bind.port,
                process: bind.process.clone(),
            })
            .collect();
        let models = report
            .models
            .iter()
            .map(|model| ModelEntry {
                name: model.name.clone(),
                manifest_path: Some(model.manifest_path.display().to_string()),
                files: model
                    .files
                    .iter()
                    .map(|file| FileEntry {
                        digest: file.digest.clone(),
                        path: file.path.display().to_string(),
                        size: file.size,
                        sha256: file.sha256.clone(),
                        kind: file.kind.clone(),
                    })
                    .collect(),
            })
            .collect();
        let findings = report
            .findings
            .iter()
            .map(|finding| Finding {
                id: finding.id.clone(),
                category: finding_category(&finding.id),
                severity: severity_from_str(&finding.severity),
                message: finding.message.clone(),
                evidence: finding.evidence.clone(),
            })
            .collect();
        AiBom {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: ToolInfo {
                name: "sigil".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            runtime: RuntimeInfo {
                name: report.runtime.clone(),
                host: report.host.clone(),
                models_dir: Some(report.models_dir.display().to_string()),
                api_exposure: report.api.clone(),
                status: report.runtime_status.clone(),
                version: report.version.clone(),
                exposure: ExposureInfo {
                    class: report.runtime_exposure.class,
                    source: report.runtime_exposure.source.clone(),
                    observed,
                },
            },
            models,
            findings,
            verdict: verdict_from_str(&report.verdict),
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --test aibom`
Expected: PASS (`aibom_has_stable_top_level_shape`, `aibom_omits_absent_optional_fields`, `aibom_maps_public_bind_finding_with_runtime_category_and_warn`).

- [ ] **Step 5: Commit**

```bash
git add crates/sigil-core/src/aibom.rs crates/sigil-core/tests/aibom.rs
git commit -m "feat(aibom): convert OllamaReport into stable AiBom"
```

---

### Task 4: Move `render_ai_bom` into `aibom.rs` (render from `AiBom`)

**Files:**
- Modify: `crates/sigil-core/src/aibom.rs`
- Modify: `crates/sigil-core/src/ollama.rs`
- Modify: `crates/sigil-core/tests/ollama.rs`
- Modify: `crates/sigil-cli/src/main.rs`

- [ ] **Step 1: Add `render_ai_bom(&AiBom)` to `aibom.rs`**

In `crates/sigil-core/src/aibom.rs`, add this complete public function below the `From` impl (before the `#[cfg(test)]` module). `Verdict` is already imported at the top of the file from Task 1; `Verdict::as_str`, `ApiExposure::as_str`, `RuntimeStatus::as_str`, and `RuntimeExposure::as_str` already exist in the codebase, so no new methods are required.

```rust
pub fn render_ai_bom(bom: &AiBom) -> String {
    let mut lines = vec![
        "# SIGIL AI-BOM".to_string(),
        String::new(),
        format!("- Runtime: `{}`", bom.runtime.name),
        format!("- Host: `{}`", bom.runtime.host),
        format!("- API exposure: `{}`", bom.runtime.api_exposure.as_str()),
        format!(
            "- Runtime exposure: `{}`",
            bom.runtime.exposure.class.as_str()
        ),
        format!("- Runtime status: `{}`", bom.runtime.status.as_str()),
        format!("- Verdict: `{}`", bom.verdict.as_str()),
    ];
    if let Some(version) = &bom.runtime.version {
        lines.push(format!("- Version: `{version}`"));
    }
    for bind in &bom.runtime.exposure.observed {
        match &bind.process {
            Some(process) => lines.push(format!(
                "- Runtime bind: `{}:{}` process=`{process}`",
                bind.addr, bind.port
            )),
            None => lines.push(format!("- Runtime bind: `{}:{}`", bind.addr, bind.port)),
        }
    }
    lines.push(String::new());
    lines.push("## Models".to_string());
    if bom.models.is_empty() {
        lines.push("- No matching Ollama models found.".to_string());
    }
    for model in &bom.models {
        lines.push(format!("- `{}`", model.name));
        if let Some(manifest) = &model.manifest_path {
            lines.push(format!("  - Manifest: `{manifest}`"));
        }
        for file in &model.files {
            lines.push(format!(
                "  - `{}` size={} sha256=`{}` path=`{}`",
                file.digest, file.size, file.sha256, file.path
            ));
        }
    }
    if !bom.findings.is_empty() {
        lines.push(String::new());
        lines.push("## Findings".to_string());
        for finding in &bom.findings {
            lines.push(format!(
                "- `{}` {}: {} ({})",
                finding.id,
                finding.severity.as_str(),
                finding.message,
                finding.evidence
            ));
        }
    }
    lines.join("\n") + "\n"
}
```

- [ ] **Step 2: Remove `render_ai_bom` from `ollama.rs`**

In `crates/sigil-core/src/ollama.rs`, delete the entire `pub fn render_ai_bom(report: &OllamaReport) -> String { ... }` function (currently spanning the `render_ai_bom` definition through its closing brace, around lines 293–348). Leave everything else unchanged. Do not remove any `use` statements — `RuntimeExposureReport` and `RuntimeListeners` remain used by `OllamaReport` / `OllamaInspectOptions`.

- [ ] **Step 3: Update the CLI imports and the one `render_ai_bom` call site (keep current behavior)**

In `crates/sigil-cli/src/main.rs`:

Change the ollama import line:

```rust
use sigil_core::ollama::{inspect_ollama, OllamaInspectOptions};
```

Add a new import line directly below it:

```rust
use sigil_core::aibom::{render_ai_bom, AiBom};
```

In `cmd_aibom`, change the write call from:

```rust
            std::fs::write(&args.out, render_ai_bom(&report))?;
```

to:

```rust
            std::fs::write(&args.out, render_ai_bom(&AiBom::from(&report)))?;
```

(Leave `cmd_runtime` writing `report.to_json()?` for now — Task 5 switches it.)

- [ ] **Step 4: Update the 3 render tests in `crates/sigil-core/tests/ollama.rs`**

Change the ollama-module import block at the top from:

```rust
use sigil_core::ollama::{
    inspect_ollama, render_ai_bom, ApiExposure, ModelFile, OllamaInspectOptions, RuntimeStatus,
};
```

to:

```rust
use sigil_core::aibom::{render_ai_bom, AiBom};
use sigil_core::ollama::{
    inspect_ollama, ApiExposure, ModelFile, OllamaInspectOptions, RuntimeStatus,
};
```

Then in each of the three tests `renders_ai_bom_with_model_runtime_and_files`, `ai_bom_includes_runtime_exposure_and_binds`, and `ai_bom_runtime_exposure_unknown_when_disabled`, change the render call from:

```rust
    let bom = render_ai_bom(&report);
```

to:

```rust
    let bom = render_ai_bom(&AiBom::from(&report));
```

All existing `assert!(bom.contains(...))` lines stay unchanged.

- [ ] **Step 5: Run the full core + cli test suites**

Run: `cargo test -p sigil-core && cargo test -p sigil-cli`
Expected: PASS. Markdown output is byte-for-byte identical to before, so the CLI markdown test and the core render tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/sigil-core/src/aibom.rs crates/sigil-core/src/ollama.rs crates/sigil-core/tests/ollama.rs crates/sigil-cli/src/main.rs
git commit -m "refactor(aibom): render Markdown from the stable AiBom model"
```

---

### Task 5: Switch CLI JSON output to the stable contract + `--format`

**Files:**
- Modify: `crates/sigil-cli/src/main.rs`
- Modify: `crates/sigil-cli/tests/ollama_cli.rs`

- [ ] **Step 1: Update the CLI integration tests to the new JSON shape (failing)**

In `crates/sigil-cli/tests/ollama_cli.rs`:

Replace the assertions block at the end of `runtime_inspect_ollama_writes_evidence_json` (the four `assert!(json.contains(...))` lines) with:

```rust
    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"schema_version\": \"1.0\""));
    assert!(json.contains("\"name\": \"ollama\""));
    assert!(json.contains("\"api_exposure\": \"not_probed\""));
    assert!(json.contains("\"class\": \"unknown\""));
    assert!(json.contains("gemma4:e2b"));
    assert!(json.contains("\"verdict\": \"PASS\""));
```

Replace the assertions block at the end of `runtime_inspect_ollama_honors_ollama_host_env_when_host_flag_omitted` (the two `assert!(json.contains(...))` lines) with:

```rust
    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"api_exposure\": \"public_bind\""));
    assert!(json.contains("\"ollama.public_bind\""));
```

In `aibom_generate_ollama_writes_markdown`, add `"--format", "md",` to the args array (insert right after `"ollama",`), so the command requests Markdown explicitly. The markdown assertions stay unchanged.

Add a new test at the end of the file:

```rust
#[test]
fn aibom_generate_ollama_writes_json_by_default() {
    let tmp = fake_store();
    let out = tmp.path().join("reports").join("aibom.json");

    let mut cmd = Command::cargo_bin("sigil").unwrap();
    cmd.args([
        "aibom",
        "generate",
        "--runtime",
        "ollama",
        "--model",
        "gemma4:e2b",
        "--models-dir",
        tmp.path().join("models").to_str().unwrap(),
        "--no-probe-api",
        "--no-inspect-runtime",
        "--out",
        out.to_str().unwrap(),
    ])
    .current_dir(workspace_root())
    .env_remove("OLLAMA_HOST")
    .assert()
    .success()
    .stdout(contains("SIGIL AI-BOM:"));

    let json = fs::read_to_string(out).unwrap();
    assert!(json.contains("\"schema_version\": \"1.0\""));
    assert!(json.contains("\"api_exposure\": \"not_probed\""));
    assert!(json.contains("gemma4:e2b"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p sigil-cli --test ollama_cli`
Expected: FAIL — `runtime inspect` still writes the old `OllamaReport` shape (no `schema_version`); `aibom generate` rejects the unknown `--format` argument.

- [ ] **Step 3: Add the `AiBomFormat` enum and `--format` argument**

In `crates/sigil-cli/src/main.rs`, add this enum near the other CLI types (e.g. just above `struct AiBomGenerateArgs`). clap 4 auto-detects a field whose type derives `ValueEnum`, so no `value_enum` arg attribute is needed; variant names lower-case to the `json` / `md` values.

```rust
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AiBomFormat {
    Json,
    Md,
}
```

Add a `format` field to `AiBomGenerateArgs` (place it just above `out`). Use a string `default_value` (clap parses it through `ValueEnum`); `default_value_t` is avoided because it would require `Display`, which `ValueEnum` does not provide:

```rust
    #[arg(long, default_value = "json")]
    format: AiBomFormat,
```

- [ ] **Step 4: Switch `runtime inspect` output to `AiBom` JSON**

In `cmd_runtime`, change:

```rust
                    std::fs::write(path, report.to_json()?)?;
```

to:

```rust
                    std::fs::write(path, AiBom::from(&report).to_json()?)?;
```

- [ ] **Step 5: Branch `cmd_aibom` on `--format`**

Replace the body of the `AiBomCommand::Generate(args)` arm in `cmd_aibom` with:

```rust
        AiBomCommand::Generate(args) => {
            if args.runtime != "ollama" {
                anyhow::bail!("unsupported AI-BOM runtime: {}", args.runtime);
            }
            let format = args.format;
            let out = args.out.clone();
            let options = OllamaInspectOptions {
                model: args.model,
                models_dir: args
                    .models_dir
                    .unwrap_or_else(OllamaInspectOptions::default_models_dir),
                host: resolve_host(args.host),
                probe_api: args.probe_api,
                runtime_listeners: resolve_runtime_listeners(args.inspect_runtime),
            };
            let report = inspect_ollama(options)?;
            let bom = AiBom::from(&report);
            let contents = match format {
                AiBomFormat::Json => bom.to_json()?,
                AiBomFormat::Md => render_ai_bom(&bom),
            };
            ensure_parent_dir(&out)?;
            std::fs::write(&out, contents)?;
            println!("SIGIL AI-BOM: {}", out.display());
            Ok(())
        }
```

- [ ] **Step 6: Run the full test suites**

Run: `cargo test -p sigil-core && cargo test -p sigil-cli`
Expected: PASS (all updated and new CLI tests, plus unchanged core tests).

- [ ] **Step 7: Commit**

```bash
git add crates/sigil-cli/src/main.rs crates/sigil-cli/tests/ollama_cli.rs
git commit -m "feat(aibom): emit stable AI-BOM JSON from CLI with --format"
```

---

### Task 6: Document the AI-BOM JSON contract

**Files:**
- Modify: `README.md`
- Modify: `docs/ai-bom-and-comparison.md`

- [ ] **Step 1: Add an "AI-BOM JSON contract" section to `README.md`**

In `README.md`, replace the paragraph that currently reads:

```markdown
Use `--models-dir` to inspect a non-default Ollama model store. Use `--host` to evaluate a specific Ollama API endpoint; `0.0.0.0` / public bind-style hosts are reported as WARN.
```

with:

```markdown
Use `--models-dir` to inspect a non-default Ollama model store. Use `--host` to evaluate a specific Ollama API endpoint; `0.0.0.0` / public bind-style hosts are reported as WARN.

Both `runtime inspect ollama --out` and `aibom generate --format json` write the stable AI-BOM JSON contract. `aibom generate --format md` renders the same model as Markdown.

### AI-BOM JSON contract

The JSON is versioned by `schema_version` (currently `"1.0"`). It is runtime-agnostic: future runtimes populate the same shape.

Top-level keys (all required): `schema_version`, `tool` (`name`, `version`), `runtime`, `models`, `findings`, `verdict`.

- `runtime`: `name`, `host`, `api_exposure`, `status`, `exposure` (`class`, `source`, `observed[]`), and optional `models_dir` / `version`.
- `models[]`: `name`, `files[]` (`digest`, `path`, `size`, `sha256`, `kind`), and optional `manifest_path`.
- `findings[]`: `id`, `category` (`runtime` | `model` | `binary`), `severity` (`WARN` | `FAIL`), `message`, `evidence`.
- `verdict`: `PASS` | `WARN` | `FAIL`.

Enum values are stable: `api_exposure` ∈ {`not_probed`, `localhost`, `network`, `public_bind`, `unavailable`}, `status` ∈ {`not_probed`, `reachable`, `unreachable`}, `exposure.class` ∈ {`localhost`, `lan`, `public_bind`, `docker_published`, `proxy`, `unknown`}. Optional fields are omitted when absent. Markdown output is derived from this JSON model.
```

- [ ] **Step 2: Update `docs/ai-bom-and-comparison.md`**

In `docs/ai-bom-and-comparison.md`, replace the entire `## Schema Direction` section (from that heading to the end of the file) with:

```markdown
## Schema (implemented)

The AI-BOM JSON is now a stable, versioned contract produced from a
runtime-agnostic `AiBom` model (`crates/sigil-core/src/aibom.rs`):

- `schema_version` is explicit (currently `"1.0"`).
- Enum values are stabilized and pinned by tests: `verdict`, `severity`,
  `category`, `api_exposure`, `status`, and `exposure.class`.
- Required vs optional fields are defined; optional fields are omitted when
  absent.
- Findings carry a `category` (`runtime` | `model` | `binary`) so runtime,
  model, and (future) binary findings are distinguishable in one flat list.
- Markdown is rendered from the same `AiBom` model, so JSON and Markdown never
  diverge.

Both `runtime inspect ollama --out` and `aibom generate --format json` emit this
contract; `aibom generate --format md` emits the Markdown view.

A future runtime implements its own mapping into `AiBom` and reuses the same
struct and enum definitions, so downstream consumers and baselines keep working
without schema changes.

Still planned: a formal JSON Schema document (`*.schema.json`) and AI-BOM
comparison / baseline drift detection.
```

- [ ] **Step 3: Verify the docs render and the workspace is clean**

Run: `cargo test && cargo fmt --all`
Expected: all tests PASS; `cargo fmt` leaves the tree formatted (no manual fixes needed). Review `git diff` to confirm only intended doc and formatting changes.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/ai-bom-and-comparison.md
git commit -m "docs(aibom): document the stable AI-BOM JSON contract"
```

---

## Final Verification

- [ ] Run `cargo test` — entire workspace green.
- [ ] Run `cargo fmt --all -- --check` — no formatting drift.
- [ ] Run `cargo run -p sigil-cli -- aibom generate --runtime ollama --no-probe-api --no-inspect-runtime --models-dir crates/sigil-core/tests/does-not-exist --out /tmp/aibom.json` and confirm the output begins with `{ "schema_version": "1.0", ...` (empty model store is fine — verifies the schema serializes end-to-end).
- [ ] Confirm every spec acceptance criterion is covered: schema_version present (Task 3/5), tests assert field names + enum values (Tasks 1–3, 5), README documents contract (Task 6), runtime-agnostic `AiBom` reusable by future runtimes (Task 3).
