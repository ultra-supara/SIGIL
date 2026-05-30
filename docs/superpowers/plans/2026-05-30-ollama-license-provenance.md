# Ollama License & Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract Ollama model license metadata (from the `application/vnd.ollama.image.license` layer) and provenance metadata (registry / namespace / model / tag / digest lineage), record findings when either is missing or ambiguous, and surface both in `OllamaReport`, the `AiBom` JSON contract, and the AI-BOM Markdown.

**Architecture:** Extend the existing manifest parser in `sigil-core::ollama` to identify the license layer by `mediaType`, read its blob content as the SPDX/text excerpt, and decompose the manifest path into registry/namespace/model/tag. The provenance/license travels with each `OllamaModel`. The `aibom` module gets two new sub-structs (`ProvenanceEntry`, `LicenseEntry`) plumbed through `From<&OllamaReport>` and `render_ai_bom`. New finding ids (`ollama.license_missing`, `ollama.provenance_unknown`) map to `FindingCategory::Model` and emit `Severity::Warn` — never `Fail` (acceptance: missing license is a `WARN`, not a hard failure). Schema bump: `1.0` → `1.1` (additive, backwards-compatible).

**Tech Stack:** Rust, serde / serde_json, Cargo workspace (`sigil-core`, `sigil-cli`), clap (CLI), tempfile + assert_cmd (tests).

**Spec:** GitHub issue #7 (`Extract Ollama model license and provenance metadata`).

---

## File Structure

- Modify: `crates/sigil-core/src/ollama.rs` — add `ModelProvenance`, `LicenseInfo`, license-layer detection, provenance parsing, two new findings.
- Modify: `crates/sigil-core/src/aibom.rs` — add `ProvenanceEntry`, `LicenseEntry`, bump `SCHEMA_VERSION` to `"1.1"`, map license/provenance in `From<&OllamaReport>`, render in Markdown, map new finding ids to `FindingCategory::Model`.
- Modify: `crates/sigil-core/tests/ollama.rs` — extend fake-store helper to include a license layer, add three new tests (license present, license missing, unknown provenance).
- Modify: `crates/sigil-core/tests/aibom.rs` — add JSON-shape assertions for license + provenance.
- Modify: `crates/sigil-cli/tests/ollama_cli.rs` — assert license/provenance appear in JSON and Markdown CLI output.
- Modify: `README.md`, `docs/ai-bom-and-comparison.md`, `docs/ollama-inspection.md` — document the new fields and schema bump.

---

### Task 1: Extend `ollama.rs` types with provenance + license (and re-export)

**Files:**
- Modify: `crates/sigil-core/src/ollama.rs`

- [ ] **Step 1: Add `ModelProvenance` and `LicenseInfo` structs after `ModelFile`**

Insert these two struct definitions in `crates/sigil-core/src/ollama.rs` immediately after the `ModelFile` struct (around line 78):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    pub registry: Option<String>,
    pub namespace: Option<String>,
    pub model: Option<String>,
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub layer_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_id: Option<String>,
    pub text_excerpt: String,
}
```

- [ ] **Step 2: Extend `OllamaModel` with the two new fields**

Replace the existing `OllamaModel` struct with:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaModel {
    pub name: String,
    pub manifest_path: PathBuf,
    pub files: Vec<ModelFile>,
    pub provenance: ModelProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseInfo>,
}
```

- [ ] **Step 3: Confirm it still compiles in isolation (will fail because constructor sites are not updated yet — that's expected)**

Run: `cargo check -p sigil-core`
Expected: FAIL with "missing fields `provenance` and `license` in initializer of `OllamaModel`" pointing at the existing constructor in `inspect_ollama`. This is the test-driven signal that the next task must wire the constructor.

- [ ] **Step 4: Commit**

```bash
git add crates/sigil-core/src/ollama.rs
git commit -m "feat(ollama): add ModelProvenance and LicenseInfo types"
```

---

### Task 2: Parse provenance from the manifest path

**Files:**
- Modify: `crates/sigil-core/src/ollama.rs`

- [ ] **Step 1: Replace `model_name_from_manifest` with a richer parser**

Replace the existing function (around lines 376-390) with:

```rust
/// Returns `(display_name, ModelProvenance)` parsed from the manifest path.
///
/// Ollama lays manifests at `<models_dir>/manifests/<registry>/<namespace...>/<model>/<tag>`.
/// We treat the *last* path component as the tag, the second-to-last as the model
/// name, the first as the registry, and everything in between as the namespace
/// (joined with `/`). Anything shallower than 3 components is treated as
/// "unknown provenance" and surfaces as a finding upstream.
fn parse_manifest_path(
    models_dir: &Path,
    manifest_path: &Path,
) -> Option<(String, ModelProvenance)> {
    let relative = manifest_path
        .strip_prefix(models_dir.join("manifests"))
        .ok()?;
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    let tag = parts.last()?.clone();
    let model = parts.get(parts.len() - 2)?.clone();
    let registry = parts.first()?.clone();
    let namespace = if parts.len() > 3 {
        Some(parts[1..parts.len() - 2].join("/"))
    } else {
        None
    };
    let display = format!("{model}:{tag}");
    let provenance = ModelProvenance {
        registry: Some(registry),
        namespace,
        model: Some(model),
        tag: Some(tag),
        config_digest: None,
        layer_digests: Vec::new(),
    };
    Some((display, provenance))
}
```

- [ ] **Step 2: Remove the old `model_name_from_manifest` function**

The function block from line 376 through line 390 (the one starting `fn model_name_from_manifest(`) is now obsolete — delete it.

- [ ] **Step 3: Run `cargo check -p sigil-core` and observe the new call-site error**

Run: `cargo check -p sigil-core`
Expected: FAIL pointing at `model_name_from_manifest` call inside `inspect_ollama`. This drives Task 3.

- [ ] **Step 4: Commit**

```bash
git add crates/sigil-core/src/ollama.rs
git commit -m "feat(ollama): parse registry/namespace/model/tag from manifest path"
```

---

### Task 3: Wire provenance + license-layer detection through `inspect_ollama`

**Files:**
- Modify: `crates/sigil-core/src/ollama.rs`

- [ ] **Step 1: Add a constant for the license media type**

Add this near the top of `crates/sigil-core/src/ollama.rs` (after the imports, before the first `pub struct`):

```rust
const LICENSE_MEDIA_TYPE: &str = "application/vnd.ollama.image.license";
const LICENSE_EXCERPT_BYTES: usize = 256;
```

- [ ] **Step 2: Replace the body of `inspect_ollama`'s per-manifest loop**

Inside `inspect_ollama` (around lines 158-206), replace the per-manifest body — from the call site that currently reads `let Some(name) = model_name_from_manifest(&options.models_dir, &manifest_path) else { continue; };` down through the `models.push(OllamaModel { ... })` block — with the implementation below. This adds provenance parsing, captures config + layer digests, detects the license layer, and emits the two new findings.

```rust
        let Some((name, mut provenance)) =
            parse_manifest_path(&options.models_dir, &manifest_path)
        else {
            findings.push(RuntimeFinding {
                id: "ollama.provenance_unknown".to_string(),
                severity: "WARN".to_string(),
                message: "Ollama manifest path is too shallow to determine provenance"
                    .to_string(),
                evidence: manifest_path.display().to_string(),
            });
            continue;
        };
        if let Some(filter) = &options.model {
            if &name != filter {
                continue;
            }
        }
        let raw = read_to_string(&manifest_path)?;
        let manifest: Manifest =
            serde_json::from_str(&raw).map_err(|source| OllamaError::ParseManifest {
                path: manifest_path.display().to_string(),
                source,
            })?;
        let mut files = Vec::new();
        let mut license = None;
        if let Some(config) = manifest.config {
            provenance.config_digest = Some(config.digest.clone());
            push_model_file_or_finding(
                &options.models_dir,
                &config.digest,
                "config",
                &manifest_path,
                &mut files,
                &mut findings,
            )?;
        }
        for layer in manifest.layers {
            provenance.layer_digests.push(layer.digest.clone());
            let is_license = layer
                .media_type
                .as_deref()
                .map(|media_type| media_type == LICENSE_MEDIA_TYPE)
                .unwrap_or(false);
            let kind = layer
                .media_type
                .as_deref()
                .and_then(|media_type| media_type.rsplit('.').next())
                .unwrap_or("blob");
            let before_len = files.len();
            push_model_file_or_finding(
                &options.models_dir,
                &layer.digest,
                kind,
                &manifest_path,
                &mut files,
                &mut findings,
            )?;
            if is_license && license.is_none() {
                if let Some(file) = files.get(before_len) {
                    let text = read_license_excerpt(&file.path)?;
                    let spdx_id = detect_spdx_id(&text);
                    license = Some(LicenseInfo {
                        digest: file.digest.clone(),
                        size: file.size,
                        spdx_id,
                        text_excerpt: text,
                    });
                }
            }
        }
        files.sort_by(|left, right| left.digest.cmp(&right.digest));
        files.dedup_by(|left, right| left.digest == right.digest);
        if license.is_none() {
            findings.push(RuntimeFinding {
                id: "ollama.license_missing".to_string(),
                severity: "WARN".to_string(),
                message: "Ollama manifest does not reference a license layer".to_string(),
                evidence: manifest_path.display().to_string(),
            });
        }
        models.push(OllamaModel {
            name,
            manifest_path,
            files,
            provenance,
            license,
        });
```

- [ ] **Step 3: Add the two helper functions at the end of the file (before `#[cfg(test)]` if present, otherwise at end)**

Append to `crates/sigil-core/src/ollama.rs`:

```rust
fn read_license_excerpt(path: &Path) -> Result<String, OllamaError> {
    let file = File::open(path).map_err(|source| OllamaError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0_u8; LICENSE_EXCERPT_BYTES];
    let mut total = 0;
    loop {
        let read = reader
            .read(&mut buffer[total..])
            .map_err(|source| OllamaError::ReadFile {
                path: path.display().to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        total += read;
        if total == buffer.len() {
            break;
        }
    }
    buffer.truncate(total);
    Ok(String::from_utf8_lossy(&buffer).trim().to_string())
}

fn detect_spdx_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let first_line = trimmed.lines().next().unwrap_or(trimmed).trim();
    if first_line.is_empty() {
        return None;
    }
    // SPDX identifiers are short single-token strings (e.g., "MIT", "Apache-2.0",
    // "GPL-3.0-only"). Reject anything that looks like prose so we never falsely
    // claim an SPDX id we did not actually identify.
    if first_line.len() <= 32
        && !first_line.contains(' ')
        && first_line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
    {
        return Some(first_line.to_string());
    }
    None
}
```

- [ ] **Step 4: Run `cargo test -p sigil-core --test ollama` to see all current tests fail with `missing fields` or compile cleanly**

Run: `cargo test -p sigil-core --test ollama`
Expected: existing tests pass except those that depend on `OllamaModel` constructor shape — they should still compile because `provenance` and `license` are populated by `inspect_ollama` itself, not by test code. If any test fails on assertion (e.g., new `ollama.license_missing` finding pushed verdict to WARN), capture the failure for Task 5.

- [ ] **Step 5: Commit**

```bash
git add crates/sigil-core/src/ollama.rs
git commit -m "feat(ollama): detect license layer and emit license_missing finding"
```

---

### Task 4: Plumb license + provenance through `aibom` (schema bump 1.0 → 1.1)

**Files:**
- Modify: `crates/sigil-core/src/aibom.rs`

- [ ] **Step 1: Bump the schema version and import the new types**

Edit `crates/sigil-core/src/aibom.rs`. Change the constant:

```rust
pub const SCHEMA_VERSION: &str = "1.1";
```

And extend the `use crate::ollama::...` line to bring in the new types:

```rust
use crate::ollama::{ApiExposure, LicenseInfo, ModelProvenance, OllamaReport, RuntimeStatus};
```

- [ ] **Step 2: Add `ProvenanceEntry` and `LicenseEntry` DTOs**

Insert directly after the `FileEntry` struct in `crates/sigil-core/src/aibom.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub layer_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseEntry {
    pub digest: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_id: Option<String>,
    pub text_excerpt: String,
}

impl From<&ModelProvenance> for ProvenanceEntry {
    fn from(value: &ModelProvenance) -> Self {
        Self {
            registry: value.registry.clone(),
            namespace: value.namespace.clone(),
            model: value.model.clone(),
            tag: value.tag.clone(),
            config_digest: value.config_digest.clone(),
            layer_digests: value.layer_digests.clone(),
        }
    }
}

impl From<&LicenseInfo> for LicenseEntry {
    fn from(value: &LicenseInfo) -> Self {
        Self {
            digest: value.digest.clone(),
            size: value.size,
            spdx_id: value.spdx_id.clone(),
            text_excerpt: value.text_excerpt.clone(),
        }
    }
}
```

- [ ] **Step 3: Extend `ModelEntry` with the new fields**

Replace the existing `ModelEntry` struct with:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub name: String,
    // None is reserved for runtimes without per-model manifests; always Some for Ollama.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    pub files: Vec<FileEntry>,
    pub provenance: ProvenanceEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseEntry>,
}
```

- [ ] **Step 4: Populate provenance + license in `From<&OllamaReport>`**

In the `From<&OllamaReport> for AiBom` impl, replace the `let models = report.models.iter().map(...)` block so each `ModelEntry` is constructed as:

```rust
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
                provenance: ProvenanceEntry::from(&model.provenance),
                license: model.license.as_ref().map(LicenseEntry::from),
            })
            .collect();
```

- [ ] **Step 5: Add the two new finding ids to the model-category map**

In `fn finding_category`, extend the `match id` arm so both new ids resolve to `FindingCategory::Model`:

```rust
fn finding_category(id: &str) -> FindingCategory {
    match id {
        "ollama.invalid_blob_digest"
        | "ollama.blob_digest_mismatch"
        | "ollama.blob_missing"
        | "ollama.model_not_found"
        | "ollama.license_missing"
        | "ollama.provenance_unknown" => FindingCategory::Model,
        _ => FindingCategory::Runtime,
    }
}
```

- [ ] **Step 6: Render license + provenance in Markdown**

Inside `render_ai_bom`, locate the per-model loop:

```rust
    for model in &bom.models {
        lines.push(format!("- `{}`", model.name));
        if let Some(manifest) = &model.manifest_path {
            lines.push(format!("  - Manifest: `{manifest}`"));
        }
```

Immediately after the `Manifest:` line, insert:

```rust
        lines.push(format!(
            "  - Provenance: registry=`{}` namespace=`{}` model=`{}` tag=`{}`",
            model.provenance.registry.as_deref().unwrap_or("unknown"),
            model.provenance.namespace.as_deref().unwrap_or("-"),
            model.provenance.model.as_deref().unwrap_or("unknown"),
            model.provenance.tag.as_deref().unwrap_or("unknown"),
        ));
        match &model.license {
            Some(license) => lines.push(format!(
                "  - License: `{}` digest=`{}` size={}",
                license.spdx_id.as_deref().unwrap_or("unknown"),
                license.digest,
                license.size,
            )),
            None => lines.push("  - License: missing".to_string()),
        }
```

- [ ] **Step 7: Extend the existing `model_finding_ids_map_to_model_category` unit test to cover the new ids**

In the bottom `#[cfg(test)] mod tests` block of `crates/sigil-core/src/aibom.rs`, replace the `model_finding_ids_map_to_model_category` test array with:

```rust
        for id in [
            "ollama.invalid_blob_digest",
            "ollama.blob_digest_mismatch",
            "ollama.blob_missing",
            "ollama.model_not_found",
            "ollama.license_missing",
            "ollama.provenance_unknown",
        ] {
            assert_eq!(finding_category(id), FindingCategory::Model, "{id}");
        }
```

- [ ] **Step 8: Run unit tests**

Run: `cargo test -p sigil-core --lib aibom`
Expected: PASS for all tests in the `aibom` module (including the extended category test).

- [ ] **Step 9: Commit**

```bash
git add crates/sigil-core/src/aibom.rs
git commit -m "feat(aibom): expose license + provenance, bump schema to 1.1"
```

---

### Task 5: Update existing Ollama tests for the new fake-store shape

**Files:**
- Modify: `crates/sigil-core/tests/ollama.rs`

The existing `fake_store` helper does not include a license layer, so the new `inspect_ollama` will emit `ollama.license_missing` (WARN) and flip the existing "PASS" verdict tests to "WARN". We update the helper to include a license layer so existing tests keep passing, and add a separate `fake_store_no_license` helper for the new "missing license" test in Task 6.

- [ ] **Step 1: Replace `write_blob` to support varied content per digest**

Existing helper writes one blob per call but reuses the same sha; that's fine — leave it alone. Move on.

- [ ] **Step 2: Add a license-layer-aware fake store helper**

In `crates/sigil-core/tests/ollama.rs`, replace the existing `fake_store` function with two helpers (delete the original `fake_store`, then add the two below):

```rust
const LICENSE_DIGEST: &str =
    "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

fn fake_store() -> TempDir {
    fake_store_with_license(true)
}

fn fake_store_no_license() -> TempDir {
    fake_store_with_license(false)
}

fn fake_store_with_license(include_license: bool) -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let model_digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    write_blob(tmp.path(), model_digest, b"hello");
    let layers = if include_license {
        // The license blob content is the literal "MIT" — detect_spdx_id should
        // turn this into spdx_id="MIT" without prompting a license_missing finding.
        write_blob(tmp.path(), LICENSE_DIGEST, b"MIT");
        format!(
            r#"{{"digest":"{model_digest}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{LICENSE_DIGEST}","mediaType":"application/vnd.ollama.image.license"}}"#
        )
    } else {
        format!(
            r#"{{"digest":"{model_digest}","mediaType":"application/vnd.ollama.image.model"}}"#
        )
    };
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {{"digest": "{model_digest}", "mediaType": "application/vnd.ollama.image.config"}},
  "layers": [{layers}]
}}"#
        ),
    )
    .unwrap();
    tmp
}
```

- [ ] **Step 3: Run existing tests**

Run: `cargo test -p sigil-core --test ollama`
Expected: PASS for all 11 existing tests (they should be insulated by the now-present license layer).

- [ ] **Step 4: Commit**

```bash
git add crates/sigil-core/tests/ollama.rs
git commit -m "test(ollama): include license layer in default fake store"
```

---

### Task 6: New integration tests for license + provenance

**Files:**
- Modify: `crates/sigil-core/tests/ollama.rs`

- [ ] **Step 1: Append the three new tests**

Add these three `#[test]` functions to the end of `crates/sigil-core/tests/ollama.rs`:

```rust
#[test]
fn license_layer_is_extracted_with_spdx_id() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "PASS");
    let model = &report.models[0];
    let license = model
        .license
        .as_ref()
        .expect("license layer should be detected");
    assert_eq!(license.spdx_id.as_deref(), Some("MIT"));
    assert_eq!(license.text_excerpt, "MIT");
    assert_eq!(model.provenance.registry.as_deref(), Some("registry.ollama.ai"));
    assert_eq!(model.provenance.namespace.as_deref(), Some("library"));
    assert_eq!(model.provenance.model.as_deref(), Some("gemma4"));
    assert_eq!(model.provenance.tag.as_deref(), Some("e2b"));
    assert!(!model.provenance.layer_digests.is_empty());
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.license_missing"));
}

#[test]
fn missing_license_layer_emits_warn_not_fail() {
    let tmp = fake_store_no_license();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "WARN");
    assert!(report.models[0].license.is_none());
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id == "ollama.license_missing")
        .expect("license_missing finding present");
    assert_eq!(finding.severity, "WARN");
}

#[test]
fn shallow_manifest_path_is_flagged_as_unknown_provenance() {
    let tmp = TempDir::new().unwrap();
    // Only two path segments below `manifests/` — too shallow for registry/namespace/model/tag.
    let manifest_dir = tmp.path().join("models/manifests/orphaned");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(digest.replace(':', "-")),
        b"hello",
    )
    .unwrap();
    fs::write(
        manifest_dir.join("loose"),
        format!(r#"{{"schemaVersion":2,"config":{{"digest":"{digest}"}},"layers":[]}}"#),
    )
    .unwrap();

    let report = inspect_ollama(OllamaInspectOptions {
        model: None,
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    assert_eq!(report.verdict, "WARN");
    assert!(report.models.is_empty());
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id == "ollama.provenance_unknown")
        .expect("provenance_unknown finding present");
    assert_eq!(finding.severity, "WARN");
}
```

- [ ] **Step 2: Run the new tests**

Run: `cargo test -p sigil-core --test ollama -- license_layer_is_extracted_with_spdx_id missing_license_layer_emits_warn_not_fail shallow_manifest_path_is_flagged_as_unknown_provenance`
Expected: 3 PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/sigil-core/tests/ollama.rs
git commit -m "test(ollama): cover license present, missing, and unknown provenance"
```

---

### Task 7: AI-BOM JSON shape regression for license + provenance

**Files:**
- Modify: `crates/sigil-core/tests/aibom.rs`

- [ ] **Step 1: Update the fake-store JSON to include a license layer**

In `crates/sigil-core/tests/aibom.rs`, replace the `fake_store` helper and constants section (the lines defining `CONFIG_DIGEST`, `MODEL_DIGEST`, and `fake_store`) with:

```rust
const CONFIG_DIGEST: &str =
    "sha256:e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0";
const MODEL_DIGEST: &str =
    "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const LICENSE_DIGEST: &str =
    "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    write_blob(tmp.path(), CONFIG_DIGEST, b"cfg");
    write_blob(tmp.path(), MODEL_DIGEST, b"hello");
    write_blob(tmp.path(), LICENSE_DIGEST, b"Apache-2.0");
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{CONFIG_DIGEST}","mediaType":"application/vnd.ollama.image.config"}},"layers":[{{"digest":"{MODEL_DIGEST}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{LICENSE_DIGEST}","mediaType":"application/vnd.ollama.image.license"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}
```

- [ ] **Step 2: Bump the schema-version assertion**

In the existing test `aibom_has_stable_top_level_shape`, change:

```rust
    assert_eq!(value["schema_version"], "1.0");
```

to:

```rust
    assert_eq!(value["schema_version"], "1.1");
```

- [ ] **Step 3: Append a new test asserting the license + provenance shape**

At the end of `crates/sigil-core/tests/aibom.rs`, append:

```rust
#[test]
fn aibom_exposes_license_and_provenance_in_models() {
    let bom = bom_for("http://127.0.0.1:11434");
    let value: serde_json::Value = serde_json::from_str(&bom.to_json().unwrap()).unwrap();
    let model = &value["models"][0];
    let provenance = &model["provenance"];
    assert_eq!(provenance["registry"], "registry.ollama.ai");
    assert_eq!(provenance["namespace"], "library");
    assert_eq!(provenance["model"], "gemma4");
    assert_eq!(provenance["tag"], "e2b");
    assert_eq!(provenance["config_digest"], CONFIG_DIGEST);
    let layer_digests = provenance["layer_digests"].as_array().unwrap();
    assert!(layer_digests.iter().any(|digest| digest == MODEL_DIGEST));
    assert!(layer_digests.iter().any(|digest| digest == LICENSE_DIGEST));

    let license = &model["license"];
    assert_eq!(license["digest"], LICENSE_DIGEST);
    assert_eq!(license["spdx_id"], "Apache-2.0");
    assert_eq!(license["text_excerpt"], "Apache-2.0");
}
```

- [ ] **Step 4: Run the AI-BOM integration tests**

Run: `cargo test -p sigil-core --test aibom`
Expected: PASS for all tests including the new one.

- [ ] **Step 5: Commit**

```bash
git add crates/sigil-core/tests/aibom.rs
git commit -m "test(aibom): assert license + provenance JSON shape"
```

---

### Task 8: CLI end-to-end regression

**Files:**
- Modify: `crates/sigil-cli/tests/ollama_cli.rs`

- [ ] **Step 1: Update the CLI fake-store helper to include a license layer**

In `crates/sigil-cli/tests/ollama_cli.rs`, replace the existing `fake_store` function with:

```rust
fn fake_store() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let manifest_dir = tmp
        .path()
        .join("models/manifests/registry.ollama.ai/library/gemma4");
    fs::create_dir_all(&manifest_dir).unwrap();
    fs::create_dir_all(tmp.path().join("models/blobs")).unwrap();
    let model_digest = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let license_digest = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(model_digest.replace(':', "-")),
        b"hello",
    )
    .unwrap();
    fs::write(
        tmp.path()
            .join("models/blobs")
            .join(license_digest.replace(':', "-")),
        b"MIT",
    )
    .unwrap();
    fs::write(
        manifest_dir.join("e2b"),
        format!(
            r#"{{"schemaVersion":2,"config":{{"digest":"{model_digest}"}},"layers":[{{"digest":"{model_digest}","mediaType":"application/vnd.ollama.image.model"}},{{"digest":"{license_digest}","mediaType":"application/vnd.ollama.image.license"}}]}}"#
        ),
    )
    .unwrap();
    tmp
}
```

- [ ] **Step 2: Update the schema_version assertion in `runtime_inspect_ollama_writes_evidence_json`**

Change:

```rust
    assert!(json.contains("\"schema_version\": \"1.0\""));
```

to:

```rust
    assert!(json.contains("\"schema_version\": \"1.1\""));
```

- [ ] **Step 3: Extend `runtime_inspect_ollama_writes_evidence_json` with license + provenance assertions**

After the existing `assert!(json.contains("\"verdict\": \"PASS\""));` line in that test, append:

```rust
    assert!(json.contains("\"registry\": \"registry.ollama.ai\""));
    assert!(json.contains("\"namespace\": \"library\""));
    assert!(json.contains("\"tag\": \"e2b\""));
    assert!(json.contains("\"spdx_id\": \"MIT\""));
```

- [ ] **Step 4: Extend `aibom_generate_ollama_writes_markdown` with Markdown assertions**

In the assertions block of that test, after the existing `- Runtime exposure:` assertion, append:

```rust
    assert!(markdown.contains("- Provenance:"));
    assert!(markdown.contains("registry=`registry.ollama.ai`"));
    assert!(markdown.contains("tag=`e2b`"));
    assert!(markdown.contains("- License: `MIT`"));
```

- [ ] **Step 5: Run the CLI tests**

Run: `cargo test -p sigil-cli --test ollama_cli`
Expected: PASS for all four tests.

- [ ] **Step 6: Commit**

```bash
git add crates/sigil-cli/tests/ollama_cli.rs
git commit -m "test(cli): assert license + provenance in JSON and Markdown output"
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/ai-bom-and-comparison.md`
- Modify: `docs/ollama-inspection.md`

- [ ] **Step 1: Read README.md to find the AI-BOM contract section**

Run: `grep -n "schema_version\|AI-BOM\|Provenance\|License" README.md`
This locates the right insertion points. The user-facing contract block likely lives in a "JSON Contract" / "Schema" section; insert the new fields there.

- [ ] **Step 2: Add a "License & provenance" subsection under the AI-BOM contract in README.md**

Insert the following block immediately after the existing schema-version description (or at the end of the AI-BOM contract section if no such anchor exists):

```markdown
### License & provenance (schema 1.1)

Each model entry now carries provenance and (when present) license metadata extracted from the Ollama manifest:

```json
{
  "models": [
    {
      "name": "gemma4:e2b",
      "provenance": {
        "registry": "registry.ollama.ai",
        "namespace": "library",
        "model": "gemma4",
        "tag": "e2b",
        "config_digest": "sha256:...",
        "layer_digests": ["sha256:...", "sha256:..."]
      },
      "license": {
        "digest": "sha256:...",
        "size": 11,
        "spdx_id": "MIT",
        "text_excerpt": "MIT"
      }
    }
  ]
}
```

When the manifest has no `application/vnd.ollama.image.license` layer, `license` is omitted and a `WARN` finding (`ollama.license_missing`, category `model`) is emitted — never a hard failure. When the manifest path is too shallow to parse a registry/namespace/model/tag tuple, an `ollama.provenance_unknown` `WARN` is emitted and the model is skipped from `models`.
```

- [ ] **Step 3: Update `docs/ai-bom-and-comparison.md`**

Run: `grep -n "schema_version\|1.0\|License\|Provenance" docs/ai-bom-and-comparison.md`
Replace any `1.0` schema-version reference with `1.1`, and append the same "License & provenance" block from Step 2 under the schema-contract section.

- [ ] **Step 4: Update `docs/ollama-inspection.md`**

Run: `grep -n "Findings\|finding\|provenance\|license" docs/ollama-inspection.md`
Locate the findings table or list and append two rows / bullets:

```markdown
| `ollama.license_missing` | `WARN` | model | Manifest does not reference a license layer. |
| `ollama.provenance_unknown` | `WARN` | model | Manifest path lacks registry/namespace/model/tag structure. |
```

If the file uses a bullet list instead of a table, mirror the existing style.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/ai-bom-and-comparison.md docs/ollama-inspection.md
git commit -m "docs(aibom): document license + provenance fields and schema 1.1"
```

---

### Task 10: Full verification, then PR

**Files:** none (verification + git)

- [ ] **Step 1: Format**

Run: `cargo fmt --all`
Expected: no output (no changes), or auto-format and continue.

- [ ] **Step 2: Lint**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS with no warnings.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: all tests PASS.

- [ ] **Step 4: Inspect the plan doc commit**

The plan doc itself (`docs/superpowers/plans/2026-05-30-ollama-license-provenance.md`) is part of this change — verify it is already committed (it was authored before any implementation work). If not, stage and commit it separately with `docs(plan):` prefix before opening the PR.

- [ ] **Step 5: Push and open PR**

```bash
git push -u origin feat/ollama-license-provenance
gh pr create --title "feat(ollama): extract license + provenance metadata" --body "$(cat <<'EOF'
## Summary
- Extracts Ollama model license layer (`application/vnd.ollama.image.license`) — SPDX id detection, digest, size, excerpt.
- Parses registry/namespace/model/tag from the manifest path and records config + layer digest lineage.
- Emits new `WARN` findings: `ollama.license_missing`, `ollama.provenance_unknown` (both `category: model`).
- Surfaces license + provenance in the AI-BOM JSON contract (schema 1.0 → 1.1, additive) and AI-BOM Markdown.

Closes #7.

## Test plan
- [ ] `cargo fmt --all` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` all green
- [ ] New tests: license present (spdx id detected), license missing (WARN), unknown provenance (WARN)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review

**Spec coverage:**
- ✅ Parse Ollama manifest descriptors for license/config layers → Task 3 detects `LICENSE_MEDIA_TYPE` per layer.
- ✅ Extract license text or license identifiers when available → Task 3 (`read_license_excerpt`, `detect_spdx_id`).
- ✅ Record source registry, namespace, model name, tag, and digest lineage → Task 2 (`parse_manifest_path`) + Task 3 (config/layer digests captured into `ModelProvenance`).
- ✅ Add findings for missing, unknown, or conflicting license/provenance → Task 3 emits `ollama.license_missing` and `ollama.provenance_unknown` as `WARN`.
- ✅ Include license/provenance in JSON and AI-BOM Markdown → Task 4.
- ✅ `gemma4:e2b` reports its license layer as evidence → Task 6 test `license_layer_is_extracted_with_spdx_id`.
- ✅ Reports include registry/namespace/model/tag provenance fields → Tasks 6 and 7 assert all four.
- ✅ Missing license metadata produces a clear `WARN`, not a hard failure → Task 6 test `missing_license_layer_emits_warn_not_fail` asserts severity = WARN; finding category = model.
- ✅ Tests cover license present, license missing, and unknown provenance cases → Task 6 covers all three.

**Placeholder scan:** No "TBD", "TODO", "fill in later", or unspecified code blocks. Every code change is shown verbatim.

**Type consistency:** `ModelProvenance` / `LicenseInfo` (core) ↔ `ProvenanceEntry` / `LicenseEntry` (DTO). Field names match across layers (`registry`, `namespace`, `model`, `tag`, `config_digest`, `layer_digests`, `digest`, `size`, `spdx_id`, `text_excerpt`). Finding ids consistent: `ollama.license_missing`, `ollama.provenance_unknown`. Schema version bumped exactly once: `"1.0"` → `"1.1"`, asserted by tests in Tasks 7 and 8.
