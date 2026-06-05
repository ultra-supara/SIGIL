# AI-BOM and Comparison Direction

SIGIL's AI-BOM is an evidence record for local AI deployments. It is inspired by SBOM workflows, but it focuses on AI runtime and model-store concerns rather than package dependencies alone.

## Why AI-BOM Matters

Local LLM deployments can change without a package manager or central inventory:

- A model tag can point to different local blobs over time.
- A custom model can derive from a base model with a new Modelfile.
- A runtime can move from localhost-only to LAN-accessible.
- A local model store can contain unknown or corrupted artifacts.
- A license layer can be removed or replaced.
- Runtime binaries can change independently of model files.

An AI-BOM gives SIGIL a stable record to compare against later.

## Current AI-BOM Output

SIGIL currently emits:

- JSON evidence from `runtime inspect ollama --out <path>` (always the AI-BOM JSON contract)
- JSON or Markdown from `aibom generate --runtime ollama --format {json,md} --out <path>`

The two paths produce the **same** AI-BOM model — JSON and Markdown never diverge. Markdown is a rendering of the JSON, not a separate report.

## Schema (implemented)

The AI-BOM JSON is a stable, versioned contract produced from a runtime-agnostic `AiBom` model (`crates/sigil-core/src/aibom.rs`).
The contract is formally specified in [`schemas/aibom-v1.schema.json`](../schemas/aibom-v1.schema.json) (JSON Schema draft 2020-12, self-contained, strict `additionalProperties: false`).

The schema captures:

- `schema_version` is explicit (currently `"1.1"`). Minor bumps are additive; major bumps are breaking.
- Enum values are stabilized and pinned by tests: `verdict`, `severity`, `category`, `api_exposure`, `status`, `exposure.class`.
- Required vs optional fields are defined. Optional fields are omitted when absent.
- Findings carry a `category` (`runtime` | `model` | `binary`). `binary` is reserved for native-binary findings and is not yet produced by the Ollama path.

### Top-level shape

```json
{
  "schema_version": "1.1",
  "tool": { "name": "sigil", "version": "0.1.0" },
  "runtime": {
    "name": "ollama",
    "host": "http://127.0.0.1:11434",
    "models_dir": "/home/you/.ollama/models",
    "api_exposure": "not_probed",
    "status": "not_probed",
    "exposure": {
      "class": "unknown",
      "source": "disabled",
      "observed": []
    }
  },
  "models": [
    {
      "name": "gemma4:e2b",
      "manifest_path": "/home/you/.ollama/models/manifests/registry.ollama.ai/library/gemma4/e2b",
      "files": [
        { "digest": "sha256:4e30…", "path": "…", "size": 7162394016, "sha256": "4e30…", "kind": "model" },
        { "digest": "sha256:c6bc…", "path": "…", "size": 473,         "sha256": "c6bc…", "kind": "config" },
        { "digest": "sha256:7339…", "path": "…", "size": 11355,       "sha256": "7339…", "kind": "license" },
        { "digest": "sha256:5638…", "path": "…", "size": 42,          "sha256": "5638…", "kind": "params" }
      ],
      "provenance": {
        "registry": "registry.ollama.ai",
        "namespace": "library",
        "model": "gemma4",
        "tag": "e2b",
        "config_digest": "sha256:c6bc…",
        "layer_digests": ["sha256:4e30…", "sha256:c6bc…", "sha256:7339…", "sha256:5638…"]
      },
      "license": {
        "digest": "sha256:7339…",
        "size": 11355,
        "spdx_id": "Apache-2.0",
        "text_excerpt": "Apache License\n  Version 2.0, January 2004..."
      }
    }
  ],
  "findings": [],
  "verdict": "PASS"
}
```

### Enum values

| Field | Values |
|---|---|
| `verdict` | `PASS` / `WARN` / `FAIL` |
| `findings[].severity` | `WARN` / `FAIL` |
| `findings[].category` | `runtime` / `model` / `binary` |
| `runtime.api_exposure` | `not_probed` / `localhost` / `network` / `public_bind` / `unavailable` |
| `runtime.status` | `not_probed` / `reachable` / `unreachable` |
| `runtime.exposure.class` | `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` / `unknown` |

### Provenance (required)

Each model entry carries provenance parsed from the Ollama manifest path:

- `registry`, `namespace`, `model`, `tag` — `Option<String>` to leave room for runtimes that cannot populate all four. Ollama populates all four when the manifest path has the expected `<registry>/<namespace>/<model>/<tag>` shape. When the path is too shallow, the model is skipped from `models[]` and an `ollama.provenance_unknown` `WARN` finding is emitted (never `FAIL`).
- `config_digest` — optional, set when the manifest has a `config` descriptor.
- `layer_digests` — always present (may be empty), full digest lineage of declared layers.

### License (optional)

License metadata is recommended but not required:

- `digest`, `size` — pointing at the `application/vnd.ollama.image.license` layer.
- `spdx_id` — optional. Detected from the first line (fast path) or from body-text signature matching against ten well-known licenses. See [Ollama Inspection](ollama-inspection.md#license--spdx-detection) for the full detection table. When the body cannot be unambiguously identified, `spdx_id` is omitted rather than guessed.
- `text_excerpt` — up to 256 bytes of trimmed body text, so a human reviewer can confirm the detection.

When the manifest has no license layer, `license` is omitted and an `ollama.license_missing` `WARN` finding is emitted (never `FAIL`).

## Markdown View

The Markdown view is rendered from the same `AiBom` model. See the [Ollama Inspection example](ollama-inspection.md#example-ai-bom-markdown) for a real sample. Structure:

- Banner: `# SIGIL AI-BOM: [PASS|WARN|FAIL]`
- Schema + tool header
- `## Runtime` — property table
- `### Observed binds` — only when listeners were inspected
- `## Models` — one model card per entry with License / Provenance / Manifest + a Layers table
- `## Findings` — empty placeholder or severity / category / id / message / evidence table

## Planned Comparison Work

Future comparison should answer:

- Which models were added or removed?
- Did any model blob digest change?
- Did runtime exposure become less restrictive?
- Did a runtime binary change?
- Did a model lose license or provenance metadata?
- Did a custom model's Modelfile or adapter chain change?
- Do current findings violate local policy?

A possible future command shape:

```bash
sigil compare \
  --baseline baseline/aibom.json \
  --current out/current-aibom.json \
  --policy examples/policies/local-llm.yml
```

## Runtime Comparison

The same model can be served by different runtimes with different risk profiles. SIGIL's direction is to compare local runtimes across:

- Runtime API exposure
- OpenAI-compatible endpoint availability
- Model inventory
- Blob integrity
- License and provenance metadata
- Native binary capabilities
- Policy verdicts

Candidate future runtimes:

- Ollama (implemented)
- llama.cpp server
- LM Studio
- vLLM
- text-generation-inference
- Other local OpenAI-compatible endpoints

A future runtime implements its own mapping into the `AiBom` model and reuses the same struct and enum definitions, so downstream consumers and baselines keep working without schema changes.

The AI-BOM JSON contract is formally specified in [`schemas/aibom-v1.schema.json`](../schemas/aibom-v1.schema.json) (JSON Schema draft 2020-12). Downstream consumers can validate AI-BOM JSON against this schema directly. AI-BOM comparison / baseline drift detection is tracked in issue #16.
