# AI-BOM and Comparison Direction

SIGIL's AI-BOM output is an evidence record for local AI deployments. It is inspired by SBOM workflows, but it focuses on AI runtime and model-store concerns rather than package dependencies alone.

## Current AI-BOM Output

SIGIL currently emits:

- JSON evidence from `runtime inspect ollama`
- Markdown AI-BOM from `aibom generate --runtime ollama`

The current AI-BOM contains:

- Runtime identity
- Host and API exposure
- Runtime reachability
- Runtime version when available
- Verdict
- Model names
- Manifest paths
- Blob paths
- Blob sizes
- Manifest digests
- Calculated SHA-256 values
- Findings

## Why AI-BOM Matters

Local LLM deployments can change without a package manager or central inventory:

- A model tag can point to different local blobs over time.
- A custom model can derive from a base model with a new Modelfile.
- A runtime can move from localhost-only to LAN-accessible.
- A local model store can contain unknown or corrupted artifacts.
- Runtime binaries can change independently of model files.

An AI-BOM gives SIGIL a stable record to compare against later.

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

The same model can be served by different runtimes with different risk profiles. SIGIL's direction is to compare local runtimes across axes such as:

- Runtime API exposure
- OpenAI-compatible endpoint availability
- Model inventory
- Blob integrity
- License and provenance metadata
- Native binary capabilities
- Policy verdicts

Candidate future runtimes:

- Ollama
- llama.cpp server
- LM Studio
- vLLM
- text-generation-inference
- Other local OpenAI-compatible endpoints

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

