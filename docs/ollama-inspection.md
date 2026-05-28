# Ollama Inspection

SIGIL currently supports Ollama as its first local LLM runtime inspection target.

The Ollama inspection path inventories the local model store, validates manifest-referenced blobs, probes a configured Ollama API endpoint, and emits both JSON evidence and an AI-BOM-style Markdown report.

## Commands

```bash
ollama pull gemma4:e2b

cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --out out/gemma4-aibom.md
```

Use `--models-dir` to inspect a non-default model store. Use `--host` to evaluate a specific Ollama API endpoint. Use `--no-probe-api` when the model store should be inspected without touching the API.

## Real Gemma 4 Run

SIGIL was tested against a real local Ollama installation with `gemma4:e2b`
on May 29, 2026.

Observed local result:

- Ollama version: `0.24.0`
- Model: `gemma4:e2b`
- Model-store evidence: 4 files
- Total inspected model-store size: `7,162,405,886` bytes
- API exposure: `localhost`
- Runtime status: `reachable`
- Verdict: `PASS`
- Findings: none

The generated local artifacts were:

- `out/gemma4-ollama.evidence.json`
- `out/gemma4-aibom.md`

These outputs are intentionally ignored by Git because they are local evidence artifacts.

## Evidence Collected

For matching Ollama models, SIGIL records:

- Runtime name
- Requested model filter
- Model-store path
- API host
- API exposure classification
- Runtime probe status
- Ollama version when reachable
- Manifest path
- Blob digest
- Blob file path
- Blob size
- Calculated SHA-256
- Findings
- Verdict

## Findings

Current Ollama findings include:

- `ollama.public_bind`
  The configured host uses a public bind address such as `0.0.0.0`.

- `ollama.network_endpoint`
  The configured host points at a non-local network endpoint.

- `ollama.model_not_found`
  A requested model filter did not match the model store.

- `ollama.blob_missing`
  A manifest references a blob that is absent from the local blob store.

- `ollama.blob_digest_mismatch`
  A local blob's calculated SHA-256 does not match the manifest digest.

- `ollama.invalid_blob_digest`
  A manifest references a digest that is not a valid `sha256:<64 hex>` value. This prevents path traversal through malformed digest values.

## Security Notes

SIGIL treats the local model store as an artifact to inspect, not as trusted input.

Manifest digests are validated before file paths are constructed. This avoids turning malformed digests such as `sha256:foo/../../secret` into filesystem paths outside the Ollama blob store.

Blob hashing is streaming-based, so large model blobs do not need to be loaded into memory at once.
