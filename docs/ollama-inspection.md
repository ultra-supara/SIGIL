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

## Runtime Exposure

Beyond the configured `--host` endpoint check, SIGIL inspects how Ollama is
actually bound on the local machine. On Linux it parses `/proc/net/tcp` and
`/proc/net/tcp6` for listening sockets and, best-effort, attributes a process
name via `/proc/<pid>/fd` and `/proc/<pid>/comm`. No external command is
spawned.

The Ollama port is resolved from `--host`, then `OLLAMA_HOST`, then the default
`11434`. The bind on that port is classified as one of:

- `localhost` — loopback only (`127.0.0.0/8`, `::1`). No finding; PASS preserved.
- `lan` — a private/link-local address (`10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, `fc00::/7`, `fe80::/10`). WARN.
- `public_bind` — a wildcard (`0.0.0.0`, `::`) or globally routable address. WARN.
- `docker_published` — the listening process is `docker-proxy`. WARN.
- `proxy` — the listening process is a known reverse proxy
  (`nginx`, `caddy`, `traefik`, `haproxy`, `envoy`). WARN.
- `unknown` — listener inspection unavailable or no listener on the port. No
  finding.

Disable runtime inspection with `--no-inspect-runtime`. On non-Linux platforms
runtime inspection degrades gracefully to `unknown`.

Runtime findings:

- `ollama.runtime_lan_exposure`
- `ollama.runtime_public_bind`
- `ollama.runtime_docker_published`
- `ollama.runtime_proxy`

## Security Notes

SIGIL treats the local model store as an artifact to inspect, not as trusted input.

Manifest digests are validated before file paths are constructed. This avoids turning malformed digests such as `sha256:foo/../../secret` into filesystem paths outside the Ollama blob store.

Blob hashing is streaming-based, so large model blobs do not need to be loaded into memory at once.
