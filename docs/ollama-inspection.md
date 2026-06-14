# Ollama Inspection

Ollama is SIGIL's first local LLM runtime inspection target.

The Ollama inspection path inventories the local model store, validates manifest-referenced blobs, optionally probes the Ollama API endpoint, optionally inspects local listening sockets via `/proc`, and emits both JSON evidence and a structured Markdown AI-BOM report.

## Commands

```bash
ollama pull gemma4:e2b

# Default: probes API and inspects /proc listeners
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

# AI-BOM in Markdown
cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --format md \
  --out out/gemma4-aibom.md

# Static inspection only — no API probe, no /proc walk
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --no-probe-api \
  --no-inspect-runtime \
  --out out/gemma4-static.evidence.json
```

Flags:

- `--models-dir <path>` — inspect a non-default model store (defaults to `$OLLAMA_MODELS` or `~/.ollama/models`).
- `--host <url>` — evaluate a specific Ollama API endpoint. `0.0.0.0` / public-bind hosts are reported as WARN.
- `--no-probe-api` — skip the configured API probe (`status` stays `not_probed`).
- `--no-inspect-runtime` — skip local listener inspection (`exposure.class` stays `unknown`).
- Resolution order for the host: explicit `--host` → `OLLAMA_HOST` env → default `http://127.0.0.1:11434`.

## Example AI-BOM (Markdown)

Generated from a real local `gemma4:e2b` store (no API probe, no runtime walk):

```markdown
# SIGIL AI-BOM: [PASS]

- Schema: `1.1`
- Tool: `sigil 0.1.0`

## Runtime
| Property | Value |
|----------|-------|
| Name | `ollama` |
| Host | `http://127.0.0.1:11434` |
| Models dir | `/home/you/.ollama/models` |
| API exposure | `not_probed` |
| Runtime exposure | `unknown` (source: `disabled`) |
| Status | `not_probed` |

## Models

### `gemma4:e2b`
- **License:** `Apache-2.0` (digest `sha256:7339…`, 11355 B)
- **Provenance:** `registry.ollama.ai / library / gemma4 / e2b`
- **Manifest:** `/home/you/.ollama/models/manifests/registry.ollama.ai/library/gemma4/e2b`

| Kind | Size | Digest |
|------|------|--------|
| model | 7162394016 B | `sha256:4e30…` |
| params | 42 B | `sha256:5638…` |
| license | 11355 B | `sha256:7339…` |
| config | 473 B | `sha256:c6bc…` |

## Findings
_No findings._
```

## Evidence Collected

For each matching Ollama model SIGIL records:

- Runtime name, requested model filter, model-store path, configured host
- API exposure class, runtime probe status, Ollama version (when reachable)
- Manifest path
- For each blob layer: digest, file path, size, calculated SHA-256, kind (`model` / `config` / `license` / `params`)
- Provenance: `registry`, `namespace`, `model`, `tag` parsed from the manifest path, plus `config_digest` and `layer_digests` for full digest lineage
- License: `digest`, `size`, optional `spdx_id`, and `text_excerpt` (up to 256 bytes of trimmed body text)
- Findings and verdict

## License & SPDX Detection

The Ollama image format ships license metadata as a layer with media type `application/vnd.ollama.image.license`. The blob body is usually the full license text rather than a short SPDX shortname.

SIGIL reads up to 4 KB of the license blob for detection (so longer signatures like BSD-3-Clause's "Neither the name…" clause are not truncated) and stores the first 256 bytes as `text_excerpt` in the report.

Detection priority:

1. **Fast path** — the first line is a recognized short SPDX identifier (e.g. `MIT`, `Apache-2.0`, `BSD-3-Clause`). SIGIL validates the token against the supported family set before accepting it.
2. **Body match** — whitespace-condensed, lowercased text is scanned for unambiguous license preambles. Order matters; the more-specific variant is checked first so we never confuse two similar licenses:

   | License | Signature |
   |---|---|
   | `LGPL-3.0` | `gnu lesser general public license` + `version 3` |
   | `LGPL-2.1` | `gnu lesser general public license` + `version 2.1` |
   | `GPL-3.0` | `gnu general public license` + `version 3` |
   | `GPL-2.0` | `gnu general public license` + `version 2` |
   | `MPL-2.0` | `mozilla public license` + `version 2.0` |
   | `Apache-2.0` | `apache license` + `version 2.0` |
   | `BSD-3-Clause` | `redistribution and use in source and binary forms` + `neither the name` |
   | `BSD-2-Clause` | `redistribution and use in source and binary forms` (no 3rd clause) |
   | `ISC` | `isc license` header or `permission to use, copy, modify` + `with or without fee is hereby granted` |
   | `MIT` | `mit license` header or `permission is hereby granted, free of charge` |

If the body matches none of the above, `spdx_id` is omitted rather than guessed. The `text_excerpt` is still recorded so a human reviewer can confirm.

## Findings

Current Ollama findings:

| ID | Category | Severity | When |
|---|---|---|---|
| `ollama.public_bind` | runtime | WARN | Configured host uses a public bind such as `0.0.0.0` |
| `ollama.network_endpoint` | runtime | WARN | Configured host points at a non-local endpoint |
| `ollama.runtime_lan_exposure` | runtime | WARN | Local listener bound to a private/link-local address |
| `ollama.runtime_public_bind` | runtime | WARN | Local listener bound to a wildcard or globally routable address |
| `ollama.runtime_docker_published` | runtime | WARN | Local listener is `docker-proxy` (port published from a container) |
| `ollama.runtime_proxy` | runtime | WARN | Local listener is a known reverse proxy (`nginx`, `caddy`, `traefik`, `haproxy`, `envoy`) |
| `ollama.model_not_found` | model | WARN | `--model` filter did not match the local store |
| `ollama.blob_missing` | model | FAIL | Manifest references a blob absent from the local blob store |
| `ollama.blob_digest_mismatch` | model | FAIL | Local blob's calculated SHA-256 does not match the manifest digest |
| `ollama.invalid_blob_digest` | model | FAIL | Manifest references a digest that is not a valid `sha256:<64 hex>` value (prevents path traversal through malformed digests) |
| `ollama.license_missing` | model | WARN | Manifest has no `application/vnd.ollama.image.license` layer (license metadata is recommended but not required) |
| `ollama.provenance_unknown` | model | WARN | Manifest path under `<models_dir>/manifests/` is shallower than the expected `<registry>/<namespace>/<model>/<tag>` shape (model is skipped from `models[]`) |

## Runtime Exposure

Beyond the configured `--host` endpoint check, SIGIL inspects how Ollama is actually bound on the local machine. On Linux it parses `/proc/net/tcp` and `/proc/net/tcp6` for listening sockets, and best-effort attributes a process name via `/proc/<pid>/fd` and `/proc/<pid>/comm`. **No external command is spawned.** On non-Linux platforms runtime inspection degrades to `unknown` without failing.

The Ollama port is resolved from `--host`, then `OLLAMA_HOST`, then the default `11434`. The bind on that port is classified as one of:

| Class | Meaning | Verdict effect |
|---|---|---|
| `localhost` | Loopback only (`127.0.0.0/8`, `::1`) | None (PASS preserved) |
| `lan` | Private / link-local (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7`, `fe80::/10`) | WARN |
| `public_bind` | Wildcard (`0.0.0.0`, `::`) or globally routable address | WARN |
| `docker_published` | Listening process is `docker-proxy` | WARN |
| `proxy` | Listening process is a known reverse proxy | WARN |
| `unknown` | Inspection unavailable or no listener on the port | None |

Disable runtime inspection with `--no-inspect-runtime`.

## Security Notes

SIGIL treats the local model store as an untrusted artifact to inspect, not as trusted input.

- Manifest digests are validated **before** file paths are constructed. This avoids turning malformed digests such as `sha256:foo/../../secret` into filesystem paths outside the Ollama blob store.
- Blob hashing is streaming-based, so large model blobs do not need to be loaded into memory at once.
- License blob reading is bounded (4 KB for SPDX detection, 256 B character-boundary-trimmed for the report excerpt).
- Runtime inspection reads `/proc` directly — no `ss`, `lsof`, `netstat`, or `docker` invocations.
