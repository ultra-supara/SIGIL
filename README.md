# SIGIL

**Semantic Inspection for Guarded Intelligence Layers**

A local-first AI-BOM that compliance and security can actually attach to a review ticket — no cloud, no LLM in the verdict path, no subprocess spawned.

SIGIL is a defensive, read-only inspection tool for AI runtimes, model stores, and native execution surfaces. It inventories local LLM deployments, classifies how the runtime is exposed, identifies license metadata, lifts native binaries through a guarded SafeISA, and emits a stable, versioned AI-BOM (JSON + Markdown) — all from a single static Rust binary.

## Who it's for

| You are… | What SIGIL gives you |
|---|---|
| An AI compliance / GRC reviewer | One AI-BOM JSON per review cycle that captures provenance, SPDX id, runtime exposure, layer digests, and findings — stable across runs because the schema is versioned. |
| A security or AI platform engineer running the audit | A read-only CLI that never shells out to `ss` / `lsof` / `docker`, streams SHA-256 over multi-GB blobs, and produces the artifact the reviewer needs in one command. |
| A CISO / Head of AI Risk | A defensible local-AI audit story you can show an external auditor: every verdict is derived from a deterministic analyzer plus a YAML policy, in the open, unit-tested. |
| A legal / IP reviewer | License layer + SPDX id + provenance tuple recorded per model — covers Apache-2.0, MIT, MPL-2.0, GPL-2.0/3.0, LGPL-2.1/3.0, BSD-2/3-Clause, and ISC. |

If your entire AI footprint is cloud-hosted (OpenAI API, Bedrock, Vertex AI) and there is no local model store, local runtime, or local native binary to inspect, SIGIL has nothing to do today.

## Why it's local-first and LLM-free

- **No data leaves the machine.** Model bytes, manifests, license text, and runtime metadata are read in place. There is no network egress.
- **No subprocess spawn.** Runtime bind detection parses `/proc/net/tcp{,6}` and `/proc/<pid>/comm` directly. `ss`, `lsof`, `netstat`, and `docker` are never invoked.
- **No LLM in the verdict path.** Every `PASS` / `WARN` / `FAIL` is derived from a deterministic analyzer (`crates/sigil-core/src/assess`) plus a YAML policy rule. An LLM-derived verdict isn't acceptable evidence to an auditor; SIGIL doesn't produce one.
- **Read-only.** SIGIL does not execute lifted code, call inspected external symbols, or mutate any artifact it inspects.

See [docs/architecture-and-safety.md](docs/architecture-and-safety.md) for the safety boundary in full.

## What SIGIL produces today

A single AI-BOM artifact per inspection, in two synchronized renderings:

- **JSON** — `schema_version: "1.1"`, runtime-agnostic, enum-stabilized, pinned by tests. JSON and Markdown share the same model so they never diverge.
- **Markdown** — verdict banner, runtime property table, model card (License / Provenance / Manifest / Layers table), findings table. Suitable for review-ticket attachments.

The artifact covers:

| Surface | Evidence |
|---|---|
| Ollama model store | manifest path, blob digests, SHA-256, sizes, kind (`model` / `config` / `license` / `params`) |
| Provenance | `registry / namespace / model / tag` parsed from the manifest path, plus `config_digest` and `layer_digests` |
| License | digest, size, SPDX id (10 license families detected from shortname or body), 256 B text excerpt |
| Runtime API exposure | `not_probed` / `localhost` / `network` / `public_bind` / `unavailable` |
| Runtime listener bind | `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` / `unknown` (from `/proc`) |
| Native binary capabilities | x86_64 → IR → SafeISA, external symbols mapped to `network` / `file_read` / `file_write` / `process_spawn` / `dynamic_loading` / `environment_access` / `anti_debug` |
| Verdict | `PASS` / `WARN` / `FAIL` from analyzer output + policy |

## Quickstart

### macOS (one-command bootstrap)

```bash
./scripts/setup_macos_m3.sh
```

Installs Rust via `rustup` (if missing) and the Homebrew LLVM/Clang toolchain, then runs `cargo test`.

### Manual

```bash
# Linux
sudo apt-get install -y clang
cargo test
cargo run -p sigil-cli -- --help

# macOS
brew install llvm
export PATH="$(brew --prefix llvm)/bin:$PATH"
cargo test
cargo run -p sigil-cli -- --help
```

## Demos

Two end-to-end demos that produce real evidence + Markdown reports under `out/`:

```bash
./demos/demo_clean_pass.sh        # arithmetic-only kernel → SIGIL Verdict: [PASS]
./demos/demo_suspicious_fail.sh   # kernel that calls connect → SIGIL Verdict: [FAIL]
```

The suspicious demo's Markdown report includes a capabilities table with the `network` row pointing at address `0x26` and the SafeISA excerpt showing `CALL_STUB connect` — the external call was recorded as evidence, not executed.

## Ollama / Gemma 4 inspection

```bash
ollama pull gemma4:e2b

# Full inspection: API probe + /proc listener walk
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

# AI-BOM Markdown for the review ticket
cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --format md \
  --out out/gemma4-aibom.md

# Static-only (skip API probe + /proc walk)
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --no-probe-api --no-inspect-runtime \
  --out out/gemma4-static.evidence.json
```

Other flags:

- `--models-dir <path>` — inspect a non-default model store (defaults to `$OLLAMA_MODELS` or `~/.ollama/models`).
- `--host <url>` — evaluate a specific Ollama API endpoint. `0.0.0.0` and public-bind hosts are reported as `WARN`.
- Host resolution order: explicit `--host` → `OLLAMA_HOST` env → default `http://127.0.0.1:11434`.

Full evidence-field reference, SPDX detection table, finding ids, and bind classification are in [docs/ollama-inspection.md](docs/ollama-inspection.md). The AI-BOM JSON contract is documented in [docs/ai-bom-and-comparison.md](docs/ai-bom-and-comparison.md).

## Direction

SIGIL is designed to grow from single-runtime inspection into local AI environment **comparison**:

- Diff a current AI-BOM against a trusted baseline (planned).
- Detect model digest drift, missing license, downgraded runtime exposure, new findings.
- Add llama.cpp, LM Studio, vLLM, and other local OpenAI-compatible runtimes (planned).
- AI-BOM JSON Schema published at [`schemas/aibom-v1.schema.json`](schemas/aibom-v1.schema.json) (JSON Schema draft 2020-12).

See [ROADMAP.md](ROADMAP.md) and [docs/ai-bom-and-comparison.md](docs/ai-bom-and-comparison.md).

## Current scope

Implemented:
- Deterministic policy parser + evaluator (`crates/sigil-core/src/assess`).
- Capability mapping from external symbols.
- SafeISA model + emulator with blocked `CALL_STUB` / `SYSCALL_STUB`.
- ELF function loading + `iced-x86` decoding (narrow x86_64 integer subset).
- IR → SafeISA emission.
- CLI: `lift` and `assess` through the deterministic analysis path; structured Markdown report with verdict banner, capability table, policy violations with call-site lookup, and SafeISA excerpt.
- Ollama model-store inventory, manifest + blob SHA-256 verification, provenance extraction.
- SPDX license detection across ten families (Apache-2.0, MIT, MPL-2.0, GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, BSD-2-Clause, BSD-3-Clause, ISC).
- Runtime API exposure classification, Linux `/proc`-based listener walk with `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` classes.
- Stable AI-BOM JSON contract at `schema_version: "1.1"`, runtime-agnostic, shared by `runtime inspect ollama --out` and `aibom generate`.

Not yet:
- Decompiler-level coverage of x86_64 (narrow by design).
- Runtimes beyond Ollama.
- AI-BOM baseline comparison and drift detection.
- `trace`, `policy-from-source`, and `explain` are placeholder CLI commands.

## Documentation

- [Overview](docs/sigil-overview.md) — product position, current scope, design principles.
- [Ollama Inspection](docs/ollama-inspection.md) — commands, evidence fields, SPDX detection table, findings, runtime bind classes.
- [AI-BOM and Comparison](docs/ai-bom-and-comparison.md) — schema 1.1 contract, enum reference, planned comparison direction.
- [Architecture and Safety](docs/architecture-and-safety.md) — crates, SafeISA, capability mapping, policy YAML, analysis-only safety boundary.
- [Public overview page](site/index.html)
