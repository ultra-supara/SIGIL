# SIGIL

**Semantic Inspection for Guarded Intelligence Layers.**

The local-AI audit artifact you can attach to a review ticket — no cloud, no LLM in the verdict path, no subprocess spawned.

```bash
git clone https://github.com/ultra-supara/SIGIL && cd SIGIL
./demos/demo_suspicious_fail.sh
# → SIGIL Verdict: [FAIL]    out/suspicious.report.md
```

A single static Rust binary inventories every local LLM, verifies model artefacts against their manifest digests, classifies how the runtime is exposed, identifies license metadata, and lifts native binaries through a guarded SafeISA. Every PASS / WARN / FAIL comes from a deterministic analyzer plus a YAML policy — nothing leaves your machine, no LLM ever decides the verdict.

[Live site](https://ultra-supara.github.io/SIGIL/) · [Try the AI-BOM viewer in your browser](https://ultra-supara.github.io/SIGIL/viewer/) · [Compare to other tools](https://ultra-supara.github.io/SIGIL/compare/) · [State of Local AI Audit — 2026 H1](https://ultra-supara.github.io/SIGIL/reports/2026-h1/)

---

## The audit you can't get today

Local LLMs slip past every SBOM tool you already run. Models arrive via `ollama pull` with no package-manager trace. Runtime APIs bind to ports nobody audits. License obligations are invisible. The native binaries serving the model bring their own attack surface. When the auditor asks _"what AI is running here, where is it exposed, under what license, and with what native capabilities?"_, there is no single artefact to hand them.

SIGIL produces that artefact. One JSON, one Markdown — same model, never out of sync.

## What you get

A single AI-BOM per inspection, in two synchronized renderings the schema guarantees identical:

- **JSON** — `schema_version: "1.1"`, runtime-agnostic, enum-stabilized, pinned by tests. Diff it across review cycles.
- **Markdown** — verdict banner, runtime property table, model card (License / Provenance / Manifest / Layers), findings table. Attach it to the review ticket.

The artefact covers:

| Surface | Evidence captured |
|---|---|
| Ollama model store | Manifest path, blob digests, SHA-256, sizes, kind (`model` / `config` / `license` / `params`) |
| Provenance | `registry / namespace / model / tag` parsed from the manifest path, plus `config_digest` and `layer_digests` |
| License | Digest, size, SPDX id from 10 detected families, 256-byte text excerpt |
| Runtime API exposure | `not_probed` / `localhost` / `network` / `public_bind` / `unavailable` |
| Runtime listener bind | `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` / `unknown`, classified from `/proc` |
| Native binary capabilities | x86_64 → IR → SafeISA, with external symbols mapped to `network` / `file_read` / `file_write` / `process_spawn` / `dynamic_loading` / `environment_access` / `anti_debug` |
| Verdict | `PASS` / `WARN` / `FAIL` from analyzer output + policy |

## Why local-first, LLM-free

- **Nothing leaves the machine.** Model bytes, manifests, license text, and runtime metadata are read in place. Zero network egress.
- **No subprocess spawn.** Runtime bind detection parses `/proc/net/tcp{,6}` and `/proc/<pid>/comm` directly. `ss`, `lsof`, `netstat`, and `docker` are never invoked.
- **No LLM in the verdict path.** Every verdict comes from a deterministic analyzer ([`crates/sigil-core/src/assess`](crates/sigil-core/src/assess)) plus a YAML policy rule. An LLM-derived verdict isn't acceptable evidence to an auditor; SIGIL doesn't produce one.
- **Read-only.** SIGIL does not execute lifted code, call inspected external symbols, or mutate any artefact it inspects.

Full safety boundary in [docs/architecture-and-safety.md](docs/architecture-and-safety.md).

## Quickstart

### macOS

```bash
./scripts/setup_macos_m3.sh
```

Installs Rust via `rustup` (if missing) and the Homebrew LLVM / Clang toolchain, then runs `cargo test`.

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

## Run the demos

Two end-to-end demos that produce real evidence + Markdown reports under `out/`:

```bash
./demos/demo_clean_pass.sh        # arithmetic-only kernel → SIGIL Verdict: [PASS]
./demos/demo_suspicious_fail.sh   # kernel that calls connect → SIGIL Verdict: [FAIL]
```

The suspicious demo's Markdown report includes a capabilities table with the `network` row pointing at address `0x26` and the SafeISA excerpt showing `CALL_STUB connect` — the external call was recorded as evidence, not executed.

## Inspect a real Ollama deployment

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

Other flags worth knowing:

- `--models-dir <path>` — inspect a non-default model store (defaults to `$OLLAMA_MODELS` or `~/.ollama/models`).
- `--host <url>` — evaluate a specific Ollama API endpoint. `0.0.0.0` and public-bind hosts are reported as `WARN`.
- Host resolution order: explicit `--host` → `OLLAMA_HOST` env → default `http://127.0.0.1:11434`.

Full evidence-field reference, SPDX detection table, finding ids, and bind classification: [docs/ollama-inspection.md](docs/ollama-inspection.md). The AI-BOM JSON contract: [docs/ai-bom-and-comparison.md](docs/ai-bom-and-comparison.md).

## Who SIGIL is for

| If you are… | SIGIL gives you |
|---|---|
| An AI compliance / GRC reviewer | One AI-BOM JSON per review cycle that captures provenance, SPDX id, runtime exposure, layer digests, and findings — stable across runs because the schema is versioned. |
| A security or AI platform engineer running the audit | A read-only CLI that never shells out, streams SHA-256 over multi-GB blobs, and produces the artefact the reviewer needs in one command. |
| A CISO / Head of AI Risk | A defensible local-AI audit story you can show an external auditor: every verdict is derived from a deterministic analyzer plus a YAML policy, in the open, unit-tested. |
| A legal / IP reviewer | License layer + SPDX id + provenance tuple per model — covers Apache-2.0, MIT, MPL-2.0, GPL-2.0 / 3.0, LGPL-2.1 / 3.0, BSD-2 / 3-Clause, ISC. |

If your entire AI footprint is hosted (OpenAI API, Bedrock, Vertex AI) and there is no local model store, local runtime, or local native binary to inspect — SIGIL has nothing to do today.

## Try it in the browser

The AI-BOM viewer at [`/viewer/`](https://ultra-supara.github.io/SIGIL/viewer/) renders the same Markdown the CLI would, fully client-side via `wasm32-unknown-unknown`. Drop your own `.aibom.json` or load one of the three sample verdicts — no upload, no sign-up, no network call after the page loads. The same Rust `render_ai_bom` drives both the CLI and the browser, and CI compares the committed wasm bundle against the source on every PR.

## Direction

SIGIL grows from single-runtime inspection into local AI environment **comparison**:

- Diff a current AI-BOM against a trusted baseline (planned).
- Detect model digest drift, missing license, downgraded runtime exposure, new findings.
- Add llama.cpp, LM Studio, vLLM, and other local OpenAI-compatible runtimes (planned).
- Continue publishing the AI-BOM JSON Schema at [`schemas/aibom-v1.schema.json`](schemas/aibom-v1.schema.json) (JSON Schema draft 2020-12).

See [ROADMAP.md](ROADMAP.md) and [docs/ai-bom-and-comparison.md](docs/ai-bom-and-comparison.md).

## What's in the box

**Implemented today**

- Deterministic policy parser + evaluator ([`crates/sigil-core/src/assess`](crates/sigil-core/src/assess)).
- Capability mapping from external symbols.
- SafeISA model + emulator with blocked `CALL_STUB` / `SYSCALL_STUB`.
- ELF function loading + `iced-x86` decoding (narrow x86_64 integer subset).
- IR → SafeISA emission.
- CLI: `lift` and `assess` through the deterministic analysis path; structured Markdown report with verdict banner, capability table, policy violations with call-site lookup, and SafeISA excerpt.
- Ollama model-store inventory, manifest + blob SHA-256 verification, provenance extraction.
- SPDX license detection across 10 families (Apache-2.0, MIT, MPL-2.0, GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, BSD-2-Clause, BSD-3-Clause, ISC). Known fast-path false positive when a license layer begins with a leading non-license token — [#33](https://github.com/ultra-supara/SIGIL/issues/33).
- Runtime API exposure classification, Linux `/proc`-based listener walk with `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` classes.
- Stable AI-BOM JSON contract at `schema_version: "1.1"`, runtime-agnostic, shared by `runtime inspect ollama --out` and `aibom generate`.
- Browser AI-BOM viewer at [`site/viewer/`](site/viewer/) — same renderer compiled to wasm32, schema-validated client-side, CI-pinned against the Rust source on every PR.

**Not yet**

- Decompiler-level coverage of x86_64 (narrow by design).
- Runtimes beyond Ollama.
- AI-BOM baseline comparison and drift detection.
- `trace`, `policy-from-source`, and `explain` are placeholder CLI commands.

## Documentation

- [Overview](docs/sigil-overview.md) — product position, current scope, design principles.
- [Ollama inspection](docs/ollama-inspection.md) — commands, evidence fields, SPDX detection table, findings, runtime bind classes.
- [AI-BOM and comparison](docs/ai-bom-and-comparison.md) — schema 1.1 contract, enum reference, planned comparison direction.
- [Architecture and safety](docs/architecture-and-safety.md) — crates, SafeISA, capability mapping, policy YAML, analysis-only safety boundary.

## License

MIT.
