# SIGIL

**Semantic Inspection for Guarded Intelligence Layers**

SIGIL is a **defensive, local-first security inspection tool** for AI runtimes, model stores, and native execution surfaces. It inventories local LLM deployments, checks runtime exposure, verifies model artifacts, and uses deterministic analyzers for security verdicts instead of delegating PASS/WARN/FAIL decisions to an LLM.

SIGIL also includes a guarded ISA lifting path for native binary capability analysis. That lower-level path is the foundation for inspecting runtime binaries and connecting model-store evidence with the execution surface that serves the model.

## Website and docs

- Public overview page: [site/index.html](site/index.html)
- Detailed overview: [docs/sigil-overview.md](docs/sigil-overview.md)
- Ollama inspection: [docs/ollama-inspection.md](docs/ollama-inspection.md)
- AI-BOM and comparison direction: [docs/ai-bom-and-comparison.md](docs/ai-bom-and-comparison.md)
- Architecture and safety model: [docs/architecture-and-safety.md](docs/architecture-and-safety.md)

## Direction

SIGIL is designed to grow from single-runtime inspection into local AI environment comparison:

- Generate AI-BOM evidence for local model stores and runtimes
- Compare current state against a trusted baseline
- Detect model digest drift, unknown provenance, license gaps, and exposed APIs
- Compare local LLM runtimes such as Ollama, llama.cpp server, LM Studio, vLLM, and OpenAI-compatible local endpoints
- Connect runtime binary capability evidence with model and deployment findings
- Apply local policy to produce deterministic PASS/WARN/FAIL results

## Current scope

Implemented so far:
- Project skeleton and package layout
- Deterministic policy parser and evaluator
- Capability mapping from external symbols
- SafeISA model and emulator with blocked `CALL_STUB` / `SYSCALL_STUB`
- ELF function loading and `iced-x86` based decoding (narrow scope)
- x86 lifting for a minimal integer subset into SIGIL IR
- SafeISA emission from lifted IR
- Rust CLI `lift`/`assess` integration through the deterministic analysis path
- Ollama model-store inventory, API exposure probing, blob digest verification, and AI-BOM report generation

Current limitations:
- x86 support is intentionally narrow and is not a full decompiler
- Local LLM deployment support currently targets Ollama first
- AI-BOM comparison, baseline drift detection, and multi-runtime comparison are planned follow-up work
- `trace`, `policy-from-source`, and `explain` are still placeholders
- Some integration paths require local tooling (`clang`)

## Quickstart (macOS M3)

### 1) One-command bootstrap

```bash
./scripts/setup_macos_m3.sh
```

This installs:
- Rust toolchain via `rustup` when missing
- Homebrew LLVM/Clang toolchain

Then verifies the Rust workspace with `cargo test`.

### 2) Verify

```bash
cargo test
cargo run -p sigil-cli -- --help
```

## Manual setup (if you prefer)

```bash
brew install llvm
export PATH="$(brew --prefix llvm)/bin:$PATH"
cargo test
cargo run -p sigil-cli -- --help
```

## Demos

```bash
./demos/demo_clean_pass.sh
./demos/demo_suspicious_fail.sh
```

Expected behavior:
- `clean_kernel.o` returns `SIGIL Verdict: PASS` under the numeric policy.
- `suspicious_kernel.o` returns `SIGIL Verdict: FAIL` or `WARN` when an unexpected external capability is detected.

## Gemma 4 / Ollama inspection

SIGIL can inventory an Ollama model store and produce an AI-BOM-style report for local Gemma 4 deployments.

```bash
ollama pull gemma4:e2b

cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --format md \
  --out out/gemma4-aibom.md
```

Use `--models-dir` to inspect a non-default Ollama model store. Use `--host` to evaluate a specific Ollama API endpoint; `0.0.0.0` / public bind-style hosts are reported as WARN.

Both `runtime inspect ollama --out` and `aibom generate --format json` write the stable AI-BOM JSON contract. `aibom generate --format md` renders the same model as Markdown.

### AI-BOM JSON contract

The JSON is versioned by `schema_version` (currently `"1.0"`). It is runtime-agnostic: future runtimes populate the same shape.

Top-level keys (all required): `schema_version`, `tool` (`name`, `version`), `runtime`, `models`, `findings`, `verdict`.

- `runtime`: `name`, `host`, `api_exposure`, `status`, `exposure` (`class`, `source`, `observed[]`), and optional `models_dir` / `version`.
- `models[]`: `name`, `files[]` (`digest`, `path`, `size`, `sha256`, `kind`), and optional `manifest_path`.
- `findings[]`: `id`, `category` (`runtime` | `model` | `binary`; `binary` is reserved for future native-binary findings and not yet produced), `severity` (`WARN` | `FAIL`), `message`, `evidence`.
- `verdict`: `PASS` | `WARN` | `FAIL`.

Enum values are stable: `api_exposure` ∈ {`not_probed`, `localhost`, `network`, `public_bind`, `unavailable`}, `status` ∈ {`not_probed`, `reachable`, `unreachable`}, `exposure.class` ∈ {`localhost`, `lan`, `public_bind`, `docker_published`, `proxy`, `unknown`}. Optional fields are omitted when absent. Markdown output is derived from this JSON model.

## Safety model

- SIGIL is analysis-only and defensive.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External calls become `CALL_STUB` events and syscalls become `SYSCALL_STUB` events.
- Network, file, process, dynamic-loading, and environment capabilities are logged as evidence when detected; they are not performed by SIGIL.
- LLM use remains optional and must never determine security verdicts. Deterministic analyzers and policy evaluation own PASS/WARN/FAIL decisions.
