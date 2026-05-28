# SIGIL

SIGIL is a **defensive, local-first security assessment tool** for local LLM deployments and AI-native binaries. Its deterministic analyzers inspect deployment artifacts, native code, and runtime exposure without delegating security verdicts to an LLM.

The current Rust implementation keeps the x86 → IR → SafeISA work as SIGIL's **binary-analysis foundation** and adds a first local-LLM deployment assessment path for Ollama model stores.

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
  --out out/gemma4-aibom.md
```

Use `--models-dir` to inspect a non-default Ollama model store. Use `--host` to evaluate a specific Ollama API endpoint; `0.0.0.0` / public bind-style hosts are reported as WARN.

## Safety model

- SIGIL is analysis-only and defensive.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External calls become `CALL_STUB` events and syscalls become `SYSCALL_STUB` events.
- Network, file, process, dynamic-loading, and environment capabilities are logged as evidence when detected; they are not performed by SIGIL.
- LLM use remains optional and must never determine security verdicts. Deterministic analyzers and policy evaluation own PASS/WARN/FAIL decisions.
