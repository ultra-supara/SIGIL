# SIGIL

SIGIL is a **defensive, local-first security assessment tool** for local LLM deployments and AI-native binaries. Its deterministic analyzers inspect deployment artifacts, native code, and runtime exposure without delegating security verdicts to an LLM.

This PR keeps the current x86 → IR → SafeISA work as SIGIL's **binary-analysis foundation**. Future local-LLM deployment assessment modules are documented in [ROADMAP.md](ROADMAP.md), but are intentionally not implemented in this PR.

## Current scope

Implemented so far:
- Project skeleton and package layout
- Deterministic policy parser and evaluator
- Capability mapping from external symbols
- SafeISA model and emulator with blocked `CALL_STUB` / `SYSCALL_STUB`
- ELF function loading and Capstone-based decoding (narrow scope)
- x86 lifting for a minimal integer subset into SIGIL IR
- SafeISA emission from lifted IR
- CLI `lift`/`assess` integration through the deterministic analysis path

Current limitations:
- x86 support is intentionally narrow and is not a full decompiler
- Local LLM deployment modules are planned but not implemented in this PR
- `trace`, `policy-from-source`, and `explain` are still placeholders
- Some integration paths require local tooling (`clang`, `capstone`, `pyelftools`)

## Quickstart (macOS M3)

### 1) One-command bootstrap

```bash
./scripts/setup_macos_m3.sh
```

This installs:
- `uv` (env/dependency manager)
- Homebrew LLVM/Clang toolchain

Then creates `.venv` and installs dependencies with `uv sync --dev`.

### 2) Verify

```bash
source .venv/bin/activate
uv run pytest -q
uv run python -m sigil.cli --help
```

## Manual setup (if you prefer)

```bash
brew install uv llvm
export PATH="$(brew --prefix llvm)/bin:$PATH"
uv venv
source .venv/bin/activate
uv sync --dev
```

## Demos

```bash
./demos/demo_clean_pass.sh
./demos/demo_suspicious_fail.sh
```

Expected behavior:
- `clean_kernel.o` returns `SIGIL Verdict: PASS` under the numeric policy.
- `suspicious_kernel.o` returns `SIGIL Verdict: FAIL` or `WARN` when an unexpected external capability is detected.

## Safety model

- SIGIL is analysis-only and defensive.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External calls become `CALL_STUB` events and syscalls become `SYSCALL_STUB` events.
- Network, file, process, dynamic-loading, and environment capabilities are logged as evidence when detected; they are not performed by SIGIL.
- LLM use remains optional and must never determine security verdicts. Deterministic analyzers and policy evaluation own PASS/WARN/FAIL decisions.
