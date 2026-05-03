# SIGIL

SIGIL is a **defensive, local-first binary assessment tool** for AI-native binaries. It performs deterministic analysis and never lets an LLM decide security verdicts.

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

## Milestone status

Implemented so far:
- Project skeleton and package layout
- Deterministic policy parser and evaluator
- Capability mapping from external symbols
- SafeISA model and emulator with blocked `CALL_STUB` / `SYSCALL_STUB`
- ELF function loading and Capstone-based decoding (narrow scope)
- x86 lifting for a minimal integer subset into SIGIL IR
- SafeISA emission from lifted IR
- Evidence model and markdown report writer
- CLI `lift`/`assess` integration through the deterministic analysis path

Current limitations:
- x86 support is intentionally narrow (not a full decompiler)
- `trace`, `policy-from-source`, and `explain` are still placeholders
- Some integration paths require local tooling (`clang`, `capstone`, `pyelftools`)

## Safety

- SIGIL is analysis-only.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External and syscall behavior is recorded as blocked trace events.
