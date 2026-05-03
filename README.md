# SIGIL

SIGIL is a **defensive, local-first binary assessment tool** for AI-native binaries. It performs deterministic analysis and never lets an LLM decide security verdicts.

## Quickstart (uv)

```bash
uv venv
source .venv/bin/activate
uv sync --dev
uv run pytest
uv run python -m sigil.cli --help
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
- CLI `lift`/`assess` integration through the deterministic analysis path

Current limitations:
- x86 support is intentionally narrow (not a full decompiler)
- `trace`, `policy-from-source`, and `explain` are still placeholders
- Some integration paths require local tooling (`clang`, `capstone`, `pyelftools`)

## Safety

- SIGIL is analysis-only.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External and syscall behavior is recorded as blocked trace events.
