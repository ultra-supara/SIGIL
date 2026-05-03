# SIGIL

SIGIL is a **defensive, local-first binary assessment tool** for AI-native binaries. It performs deterministic analysis and never lets an LLM decide security verdicts.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
python -m sigil.cli --help
```

## Milestone 1 status

Implemented:
- Project skeleton and package layout
- Deterministic policy parser and evaluator
- Capability mapping from external symbols
- SafeISA model and emulator with blocked `CALL_STUB` / `SYSCALL_STUB`
- Evidence model and markdown report writer
- CLI with `assess` plus placeholder commands for future milestones

Current limitations:
- No ELF/Capstone decoding yet
- No x86 lifting yet
- `lift`, `trace`, `policy-from-source`, and `explain` are placeholders

## Safety

- SIGIL is analysis-only.
- SafeISA emulator does **not** execute host syscalls or external effects.
- External and syscall behavior is recorded as blocked trace events.
