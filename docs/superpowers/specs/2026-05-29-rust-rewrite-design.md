# SIGIL Rust Rewrite Design

## Goal

Rewrite SIGIL from the current Python MVP into a Rust-first, distributable analysis CLI for local AI runtime and AI-native binary assessment.

The rewrite should preserve the existing product direction:

- deterministic security verdicts
- local-first operation
- no LLM-controlled PASS/WARN/FAIL decisions
- x86 -> SIGIL IR -> SafeISA as the binary-analysis foundation
- evidence-first reporting for policies and capability findings

The first Rust work should prepare the architecture without expanding scope into new runtime scanners yet.

## Non-Goals

- Do not build Gemma/Ollama/llama.cpp runtime scanners in the first Rust PR.
- Do not depend on cloud APIs for verdicts, enrichment, or artifact upload.
- Do not attempt a complete x86 decompiler.
- Do not keep Python as a long-term orchestration layer once Rust CLI parity exists.

## Repository Shape

Use a Cargo workspace:

```text
SIGIL/
  Cargo.toml
  crates/
    sigil-core/
      Cargo.toml
      src/
        lib.rs
        assess/
        evidence/
        ir/
        safeisa/
        x86/
    sigil-cli/
      Cargo.toml
      src/main.rs
  examples/
  tests/
  docs/
```

`sigil-core` owns the library surface. `sigil-cli` is a thin command-line wrapper around `sigil-core`.

The existing Python package can stay during migration as a parity reference. It should be removed after Rust `lift` and `assess` produce equivalent behavior for the current fixtures and tests.

## Core Crates

Use these dependencies initially:

- `clap` for CLI parsing
- `serde`, `serde_json`, and `serde_yaml` for policy and evidence data
- `thiserror` for library errors
- `anyhow` for CLI error handling
- `object` for ELF/object parsing
- `iced-x86` for x86-64 decoding

`iced-x86` is preferred over Capstone for the Rust rewrite because it is Rust-native, strongly typed, and better aligned with future lifter precision. If early decoder friction blocks progress, reassess with a small spike rather than switching immediately.

## Module Boundaries

### `assess`

Owns deterministic policy evaluation and capability mapping.

Responsibilities:

- parse policy YAML into typed structs
- map symbols such as `connect`, `openat`, `dlopen`, and `getenv` to capabilities
- evaluate allowlist and forbidden capability rules
- return typed `Verdict` and `PolicyViolation` values

### `evidence`

Owns serializable evidence data.

Responsibilities:

- represent binary path, entry symbol, verdict, capabilities, external calls, unsupported instructions, and policy violations
- serialize deterministic JSON
- support markdown report rendering either directly or through a small report submodule

### `ir`

Owns SIGIL IR data structures.

Responsibilities:

- represent `Function`, `BasicBlock`, and `IROp`
- keep source instruction address and text on lifted operations
- avoid architecture-specific details where possible

### `safeisa`

Owns SafeISA model, emission, and emulation.

Responsibilities:

- represent SafeISA instructions and programs
- emit SafeISA from SIGIL IR
- emulate safe integer operations
- block external effects as `CALL_STUB` and `SYSCALL_STUB` trace events
- reset emulator registers and trace state on each run

### `x86`

Owns x86-64 binary analysis.

Responsibilities:

- load ELF/object functions by symbol
- decode x86-64 bytes
- lift a narrow integer and external-call subset into SIGIL IR
- resolve call symbols from relocations and target symbols where available
- mark unsupported instructions explicitly

## CLI Behavior

The Rust CLI should preserve the current user-facing commands:

```bash
sigil lift <binary> --entry kernel --emit-ir out.ir --emit-safeisa out.safeisa
sigil assess <binary> --entry kernel --policy examples/policies/numeric_kernel.yml
```

Keep `trace`, `policy-from-source`, and `explain` as placeholders until their behavior is designed.

During migration, preserve `assess --external-call <symbol>` as a deterministic test and demo path for capability evaluation without requiring a binary fixture.

## Migration Plan

### PR 1: Rust workspace and deterministic assessment core

Add the Cargo workspace, `sigil-core`, and `sigil-cli` skeleton.

Implement:

- verdict model
- capability mapping
- policy loading and evaluation
- evidence model and JSON serialization
- minimal CLI command for `assess --external-call`

Keep Python unchanged.

Acceptance:

- `cargo test` passes
- Rust policy tests mirror current Python policy tests
- Rust `assess --external-call connect` returns `FAIL` for the numeric policy

### PR 2: SafeISA and IR

Implement:

- SIGIL IR model
- SafeISA model
- SafeISA emitter
- SafeISA emulator

Acceptance:

- Rust tests mirror current Python IR and SafeISA emulator tests
- emulator state resets between runs
- `CALL_STUB` records blocked capability evidence

### PR 3: x86 object pipeline and CLI parity

Implement:

- ELF/object function loading
- x86-64 decoding with `iced-x86`
- narrow lifter
- `lift` command
- full binary-backed `assess` command

Acceptance:

- Rust CLI passes the current clean and suspicious kernel smoke tests
- generated IR and SafeISA are deterministic
- unsupported instructions are visible in evidence

### PR 4: Retire Python implementation

Remove the Python package and Python-only packaging once Rust CLI parity is proven.

Acceptance:

- `cargo test` passes
- README quickstart uses Rust toolchain
- demos invoke the Rust `sigil` binary
- no Python runtime is needed for core SIGIL use

## Testing Strategy

Use unit tests for module-level behavior and CLI integration tests for end-to-end behavior.

Required test groups:

- policy evaluation
- allowlist and forbidden capability violations
- capability mapping
- evidence serialization
- SafeISA arithmetic and blocked calls
- emulator reset behavior
- x86 decode/lift for fixture object files
- CLI smoke tests for `--help`, `lift`, and `assess`

Tests that require local tooling such as `clang` should be skipped or isolated when unavailable.

## Implementation Defaults

Use these defaults unless implementation proves they are wrong:

1. Report rendering belongs in a separate `report` module in `sigil-core`.
2. Start with `object` for ELF/object parsing. If relocation or symbol resolution is insufficient during PR 3, add a focused parser helper then.
3. Preserve semantic parity rather than exact Python text formatting. Evidence field names, verdicts, capabilities, and exit behavior must remain stable; whitespace in rendered IR, SafeISA, and markdown may change if tests are updated intentionally.

## Review Gates

Before deleting Python:

- Rust CLI supports current `lift` and `assess` behavior.
- Rust tests cover every current Python test category.
- Evidence JSON has stable field names suitable for future AI-BOM output.
- README and demos have been updated to Rust commands.
