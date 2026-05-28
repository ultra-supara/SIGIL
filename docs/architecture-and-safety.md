# Architecture and Safety Model

SIGIL is a Rust workspace with a core analysis crate and a CLI crate.

## Crates

- `sigil-core`
  Contains policy evaluation, evidence models, IR, SafeISA, x86 loading/lifting, report rendering, and Ollama inspection.

- `sigil-cli`
  Exposes the command-line interface for `lift`, `assess`, `runtime inspect ollama`, and `aibom generate`.

## Current CLI Surface

```bash
cargo run -p sigil-cli -- lift <binary> \
  --entry kernel \
  --emit-ir out/kernel.ir \
  --emit-safeisa out/kernel.safeisa

cargo run -p sigil-cli -- assess <binary> \
  --entry kernel \
  --policy examples/policies/numeric_kernel.yml \
  --out out/report.md \
  --emit-evidence out/evidence.json

cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --out out/gemma4-aibom.md
```

## Native Analysis Path

SIGIL's native path currently targets x86_64 object analysis.

The flow is:

1. Read object file.
2. Reject non-x86_64 objects before decoding.
3. Locate the requested entry symbol from regular or dynamic symbols.
4. Normalize Mach-O leading underscores for C symbols.
5. Decode bytes with `iced-x86`.
6. Lift supported instructions into SIGIL IR.
7. Convert supported IR into SafeISA.
8. Map external calls to capabilities.
9. Evaluate capabilities against policy.

This is intentionally narrow. It is not a full decompiler.

## SafeISA

SafeISA is a guarded intermediate representation for analysis. It can represent arithmetic and blocked external effects.

Important behavior:

- `CALL_STUB` records external calls without executing them.
- `SYSCALL_STUB` records syscall-like effects without executing them.
- Unsupported instructions become blocked evidence rather than host behavior.

The emulator does not perform host syscalls, network calls, filesystem mutations, process launches, or dynamic loading.

## Capability Mapping

External symbols are mapped to coarse capabilities such as:

- `network`
- `file_read`
- `file_write`
- `process_spawn`
- `dynamic_loading`
- `environment_access`
- `anti_debug`

Examples:

- `connect`, `socket`, `getaddrinfo` -> `network`
- `open`, `openat`, `read` -> `file_read`
- `write`, `rename`, `unlink` -> `file_write`
- `execve`, `fork`, `system` -> `process_spawn`

## Policy Model

Policies define allowed and forbidden capabilities and map violations to verdict behavior.

Example:

```yaml
allowed:
  capabilities:
    - arithmetic
forbidden:
  capabilities:
    - network
    - process_spawn
verdict_rules:
  forbidden_capability: FAIL
  unsupported_instruction: WARN
```

Policy evaluation produces deterministic `PASS`, `WARN`, or `FAIL`.

## Safety Boundaries

SIGIL is analysis-only:

- It does not execute inspected object code.
- It does not call inspected external symbols.
- It does not delegate verdicts to an LLM.
- It treats local model-store metadata as untrusted input.
- It reports evidence rather than hiding uncertainty.

These constraints are central to the project. Future analyzers should preserve them.
