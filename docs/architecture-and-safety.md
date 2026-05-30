# Architecture and Safety Model

SIGIL is a Rust workspace with a core analysis crate and a CLI crate. Everything is read-only and analysis-only.

## Crates

- **`sigil-core`** — policy evaluation, evidence models, IR, SafeISA, x86 loading / lifting, report rendering, AI-BOM model, runtime inspection helpers, Ollama inspection. Pure-Rust, no subprocess spawning.
- **`sigil-cli`** — command-line interface for `lift`, `assess`, `runtime inspect ollama`, and `aibom generate`. Thin wrapper that translates flags into `sigil-core` calls.

## Current CLI Surface

```bash
# Lift a binary to IR + SafeISA
cargo run -p sigil-cli -- lift <binary> \
  --entry kernel \
  --emit-ir out/kernel.ir \
  --emit-safeisa out/kernel.safeisa

# Assess a binary against a policy
cargo run -p sigil-cli -- assess <binary> \
  --entry kernel \
  --policy examples/policies/numeric_kernel.yml \
  --out out/report.md \
  --emit-evidence out/evidence.json

# Inspect Ollama (full: API probe + /proc walk)
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --out out/gemma4-ollama.evidence.json

# Inspect Ollama (static only)
cargo run -p sigil-cli -- runtime inspect ollama \
  --model gemma4:e2b \
  --no-probe-api \
  --no-inspect-runtime \
  --out out/gemma4-static.evidence.json

# Generate an AI-BOM (Markdown)
cargo run -p sigil-cli -- aibom generate \
  --runtime ollama \
  --model gemma4:e2b \
  --format md \
  --out out/gemma4-aibom.md
```

`trace`, `policy-from-source`, and `explain` are placeholder commands that print "not implemented yet".

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

This is intentionally narrow — not a full decompiler. The point is to give the assess and report path concrete address-level evidence to surface in the Markdown report.

### Example SafeISA excerpt

Run `assess` on `examples/binaries/suspicious_kernel.o` (a kernel that calls `connect`) and the Markdown report's `## SafeISA` section contains:

```
FUNC kernel
  MOV rbp rsp
  SUB rsp rsp 10h
  MOV [rbp-4] edi
  MOV [rbp-8] esi
  MOV [rbp-0Ch] edx
  MOV eax [rbp-4]
  MUL eax eax [rbp-8]
  ADD eax eax [rbp-0Ch]
  MOV [rbp-10h] eax
  XOR edx edx edx
  XOR eax eax eax
  MOV esi eax
  MOV edi edx
  CALL_STUB connect
  MOV eax [rbp-10h]
  ADD rsp rsp 10h
  RET
END
```

The external call to `connect` shows up as `CALL_STUB connect` — the SafeISA model records the call without executing it.

## SafeISA

SafeISA is a guarded intermediate representation for analysis. It can represent arithmetic and blocked external effects.

Important behavior:

- `CALL_STUB` records external calls without executing them.
- `SYSCALL_STUB` records syscall-like effects without executing them.
- Unsupported instructions become blocked evidence rather than host behavior.

The emulator does not perform host syscalls, network calls, filesystem mutations, process launches, or dynamic loading.

## Capability Mapping

External symbols are mapped to coarse capabilities:

| Capability | Example symbols |
|---|---|
| `network` | `connect`, `socket`, `getaddrinfo`, `send`, `recv` |
| `file_read` | `open`, `openat`, `read`, `fopen` |
| `file_write` | `write`, `rename`, `unlink`, `fwrite` |
| `process_spawn` | `execve`, `fork`, `system`, `posix_spawn` |
| `dynamic_loading` | `dlopen`, `dlsym` |
| `environment_access` | `getenv`, `setenv` |
| `anti_debug` | `ptrace` |

These are the coarse categories the policy YAML allows or forbids.

## Policy Model

Policies define allowed and forbidden capabilities and map violations to verdict behavior.

```yaml
name: numeric_kernel_policy
version: 1
entry: kernel
allowed:
  capabilities:
    - arithmetic
    - stack_memory
forbidden:
  capabilities:
    - network
    - file_read
    - file_write
    - process_spawn
    - dynamic_loading
    - environment_access
    - anti_debug
verdict_rules:
  forbidden_capability: FAIL
  unsupported_instruction: WARN
```

Policy evaluation produces deterministic `PASS`, `WARN`, or `FAIL`. The output Markdown report shows the verdict, every observed capability with its address, every policy violation tagged with severity and the call site (when known), and the SafeISA excerpt.

## Runtime Bind Detection (Linux)

The Ollama inspection path inspects local listening sockets without spawning external tools:

- Parses `/proc/net/tcp` and `/proc/net/tcp6` for listener inodes on the resolved Ollama port.
- Walks `/proc/<pid>/fd` to map socket inodes to PIDs.
- Reads `/proc/<pid>/comm` for the process name.
- Classifies the bind as `localhost` / `lan` / `public_bind` / `docker_published` / `proxy` / `unknown`.

No `ss`, `lsof`, `netstat`, `docker`, or other subprocess is launched. On non-Linux platforms the runtime inspection degrades gracefully to `unknown` and emits no findings, so the rest of the report is still produced.

## Safety Boundaries

SIGIL is analysis-only:

- It does not execute inspected object code.
- It does not call inspected external symbols.
- It does not delegate verdicts to an LLM.
- It treats local model-store metadata as untrusted input — manifest digests are validated for `sha256:<64 hex>` shape before they are turned into filesystem paths, so a malformed digest like `sha256:foo/../../secret` cannot escape the blob store.
- It does not spawn external subprocesses for runtime inspection; `/proc` is read directly.
- License blob reads are bounded (4 KB for SPDX detection, 256 B trimmed for the excerpt) so SIGIL cannot be made to slurp a large layer into memory.
- Blob hashing is streaming so multi-GB model files do not need to fit in memory.
- It reports evidence rather than hiding uncertainty.

These constraints are central to the project. Future analyzers should preserve them — flag any deviation up-front.
