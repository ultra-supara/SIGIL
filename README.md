# SIGIL

**Inspect local AI deployments, from model stores to native code.**

SIGIL is a Rust CLI for auditing Ollama installations and the binaries that make up a local AI stack. It checks model integrity and licenses, identifies runtime components, records network exposure, and finds direct calls to capability imports in supported native code. Every run produces an evidence-backed session with a deterministic policy verdict and an explicit account of what the inspection could cover.

Inspection is local and read-only. SIGIL never executes the files it inspects, spawns a subprocess, or asks an LLM to decide a verdict. Network access requires an explicit API probe.

[Website](https://ultra-supara.github.io/SIGIL/) · [Browser viewer](https://ultra-supara.github.io/SIGIL/viewer/) · [Ollama guide](docs/ollama-inspection.md) · [Binary inspection guide](docs/binary-inspect.md) · [Policy reference](docs/policy.md)

## What you can inspect

| Surface | What SIGIL records |
|---|---|
| **Ollama model store** | Models and their registry provenance, manifest layers, blob SHA-256 verification, license text, and detected SPDX identifiers. |
| **Ollama installation** | Files under `bin/ollama` and `lib/ollama`, their matches against embedded official release manifests, and missing installation members. |
| **Runtime components** | ELF component claims from file names, SONAMEs, embedded versions and commits, and reference hashes. Conflicting evidence stays visible. |
| **Standalone binaries** | Digests and container facts for ELF executables, shared libraries, and object files, plus thin and universal Mach-O files. No model store or running runtime is needed. |
| **Capabilities and code** | POSIX, libstdc++, and libc++ capability imports, Go function-name and export hints in ELF files, and—with `binary inspect --code`—direct call sites and argument values in x86-64 ELF code. |
| **Runtime exposure** | In observe mode, listening sockets attributed to `ollama serve` through `/proc` file descriptors. The optional API probe records the response from one requested endpoint. |

Use SIGIL to collect evidence for a security review, check a local deployment in CI, or inspect a native library before including it in an AI environment. Each finding links back to the facts and evidence that support it.

## Quickstart

The CLI currently targets **Linux** and builds with a stable Rust toolchain. The commands below run from the repository root.

```bash
git clone https://github.com/ultra-supara/SIGIL
cd SIGIL
cargo run --locked -q -p sigil-cli -- --help
```

For an installed `sigil` command, use `cargo install --locked --path crates/sigil-cli`.

### Try the bundled binary example

This example needs no Ollama installation. It inspects a committed test fixture without executing it, then renders the saved session as Markdown:

```bash
cargo run --locked -q -p sigil-cli -- binary inspect --code \
  crates/sigil-engine/tests/fixtures/code/suspicious_kernel-gcc-O2.o \
  --out out/binary.json
cargo run --locked -q -p sigil-cli -- session render out/binary.json --out out/binary.md
```

The report includes this capability evidence:

| Capability | Import | Direct call sites |
|---|---|---|
| `posix.network` | `connect` | `kernel @ 0x4d: connect(rdi=0, rsi=0, rdx=0)` |

This is a call site found in the file's code. A policy decides whether that evidence is allowed: the default policy denies no capabilities, so finding this call alone does not produce a failure.

Replace the fixture path with your own executable, `.so`, or `.o`; multiple paths can be inspected into one session. See the [binary guide](docs/binary-inspect.md) for format support, budgets, and coverage states.

### Audit an Ollama model store

```bash
cargo run --locked -q -p sigil-cli -- inspect ollama --out out/session.json
cargo run --locked -q -p sigil-cli -- session render out/session.json --out out/report.md
```

The store defaults to `$OLLAMA_MODELS`, then `~/.ollama/models`. Use `--models-dir /path/to/models` to select another store, including one owned by a system service. Static inspection needs only the files; Ollama does not need to be running.

The document goes to `--out` (or stdout when omitted), and the outcome summary goes to stderr. SIGIL creates missing output directories. Keep output paths outside the inspected model store, installation, and service unit's directory, and separate from binary inputs.

### Include the installation or runtime

```bash
# Also identify the installation's files and compare them with release references.
cargo run --locked -q -p sigil-cli -- inspect ollama \
  --install-dir /usr/local --out out/install.json

# Or find the installation from its systemd unit's ExecStart=.
cargo run --locked -q -p sigil-cli -- inspect ollama \
  --service-unit /etc/systemd/system/ollama.service --out out/unit.json

# Also attribute the running server's listening sockets through /proc.
cargo run --locked -q -p sigil-cli -- inspect ollama \
  --mode observe --out out/observe.json

# Explicitly request one GET /api/version at the default loopback address.
cargo run --locked -q -p sigil-cli -- inspect ollama \
  --active api-probe --out out/active.json
```

These options can be combined, except `--install-dir` with `--service-unit`. The API probe defaults to `127.0.0.1:11434`; `--api-addr` selects an address, and a non-loopback target requires `--allow-remote`. It resolves no DNS names. The [Ollama guide](docs/ollama-inspection.md) covers all options and the scope of each observation.

## Read the verdict and the coverage together

Every session reports two independent results:

| Result | Meaning |
|---|---|
| **Verdict: `PASS`, `WARN`, or `FAIL`** | What the recorded findings, policy violations, and policy treatment of open questions require. |
| **Completeness: `COMPLETE` or `INCOMPLETE`** | Whether the policy's required checks are closed and no open questions remain counted as gaps. |

**`PASS` + `INCOMPLETE` is not a clean audit.** It can mean a file was unreadable, a format was unsupported, a read budget was exhausted, or a denied capability was imported but its use could not be established. A confirmed failure remains `FAIL` even if other checks are incomplete.

`COMPLETE` is relative to the requested checks and their documented scope. It does not establish that a program is safe under every possible execution.

```bash
cargo run --locked -q -p sigil-cli -- explain out/session.json --verdict
cargo run --locked -q -p sigil-cli -- explain out/session.json --coverage
cargo run --locked -q -p sigil-cli -- rules
```

Use `explain out/session.json --finding ID` for a specific finding or open question. The [session model](docs/session-model.md) defines the evidence and coverage records.

## Understand binary evidence

SIGIL preserves how each conclusion was reached:

| Evidence | What it establishes |
|---|---|
| **Reference match** | File content matches an entry in an embedded release manifest. Installation completeness is assessed separately. This is a content comparison, not signature verification. |
| **Component identity** | Names, embedded build values, and reference hashes support a component claim. Versions retain their sources; conflicting claims are reported explicitly. |
| **Signature hint** | A known export or an exact Go function name was found in the ELF file. For example, `go.process_spawn` records a function-name match, not a call. |
| **Capability import** | The binary requests a known function from its loader or linker, such as `connect` → `posix.network` or a mapped libstdc++ or libc++ file operation → `cxx.file_write`. |
| **Direct call site** | With `--code`, supported code contains a direct call or tail jump to a capability import, with its location, containing function, and recovered argument values. This is static evidence, not an observation of runtime execution. |

Component identification also reads supported `ggml_version()` and `ggml_commit()` return values without running those functions. When reference hashes cannot establish an installation's release, an embedded commit may produce an open set of releases it is **consistent with**; that does not close release coverage.

Current analysis boundaries:

- **Code analysis is x86-64 ELF only**, including relocatable objects. It searches executable code covered by `.eh_frame` function ranges. Function-pointer calls, statically linked capability implementations, and raw system calls are outside this analysis.
- **`--code` is available on `binary inspect`.** Installation inspection collects container facts, identities, and hints; it does not yet analyze call sites. Inspect an installation's individual files with `binary inspect --code` when needed.
- **Mach-O support covers containers and imports**, including per-architecture slices in universal files. Identity scans and code analysis remain unsupported, so these required checks leave the default result incomplete.
- **Capability mappings cover specific names.** POSIX, libstdc++, and libc++ import mappings are listed in the [binary guide](docs/binary-inspect.md#capabilities-and-code---code). Missing hints do not establish that a capability is absent. Go, Ollama, and RPC signature hints cannot be used as capability-denial keys.

## Apply a policy

A `sigil-policy/1` TOML policy selects audit scopes, required checks, finding actions, component denials, capability denials, and how to handle open questions. Rule overrides can record reasons and expiry dates.

For example, save this as `policy.toml` to deny mapped network calls in a binary audit:

```toml
schema = "sigil-policy/1"
name = "no-network-calls"

[open_questions]
default = "count_as_gap"

[[capabilities.deny]]
feature = "posix.network"
action = "fail"
reason = "Reviewed native kernels must not call network APIs"
```

Add `--policy policy.toml` to the `binary inspect --code` command above. The bundled fixture then produces a `FAIL` policy violation citing its `connect` call site. Without `--code`, that same import produces an open question, counted as a gap by this policy: `PASS` + `INCOMPLETE`.

A denial applies only to the mapped imports in binaries the run reads. For example, `inspect ollama` without `--install-dir` reads no binaries and evaluates no capability evidence. See the [policy reference](docs/policy.md) for component denials, scope requirements, and the full capability list.

### Verify a saved decision

```bash
cargo run --locked -q -p sigil-cli -- session verify out/session.json
```

For a custom-policy session, supply the same policy with `--policy policy.toml`. Verification checks the recorded policy identity and recomputes its decisions at the session's recorded policy time. Capability denials also require the matching capability table and consistent import hints.

`session verify` checks the policy's treatment of the recorded analysis. It does not re-inspect files, authenticate the evidence, or establish that the environment is unchanged. A correctly recorded `FAIL` can verify successfully. Verification exits `0` on agreement and `1` on a mismatch or execution error.

## Use SIGIL in CI

Inspection commands return success after producing a report unless you request an outcome threshold. To fail a job on either a `FAIL` verdict or incomplete coverage:

```bash
cargo run --locked -q -p sigil-cli -- inspect ollama \
  --fail-on fail --fail-on-incomplete --format md --out out/ci-report.md
```

The same threshold flags work with `binary inspect`. Use `--fail-on warn` for a stricter verdict threshold.

| Exit code | Meaning |
|---|---|
| `0` | Command completed; no requested inspection threshold was reached. |
| `1` | Execution error, including a session verification mismatch. |
| `2` | Usage error. |
| `3` | Verdict reached `--fail-on`. |
| `4` | Coverage is incomplete and `--fail-on-incomplete` was requested. Code `3` takes precedence. |

## Keep and share the evidence

- **Session JSON** ([`sigil-session/1`](schemas/session-v1.schema.json)) is the full record: request, facts, evidence, component claims, code facts, findings, policy decisions, coverage, and outcome. Its canonical serialization is deterministic for the same session value; separate inspections retain their own timestamps.
- **Markdown** is a readable report rendered from that session, suitable for a review ticket. Input-derived text is escaped.
- **AI-BOM v2** ([`sigil-aibom/2`](schemas/aibom-v2.schema.json)) is a compact projection for reviewers and downstream tools. It identifies its source session by SHA-256.

```bash
cargo run --locked -q -p sigil-cli -- session render out/session.json \
  --format aibom --out out/aibom.json
```

The [browser viewer](https://ultra-supara.github.io/SIGIL/viewer/) opens session JSON and AI-BOM v2 locally, using the Rust renderers compiled to WebAssembly. Files stay in the browser, and sessions are validated before rendering. It also includes samples to explore without building the CLI.

## Inspection safety

- **Read-only access to inspected files.** Reads are anchored and bounded; hashing streams large model blobs. Inspected binaries are never executed, loaded, or memory-mapped.
- **No subprocesses.** Runtime observation reads allowlisted `/proc` entries directly.
- **No network I/O during static or observe inspection.** The optional active probe makes one connection to its requested address. There is no telemetry or report upload.
- **Controlled output.** Only the requested `--out` is written; an existing output is replaced by rename, and output files are created readable by their owner only.
- **Deterministic decisions.** Findings come from analyzers and decisions from policy rules; no LLM participates in the verdict path.

Build-time API restrictions and syscall tests check these contracts over the exercised paths. They are not a runtime sandbox. See [architecture and safety](docs/architecture-and-safety.md) and [ADR-002](docs/adr/ADR-002-execution-modes.md) for the guarantees and their limits.

## Development

The Rust workspace has five crates:

| Crate | Responsibility |
|---|---|
| [`sigil-cli`](crates/sigil-cli) | Commands, output handling, and exit codes. |
| [`sigil-engine`](crates/sigil-engine) | File collection, runtime observation, binary analysis, identification, and policy evaluation. |
| [`sigil-model`](crates/sigil-model) | Session types, validation, canonical serialization, and report renderers. |
| [`sigil-probe`](crates/sigil-probe) | The explicitly requested API probe. |
| [`sigil-wasm`](crates/sigil-wasm) | Browser bindings for the model's renderers. |

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The syscall safety suite needs Linux, `strace`, and a C compiler. Run `SIGIL_SAFETY_REQUIRED=1 cargo test --locked -p sigil-cli --test safety` to require those checks rather than allowing them to skip when prerequisites are missing. CI also checks schemas, saved-session examples, WebAssembly builds, and the committed viewer bundle.

Changes to the model or browser bindings also require rebuilding `site/viewer/pkg/`. Follow the [viewer wasm build guide](ci/viewer-wasm-build.md) for its pinned toolchain, size settings, and verification commands.

## What's next

The next steps build on the existing container, identity, and direct-call analysis: dependency resolution and backend loading, branch conditions and guard checks, cross-module analysis, and code analysis for more architectures and formats. Baseline comparison, GGUF parsing and advisory matching, and runtime-specific collectors beyond Ollama are planned.

The legacy `lift` and `assess` commands and their IR/emulator were removed. See [ADR-006](docs/adr/ADR-006-remove-ir-safeisa.md) for the transition and the [roadmap](docs/sigil-overview.md#roadmap) for milestones.

## Documentation

| Guide | Contents |
|---|---|
| [Ollama inspection](docs/ollama-inspection.md) | Store selection, installation inspection, modes, probe options, and CI. |
| [Binary inspection](docs/binary-inspect.md) | Formats, capabilities, direct calls, signatures, and read budgets. |
| [Policy](docs/policy.md) | Scopes, rule overrides, denials, open questions, and session verification. |
| [Session model](docs/session-model.md) | Evidence, claims, coverage, validation, and canonical form. |
| [Runtime artifacts](docs/runtime-artifacts.md) | Release references, binary facts, and component identification. |
| [Model store](docs/model-store.md) / [Exposure](docs/exposure.md) | Integrity and license checks; listener attribution and visibility limits. |
| [AI-BOM and comparison](docs/ai-bom-and-comparison.md) | AI-BOM v2 and the planned baseline comparison workflow. |
| [Architecture and safety](docs/architecture-and-safety.md) | Crate boundaries, data flow, output handling, and safety contracts. |

## License

MIT.
