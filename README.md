# SIGIL

**Local-first audits of local LLMs.**

The local-AI audit artifact you can attach to a review ticket — no cloud, no LLM in the verdict path, no subprocess spawned.

```bash
git clone https://github.com/ultra-supara/SIGIL && cd SIGIL
cargo run -q -p sigil-cli -- inspect ollama --format md --out out/report.md
# verdict: WARN           confirmed: 0 fail · 1 warn · 0 policy violations
# completeness: COMPLETE
```

A single static Rust binary inventories the models in an Ollama store, verifies every blob against its manifest digest, records license layers, and, in observe mode, attributes the runtime's listening sockets. Every result has two parts: a **verdict** (PASS / WARN / FAIL) from a deterministic analyzer and a policy, and a **completeness** that says whether everything required was actually seen. What SIGIL could not see is never reported as absent. Nothing leaves your machine, and no LLM ever decides the verdict.

[Live site](https://ultra-supara.github.io/SIGIL/) · [Try the AI-BOM viewer in your browser](https://ultra-supara.github.io/SIGIL/viewer/) · [Compare to other tools](https://ultra-supara.github.io/SIGIL/compare/) · [State of Local AI Audit — 2026 H1](https://ultra-supara.github.io/SIGIL/reports/2026-h1/)

---

## The audit you can't get today

Local LLMs slip past every SBOM tool you already run. Models arrive via `ollama pull` with no package-manager trace. Runtime APIs bind to ports nobody audits. License obligations are invisible. When the auditor asks _"what AI is running here, where is it exposed, and under what license?"_, there is no single artefact to hand them.

SIGIL produces that artefact: one session per inspection, as JSON and as Markdown, rendered from the same facts.

## What you get

- **The session** (`sigil-session/1`, [schema](schemas/session-v1.schema.json)): every fact observed, every finding with the facts it rests on, what each check covered, and the outcome. Canonical JSON, so two runs over the same input give the same bytes. Diff it across review cycles.
- **Markdown**: the outcome, findings, open coverage, models, listeners, and processes, for the review ticket. Every input-derived string is escaped.
- **`sigil explain`**: why a finding fired (its facts, the policy decision, and the fix), or how the verdict and completeness were reached.

| Surface | Evidence captured |
|---|---|
| Ollama model store | Each manifest, its layers, and each blob's SHA-256 against its digest |
| Provenance | `registry / namespace / model / tag` from the manifest path |
| License | The license layer, its SPDX id where detected, and an excerpt |
| Runtime exposure (`--mode observe`) | `ollama serve`'s listening sockets, attributed through its fd table, never by port; bind class loopback / wildcard / private / global |
| Runtime API (`--active api-probe`) | Whether `GET /api/version` answered at one literal address, and the version it reported |
| Outcome | Verdict (`PASS` / `WARN` / `FAIL`) and completeness (`COMPLETE` / `INCOMPLETE`), side by side |

## Why local-first, LLM-free

- **No network I/O unless you ask for it.** SIGIL reads files and, in observe mode, allowlisted `/proc` entries. The one exception is the API probe, an explicit active feature (`--active api-probe`) that is off by default. It sends one `GET /api/version` to a literal address, loopback unless `--allow-remote` is given, and it resolves no names.
- **No subprocess spawn.** Listener attribution reads `/proc/net/tcp{,6}` and `/proc/<pid>/fd` directly. `ss`, `lsof`, `netstat`, and `docker` are never invoked.
- **No LLM in the verdict path.** Every finding comes from a deterministic analyzer, and every decision from a policy rule ([`crates/sigil-engine/src/policy`](crates/sigil-engine/src/policy)). An LLM-derived verdict isn't acceptable evidence to an auditor; SIGIL doesn't produce one.
- **Read-only.** SIGIL never executes, loads, or maps what it inspects, and writes only the `--out` you name, which must lie outside the inspected store.

These properties are **checked** by build-time API bans and by syscall tests over the exercised CLI paths ([ADR-002](docs/adr/ADR-002-execution-modes.md)). They are not enforced by a runtime sandbox.

## Quickstart

```bash
cargo test
cargo run -p sigil-cli -- --help
```

On macOS, `./scripts/setup_macos_m3.sh` installs Rust via `rustup` (if missing) and the Homebrew LLVM / Clang toolchain, then runs `cargo test`. The syscall safety tests run on Linux with `strace` and a C compiler.

## Inspect an Ollama installation

```bash
# Static (the default): the model store only
cargo run -p sigil-cli -- inspect ollama --out out/session.json

# Markdown for the review ticket
cargo run -p sigil-cli -- inspect ollama --format md --out out/report.md

# Observe: also the runtime's listening sockets (allowlisted /proc reads)
cargo run -p sigil-cli -- inspect ollama --mode observe --out out/session.json

# Active: also ask the runtime's API for its version (one request to 127.0.0.1:11434)
cargo run -p sigil-cli -- inspect ollama --active api-probe --out out/session.json

# Explain a saved session: one finding, the verdict, or the coverage
cargo run -p sigil-cli -- explain out/session.json --verdict
cargo run -p sigil-cli -- explain out/session.json --finding <FINDING-ID> --format md
cargo run -p sigil-cli -- session render out/session.json

# The detection rules
cargo run -p sigil-cli -- rules
```

Other flags worth knowing:

- `--models-dir <dir>`: the model store (default `$OLLAMA_MODELS`, else `~/.ollama/models`). `--model <name>` inventories one model.
- `--policy <file>`: a policy (TOML, [docs/policy.md](docs/policy.md)) that sets the audit scope, rule actions with reasons and expiry, and accepted assumptions.
- `--budget KEY=VALUE`: a read budget, by the name the session records (e.g. `files_discovered=4096`). Budgets that run out leave the result incomplete, never silently clean.
- `--active api-probe [--api-addr IP[:PORT]] [--allow-remote]`: probe the API at a literal address (default `127.0.0.1:11434`; `localhost` means 127.0.0.1). A refused connection closes the check: nothing answers there. A timeout or a reply that is not the Ollama API leaves it open. The probe's budgets are `api_connect_ms` (at most 30000), `api_io_ms` (at most 60000), and `api_response_bytes` (at most 1048576).
- `--fail-on warn|fail` and `--fail-on-incomplete` for CI. Exit codes: `0` normal, `1` execution error, `2` usage error, `3` verdict threshold reached, `4` incomplete.

Details: [model store](docs/model-store.md) · [exposure](docs/exposure.md) · [policy](docs/policy.md) · [session model](docs/session-model.md).

## Who SIGIL is for

| If you are… | SIGIL gives you |
|---|---|
| An AI compliance / GRC reviewer | One session per review cycle that captures provenance, license, runtime exposure, layer digests, and findings, with a completeness you can hold the run to. |
| A security or AI platform engineer running the audit | A read-only CLI that never shells out, streams SHA-256 over multi-GB blobs, and produces the artefact the reviewer needs in one command. |
| A CISO / Head of AI Risk | A defensible local-AI audit story you can show an external auditor: every verdict comes from a deterministic analyzer plus a policy, in the open, unit-tested. |
| A legal / IP reviewer | License layer, SPDX id, and provenance per model. |

If your entire AI footprint is hosted (OpenAI API, Bedrock, Vertex AI) and there is no local model store or local runtime to inspect, SIGIL has nothing to do today.

## Try it in the browser

The AI-BOM viewer at [`/viewer/`](https://ultra-supara.github.io/SIGIL/viewer/) renders AI-BOM v1 files (SIGIL 0.1) fully client-side via `wasm32-unknown-unknown`: no upload, no sign-up, no network call after the page loads. It moves to v2 sessions with AI-BOM v2.

## Direction

SIGIL grows from single-runtime inspection into local AI environment **comparison**:

- Identify the runtime's own binaries and libraries, and how its loader picks backends.
- Diff a session against a trusted baseline: model digest drift, missing license, wider exposure, new findings (planned).
- Add llama.cpp, LM Studio, vLLM, and other local OpenAI-compatible runtimes (planned).

## What's in the box

**Implemented today**

- Anchored, bounded, read-only file access (`SafeFs`) and the Ollama model-store collector: manifests, blob SHA-256 verification, provenance, license layers with SPDX detection.
- Observe mode: `/proc` listener attribution through fd tables, network-namespace checks, and `hidepid` and permission gaps reported as incompleteness.
- Policy (`sigil-policy/1`): audit scopes, required checks, rule actions with reasons and expiry, open-question treatment.
- The session model (`sigil-session/1`) with its JSON Schema, validation, and canonical form.
- CLI: `inspect ollama` (static, observe, and the active API probe), `session render`, `explain`, `rules`.
- Syscall safety tests of contracts C-1 to C-6 over every CLI path, with the active probe held to one connection to its destination.

**Not yet**

- Binary analysis of the runtime's executables and libraries (the v0.1 `lift`/`assess` commands are removed; a new analyzer is planned).
- AI-BOM v2 and the browser viewer on v2 sessions.
- Runtimes beyond Ollama, and baseline comparison.

## Documentation

- [Session model](docs/session-model.md): what a session records, and the invariants it keeps.
- [Model store](docs/model-store.md) and [exposure](docs/exposure.md): what is read, and what each finding and coverage state means.
- [Policy](docs/policy.md): the policy format and how the outcome is computed.
- [ADR-002](docs/adr/ADR-002-execution-modes.md): execution modes and safety contracts.
- v0.1 references, to be updated with AI-BOM v2: [overview](docs/sigil-overview.md), [Ollama inspection](docs/ollama-inspection.md), [AI-BOM and comparison](docs/ai-bom-and-comparison.md), [architecture and safety](docs/architecture-and-safety.md).

## License

MIT.
