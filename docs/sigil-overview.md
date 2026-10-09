# SIGIL Overview

**Semantic Inspection for Guarded Intelligence Layers**

SIGIL is a defensive, local-first security inspection tool for local AI runtimes. Its premise is that local LLM safety is not only about the model: a local deployment also includes the runtime, its API, the model store, configuration, and policy.

SIGIL keeps verdicts deterministic. It records what it observed as evidence, and every verdict comes from deterministic analyzers plus a policy rule. No LLM decides whether something is safe.

## What SIGIL does today

- Anchored, bounded, read-only file access (`SafeFs`) and the Ollama model-store collector: manifests, blob SHA-256 verification, provenance, and license layers with SPDX detection.
- Observe mode: the runtime's listening sockets, attributed through `/proc` fd tables, with network-namespace checks. `hidepid` and permission gaps are reported as incompleteness.
- The active API probe (`--active api-probe`): one `GET /api/version` to a literal address, off by default.
- Policy (`sigil-policy/1`, TOML): audit scopes, required checks, rule actions with reasons and expiry, and open-question treatment.
- The session (`sigil-session/1`): the one record of a run, with its JSON Schema, validation, and canonical form.
- AI-BOM v2 (`sigil-aibom/2`): a compact projection of the session that names it by SHA-256.
- The browser viewer (`sigil-wasm`), which renders sessions and AI-BOM v2 with the CLI's own renderers.
- The CLI: `inspect ollama`, `session render`, `explain`, and `rules`.
- Syscall safety tests of contracts C-1 to C-6 over every CLI path.

How to run it: the [Ollama guide](ollama-inspection.md).

## What SIGIL does not do yet

- Analysis of the runtime's own executables and libraries: identification first, then call-site evidence (see the Roadmap).
- Runtimes other than Ollama.
- Comparing a session against a baseline.

## Inspection model

A run produces one session, which holds:
- **facts**, each pointing to the evidence it came from (what was read from a file, a `/proc` entry, or a probe response);
- **findings**, each naming the facts it rests on and the rule that produced it;
- **coverage**: for each check, its state (for example `Complete`, `Partial`, `Unavailable`, or `Skipped`) and why;
- the **outcome**: a verdict (`PASS` / `WARN` / `FAIL`) and a completeness (`COMPLETE` / `INCOMPLETE`), side by side.

Verdict and completeness are independent: a run can be `PASS` and `INCOMPLETE`. What SIGIL could not see is never reported as absent. Details: [session model](session-model.md) and [policy](policy.md).

## Design principles

- **Deterministic verdicts.** Findings come from deterministic analyzers, and decisions from a policy (TOML). LLMs may help explain, but they never decide a verdict.
- **Evidence first.** Every finding names the facts it rests on, and every fact names its evidence. `sigil explain` shows the chain.
- **Local by default.** Static and observe modes read files and allowlisted `/proc` entries only, and perform no network I/O. Active features are explicit and off by default ([ADR-002](adr/ADR-002-execution-modes.md)).
- **Narrow before broad.** Each analyzer is precise and tested before it expands to more runtimes or formats.
- **Versioned and comparable.** The session and the AI-BOM have versioned JSON Schemas (`sigil-session/1`, `sigil-aibom/2`). The session's canonical form gives the same bytes for the same input, and the AI-BOM names its session by SHA-256.

## Roadmap

| Milestone | What it brings | Status |
|---|---|---|
| M0 | Safety contracts and their syscall tests, the session model, the engine (model store, observe), CLI v2, the active API probe, AI-BOM v2, the viewer | Done |
| M0 | Identification of the runtime's own files and of its release, and `sigil binary inspect` ([#44](https://github.com/ultra-supara/SIGIL/issues/44)) | Next |
| M1 | Call-site evidence in the runtime's binaries (`binary inspect --code`; for example `connect` → network), semantic profiles, and how the runtime loads its backends | Planned |
| M2 | The GGUF parsing path, and advisories matched to what was identified | Planned |
| M3 | aarch64 and Mach-O binaries | Planned |
| M4 | A decision record for an active lab (dynamic tracing, kept in a separate tool) | Planned |
| M5 | Other runtimes: llama.cpp server ([#18](https://github.com/ultra-supara/SIGIL/issues/18), [#52](https://github.com/ultra-supara/SIGIL/issues/52)), LM Studio, llamafile | Planned |

Comparing sessions against a trusted baseline (digest drift, a missing license, wider exposure, new findings) is planned as well: [AI-BOM and comparison](ai-bom-and-comparison.md).
