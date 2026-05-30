# SIGIL Overview

**Semantic Inspection for Guarded Intelligence Layers**

SIGIL is a defensive, local-first security inspection tool for AI runtimes, model stores, and native execution surfaces. Its core premise is that local LLM safety is not only about the model. A local deployment also includes runtime APIs, model-store artifacts, native binaries, configuration, and policy.

SIGIL keeps verdicts deterministic. It collects evidence from local model stores and binaries, but it does not ask an LLM to decide whether something is safe. PASS / WARN / FAIL is always derived from a deterministic analyzer plus a policy rule.

## What SIGIL Does Today

The current Rust implementation provides:

- Deterministic policy parsing and evaluation
- Capability mapping from external symbols (network, file IO, process, dynamic loading, environment access, anti-debug)
- Structured Markdown and JSON evidence rendering
- A guarded SafeISA model and emulator that blocks external effects (`CALL_STUB`, `SYSCALL_STUB`)
- x86_64 object loading, decoding via `iced-x86`, and a narrow IR lifting path
- Ollama model-store inventory (manifests + blobs + sha256 verification)
- Provenance extraction from the Ollama manifest path (`registry / namespace / model / tag`)
- License layer detection with SPDX identification: fast-path SPDX shortname plus body-text matching for Apache-2.0, MIT, MPL-2.0, GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, BSD-2-Clause, BSD-3-Clause, and ISC
- Runtime API endpoint probing (configured `--host`) with `localhost` / `network` / `public_bind` / `unavailable` classification
- Local Linux runtime bind detection via `/proc/net/tcp{,6}`, best-effort process attribution from `/proc/<pid>/comm`, no subprocesses spawned
- Stable AI-BOM JSON contract at `schema_version: "1.1"` shared between `runtime inspect ollama --out` and `aibom generate --format json`

## What SIGIL Does Not Do Yet

The current implementation is intentionally narrow:

- It is not a full decompiler. x86 support covers a small integer subset.
- Ollama is the first supported local LLM runtime. llama.cpp, LM Studio, vLLM, and other local OpenAI-compatible servers are planned follow-ups.
- AI-BOM baseline comparison, drift detection, and a formal JSON Schema document (`*.schema.json`) are planned.
- `trace`, `policy-from-source`, and `explain` are still placeholder CLI commands.

## Why Local-First Matters

Local LLM deployments often run with privileged access to local files, GPUs, model stores, and developer networks. SIGIL is built around the assumption that useful security inspection should run close to those artifacts:

- No model artifact has to leave the machine.
- Native binaries can be inspected in place.
- Runtime exposure can be evaluated against the local environment.
- Reports can be kept as local evidence or CI artifacts.

## Inspection Model

SIGIL treats a local AI deployment as several related layers:

1. **Model artifacts**
   Manifests, blobs, digests, sizes, provenance (registry / namespace / model / tag), license metadata (SPDX identification when available).

2. **Runtime exposure**
   Local API availability, configured host, public-bind or non-local endpoint risk, observed listener binds with process attribution.

3. **Native execution surface**
   Runtime binaries, object files, external calls, and mapped capabilities.

4. **Policy**
   Deterministic PASS / WARN / FAIL outcomes from evidence and configured rules.

5. **Reports**
   Structured Markdown and stable AI-BOM JSON output that can be reviewed, archived, or compared later.

## Design Principles

- **Deterministic verdicts**
  LLMs may be useful for explanation, but they do not decide PASS / WARN / FAIL.

- **Evidence first**
  Findings include concrete local evidence: paths, digests, symbols, endpoints, or policy rules. The Markdown report and AI-BOM both surface this evidence inline rather than hiding it behind a single severity word.

- **Local by default**
  SIGIL inspects local artifacts without requiring remote services. Even runtime bind detection on Linux reads `/proc` directly rather than shelling out to `ss` or `lsof`.

- **Narrow before broad**
  Each analyzer should be precise and testable before it expands to more runtimes or file formats.

- **Comparison-ready**
  Reports evolve toward stable AI-BOM records that can support baseline drift detection and runtime comparison. The schema is versioned (`schema_version`) so additive changes do not break downstream consumers.
