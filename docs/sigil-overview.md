# SIGIL Overview

**Semantic Inspection for Guarded Intelligence Layers**

SIGIL is a defensive, local-first security inspection tool for AI runtimes, model stores, and native execution surfaces. Its core premise is that local LLM safety is not only about the model. A local deployment also includes runtime APIs, model-store artifacts, native binaries, configuration, and policy.

SIGIL keeps verdicts deterministic. It can collect evidence from local model stores and binaries, but it does not ask an LLM to decide whether something is safe.

## What SIGIL Does Today

The current Rust implementation provides:

- Deterministic policy parsing and evaluation
- Capability mapping from external symbols
- Evidence JSON and Markdown reporting
- A guarded SafeISA model and emulator that blocks external effects
- x86_64 object loading, decoding, and a narrow IR lifting path
- Ollama model-store inventory
- Ollama API endpoint probing
- Blob digest verification for Ollama model artifacts
- AI-BOM-style JSON and Markdown report generation

## What SIGIL Does Not Do Yet

The current implementation is intentionally narrow:

- It is not a full decompiler.
- x86 support covers a small instruction subset.
- Ollama is the first supported local LLM runtime.
- Runtime bind detection is currently based on configured host/probe behavior, not full process or socket discovery.
- AI-BOM schema stabilization, baseline comparison, license extraction, Modelfile inspection, and multi-runtime comparison are planned follow-up work.

## Why Local-First Matters

Local LLM deployments often run with privileged access to local files, GPUs, model stores, and developer networks. SIGIL is built around the assumption that useful security inspection should run close to those artifacts:

- No model artifact has to leave the machine.
- Native binaries can be inspected in place.
- Runtime exposure can be evaluated against the local environment.
- Reports can be kept as local evidence or CI artifacts.

## Inspection Model

SIGIL treats a local AI deployment as several related layers:

1. **Model artifacts**
   Manifests, blobs, digests, size, provenance, and future license metadata.

2. **Runtime exposure**
   Local API availability, configured host, public-bind or non-local endpoint risk, and future process/socket evidence.

3. **Native execution surface**
   Runtime binaries, object files, external calls, and mapped capabilities.

4. **Policy**
   Deterministic PASS/WARN/FAIL outcomes from evidence and configured rules.

5. **Reports**
   JSON evidence and Markdown AI-BOM output that can be reviewed, archived, or compared later.

## Design Principles

- **Deterministic verdicts**
  LLMs may be useful for explanation, but they do not decide PASS/WARN/FAIL.

- **Evidence first**
  Findings should include concrete local evidence: paths, digests, symbols, endpoints, or policy rules.

- **Local by default**
  SIGIL should inspect local artifacts without requiring remote services.

- **Narrow before broad**
  Each analyzer should be precise and testable before it expands to more runtimes or file formats.

- **Comparison-ready**
  Reports should evolve toward stable AI-BOM records that can support baseline drift detection and runtime comparison.

