# SIGIL Roadmap: Local-First LLM Deployment and AI-Native Binary Assessment

SIGIL is pivoting from a binary-only guarded lifter into a broader local-first security assessment tool for local LLM deployments and AI-native binaries.

This PR keeps the x86 → IR → SafeISA pipeline as the binary-analysis foundation. The modules below are planned next steps and are intentionally not implemented in this PR.

## 1. Model artifact inspection

Planned inspection targets:
- GGUF model files
- `safetensors` files
- Ollama `Modelfile` inputs
- tokenizer configuration and vocabulary artifacts
- LoRA/adapters and other model-side overlays

Assessment goals:
- identify model provenance and hashes
- detect unexpected adapters or tokenizer drift
- record local-only artifact metadata for audit evidence
- avoid uploading model artifacts or prompts to cloud services

## 2. Runtime assessment

Planned runtime targets:
- Ollama local deployments
- `llama.cpp` servers and CLIs
- native extensions loaded by local AI applications
- local OpenAI-compatible inference servers

Assessment goals:
- inventory local runtime configuration
- identify model/runtime mismatch and unsafe defaults
- detect native extension and dynamic-loading exposure
- keep runtime checks read-only and local-first

## 3. Deployment assessment

Planned deployment checks:
- API bind address and exposed ports
- authentication and authorization settings
- tool/function permission configuration
- filesystem, network, process, and environment access boundaries
- local secrets and environment-variable exposure indicators

Assessment goals:
- identify accidental public binding
- flag missing auth for local inference APIs
- report overbroad tool permissions
- generate deterministic findings with evidence locations

## 4. Attestation report / AI-BOM

Planned outputs:
- deterministic attestation report
- AI-BOM for local model/runtime/deployment components
- binary-analysis evidence from the existing x86 → IR → SafeISA foundation
- policy verdict details with PASS/WARN/FAIL reasons

The AI-BOM should summarize:
- model artifacts and hashes
- tokenizer and adapter metadata
- runtime version/configuration
- API exposure and tool permissions
- native binary capability evidence when applicable

## LLM role boundary

LLMs may optionally help draft policies or explain deterministic evidence, but they must never make security verdicts. SIGIL verdicts must remain deterministic and based on analyzer output plus policy evaluation.
