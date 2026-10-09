# AI-BOM and Comparison Direction

SIGIL's AI-BOM is an evidence record for local AI deployments. It is inspired by SBOM workflows, but it focuses on AI runtime and model-store concerns rather than package dependencies alone.

## Why AI-BOM Matters

Local LLM deployments can change without a package manager or central inventory:

- A model tag can point to different local blobs over time.
- A custom model can derive from a base model with a new Modelfile.
- A runtime can move from localhost-only to LAN-accessible.
- A local model store can contain unknown or corrupted artifacts.
- A license layer can be removed or replaced.
- Runtime binaries can change independently of model files.

An AI-BOM gives SIGIL a stable record to compare against later.

## AI-BOM v2

The source of truth is the **session** (`sigil-session/1`, [docs/session-model.md](session-model.md)): every fact observed, every finding with the facts it rests on, and what each check covered. The AI-BOM v2 (`schema: "sigil-aibom/2"`) is a compact projection of a session for reviewers and downstream tools. It is defined by `sigil_model::render::aibom` and specified in [`schemas/aibom-v2.schema.json`](../schemas/aibom-v2.schema.json) (JSON Schema draft 2020-12, self-contained, strict).

```bash
# From an inspection: the AI-BOM only (the session itself is not saved)
sigil inspect ollama --format aibom --out out/aibom.json

# From a saved session: keep the session as the evidence, derive the AI-BOM from it
sigil inspect ollama --out out/session.json
sigil session render out/session.json --format aibom --out out/aibom.json
```

### It names its session

`session.sha256` is the SHA-256 of the session's canonical JSON (`Session::to_canonical_json`). A session SIGIL saved hashes to its file, so the AI-BOM points at the exact evidence behind every line. `inspect --format aibom` does not save the session, and its summary prints the hash and says so. To keep the evidence, also write the session (`--format session`).

A session written before PR #76 has no `request.active` or `probes`. It hashes in its upgraded form, with both added as empty lists, which differs from its file's bytes.

### Shape

| Field | Holds |
|---|---|
| `schema` | `"sigil-aibom/2"` |
| `tool` | name, version, git revision |
| `session` | `schema` (`sigil-session/1`), `sha256`, `mode`, `started_at`, the applied `policy` (id, version, SHA-256) |
| `outcome` | `verdict` (PASS / WARN / FAIL) and `completeness` (COMPLETE / INCOMPLETE with the open checks), side by side, plus the confirmed counts |
| `runtime` | `processes` (PID, start, roles, name, executable), `listeners` (address, port, socket, owner), `api` (each API probe and how it ended), `releases` (product, candidates, the kind of basis) |
| `models` | id, name, provenance (registry / namespace / model / tag), layers (role, media type, digest, and where the blob was found with the content read there, or that it is absent, unresolved, or not looked up), license (SPDX id, excerpt) |
| `artifacts` | each file content: SHA-256 id, size, format, the paths it was found at, and per architecture slice the components identified in it (with `IdentityStatus` and versions) |
| `findings` | id, rule, kind, subject, summary, default severity, the policy decision, limits |
| `policy_violations` | policy rule, subject, decision |
| `coverage` | per check: whether it is required, whether it is closed, and its entries per coverage state |

- Evidence, identity assertions, finding conditions, code facts, relations, and load facts are not copied. Follow `session.sha256` to the session for them.
- Input-derived text (names, paths, versions, OS messages) stays **untrusted text**: a string when it is UTF-8, `{"hex": …}` otherwise. Consumers must escape it before display.
- An API probe in `runtime.api` is the endpoint's own claim, from SIGIL's network namespace. A refusal there says nothing about a runtime in another namespace or on another host.

### Markdown

`sigil_model::render::aibom::markdown` renders an AI-BOM as Markdown, with the same escaping as the session report. Its sections:
- a header;
- the outcome;
- the runtime API (with the probe's limits), processes, listeners, and releases;
- models;
- artifacts;
- findings;
- policy violations;
- coverage.

The browser viewer will use it through wasm (PR-3b-3b). The CLI's `--format md` renders the session itself, which has more detail.

### Compatibility

- AI-BOM v2 is a new major version. It is not a superset of v1, and a v1 document is refused.
- [`schemas/aibom-v1.schema.json`](../schemas/aibom-v1.schema.json) stays for the reports SIGIL 0.1 wrote.
- Within `sigil-aibom/2`, every field is always written and required.
- Types shared with the session are copied from `session-v1.schema.json`, and a test keeps them equal.

## Planned Comparison Work

Future comparison should answer:

- Which models were added or removed?
- Did any model blob digest change?
- Did runtime exposure become less restrictive?
- Did a runtime binary change?
- Did a model lose license or provenance metadata?
- Did a custom model's Modelfile or adapter chain change?
- Do current findings violate local policy?

Comparison will work on sessions, with AI-BOMs as their summaries, so that every difference can be traced to evidence. A possible future command shape:

```bash
sigil compare --baseline baseline/session.json --current out/session.json
```

AI-BOM comparison and baseline drift detection are tracked in issue #16.

## Runtime Comparison

The same model can be served by different runtimes with different risk profiles. SIGIL's direction is to compare local runtimes across:

- Runtime API exposure
- OpenAI-compatible endpoint availability
- Model inventory
- Blob integrity
- License and provenance metadata
- Native binary capabilities
- Policy verdicts

Candidate future runtimes:

- Ollama (implemented)
- llama.cpp server
- LM Studio
- vLLM
- text-generation-inference
- Other local OpenAI-compatible endpoints

A future runtime records its facts in the same session model. The AI-BOM projection then gains what that runtime needs, with a new schema version if a field changes meaning.
