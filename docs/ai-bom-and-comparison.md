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
| `open_questions` | id, rule, subject, decision; written only when the session has one (#51), so an AI-BOM without open questions keeps its bytes. A reader from before #51 refuses an AI-BOM that has them (unknown fields are refused) |
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
- open questions, when there are any;
- coverage.

The browser viewer uses it through wasm (`crates/sigil-wasm`), after checking the AI-BOM (`AiBom::validate`): coverage summaries may name only coverage states, each with entries, and `closed` must agree with them. An inconsistent AI-BOM is refused, not shown. The CLI's `--format md` renders the session itself, which has more detail.

### Compatibility

- AI-BOM v2 is a new major version. It is not a superset of v1, and a v1 document is refused.
- [`schemas/aibom-v1.schema.json`](../schemas/aibom-v1.schema.json) stays for the reports SIGIL 0.1 wrote.
- Within `sigil-aibom/2`, every field is always written and required.
- Types shared with the session are copied from `session-v1.schema.json`, and a test keeps them equal.

## Comparing two sessions

`sigil compare` (#16) reports what changed between two saved sessions. It writes a versioned
document (`sigil-diff/1`, [`schemas/diff-v1.schema.json`](../schemas/diff-v1.schema.json)) as
canonical JSON, or its Markdown. It reads its two inputs and the policy file `--policy` names, if
any, and writes `--out`, nothing else.

```bash
sigil inspect ollama --out baseline/session.json
# later
sigil inspect ollama --out out/session.json
sigil compare --baseline baseline/session.json --current out/session.json --format md
```

Each input is loaded and re-verified as `session render` does; a failure names the input and exits
1, as a policy that does not load does. A usage error exits 2. A one-line summary goes to stderr
("1 change" for one):
`compare: {N} changes, {M} not comparable: {VERDICT} + {COMPLETENESS} under {policy} (sha256:…) (baseline sha256:…, current sha256:…)`.
`--out` may not name an input: either session or the policy file. The same file as both inputs
gives no differences.

The diff names each session by the SHA-256 of its canonical JSON, as the AI-BOM does. Each change
carries the IDs of its item in the session that holds it. Fixture pairs, with their diffs and
Markdown, are in [`schemas/examples/diff-v1/`](../schemas/examples/diff-v1/).

| Kind | Changes |
|---|---|
| Outcome | `PolicyChanged`, `VerdictChanged`, `CompletenessChanged` (`Complete` against `Incomplete`) |
| Coverage | `CheckOpened`, `CheckClosed` |
| Findings and policy violations | `FindingNew`, `FindingResolved`, `ViolationNew`, `ViolationResolved`, by rule and subject; `FindingDecisionChanged`, `ViolationDecisionChanged` when the same item has other policy decisions (an action, a reason, an expiry, or an override that expired), with each side's finding IDs or violation subjects |
| Open questions | `OpenQuestionNew`, `OpenQuestionResolved`, by rule and subject; `OpenQuestionTreatmentChanged` when the same question has other decisions (a treatment, a source or a reason), with each side's question IDs (#138) |
| Models | `ModelAdded`, `ModelRemoved`, `LayerChanged`, `LicenseChanged` |
| Installation | `FileAdded`, `FileRemoved`, `FileContentChanged`, `ReleaseChanged`, `ComponentChanged` |
| Listeners | `ListenerAdded`, `ListenerRemoved`, `BindWidened`, `BindNarrowed`, by port |

- **Matching.** Items are matched by keys that survive a new run:
  - model IDs (manifest paths);
  - where a file was found: the root-relative path under `models`, `install` and
    `service-unit`, or the recorded path of a `binary inspect` input;
  - ports;
  - rules, with their subjects normalized the same way.

  Listener inodes, `binary-<n>` numbers and slice IDs are pointers, not keys. A restart, files
  given in another order are not changes. An upgraded file is one `FileContentChanged`; its
  claims keep their key (placement, arch, component), so a new slice ID alone is no claim change.
  Its open questions keep their key too: a capability question
  (`capability:<feature>@<slice>`) keys as `capability:<feature>@` on the placement and arch of
  its slice.
- **Comparability.** Saying that something is absent on one side needs the check that would
  have recorded it to be closed on that side. Otherwise the item is *not comparable*, never
  removed or resolved. The diff's `not_comparable` lists it with a `cause`, the checks, and the
  side they are open on. Values recorded on both sides (layer digests, file contents, claims) are
  compared directly. A new finding is reported even when the current run's coverage is partial,
  since its conditions establish it.
  - `Coverage`: a check is open on that side.
  - `Request`: the two runs asked for different things. They used different `--model` filters, or
    one named a binary input or a service unit that the other did not. The claims, violations
    and open questions about such an input are included.
  - `Policy`: the sessions applied different policies, so a violation, or a capability open
    question, on one side only is not judged (the rule may be absent from the other policy).
    `PolicyChanged` reports the two. A
    session that records no policy did not apply the same policy as any other, even one that
    records none either.
- **Model findings.** A finding of the model store is judged by the check of its rule (integrity,
  license or inventory). The findings of a model that is gone are judged by the inventory check of
  its manifest.
- **Open questions** (#138). A capability question (`binary.capability_call`) on one side only
  is judged under the same policy, by the container check of its file's placement
  (`artifacts.container` or `binary.container`) on the other side: the imports are read there.
  A question of another rule needs the other side complete.
- **Limits.**
  - Only open/closed transitions of checks are reported. A check open on both sides whose
    states or gaps changed is not.
  - The layers of a manifest that is unstable on either side are not compared.
  - Text that came from the inspected system (model names, paths, rule subjects) stays untrusted
    in both documents, and the Markdown escapes it.
- **Not compared yet:** hints and code facts, AI-BOM input.

### Judging the differences

Every diff is judged under a policy's `[compare]` section (#16): `--policy FILE`, or the
built-in policy. Each change kind has an action (`fail`, `warn`, `ignore`, or for a new or
changed finding, violation or open question `decided`: what its decisions in the current
session say (a question's treatment: `fail` and `warn` weigh as those actions, a gap or `ignore`
nothing); a changed decision weighs that only when it got heavier than the baseline's, and `warn`
otherwise; a
changed verdict, also `decided` by default, weighs the current verdict when it got worse, and
nothing otherwise), and each cause of an item not comparable a treatment. The diff's
`evaluation` records the policy, the whole table, and two results, as a session has: a verdict
(`PASS`, `WARN`, `FAIL`) and a completeness (`INCOMPLETE` when either session is incomplete
itself, or when an item not comparable counts as a gap, the default). Each side of the diff
records its session's own completeness. A diff reads back only if it is consistent with itself:
its table complete, with sources and reasons as SIGIL writes them, and its recorded verdict and
completeness equal to a fresh judgment of its changes under that table. That does not prove
which policy file made it: running `sigil compare --policy` with that file again does. The
defaults and the format: [policy](policy.md#comparing-sessions-compare).

| Code | Meaning |
|---|---|
| 0 | Compared, and neither 3 nor 4 applies, for example whether or not anything changed |
| 1 | Execution error: an input that is not a valid session, or a policy that does not load |
| 2 | Usage error, for example `--out` naming an input |
| 3 | The diff's verdict reached `--fail-on` |
| 4 | The diff is incomplete (an input is, or an item not comparable counts as a gap) and `--fail-on-incomplete` was given (3 takes precedence) |

A CI step that fails on drift against a trusted baseline, and keeps the report:

```bash
sigil compare --baseline baseline/session.json --current out/session.json \
  --policy org-policy.toml --fail-on fail --fail-on-incomplete --format md --out out/compare.md
```

**`sigil-diff/1` was revised before its first release** (#16, PR-16b). Diffs that main wrote
between #136 and that change have no `evaluation`, no `completeness` per side, and no `decisions`
on `FindingNew` and `ViolationNew`: they neither validate against `diff-v1.schema.json` nor load.
Compare the two sessions again for a current diff.
It was revised again for open questions (#138): diffs that main wrote between PR-16b and that
change (an `evaluation` of 24 change kinds) neither validate nor load either.

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
