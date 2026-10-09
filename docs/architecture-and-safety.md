# Architecture and Safety Model

SIGIL is a Rust workspace of five crates. Everything it does to an inspected system is read-only.

## Crates

- **`sigil-model`**: the session's types (including each finding's policy decision), its validation and canonical form, and the renderers (Markdown, AI-BOM v2, and the viewer's HTML). Pure: no file, process, or network I/O, so it also builds for `wasm32-unknown-unknown`.
- **`sigil-engine`**: anchored, bounded file access (`SafeFs`), the Ollama store collector, observe mode (`/proc`), the analyses, and policy loading and evaluation. Network APIs are banned in it at build time.
- **`sigil-probe`**: the active API probe, the only code that performs network I/O. Only the CLI depends on it.
- **`sigil-cli`**: the `sigil` command (`inspect ollama`, `session render`, `explain`, `rules`).
- **`sigil-wasm`**: the browser viewer's renderers. It depends only on `sigil-model`.

```text
sigil-cli ──▶ sigil-engine ──▶ sigil-model
    │                              ▲  ▲
    └──────▶ sigil-probe ──────────┘  │
                                      │
sigil-wasm ───────────────────────────┘
```

## Data flow

1. **Collect and observe.** The engine reads the model store through `SafeFs`; in observe mode it also reads the allowlisted `/proc` entries; with `--active api-probe` the CLI asks `sigil-probe` for one API response.
2. **Facts.** Each observation becomes a fact with its evidence. What could not be read becomes a coverage gap, not a fact.
3. **Analysis.** Rules turn facts into findings, and record coverage for each check.
4. **Policy.** The policy decides each finding (`fail`, `warn`, or `ignore`, which needs a reason) and which checks are required ([policy](policy.md)).
5. **Outcome.** The verdict and the completeness, computed independently.
6. **Session.** All of the above, validated (`Session::validate`) and written as canonical JSON.
7. **Render.** Markdown, AI-BOM v2, and the viewer's HTML are projections of the session; none adds facts.

## Modes

- **static** (default): files only.
- **observe**: also the allowlisted `/proc` entries.
- **active**: explicitly requested features that contact something; today only the API probe.

The contracts of each mode, and how each is checked: [ADR-002](adr/ADR-002-execution-modes.md).

## Safety Boundaries

SIGIL is analysis-only:

- It does not execute, load, or map what it inspects.
- It does not spawn processes; `/proc` is read directly, never through `ss`, `lsof`, `netstat`, or `docker`.
- It performs no network I/O in static and observe modes. The active probe makes one connection to a literal address, loopback unless `--allow-remote` is given.
- It writes only the `--out` it is given, which must lie outside the inspected store.
- It does not delegate verdicts to an LLM.
- It treats the model store as untrusted input: manifest digests are checked for the `sha256:<64 hex>` shape before they become paths, so a malformed digest like `sha256:foo/../../secret` cannot escape the blob store.
- Its reads are bounded (budgets recorded in the session), and blob hashing is streaming, so multi-GB model files never have to fit in memory.
- It reports what it could not see as incompleteness, never as absence.

These constraints are central to the project. Future analyzers should preserve them — flag any deviation up-front.

### How the boundaries are checked

The contracts C-1…C-6 cover four things:
- no child processes;
- no `dlopen` or `mmap` of inspected files;
- no network I/O;
- read-only access, and only documented `/proc` reads.

**SIGIL checks them through build-time API restrictions (`clippy.toml`, `deny.toml`) and syscall tests over the exercised CLI paths (`crates/sigil-cli/tests/safety`, run under strace in the CI `safety` job), including negative controls that prove each detector fires.** These checks are not a runtime sandbox: a code path the tests do not exercise could still violate a contract, and runtime enforcement such as seccomp is a separate future decision.

The one exception to "no network I/O" is the **active** API probe, which runs only when asked for (`inspect ollama --active api-probe`). It makes one TCP connection to a literal address, loopback unless `--allow-remote` is given, and the safety tests check that it connects only there. See [ADR-002](adr/ADR-002-execution-modes.md) for the full contract list, what each check covers, and its limitations.

## Output safety

- Every string that comes from the inspected system (paths, names, license text, probe replies) is carried as untrusted text. The Markdown renderers escape it, so it cannot form Markdown structure.
- The viewer's HTML comes only from `sigil_model::render::html`, which converts SIGIL's own Markdown subset to a fixed set of tags with no attributes, and escapes all text (U-10). The page runs under a strict Content Security Policy.

## v0.1

SIGIL 0.1's native analysis path (`lift` and `assess`, the IR, SafeISA and its emulator, and the YAML capability policy of `examples/policies/numeric_kernel.yml`) was removed; why, and where each v0.1 capability went: [ADR-006](adr/ADR-006-remove-ir-safeisa.md). This document as of v0.1: [docs/architecture-and-safety.md at 8e17ec0](https://github.com/ultra-supara/SIGIL/blob/8e17ec0/docs/architecture-and-safety.md).
