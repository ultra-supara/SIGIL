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
- It writes only the `--out` it is given, which must lie outside the inspected store:
  - **Checked once, then pinned.** An existing symlink at `--out` is resolved when `--out` is checked, and the file it leads to must lie outside the store too. The output's directory is opened then, without following a symlink, and kept open. It must not be, or lie under, a scan root, by `dev:ino`, and that is checked again just before the write. A directory renamed after the check therefore cannot redirect the write into the store.
  - **Replaced, never written through.** The document goes to a new file next to the output, created readable by its owner only (`0600`), and is exchanged with the file at the output (`RENAME_EXCHANGE`). A hard link or a symlink there cannot make SIGIL write another file. The file it displaced is checked: a directory, a protected input, or a file that cannot be checked is put back. An existing directory at the output is refused when `--out` is checked. The replaced file's mode and owner are not kept.
  - **Each directory before it is touched.** The pinned directory is checked before anything is created in it, and each missing directory is checked once it is created, before the next one.
  - **Without `RENAME_EXCHANGE`** (a file system that cannot exchange files), a run that protects inputs writes only a new name and refuses an existing output; other runs fall back to a plain rename.
  - **What remains:**
    - a directory moved into a scan root between one of those checks and the next step (a `mkdirat`, or the exchange);
    - **a run killed after the exchange and before a put-back.** They are two system calls. A run killed between them (`SIGKILL`) leaves the directory or protected input it displaced at the temporary name, with its contents intact, and the document at the output. The temporary name is `.<name>.sigil-<pid>-<k>.tmp` in the output's directory: `<name>` is the output's file name (at most its first 200 bytes), and `k` is below 100. A file is restored by renaming it back over the document; a directory, once the document is removed. A directory, or an input, is at the output then only if another process moved or linked it there after `--out` was checked (against the inputs as read, for an input). Nothing is synced: after a power loss, the file system may show either side of the exchange, and the document may be incomplete.
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
