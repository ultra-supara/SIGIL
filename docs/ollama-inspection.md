# Inspecting Ollama

`sigil inspect ollama` reads an Ollama model store and writes one session: every fact it observed, every finding with the facts it rests on, what each check covered, and the outcome. With `--install-dir` it also compares the installation's files with the official release manifests. In observe mode it also reads the runtime's listening sockets, and with `--active api-probe` it also asks the runtime's API for its version.

## Modes

| Mode | Ask for it with | Reads | Never |
|---|---|---|---|
| static (default) | `--mode static` | files under the model store, and with `--install-dir` `bin/ollama` and `lib/ollama/` of the installation ([runtime artifacts](runtime-artifacts.md)) | |
| observe | `--mode observe` | also the allowlisted `/proc` entries ([exposure](exposure.md)) | |
| active | `--active api-probe`, with either mode | also one `GET /api/version` to a literal address | |
| all modes | | | execute, load, or map what is inspected; spawn a process; write anything but `--out` |

Static and observe perform no network I/O. The active probe is off by default. The contracts, and how each is checked, are in [ADR-002](adr/ADR-002-execution-modes.md).

## Outputs

- `--format session` (the default): the session, as canonical JSON. It is the evidence; keep it.
- `--format md`: the session as Markdown, for a review ticket. Every input-derived string is escaped.
- `--format aibom`: the AI-BOM v2, a compact projection that names its session by SHA-256 ([AI-BOM](ai-bom-and-comparison.md)).
- `--out <FILE>` writes the document there instead of stdout, creating its directories. It must lie outside the models directory and the install directory. A short summary goes to stderr. With `--install-dir` it has a `release:` line:

  ```
  release: ollama v0.30.6 (34/34 files, 17/17 symlinks, 3/3 directories reference-matched; nothing absent)
  ```

  The line says `content matches …; incomplete` when members are absent, `not established (…)` when no release matches every file, and `install not found` when the directory has no installation.
- `sigil session render <SESSION> [--format md|aibom]` renders a saved session again, without inspecting anything.

## A first run

```bash
cargo run -p sigil-cli -- inspect ollama --out out/session.json
cargo run -p sigil-cli -- session render out/session.json
cargo run -p sigil-cli -- explain out/session.json --verdict
cargo run -p sigil-cli -- explain out/session.json --coverage
cargo run -p sigil-cli -- explain out/session.json --finding <FINDING-ID> --format md
cargo run -p sigil-cli -- inspect ollama --install-dir /usr/local --format md --out out/install.md
cargo run -p sigil-cli -- inspect ollama --mode observe --format md --out out/observe.md
cargo run -p sigil-cli -- inspect ollama --active api-probe --api-addr 127.0.0.1:11434 --out out/active.json
cargo run -p sigil-cli -- session render out/session.json --format aibom --out out/aibom.json
cargo run -p sigil-cli -- rules
```

`<FINDING-ID>` is the `id` of an entry in the session's `findings`; the Markdown lists them too.

## Options

- `--models-dir <dir>`: the model store (default `$OLLAMA_MODELS`, else `~/.ollama/models`). `--model <name>` inventories one model.
- `--install-dir <prefix>`: the installation, for example `/usr/local` for the official install script. SIGIL reads `bin/ollama` and `lib/ollama/` under it, and nothing else: it follows no symlink there. It compares each file with the release manifests of Ollama v0.30.5 to v0.30.7 embedded in SIGIL. That is a comparison with the official archives' contents, not a signature check ([runtime artifacts](runtime-artifacts.md)). Without it, the installation is not inspected.
- `--policy <file>`: a policy (TOML, [policy](policy.md)) that sets the audit scope, rule actions with reasons and expiry, and accepted assumptions. Without it, the built-in policy applies.
- `--policy-time now|RFC3339`: the instant at which policy expiry is judged (default `now`).
- `--budget KEY=VALUE`: a read budget, by the name the session records (e.g. `files_discovered=4096`, `manifest_bytes`). Budgets that run out leave the result incomplete, never silently clean. With `--install-dir`, the installation has its own: `install_files_discovered`, `install_entries_listed`, and `install_bytes` (summed over the whole installation, default 64 GiB), and each ELF file's parse `binary_parse_bytes` (default 64 MiB) and `binary_imports` (default 4096).
- `--active api-probe [--api-addr IP[:PORT]] [--allow-remote]`: probe the API at a literal address (default `127.0.0.1:11434`; `localhost` means 127.0.0.1). A refused connection closes the check: nothing answers at that address from SIGIL's network namespace. That is not "no Ollama on this system": a runtime in another namespace (for example, outside SIGIL's container) or on another host is neither seen nor ruled out, and a version is the endpoint's own claim, not tied to an observed process or binary. A timeout or a reply that is not the Ollama API leaves the check open. The probe's budgets are `api_connect_ms` (at most 30000), `api_io_ms` (at most 60000), and `api_response_bytes` (at most 1048576).
- `--fail-on warn|fail` and `--fail-on-incomplete`: exit codes for CI (below).

## Exit codes and CI

| Code | Meaning |
|---|---|
| 0 | Normal |
| 1 | Execution error (for example, an unreadable policy) |
| 2 | Usage error (for example, an unknown flag, or `--out` inside the models or install directory) |
| 3 | The verdict reached `--fail-on` |
| 4 | The result is incomplete and `--fail-on-incomplete` was given (3 takes precedence) |

A CI step that fails on a FAIL verdict or on an incomplete result, and keeps the report:

```bash
cargo run -p sigil-cli -- inspect ollama --fail-on fail --fail-on-incomplete --format md --out out/report.md
```

## Reading the result

Every result has two parts, side by side:
- the **verdict** (`PASS` / `WARN` / `FAIL`), from deterministic analyzers and the policy;
- the **completeness** (`COMPLETE` / `INCOMPLETE`): whether every required check was closed.

What SIGIL could not see is never reported as absent; it leaves a check open and the result incomplete.

`sigil explain <SESSION>` answers one question at a time:
- `--finding <ID>`: the rule, the policy decision, the facts the finding rests on, and the remediation;
- `--verdict`: how the verdict and completeness were reached;
- `--coverage`: the state of every check.

`--format text` (the default) is for a terminal, and `--format md` for a review ticket. The same session always gives the same text.

`sigil rules` lists every rule. What each rule and coverage state means: [model store](model-store.md), [exposure](exposure.md), and [runtime artifacts](runtime-artifacts.md).

`session render` and `explain` also re-check a saved session's reference matches against the manifests embedded in this SIGIL, when the session names them. A session whose rows disagree is an execution error (1).

## From v0.1

SIGIL 0.1's commands and flags map to v2 as follows.

| v0.1 | v2 |
|---|---|
| `runtime inspect ollama` | `inspect ollama` |
| `aibom generate --runtime ollama` | `inspect ollama --format aibom`, or `session render --format aibom` |
| the API probe, on by default | `--active api-probe`, off by default |
| `--no-probe-api` | the default |
| `--no-inspect-runtime` | the default (`--mode static`) |
| `--host`, `OLLAMA_HOST` | planned (PR-4) |
| finding IDs `ollama.*` | the v2 rule IDs (`sigil rules`) |

The v0.1 guide: [docs/ollama-inspection.md at 8e17ec0](https://github.com/ultra-supara/SIGIL/blob/8e17ec0/docs/ollama-inspection.md). Why the v0.1 code was removed: [ADR-006](adr/ADR-006-remove-ir-safeisa.md).
