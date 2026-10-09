# Runtime artifacts (`sigil-engine`, `--install-dir`)

With `--install-dir PREFIX`, SIGIL also inspects an Ollama installation. It hashes
`PREFIX/bin/ollama` and every entry under `PREFIX/lib/ollama/`. Each of them is compared with the
official release archives, whose member lists are embedded in SIGIL. The result answers two
separate questions:

- **Attribution:** which official releases the installed content matches.
- **Completeness:** whether the installation holds every member of that release.

- **Status:** `sigil inspect ollama --install-dir PREFIX`, in any mode and with any format.
- **Source:** plan §4.4.2 and §4.6.2. The session types are described in
  [`docs/session-model.md`](session-model.md), and the scope rule in [`docs/policy.md`](policy.md).

## What is read

| Item | Read | Not read |
|---|---|---|
| `bin/ollama` | Its `lstat`, and its contents hashed as a stream (through a symlink, the target's) | — |
| `lib/ollama/` | Every entry, at any depth, each with its `lstat`. Regular files and link targets are hashed as streams | — |
| Symlinks | The target text (`readlinkat`), resolved or not. A link to a file inside the install is read through | A link to a directory is recorded and not entered. A link out of `PREFIX` is recorded and not read. A dangling link is recorded with its target text |
| Anything else under `PREFIX` | — | Never opened (`bin/` other than `ollama`, `share/`, …) |

- **Its own root.** The installation is the scan root `install`, on its own SafeFs. A link from
  the installation into the model store, or anywhere outside `PREFIX`, leads outside every root of
  that SafeFs: it is recorded, and the file is not read.
- **The first 64 bytes** of each file give its format. An ELF file is recorded with its type and
  architecture, and one slice. The format does not affect matching.
- **A link is stable** only if its target text is the same before and after the read. Otherwise the
  placement is `ChangedDuringRead`, as is a file whose `fstat` changed during its read.
- **The budgets** (`--budget`, with `--install-dir` only) are recorded in `request.budgets` with an
  `install_` prefix:

  | Budget | Default | What it bounds |
  |---|---|---|
  | `install_files_discovered` | 4096 | Entries returned by the walk, of every kind |
  | `install_entries_listed` | 16384 | Directory entries read |
  | `install_bytes` | 64 GiB | Bytes read for hashing, **summed over the whole install**. Once reached, no further read begins, and a read that would cross it is abandoned |

  `install_directory_entries` (16384), `install_walk_depth` (32), and `install_link_hops` (40) are
  recorded as well. They are fixed.

## The reference set

| Set | Releases | Members per release |
|---|---|---|
| `ollama-official`, version `2026-10-07` | v0.30.5, v0.30.6, v0.30.7 (linux-amd64) | 34 files, 17 symlinks, 3 directories |

- **Where it comes from.** Each official archive was streamed, without extraction, in PR-0, and
  its SHA-256 equals the digest published with the release. Every member was recorded with its type
  and mode, a file with its size and SHA-256, and a symlink with its target. The files are embedded
  unchanged (`crates/sigil-engine/refs/ollama-official/`).
- **In the session.** A session that compared names the set in `knowledge`:
  `KnowledgeRef { kind: ReferenceManifest, id: "ollama-official", version: "2026-10-07", sha256 }`.
  The SHA-256 covers the embedded files.
- **What a match is.** A match is a comparison with the contents of the official archives. **It is
  not a signature check**, and it does not show who built the files.
- **Adding a release.** [`scripts/refmanifest/`](../scripts/refmanifest/README.md) describes it: a
  new manifest, a new pinned set SHA-256, and a new SIGIL version.

## Rows

`reference_matches` holds one row for each placement and each release that lists the placement's
path:

| The placement | The release's member | Row |
|---|---|---|
| A regular file, read and stable | a file | `File { expected, observed }`, by SHA-256 |
| A symlink, stable | a symlink | `Symlink { expected, observed }`, by its own target text (the first hop) |
| A directory | a directory | `Directory` |
| Any kind | another kind (a FIFO is `Special`) | `KindDiffers { expected, observed }` |
| Not stable, or a file that was not read | any | `NotCompared` |
| — (no placement at the member's path) | any | `Absent { kind }`, **only when `artifacts.discovery` is `Complete`** |

- A symlink is compared as a symlink, even when the file it leads to matches a file member.
- A path no release lists gets no row. When discovery is not complete, a member that was not
  observed gets no row either: not observed is not absent.

```
{ "reference": "ollama-official", "release": "v0.30.6", "member": "lib/ollama/libggml-base.so.0",
  "instance": "inst:install/lib/ollama/libggml-base.so.0",
  "result": { "Symlink": { "expected": "libggml-base.so.0.13.1", "observed": "libggml-base.so.0.13.1" } } }
```

## Attribution and completeness

- **The candidates** are the releases for which every placement has a matching row.
- **A release claim** (`releases`, basis `ReferenceMatches`, the placements as its files) is
  recorded only when discovery is `Complete` and there is at least one candidate. Releases with
  identical content are all candidates.
- **`artifacts.release` is `Complete`** only when there is a claim and no candidate has an `Absent`
  row. An installation whose content matches v0.30.6 but which lacks some of its libraries is
  attributed to v0.30.6 and is INCOMPLETE.

| Install | Claim | `artifacts.release` |
|---|---|---|
| An unmodified v0.30.6 | `[v0.30.6]` | `Complete` |
| `bin/ollama` of v0.30.6, `lib/ollama/` empty | `[v0.30.6]` | `Partial` (members absent) |
| A library replaced by any other bytes, ELF or not | none | `Partial` (`matches no reference`) |
| `bin/ollama` of v0.30.5 and a library only v0.30.6 has | none | `Partial` (`mixed install`) |
| A dangling link with the official target text | none (discovery `Partial`) | `Partial` (`discovery incomplete`) |

The summary line says the same:

```
release: ollama v0.30.6 (34/34 files, 17/17 symlinks, 3/3 directories reference-matched; nothing absent)
release: content matches v0.30.6 (1/34 files, 0/17 symlinks, 0/3 directories present); incomplete
release: not established (2 reasons; sigil explain --coverage)
release: install not found
```

## Coverage

Both checks belong to the scope `runtime_artifacts`, which the default policy audits when
`--install-dir` is given.

**`artifacts.discovery`** (scope: the root `install`):

| State | When |
|---|---|
| `Complete` | Both places were listed in full, and every file and link target inside the install was read without a change |
| `Unavailable(NotFound)` | `PREFIX` does not exist, or has neither `bin/ollama` nor `lib/ollama/` |
| `Unavailable(PermissionDenied)` | `PREFIX` cannot be opened |
| `BudgetExceeded` | An `install_*` budget ran out |
| `Partial { missing }` | One place is missing (`<place>: not found`); an entry was not read (`<path>: <reason>`: a dangling link, a link out of the install, a FIFO, …); or a directory was not fully listed. A directory, and a link to one, are not gaps |
| `Error { message }` | An entry vanished, or changed, during the scan |

**`artifacts.release`** (same scope):

| State | When |
|---|---|
| `Complete` | A claim, and nothing absent from any candidate |
| `Partial { missing }` | Otherwise, one entry per reason: `discovery incomplete`; `<release>: <n> files, <m> symlinks, and <k> directories absent from the install`; `<path>: not in any reference`; `<path>: matches no reference`; `<path>: symlink to <t>; <release>: <t'>`; `<path>: <kind> where <release> has a <kind>`; `<path>: not compared`; `mixed install: …` |
| The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

Without `--install-dir`, a policy that requires `runtime_artifacts` anyway gets both checks
`Skipped { Flag("--install-dir") }`, so the result is INCOMPLETE.

## Verification

- **`Session::validate`** checks the rows against the session itself (V1–V11 in
  [`docs/session-model.md`](session-model.md#what-sessionvalidate-checks)). Each row's observed
  value must be the placement's own fact. A match needs a stable read. `Absent` needs a complete
  discovery. The candidates are recomputed from the rows, and `artifacts.release` is `Complete`
  exactly when the claim, the discovery, and the absent members allow it.
- **`validate` cannot know the set.** It cannot tell that a release lists a member, or that a
  release exists. A session with every row of one release removed, and that release dropped from
  the candidates, is still self-consistent.
- **The engine's verifier** (`sigil_engine::reference::verify_reference_matches`) closes that gap.
  For every release of the embedded set, whether the session has rows for it or not:
  - every member has exactly one row when a placement is at its path, an `Absent` row when there
    is none and discovery is complete, and no row otherwise;
  - every expected value is the set's;
  - the session names the set by its SHA-256.

| Where | `validate` | Verifier |
|---|---|---|
| `sigil inspect` | every session it writes | every session it writes (an internal error otherwise, exit 1) |
| `sigil session render`, `sigil explain` | every session read | when the session names the embedded set by its SHA-256 (a disagreement is exit 1). A session made with another set is rendered with a note |
| The browser viewer | every session read | **never**: it has no reference set |

## Not yet

- Mach-O and other formats: their content is matched by SHA-256 like any file, and their format is
  not identified.
- Component identity (ggml, llama.cpp), and the backends a library holds.
- Releases outside the embedded set, and releases built from a source commit.
- Optional members: an installation without a GPU backend's directory is INCOMPLETE against a
  release that ships it.
