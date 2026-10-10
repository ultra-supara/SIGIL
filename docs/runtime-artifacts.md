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
| `bin/ollama` | Its `lstat`, and, for a regular file, its contents hashed as a stream | — |
| `lib/ollama/` | Every entry, at any depth, each with its `lstat`. Regular files are hashed as streams | — |
| Symlinks | Their own `lstat` and target text (`readlinkat`): that is what a release lists for a link | **Never followed**, wherever they lead: inside `lib/ollama/`, elsewhere in `PREFIX`, or outside it. A link to a directory is not entered, and the file a link names is not opened through it |
| Anything else under `PREFIX` | — | Never opened (`bin/` other than `ollama`, `share/`, …) |

- **No symlink is followed, to the places or in them.** Every directory on the way to `bin/ollama`
  and `lib/ollama/`, and every file read, is opened with `O_NOFOLLOW`. If `bin`, `lib`, or
  `lib/ollama` is itself a symlink, that place is not inspected and discovery says so
  (`lib/ollama: a symlink, not followed`). So nothing outside the two places is read, even inside
  `PREFIX`.
- **Its own root.** The installation is the scan root `install`, on its own SafeFs, separate from
  the model store's.
- **The first 64 bytes** of each file give its format. An ELF file is recorded with its type and
  architecture, and one slice. The format does not affect matching. When the same bytes are also a
  model blob, the one artifact keeps the ELF format and slice.
- **A link is stable** only if a second `readlinkat` gives the same target text. Otherwise the
  placement is `ChangedDuringRead`, as is a file whose `fstat` changed during its read.
- **The budgets** (`--budget`, with `--install-dir` only) are recorded in `request.budgets` with an
  `install_` prefix:

  | Budget | Default | What it bounds |
  |---|---|---|
  | `install_files_discovered` | 4096 | Entries found: `bin/ollama`, and every entry under `lib/ollama/` of every kind |
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
| A link with the official target text whose target file is missing | `[v0.30.6]` (the link matches by text) | `Partial` (the file is absent) |
| `lib/ollama` replaced by a symlink to a copy elsewhere | none (discovery `Partial`) | `Partial` (`discovery incomplete`) |

The summary line says the same:

```
release: ollama v0.30.6 (34/34 files, 17/17 symlinks, 3/3 directories reference-matched; nothing absent)
release: content matches v0.30.6 (1/34 files, 0/17 symlinks, 0/3 directories present); incomplete
release: not established (2 reasons; sigil explain --coverage)
release: install not found
```

## Coverage

`artifacts.discovery`, `artifacts.release`, and `artifacts.container` (see Binaries) belong to the
scope `runtime_artifacts`, which the default policy audits when `--install-dir` is given.

**`artifacts.discovery`** (scope: the root `install`):

| State | When |
|---|---|
| `Complete` | Both places were listed in full, and every file and link target inside the install was read without a change |
| `Unavailable(NotFound)` | `PREFIX` does not exist, or has neither `bin/ollama` nor `lib/ollama/` |
| `Unavailable(PermissionDenied)` | `PREFIX` cannot be opened |
| `BudgetExceeded` | An `install_*` budget ran out |
| `Partial { missing }` | One place is missing (`<place>: not found`), or is reached through a symlink (`<path>: a symlink, not followed`); an entry was not read (`<path>: <reason>`: a FIFO, a permission, …); or a directory was not fully listed. A directory and a symlink are not gaps: both are observed in full |
| `Error { message }` | An entry vanished, or changed, during the scan |

**`artifacts.release`** (same scope):

| State | When |
|---|---|
| `Complete` | A claim, and nothing absent from any candidate |
| `Partial { missing }` | Otherwise, one entry per reason: `discovery incomplete`; `<release>: <n> files, <m> symlinks, and <k> directories absent from the install`; `<path>: not in any reference`; `<path>: matches no reference`; `<path>: symlink to <t>; <release>: <t'>`; `<path>: <kind> where <release> has a <kind>`; `<path>: not compared`; `mixed install: …` |
| The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

Without `--install-dir`, a policy that requires `runtime_artifacts` anyway gets its checks
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

## Binaries

Every ELF file of the install also gets its container facts: a `binaries` record per slice in the
session, read from the file's own bytes. They are observations, not identity.

- **How it is read.**
  - The parse runs on the fd that hashed the file, after hashing and before the post-read check.
    A file that changes while it is parsed is `ChangedDuringRead`, and its facts are dropped.
  - Each content is parsed once.
  - Everything goes through `pread`, never mapped or loaded, within `binary_parse_bytes`.
  - An ELF needs its whole header: 52 bytes for ELF32, 64 for ELF64.
- **What is read: the program headers first** (what the dynamic loader reads), then the sections:

  | Fact | Source | Confirmed absent (no gap) | Gap |
  |---|---|---|---|
  | Interpreter | `PT_INTERP` | no `PT_INTERP` | outside the file, or no NUL within 4 KiB |
  | SONAME, NEEDED (in order), RPATH, RUNPATH | `PT_DYNAMIC`, its strings through `DT_STRTAB`/`DT_STRSZ` in a `PT_LOAD`'s file-backed range | no `PT_DYNAMIC` (a static executable, a relocatable object) | `PT_DYNAMIC` out of the file, not a whole number of entries, or without its `DT_NULL` (the table may go on past what was read); strings not file-backed, an offset past `DT_STRSZ`; a `DT_RELASZ` or RELA `DT_PLTRELSZ` that is not a whole number of entries (the loader would apply a partial last one), or a `DT_RELAENT` other than the entry size (the loader refuses it), whether or not a data symbol needs the tables |
  | build-id | `PT_NOTE`, then `SHT_NOTE` | every note read, none `NT_GNU_BUILD_ID` | a malformed note |
  | `.comment`, stripped | the sections | a section header table without `.comment` | no section header table, or one out of the file (`sections: …`; stripped is then unknown) |
  | Export count, imports with versions, data symbols | `.dynsym` with its version tables; the relocations the loader applies, from `PT_DYNAMIC` | no `PT_DYNAMIC` | dynamic symbols without a `.dynsym` section, a malformed table, a version index that resolves to nothing, a `.gnu.version` shorter than `.dynsym`, a known data symbol defined twice |
  | Go build info | below | the whole range searched, no magic | below |

- **Known data symbols.** Four symbols from llama.cpp's `common/build-info.cpp`: `LLAMA_COMMIT`,
  `LLAMA_COMPILER`, `LLAMA_BUILD_TARGET` (pointers), and `LLAMA_BUILD_NUMBER` (an `int`). A value
  is the one the loader leaves, or `Unknown` with the reason. It is never guessed from a stored word:

  | At the symbol's address | Value |
  |---|---|
  | A RELA `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE` | the string at its addend |
  | Any other relocation | `Unknown` (`relocated by R_X86_64_64`, …) |
  | No RELA relocation, and the file has `DT_REL`/`DT_RELR` | `Unknown` (not read) |
  | A RELA table whose size or entry size is malformed (above) | `Unknown` (relocations not read) |
  | No relocation, in a non-PIE executable | the string at the stored address |
  | No relocation, in a position-independent file | `Unknown` |

- **Go build info**, as Go's `debug/buildinfo` reads it:
  - **Where:** the `.go.buildinfo` section, else the first writable, non-executable `PT_LOAD`.
  - **The search:** to its end, at 16-aligned virtual addresses, in 64 KiB chunks from an aligned start.
  - **What is read:** both formats (inline and pointer) in either byte order, Go's sentinel
    stripping, and its modinfo lines (`path`, `mod`, `dep`, `=>`, `build`). Where Go would read
    a malformed sentinel (an unterminated last line is one) as "no modules", SIGIL records a gap.
  - **What it is:** the binary's own claims about how it was built.
- **Output limits.** A malformed file cannot multiply a few input bytes into many values: each
  fact is built within its limit, so nothing beyond it is ever held (the relocation table keeps
  only the entries at the known symbols). At each limit, what was read is kept, and a gap says so:
  - 65,536 `PT_DYNAMIC` entries;
  - 1,024 NEEDED;
  - 64 RPATH/RUNPATH entries;
  - 4 KiB per string;
  - 1,024 notes per segment;
  - a 64-byte build-id;
  - 16 comments of 256 bytes;
  - `binary_imports` imports;
  - a 1 KiB Go version, 1 MiB of modinfo, 4,096 deps, and 1,024 build settings.
- **Budgets** (`--budget`, with `--install-dir` only):
  - `binary_parse_bytes` (64 MiB per artifact) bounds the parser's input cache, before anything
    is allocated, with 128 bytes of bookkeeping charged per cached read. A test measures the
    heap: files declaring millions of entries stay within it plus the output limits;
  - `binary_imports` (4,096 per slice).
- **`artifacts.container`** (scope: the root `install`), a third check of `runtime_artifacts`:

  | State | When |
  |---|---|
  | `Complete` | Discovery is complete, and every ELF file's facts have no gap |
  | `Partial { missing }` | Otherwise: `discovery incomplete`, and `<path>: <gap>` for each gap |
  | The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

  `Complete` means each fact was read in full or confirmed absent. Anything not parsed, not
  searched, or cut short is a gap.
- **NEEDED** is also recorded as `Declares` relations, one per distinct name. The order stays in
  the record, for the loader's lookup order.

## Not yet

- Mach-O and fat binaries, and `sigil binary inspect` (PR-4b-2). A Mach-O file's content is
  matched by SHA-256 like any file.
- Component identity (ggml, llama.cpp) from these facts, and the backends a library holds (PR-4c).
- Resolving NEEDED, RPATH, and RUNPATH to files (PR-4d).
- Releases outside the embedded set, and releases built from a source commit.
- Optional members: an installation without a GPU backend's directory is INCOMPLETE against a
  release that ships it.
