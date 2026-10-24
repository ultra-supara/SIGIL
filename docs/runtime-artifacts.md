# Runtime artifacts (`sigil-engine`, `--install-dir`)

With `--install-dir PREFIX`, SIGIL also inspects an Ollama installation. It hashes
`PREFIX/bin/ollama` and every entry under `PREFIX/lib/ollama/`. Each of them is compared with the
official release archives, whose member lists are embedded in SIGIL. The result answers two
separate questions:

- **Attribution:** which official releases the installed content matches.
- **Completeness:** whether the installation holds every member of that release.

- **Status:** `sigil inspect ollama --install-dir PREFIX`, in any mode and with any format.
- **Source:** plan §4.4.2, §4.4.3 (components), and §4.6.2. The session types are described in
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
- **The first 64 bytes** identify the format. ELF records its type and architecture as one slice.
  Thin Mach-O records its header; a fat Mach-O records each architecture, offset, size and digest.
  The format does not affect matching. When the same bytes are also a model blob, the artifact
  keeps its recognized format and slices.
- **A link is stable** only if a second `readlinkat` gives the same target text. Otherwise the
  placement is `ChangedDuringRead`, as is a file whose `fstat` changed during its read, or a file
  hashed whose open fd is not the file its `lstat` saw just before.
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
| `ollama-official`, version `2026-10-24` | v0.30.5, v0.30.6, v0.30.7 (linux-amd64) | 34 files, 17 symlinks, 3 directories |

- **Where it comes from.** Each official archive was streamed, without extraction, in PR-0, and
  its SHA-256 equals the digest published with the release. Every member was recorded with its type
  and mode, a file with its size and SHA-256, and a symlink with its target. The files are embedded
  unchanged (`crates/sigil-engine/refs/ollama-official/`).
- **What each release reports (PR-4c-2c).** `commits.toml` lists, for each release, the value one
  of its files reports for an embedded commit field: `LLAMA_COMMIT` of
  `lib/ollama/libllama-common.so.0.0.1` and `ggml_commit` (what `ggml_commit()` returns) of
  `lib/ollama/libggml-base.so.0.13.1`,
  `6f3a9f3de` in all three releases. Each member's SHA-256 is in the release's manifest, and SIGIL
  read these values from files with those SHA-256s (the official v0.30.6 install): the two members
  are byte-identical in the three releases. An open release claim compares an install's commits
  with these values.
- **In the session.** A session that compared names the set in `knowledge`:
  `KnowledgeRef { kind: ReferenceManifest, id: "ollama-official", version: "2026-10-24", sha256 }`.
  The SHA-256 covers the embedded files, `commits.toml` included. A session saved with an earlier
  version of the set is not re-verified by `sigil session render` and `sigil explain`, which say
  so ("note: reference matches and open release claims were made with another reference set and
  are not re-verified"). The embedded set's SHA-256 under another id is refused (exit 1).
- **What a match is.** A match is a comparison with the contents of the official archives. **It is
  not a signature check**, and it does not show who built the files.
- **Adding a release.** [`scripts/refmanifest/`](../scripts/refmanifest/README.md) describes it: a
  new manifest, its `commits.toml` entry, a new set version and pinned SHA-256, and a new SIGIL
  version.

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

- **The candidates** of the closed claim are the releases for which every placement has a matching
  row.
- **A release claim** (`releases`, basis `ReferenceMatches`, the placements as its files) is
  recorded only when discovery is `Complete` and there is at least one candidate. Releases with
  identical content are all candidates. It is **closed**.
- **An open release claim** (basis `SelfReportedCommit`, PR-4c-2c) is recorded when there is no
  closed one and the install's files report commits. Its commits are the `Embedded` values of the
  fields whose role is `commit` in the component database (`LLAMA_COMMIT`, `ggml_commit`), each
  7 to 40 lowercase hex digits; a value such as `unknown` is ignored. Its candidates are the
  releases of the set whose own files report, for every field collected, a value that agrees with
  the install's: one is a prefix of the other, since a commit is abbreviated to a prefix, here of at
  least 7 digits. Without a commit, or without such a release, there is none. It says only that the
  install is *consistent with* those releases: a custom build, a mixed install, or an unlisted
  release is not excluded. `artifacts.release` is unchanged by it. The values are those of the
  linux-amd64 archives; an arm64 install that reports the same commit gets the same candidates,
  which are release tags.
- **`artifacts.release` is `Complete`** only when there is a closed claim and no candidate has an
  `Absent` row. An installation whose content matches v0.30.6 but which lacks some of its
  libraries is attributed to v0.30.6 and is INCOMPLETE.

| Install | Claim | `artifacts.release` |
|---|---|---|
| An unmodified v0.30.6 | `[v0.30.6]` | `Complete` |
| `bin/ollama` of v0.30.6, `lib/ollama/` empty | `[v0.30.6]` | `Partial` (members absent) |
| A library replaced by any other bytes, ELF or not | open `[v0.30.5, v0.30.6, v0.30.7]` (the commits of the official `libllama-common` or `libggml-base` left); none when the replacement reports a commit that disagrees with `6f3a9f3de` | `Partial` (`matches no reference`) |
| `bin/ollama` of v0.30.5 and a library only v0.30.6 has | open `[v0.30.5, v0.30.6, v0.30.7]` (the libraries' commits) | `Partial` (`mixed install`) |
| A link with the official target text whose target file is missing | `[v0.30.6]` (the link matches by text) | `Partial` (the file is absent) |
| `lib/ollama` replaced by a symlink to a copy elsewhere | none (discovery `Partial`; no library read) | `Partial` (`discovery incomplete`) |

The summary line says the same:

```
release: ollama v0.30.6 (34/34 files, 17/17 symlinks, 3/3 directories reference-matched; nothing absent)
release: content matches v0.30.6 (1/34 files, 0/17 symlinks, 0/3 directories present); incomplete
release: not established (2 reasons; sigil explain --coverage)
release: install not found
```

## Coverage

`artifacts.discovery`, `artifacts.release`, `artifacts.container`, and `artifacts.identity` (see
Binaries) belong to the scope `runtime_artifacts`, which the default policy audits when
`--install-dir` is given.

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
| `Complete` | A closed claim, and nothing absent from any candidate |
| `Partial { missing }` | Otherwise, one entry per reason: `discovery incomplete`; `<release>: <n> files, <m> symlinks, and <k> directories absent from the install`; `<path>: not in any reference`; `<path>: matches no reference`; `<path>: symlink to <t>; <release>: <t'>`; `<path>: <kind> where <release> has a <kind>`; `<path>: not compared`; `mixed install: …` |
| The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

Without `--install-dir`, a policy that requires `runtime_artifacts` anyway gets its checks
`Skipped { Flag("--install-dir") }`, so the result is INCOMPLETE.

## Verification

- **`Session::validate`** checks the rows and the claims against the session itself (V1–V12 in
  [`docs/session-model.md`](session-model.md#what-sessionvalidate-checks)). Each row's observed
  value must be the placement's own fact. A match needs a stable read. `Absent` needs a complete
  discovery. The candidates are recomputed from the rows, and `artifacts.release` is `Complete`
  exactly when the claim, the discovery, and the absent members allow it. An open claim rests on
  commits that are the claims' own `Embedded` assertions.
- **`validate` cannot know the set.** It cannot tell that a release lists a member, that a
  release exists, or which commit a release reports. A session with every row of one release
  removed, and that release dropped from the candidates, is still self-consistent; so is an open
  claim with other candidates.
- **The engine's verifier** (`sigil_engine::reference::verify_reference_matches`) closes that gap.
  For every release of the embedded set, whether the session has rows for it or not:
  - every member has exactly one row when a placement is at its path, an `Absent` row when there
    is none and discovery is complete, and no row otherwise;
  - every expected value is the set's;
  - the session names the set by its id and SHA-256;
  - no row names another reference set.

  `verify_release_claims` (PR-4c-2c) recomputes the release claims of a session that names the
  set. The closed claim comes from the session's rows of this set and its placements under the
  install root (V10 and the checks above pin the rows): the releases every placement matches,
  and a claim for `ollama` after a complete discovery, none without an install root. The open
  claim comes from the component claims derived from the session's binary facts and the set's
  commit data, and only when there is no closed claim. The session's claims, of any product,
  must be exactly these, up to canonical order: so there is no open claim beside a closed one,
  and a closed claim cannot be relabelled or dropped to make room for an open one. `validate`
  requires an open claim's session to have some reference set in `knowledge` (V12), so none
  escapes the verifier by naming none. A session that names another set (or another version of
  this one) is rendered with a note instead, and one with the embedded set's SHA-256 under
  another id is refused. A session that names the set has no reference row of another set.

| Where | `validate` | Verifier |
|---|---|---|
| `sigil inspect` | every session it writes | both, on every session it writes (an internal error otherwise, exit 1) |
| `sigil session render`, `sigil explain` | every session read | both, when the session names the embedded set by its SHA-256 (a disagreement is exit 1). A session made with another set is rendered with a note |
| The browser viewer | every session read | **never**: it has no reference set |

## Binaries

Every ELF or Mach-O file of the install also gets its container facts: a `binaries` record per
slice in the session, read from the file's own bytes. They are observations, not identity.

- **How it is read.**
  - The parse runs on the fd that hashed the file, after hashing and before the post-read check.
    A file that changes while it is parsed is `ChangedDuringRead`, and its facts are dropped.
  - Each content is parsed once.
  - Everything goes through `pread`, never mapped or loaded, within `binary_parse_bytes`.
  - ELF needs its whole header: 52 bytes for ELF32, 64 for ELF64. Mach-O records thin headers or
    each architecture in a fat container.
- **What is read: the program headers first** (what the dynamic loader reads), then the sections:

  | Fact | Source | Confirmed absent (no gap) | Gap |
  |---|---|---|---|
  | Interpreter | `PT_INTERP` | no `PT_INTERP` | outside the file, or no NUL within 4 KiB |
  | SONAME, NEEDED (in order), RPATH, RUNPATH | the last `PT_DYNAMIC` (glibc and musl keep the last one), read where its `p_vaddr` is in a `PT_LOAD`'s file-backed range; its strings through `DT_STRTAB`/`DT_STRSZ` in such a range | no `PT_DYNAMIC` (a static executable, a relocatable object) | more than one `PT_DYNAMIC`; a `p_vaddr` that is not file-backed, a table out of the file, not a whole number of entries, or without its `DT_NULL` (the table may go on past what was read); strings not file-backed, an offset past `DT_STRSZ`; a `DT_RELASZ`, `DT_RELSZ`, or `DT_PLTRELSZ` that is not a whole number of entries (the loader would apply a partial last one), or a `DT_RELAENT`, `DT_RELENT`, or `DT_RELRENT` other than the entry size (the loader refuses it); a table tag without its size or entry size (`DT_RELA`, `DT_REL`, `DT_RELR`: glibc reads them with no NULL check); a `DT_RELRSZ` that is not a whole number of words; a non-empty `DT_RELA`, `DT_REL`, `DT_JMPREL`, or `DT_RELR` table that is not in the file where a `PT_LOAD` maps it (the loader reads each, whether or not a value needs it); `DT_JMPREL`, `DT_PLTREL`, and `DT_PLTRELSZ` not all present (glibc skips the table, musl applies it); a `DT_PLTREL` other than `DT_RELA` on x86-64 and AArch64, or other than `DT_REL`/`DT_RELA` elsewhere (glibc asserts it); a `DT_JMPREL` that ends where `DT_RELA` ends but is longer (glibc's size arithmetic wraps); a `DT_RELACOUNT` past `DT_RELASZ`'s entries, or one that covers a relocation that is not RELATIVE (glibc applies the first `DT_RELACOUNT` entries as RELATIVE and does not stop at `DT_RELASZ`; musl ignores it). All of these are checked whether or not a data symbol needs the tables |
  | build-id | `PT_NOTE`, then `SHT_NOTE` | every note read, none `NT_GNU_BUILD_ID` | a malformed note |
  | `.comment`, stripped | the sections | a section header table without `.comment`, every section name read | no section header table, or one out of the file (`sections: …`; stripped is then unknown); a section whose name cannot be read (`malformed: section names: …`): it could be `.comment` or `.go.buildinfo` |
  | Export count, imports with versions, data symbols | `.dynsym` with its string table and version tables, checked against what the loader uses: each section must be at its tag's address (`DT_SYMTAB`, `DT_STRTAB`, `DT_VERSYM`, `DT_VERNEED`, `DT_VERDEF`), and the `PT_LOAD`s must map that address to its `sh_offset` (object reads the section there, the loader the address); the symbols `DT_HASH` and `DT_GNU_HASH` reach, each read whole (its buckets, chains, and bloom words); the largest symbol index of the relocation tables (RELA, REL, `DT_JMPREL`, read in full whether or not a data symbol needs them), counted for each type whose symbol a loader reads (not `R_*_NONE` on x86-64 and AArch64: neither glibc nor musl reads its symbol; musl does read a RELATIVE's nonzero index); the relocations the loader applies, from `PT_DYNAMIC`. Import names are read in full up to 65,536 bytes. For a relocatable object (`ET_REL`), its `.symtab`: the undefined symbols left for the linker (not the final program's imports), with no versions; a known data symbol there is `Unknown` with its gap (its data is not linked yet) | no `PT_DYNAMIC` (never for a relocatable object: its `.symtab` is required) | dynamic symbols without a `.dynsym` section, a malformed table, a version index that resolves to nothing, a `.gnu.version` shorter than `.dynsym`, a `.dynsym` (or its string table) not at `DT_SYMTAB` (`DT_STRTAB`) or not the bytes mapped there, `DT_SYMTAB` without `DT_STRTAB` or without either hash table; with `PT_DYNAMIC` read, a `.dynsym` without `DT_SYMTAB`, or a version section without its tag (the loader reads none of them); a `.dynsym` of another length than a hash table reaches or a relocation names, a hash table that cannot be read in full, or that the loader could not index (no bucket; for `DT_GNU_HASH`, a bloom word count that is not a power of two; for `DT_HASH`, a bucket or chain index past `nchain`, or one reached twice), a `DT_GNU_HASH` bucket below its `symoffset` or a `symoffset` past `.dynsym`'s entries, `DT_VERSYM`, `DT_VERNEED`, or `DT_VERDEF` without its section (`.gnu.version`, `.gnu.version_r`, `.gnu.version_d`) or with one elsewhere or not the bytes mapped there, `DT_VERNEED` or `DT_VERDEF` without `DT_VERSYM` (glibc reads it with no NULL check, and the imports' versions are unknown), a `.gnu.version` that does not link `.dynsym` (object names the versions from the linked table's strings), an import name over 65,536 bytes, a defined symbol of any type whose name cannot be read (it could be a known one); for a relocatable object (`ET_REL`), no `SHT_SYMTAB` |
  | Go build info | below | the whole range searched, no magic | below |
  | Mach-O header, UUID, dylib ID, loaded dylibs, RPATHs, dynamic linker | Mach-O header and load commands. The other commands dyld requires (`LC_DYLD_INFO_ONLY`, `LC_MAIN`, `LC_DYLD_EXPORTS_TRIE`, `LC_DYLD_CHAINED_FIXUPS`, `LC_FILESET_ENTRY`) hold no fact and are skipped | the command is absent | malformed header or command, an out-of-range string, or an output limit; a skipped command shorter than its structure; a required (`LC_REQ_DYLD`) command SIGIL does not know, after which no command is read |
  | Fat Mach-O architecture table | fat header and architecture entries | not a fat container | truncated, overlapping, misaligned, or out-of-file slices; one architecture listed twice (the CPU type, and the subtype without its capability bits, as lipo compares them); a slice whose own header names another architecture than its entry |

- **Known data symbols.** Four symbols from llama.cpp's `common/build-info.cpp`: `LLAMA_COMMIT`,
  `LLAMA_COMPILER`, `LLAMA_BUILD_TARGET` (pointers), and `LLAMA_BUILD_NUMBER` (an `int`). A value
  is the one the loader leaves, or `Unknown` with the reason. It is never guessed from a stored word.
  An entry that `DT_RELA` and `DT_JMPREL` both list is one relocation. glibc takes a `DT_JMPREL`
  at `DT_RELA`'s end out of it; in any other overlap, the entry is applied twice and writes the
  same bytes each time. A relocation writes from its offset as many bytes as its type does:
  - `R_*_NONE` writes none, and a write of no bytes overlaps nothing, even inside a value;
  - `R_*_COPY` writes its symbol's `st_size` (glibc copies at most it, musl exactly it), or to the
    end of the address space when its symbol is past `.dynsym`;
  - `R_*_TLSDESC` writes 16 bytes;
  - any other x86-64 or AArch64 (ELF64) type writes 8 bytes;
  - another machine's type writes to the end of the address space.


  | At the symbol's address | Value |
  |---|---|
  | The file has `DT_REL`/`DT_RELR` | `Unknown` (not read: they may write the same bytes) |
  | A known name defined more than once (whatever the types), or once but not as `STT_OBJECT` | `Unknown` (`defined more than once`, `not a data object (STT_FUNC)`, …) |
  | Exactly one RELA `R_X86_64_RELATIVE` / `R_AARCH64_RELATIVE`, at the pointer itself | the string at its addend |
  | Any other relocation over the value's bytes | `Unknown` (`relocated by R_X86_64_64`, `a relocation overlaps it (…)`, `relocated more than once`) |
  | A relocation over the string's bytes | `Unknown` (`a relocation writes into the string (…)`) |
  | A RELA table whose size or entry size is malformed (above) | `Unknown` (relocations not read) |
  | In a relocatable object (`.o`): its data is not linked yet | `Unknown` (not linked yet) |
  | No relocation, in a non-PIE executable | the string at the stored address |
  | No relocation, in a position-independent file | `Unknown` |

- **Go build info**, as Go's `debug/buildinfo` reads it:
  - **How an address is read:** as Go 1.25's reader reads it, through the first program header of any type that holds it, counted in wrapping `uint64` (so a header at address 0 of size 0 listed first takes every address and holds nothing), and only as far as that header's bytes go.
  - **Where:** the `.go.buildinfo` section at its address, whatever its type, else the first writable, non-executable `PT_LOAD` up to its `p_memsz`.
  - **The search:** at 16-aligned virtual addresses, in Go's 1 MiB chunks from an aligned start. Go searches the bytes its reader gives, then moves a whole chunk on, and it stops where it gets none: the segment search then has no build info, and a section is a gap. A misaligned magic before the build info is a gap, because Go's search then returns another address.
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
  - 64 fat slices, 65,536 Mach-O load commands, 8 MiB of load commands, 1,024 names per field;
  - a 64-byte build-id;
  - 16 comments of 256 bytes;
  - `binary_imports` imports;
  - a 1 KiB Go version, 1 MiB of modinfo, 4,096 deps, and 1,024 build settings.
- **Budgets** (`--budget`, with `--install-dir` only):
  - `binary_parse_bytes` (64 MiB per artifact) bounds the parser's input cache, before anything
    is allocated, with 128 bytes of bookkeeping charged per cached read. A test measures the
    heap: files declaring millions of entries stay within it plus the output limits;
  - `binary_imports` (4,096 per slice);
  - `binary_scan_bytes` (64 MiB per artifact): the section bytes the signature scan reads
    (below).
- **`artifacts.container`** (scope: the root `install`), a third check of `runtime_artifacts`:

  | State | When |
  |---|---|
  | `Complete` | Discovery is complete, and every ELF or Mach-O slice's facts have no gap |
  | `Partial { missing }` | Otherwise: `discovery incomplete`, and `<path>: <gap>` for each gap |
  | The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

  `Complete` means each fact was read in full or confirmed absent. Anything not parsed, not
  searched, or cut short is a gap.
- **NEEDED** and Mach-O loaded dylibs are also recorded as `Declares` relations, one per distinct
  name. The order stays in the record, for the loader's lookup order.
- **Capability hints.** Each ELF slice also gets one feature hint per capability import:
  `posix.network` for `connect`, `posix.dynamic_loading` for `dlopen` or `dlsym`, and so on (the
  28 names are listed in [binary inspection](binary-inspect.md#capabilities-and-code---code)). A
  hint says that the file imports the function, never that its code calls it, and
  `inspect ollama` analyzes no code. The report's **Binaries** table shows them in the column
  **Capabilities (imports)**: the slice's distinct capability keys, in key order, or `-`. When
  the slice's import list was cut short at `binary_imports`, the keys of the imports past the cut
  are not known, and the cell says so: `- (imports cut short)`, or the keys followed by
  ` (imports cut short)`.
- **Signatures** (PR-4c-2a). Each ELF slice is also scanned for the signature database's needles,
  on the same fd, after its parse, as a binary inspection scans it
  ([binary inspection](binary-inspect.md#signatures)): export names (`rpc.code_present` for an
  export named `ggml_backend_rpc_…`), Go function names in `.gopclntab`
  (`ollama.llama_server_launch` and `ollama.device_discovery`), and strings in read-only data
  (none ship yet). Each needle found is a hint: the name is in the file, which does not show
  that its code runs. Section bytes are charged to `binary_scan_bytes`.

  The same walk of the exports finds `ggml_version` and `ggml_commit`. These are not needles: the
  strings they return are read first, without running them (PR-4c-2b;
  [binary inspection](binary-inspect.md#returned-values)), and charged to `binary_scan_bytes` with
  the functions' bytes. `libggml-base` returns `0.13.1` and `6f3a9f3de` on the official v0.30.6
  bundle.

  A file whose own file name the database gives to an NVIDIA library is never scanned (ADR-010;
  [below](#components)), unless the same content is also placed under a name that is scanned. The
  exclusion goes by name, not by content: a Go executable renamed `libcudart.so.12` is not
  scanned either, and its `cuda-runtime` claim reads `name only`, not `reference matched`, since
  its hash is not the release's. The report's **Binaries** table shows the slice's signature keys
  in the column **Signatures**, after **Capabilities (imports)**, in key order, or `-`. A `-`
  means that no signature hint was found, or that the file was not scanned: a file named as an
  NVIDIA library is never scanned (ADR-010), and an install session does not record which files
  those were.
- **`artifacts.identity`** (scope: the root `install`), a fourth check of `runtime_artifacts`:

  | State | When |
  |---|---|
  | `Complete` | Discovery is complete, no binary is a Mach-O, and every ELF slice has facts and a scan without a gap (an NVIDIA library is not scanned, and adds no gap) |
  | `Partial { missing }` | Otherwise, sorted: `discovery incomplete`; `<path>: <gap>` for each scan gap (`string scan: binary_scan_bytes <limit> exceeded`, `string scan: no section headers`, `string scan: no .gopclntab section`, …; the list is in [binary inspection](binary-inspect.md#signatures)), and for each returned value not read (`returned value: ggml_version: not decoded: x86-64 only`, …; [binary inspection](binary-inspect.md#returned-values)); `<path>: string scan: ELF only` for a Mach-O file; `<path>: not parsed` for an ELF without facts |
  | The state of `artifacts.discovery` | Discovery is `Unavailable`, `BudgetExceeded`, or `Error` |

  On the official v0.30.6 bundle it is `Complete`: its NVIDIA libraries are not scanned, and
  `bin/ollama`'s `.gopclntab` (10.9 MiB) is within the budget, with both Go-function hints. On an
  arm64 installation, `libggml-base`'s two values are not decoded (x86-64 only), so it is
  `Partial`, and the result `INCOMPLETE`: a value not read is never hidden.

## Components

An ELF slice of the installation gets a component claim from the facts above when the component
database knows one of its names (PR-4c-1). Nothing more is read.

- **The database** (`crates/sigil-engine/signatures/components.toml`) has one entry per
  component, 16 in all, keyed as the upstream library: `ollama`, `ggml`, `ggml-base`,
  `ggml-backend/cpu`, `ggml-backend/cuda`, `ggml-backend/vulkan`, `ggml-backend/rpc`,
  `llama.cpp`, `llama.cpp/common`, `llama.cpp/mtmd`, `llama.cpp/server`, `llama.cpp/quantize`,
  `gcc/libgomp`, `cuda-runtime`, `cuda/cublas`, and `cuda/cublasLt`. Each lists the names that
  name it: an exact name (`ollama`), a library with an optional version (`libggml.so`,
  `libggml.so.0`, `libggml.so.0.13.1`), or a prefix and a suffix around one variant of ASCII
  letters, digits, and `_` (`libggml-cpu-<variant>.so`). There are no regular expressions. A name
  that two entries match names no component. Every regular file of the embedded releases is
  named by exactly one entry. `ggml-backend/rpc` (`libggml-rpc.so`, upstream ggml's RPC
  backend) is in none of the embedded releases (v0.30.5–v0.30.7); a policy may deny it. NVIDIA
  libraries are identified by name and hash only (plan ADR-010): their entries (`cuda-runtime`,
  `cuda/cublas`, `cuda/cublasLt`) say `scan = false`, so a file whose own file name they name is
  never scanned for signatures. A SONAME or a link's name does not count.
- **Embedded fields** (PR-4c-2b), in the same database, give each embedded value a role: a
  version, a commit, or none.

  | Field | Read from | Role |
  |---|---|---|
  | `LLAMA_BUILD_NUMBER` | a known data symbol | a version of its own kind (it counts builds) |
  | `LLAMA_COMMIT` | a known data symbol | a commit |
  | `ggml_commit` | what the exported function returns | a commit |
  | `ggml_version` | what the exported function returns | a version, `ggml-base`'s own |

  An embedded value whose field is not listed (`LLAMA_COMPILER`, `LLAMA_BUILD_TARGET`, Go build
  info) has no role.
- **Names.** A slice is named by the file name of each stable placement of its content, by each
  stable symlink placement whose targets lead there one bare file name at a time, in the link's
  own directory (`libggml-base.so` → `libggml-base.so.0` → `libggml-base.so.0.13.1`; at most 40
  links, each read as recorded, never followed), and by its SONAME. The claim's component is the
  first name the database knows: file names in path order, then the SONAME. A slice whose names
  the database does not know gets no claim, and reports show `-` for it. A Mach-O slice gets
  none yet.
- **What a claim holds,** every source kept:
  - a `SelfName` per name, `Filename` or `Soname`, known to the database or not;
  - an `Embedded` value per `LLAMA_*` data symbol whose value is known, per string that
    `ggml_version` or `ggml_commit` was read to return (`FunctionReturn`), and the Go build info's
    `go.version` and `go.path` (`go.main`, the main module's path, when there is no path). They
    are attributed to the component the names give, and never name one on their own;
  - a `KnownHash` per reference row of a placement that holds the content (a link's own rows are
    not counted): its reference, release, and member, and whether it matched;
  - `Signature { NotChecked }`: no signature is checked, and it is not identity evidence;
  - versions: the dotted number after `.so.` of each name that names the component (`0.13.1`,
    `0`), and the value of each embedded field whose role is a version (`LLAMA_BUILD_NUMBER`,
    `ggml_version`), each with its source.
- **Status**, the first that applies:

  | Status | When |
  |---|---|
  | `Conflicting` | Two names that the database gives different components; two versions of one kind whose major keys disagree; or two different values of one commit field (`LLAMA_COMMIT`, `ggml_commit`: ggml's commit and llama.cpp's are not compared with each other) |
  | `ReferenceMatched` | A `KnownHash` matched |
  | `Corroborated` | A code check matched (none yet: code checks come with profiles) |
  | `NameOnly` | A name or an embedded value |

  **Major keys** (PR-4c-2b). A version's major key is its first number, or, when that is `0`, its
  first two (semver reads `0.y` as breaking). Two keys are compared over the numbers both have, so
  `0` (a SONAME) agrees with `0.13` and with `0.12`; `0.13.1` agrees with `0.13.2`; `0.12.0`
  disagrees with `0.13.1`; `1` disagrees with `0.13`. The names' versions and those of a field
  whose `of` names the component (`ggml_version` for `ggml-base`) are one kind: the version a file
  reports itself is compared with the versions in its names. Every other version field is its own
  kind, compared with no other version. `libggml-base`'s `0.13.1` (file name), `0` (SONAME), and
  `0.13.1` (`ggml_version`) agree.

  `Unidentified` is never given: a claim exists only when the database knows a name. On the
  official v0.30.6 bundle, each of the 34 files is `ReferenceMatched`, with a matched `KnownHash`
  for v0.30.6. A mixed installation still gets no release claim (`mixed install: …`, as above):
  each file's known hashes say which release it matches.
- **The report.** The **Binaries** table has a **Component** column after **Type**:
  `<component> (<status>)`, the status in words (for example `ggml-base (reference matched)`),
  or `-`.
- **Policy.** A `[[components.deny]]` entry applies to these claims, `NameOnly` ones included,
  through the claim's component or any of its names (PR-4c-2b): a `Conflicting` claim whose
  SONAME names a denied component is a violation, whose subject is the claim itself. Its
  component must be a key of the database: any other key does not load ([policy](policy.md)).

## Not yet

- The open release set of a self-reported commit (PR-4c-2c).
- Mach-O sections and `__gopclntab`: a Mach-O is not scanned for signatures yet.
- Resolving NEEDED, RPATH, and RUNPATH to files, and the `Required` identity assertions that need
  it (PR-4d).
- Releases outside the embedded set, and releases built from a source commit.
- Optional members: an installation without a GPU backend's directory is INCOMPLETE against a
  release that ships it.
