# Inspecting binaries directly

`sigil binary inspect` reads one or more files and writes one session (or its Markdown) for all
of them. For each file the session holds its digest, size, format, container facts, and, for ELF,
the capability imports it asks for (`connect`, `dlopen`, …). With `--code`, it also records where
an x86-64 ELF file calls those imports directly. It needs no model store, installation, or
running runtime, and it never executes or loads what it reads.

```bash
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so ./net.o --format md --out out/binary.md
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so --fail-on-incomplete
cargo run -q -p sigil-cli -- binary inspect --code ./suspicious_kernel.o --format md
```

## What is recorded

Each input is its own scan root, `binary-<n>` in the order of first appearance. The root's path is the file,
after the symlinks in the argument are resolved. A file named twice, directly or through a
symlink, is one input. For each input, the session records:
- **The read:** its digest and size, and its format. Supported containers are ELF executable,
  shared object, relocatable object (`.o`), thin Mach-O, and universal (fat) Mach-O.
- **Its container facts,** for ELF and each Mach-O slice. ELF facts match those the installation scan records (see
  [runtime artifacts](runtime-artifacts.md#binaries)):
  - interpreter, SONAME, NEEDED, RPATH, RUNPATH;
  - build-id, `.comment`, stripped;
  - exports and imports;
  - the known data symbols (in a relocatable object, each is `Unknown` with a gap: its data is
    not linked yet), and Go build info.
  Mach-O facts include the header CPU type, subtype, file type and flags; UUID, dylib ID, loaded
  dylibs, RPATHs, and dynamic linker. A fat file records each architecture slice's offset, size,
  digest, table CPU type/subtype, and alignment.
- **One `binary.container` coverage entry:** the input's status.
- **Its capability hints,** for each ELF slice, with or without `--code`
  ([below](#capabilities-and-code---code)).
- **With `--code`:** the direct call sites of the capability imports, and one `binary.code`
  coverage entry ([below](#capabilities-and-code---code)).

| The input | Status |
|---|---|
| An ELF or Mach-O, every fact read in full or confirmed absent | `Complete` |
| A recognized ELF or Mach-O with gaps, or without slice facts | `Partial`, listing them (`not parsed` without facts) |
| Anything else (a script, a PE, or another unsupported format) | `Unsupported` |
| Over the `binary_bytes` budget | `BudgetExceeded`: not read, later inputs still are |
| Changed or removed while it was read | `Error` |

Under the default policy, any status other than `Complete` makes the result `INCOMPLETE`. The same
holds for any policy that sets `binary_audit = ["binary"]` or omits the key. Only an explicit
`binary_audit = []` requires nothing, and the result is then `COMPLETE` whatever the statuses.
With `--code`, `binary_code_audit` adds `binary.code` the same way, so a run with `--code`
requires nothing only when both `binary_audit = []` and `binary_code_audit = []`.

The fat Mach-O magic also begins a Java class file. SIGIL treats a structurally valid fat
architecture table as Mach-O; when that table is invalid but the file has a valid Java class
header and constant pool, it is treated as an unsupported format. This resolves the shared-magic
ambiguity in favor of a valid fat table.

No rule judges binaries yet, so the verdict is `PASS`. Use `--fail-on-incomplete` (exit 4) to
fail on an unsupported or partial input.

The summary on stderr has one `binary:` line per input, in argument order: its path, type,
digest, and status. With `--code`, the line ends with the input's `binary.code` status, in the
same form: for example `code: complete`, `code: partial (3 gaps)`, or `code: unsupported: …`.

**Imports are not calls.**
- For an executable or a shared object, imports are the dynamic symbols its loader resolves.
- For a relocatable object, they are the undefined symbols left for the linker. They are not the
  final program's imports.
- Mach-O loaded dylibs are declared dependencies, not symbol-level imports.
- Neither shows that the code calls them. Without `--code`, no code is analyzed and no call site
  is recorded; with it, the call sites are the direct ones found in the code.

## Capabilities and code (`--code`)

**Capability hints.** A binary inspection records the capability imports of each ELF slice: 28
libc/POSIX functions in 7 groups. Each is a feature hint in the session (its `feature`, `signal:
Import`, and the import's name as `value`), with or without `--code`. `inspect ollama
--install-dir` records them too ([runtime artifacts](runtime-artifacts.md#binaries)). A hint is
import-level evidence: the file asks its loader (or, for a `.o`, its linker) for the function.
It is not proof that the code calls it. A missing hint is not proof that the code cannot: a
function linked statically into the file, one looked up at run time, and a raw system call are
not imports.

| Capability | Imports |
|---|---|
| `posix.network` | `connect`, `getaddrinfo`, `send`, `sendto`, `recv`, `recvfrom`, `socket` |
| `posix.file_read` | `open`, `openat`, `fopen`, `read`, `pread` |
| `posix.file_write` | `write`, `pwrite`, `fwrite`, `creat`, `rename`, `unlink` |
| `posix.process_spawn` | `execve`, `fork`, `posix_spawn`, `system` |
| `posix.dynamic_loading` | `dlopen`, `dlsym` |
| `posix.environment_access` | `getenv`, `setenv`, `putenv` |
| `posix.anti_debug` | `ptrace` |

The match is on the exact name; a version (`connect@GLIBC_2.2.5`) is not part of it. Only the
imports kept within `binary_imports` give hints. Mach-O imports are not mapped yet.

**`--code`** also finds where each capability import is called directly, and records each call
site:
- **where:** its address, and whether it is a call or a tail jump;
- **the target:** the import, and how it is reached: `Plt`, `PltSec`, `Got`, or, in a `.o`,
  `Reloc` (a relocation);
- **the arguments** the import takes (`connect` 3, `dlopen` 2, …). Each is the register's value
  at the call: a constant, a string in read-only data, a parameter of the function, the return
  value of another recorded call, the operand of a load (not the value loaded), the low bits of a
  value, a set of 2 to 4 values, or unknown, with the reason;
- **the function** that holds it: its bounds, from its FDE in `.eh_frame`, and its symbol names.

```bash
cargo run -q -p sigil-cli -- binary inspect --code ./suspicious_kernel.o --budget binary_code_bytes=67108864 --fail-on-incomplete
```

In the Markdown, the overview table gains a **Code** column: each input's `binary.code` status.
Each ELF file's facts are followed by its Capabilities table, with one row per capability import:
the number of its direct call sites, the first five in address order, and how many more the
session JSON holds (`… and 3 more (session JSON)`). For the test fixture
`suspicious_kernel-gcc-O2.o`, whose function `kernel` calls `connect(0, 0, 0)`, the table reads,
once rendered:

```text
| Capability | Import | Direct call sites |
|---|---|---|
| posix.network | connect | 1: kernel @ 0x4d: connect(rdi=0, rsi=0, rdx=0) |
```

- `none found (see binary.code)`: the input's code was searched (`binary.code` is complete or
  partial), and no direct call site of the import was found in it. A partial `binary.code`
  lists, under Coverage, what was not searched or not confirmed.
- `not analyzed (use --code)`: the run had no `--code`.
- `not analyzed (see binary.code)`: the run had `--code`, but the input's code was not searched
  (its `binary.code` is neither complete nor partial, e.g. unsupported for an AArch64 ELF). It is
  never `none found`.
- `No capability imports.` replaces the table for an ELF file without capability imports.
- With `--code`, a line under the table (or under `No capability imports.`) gives the input's
  `binary.code` status and, when its code was searched, the code bytes read:
  `binary.code: complete; 78 of 268435456 code bytes read.`
- A Mach-O gets neither the table nor the line.

**Scope.** Only direct calls are found:
- A call through a function pointer, a function linked statically into the file, and a raw
  system call are not found, and references from data are not followed.
- Only executable sections and the ranges of FDEs in `.eh_frame` are searched, and only code with
  an FDE is analyzed. Only the functions that hold a reference to a capability import are
  decoded, each from its FDE start.
- x86-64 ELF only (64-bit, little-endian). A Mach-O, an ELF of another machine, an ELF32, or a
  big-endian ELF is `Unsupported`.
- In a relocatable object (`.o`), addresses are file offsets.

Absence therefore means "no direct call site in the scanned code", never "not called".

**`binary.code`.** With `--code`, each input also gets one `binary.code` coverage entry:

| The input | `binary.code` |
|---|---|
| Analyzed, and every reference to a capability import in the scanned code is a confirmed direct call (or part of another instruction) | `Complete`, with the code bytes read |
| Analyzed with gaps (a reference not confirmed, a function not decoded or solved, a refused read, a limit reached), or an x86-64 ELF whose facts were not parsed | `Partial`, listing them (`not parsed` for the last); the confirmed calls are recorded all the same |
| A Mach-O, an ELF of another machine, an ELF32 or big-endian ELF | `Unsupported` (`code analysis: x86-64 ELF64 little-endian only`) |
| Not a supported container, over `binary_bytes`, or changed or removed while read | the `binary.container` status |

Under the default policy, `binary.code` is required, so any status other than `Complete` makes the
result `INCOMPLETE` (exit 4 with `--fail-on-incomplete`).

**Budgets and limits.**
- **`binary_code_bytes`** (default 256 MiB per artifact) bounds the bytes read for code: code,
  `.eh_frame`, PLT sections, and strings. A read over it is refused, and `binary.code` is
  `Partial` with `binary_code_bytes: <limit> exceeded`. Section headers, symbols, and relocations
  are read under `binary_parse_bytes` instead. `binary_code_bytes` is the only code budget
  `--budget` takes, and only with `--code` (exit 2 otherwise).
- **The other limits are fixed,** per artifact: 65,536 references; 1,048,576 FDEs, GOT slots, and
  relocations; 4,000,000 decoded instructions; 134,217,728 register-value steps; 65,536 call
  sites; and 16 MiB of call-target names. Reaching one records a gap and stops the analysis, so
  `binary.code` is `Partial`. Function names and an internal callee's export name count against
  the same 16 MiB, but they are filled last: one that does not fit is left out, with no gap. At
  most 256 distinct gaps are listed; the others are counted. These limits are not recorded in
  the session. The [session model](session-model.md#code-analysis-pr-5a) lists each one with its
  gap.

## Inputs and errors

A path that cannot be inspected stops the run with exit 1, and nothing is written. That covers
a path that is:
- missing;
- a directory, a FIFO, or a device;
- a file SIGIL may `lstat` but not open;
- a file with a non-UTF-8 name;
- a file replaced after it was resolved and before it is opened, also while the inputs before
  it are read: by a symlink, or by another file. The file opened, read or over budget, must be
  the one resolved, by `dev:ino`. A new file that reuses the inode number of the one it replaced
  is not told apart; on a file system whose inode numbers are not stable (some FUSE file
  systems), an unchanged file can be refused;
- a file whose directory was replaced after it was resolved. The directory is opened from `/`
  without following a symlink.

A file changed or replaced while it is read is not fatal: it is recorded, with `Error`.

Inputs are read one at a time, so the number of inputs does not raise the number of open file
descriptors. An input's directory is opened only to reach the input by name, never listed, so a
directory that may be entered but not listed (mode 0711) is fine. An input over `binary_bytes` is
not read: it has no digest or format, only its `BudgetExceeded` status.

Budgets are set with `--budget KEY=VALUE` (repeatable); the session records them:

| Budget | Default | |
|---|---|---|
| `binary_bytes` | 64 GiB | bytes hashed over all inputs |
| `binary_parse_bytes` | 64 MiB | per artifact's parse |
| `binary_imports` | 4096 | imports kept per artifact |
| `binary_code_bytes` | 256 MiB | bytes read for code, per artifact; with `--code` only |

## `--out`

- **Not an input.** `--out` may not be an input, or a hard link of one (exit 2). This is checked
  before the inputs are read, and again against the inputs as they were read. Next to an input
  is fine.
- **Symlinks.** An existing symlink at `--out` is resolved when `--out` is checked. The file it
  leads to is what is replaced.
- **Replaced, never written through.** SIGIL writes a new file next to that path, readable by
  its owner only, and exchanges it with the existing file. An existing file there is replaced,
  never written through, and its mode and owner are not kept. An input displaced by the
  exchange is put back, and the run fails. An existing directory at `--out` is refused (exit 2).
- **Killed after the exchange.** The exchange and the put-back are two system calls. A run
  killed between them leaves the input in the output's directory, at
  `.<name>.sigil-<pid>-<k>.tmp` (`<name>`: the output's file name, at most its first 200 bytes),
  with its contents intact: rename it back over the document. An input is at `--out` then only
  if another process moved or linked it there after `--out` was checked.
- **File systems without the exchange.** On a file system that cannot exchange files
  (`RENAME_EXCHANGE`), `--out` must name a file that does not exist yet.

## Policy

The policy's `binary_audit` is what a binary inspection requires: `["binary"]`, whose check is
`binary.container`, when the policy sets it that way or leaves it out. With `--code`,
`binary_code_audit` is added after it: `["binary_code"]`, whose check is `binary.code`, when the
policy sets it that way or leaves it out. See [policy](policy.md).
