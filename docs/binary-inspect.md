# Inspecting binaries directly

`sigil binary inspect` reads one or more files and writes one session (or its Markdown) for all
of them. For each file the session holds its digest, size, format, and container facts. It needs
no model store, installation, or running runtime, and it never executes or loads what it reads.

```bash
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so ./net.o --format md --out out/binary.md
cargo run -q -p sigil-cli -- binary inspect ./libggml-base.so --fail-on-incomplete
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

The fat Mach-O magic also begins a Java class file. SIGIL treats a structurally valid fat
architecture table as Mach-O; when that table is invalid but the file has a valid Java class
header and constant pool, it is treated as an unsupported format. This resolves the shared-magic
ambiguity in favor of a valid fat table.

No rule judges binaries yet, so the verdict is `PASS`. Use `--fail-on-incomplete` (exit 4) to
fail on an unsupported or partial input.

The summary on stderr has one `binary:` line per input, in argument order: its path, type,
digest, and status.

**Imports are not calls.**
- For an executable or a shared object, imports are the dynamic symbols its loader resolves.
- For a relocatable object, they are the undefined symbols left for the linker. They are not the
  final program's imports.
- Mach-O loaded dylibs are declared dependencies, not symbol-level imports.
- Neither shows that the code calls them: no code is analyzed, so no call site is recorded.

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
`binary.container`, when the policy sets it that way or leaves it out. See [policy](policy.md).
