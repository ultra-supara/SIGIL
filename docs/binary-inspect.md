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
- **The read:** its digest and size, and its format. The format is an ELF executable, shared
  object, or relocatable object (`.o`), or anything else.
- **Its container facts,** for an ELF. These are the facts the installation scan records (see
  [runtime artifacts](runtime-artifacts.md#binaries)):
  - interpreter, SONAME, NEEDED, RPATH, RUNPATH;
  - build-id, `.comment`, stripped;
  - exports and imports;
  - the known data symbols (in a relocatable object, each is `Unknown` with a gap: its data is
    not linked yet), and Go build info.
- **One `binary.container` coverage entry:** the input's status.

| The input | Status |
|---|---|
| An ELF, every fact read in full or confirmed absent | `Complete` |
| An ELF with gaps, or without its facts | `Partial`, listing them (`not parsed` without facts) |
| Anything else (a script, a PE, a Mach-O for now) | `Unsupported` |
| Over the `binary_bytes` budget | `BudgetExceeded`: not read, later inputs still are |
| Changed or removed while it was read | `Error` |

Under the default policy, any status other than `Complete` makes the result `INCOMPLETE`. The same
holds for any policy that sets `binary_audit = ["binary"]` or omits the key. Only an explicit
`binary_audit = []` requires nothing, and the result is then `COMPLETE` whatever the statuses.

No rule judges binaries yet, so the verdict is `PASS`. Use `--fail-on-incomplete` (exit 4) to
fail on an unsupported or partial input.

The summary on stderr has one `binary:` line per input, in argument order: its path, type,
digest, and status.

**Imports are not calls.**
- For an executable or a shared object, imports are the dynamic symbols its loader resolves.
- For a relocatable object, they are the undefined symbols left for the linker. They are not the
  final program's imports.
- Neither shows that the code calls them: no code is analyzed, so no call site is recorded.

## Inputs and errors

A path that cannot be inspected stops the run with exit 1, and nothing is written. That covers
a path that is:
- missing;
- a directory, a FIFO, or a device;
- a file SIGIL may `lstat` but not open;
- a file with a non-UTF-8 name;
- a file replaced by a symlink after it was resolved.

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
  exchange is put back, and the run fails.
- **File systems without the exchange.** On a file system that cannot exchange files
  (`RENAME_EXCHANGE`), `--out` must name a file that does not exist yet.

## Policy

The policy's `binary_audit` is what a binary inspection requires: `["binary"]`, whose check is
`binary.container`, when the policy sets it that way or leaves it out. See [policy](policy.md).
