# ADR-002: Execution modes and safety contracts

- **Status:** Accepted. PR-1 implemented the checks for C-1…C-6. PR-3b-1 replaced the v0.1 CLI with the v2 commands and the static / observe split. PR-3b-2 added the active mode: the API probe (`--active api-probe`) and its C-4 rule. PR-3b-3c-1 removed `sigil-core` and its legacy API probe ([ADR-006](ADR-006-remove-ir-safeisa.md)).
- **Date:** 2026-10-07
- **Scope:** the SIGIL CLI and its engine crates on Linux.

## Context

SIGIL inspects local LLM installations, including model stores, runtime binaries, and configuration, that it must treat as **untrusted**.

Its value as an audit tool depends on a few promises:
- it does not run what it inspects;
- it does not load inspected code;
- it does not change the system;
- it does not talk to the network while inspecting.

Until now these promises were prose in the README and in `docs/architecture-and-safety.md`, and one of them was not true by default: the Ollama API probe connects to the configured host unless `--no-probe-api` is given.

This ADR turns the promises into named contracts and states **exactly how each is checked**. It also states what is **not** guaranteed.

## Decision

### 1. Execution modes

| Mode | Purpose | CLI paths |
|---|---|---|
| **static** (default) | Read files only: binaries, model store, configuration | `inspect ollama` (`--mode static`); `session render`, `explain`, and `rules`, which read only a saved session or nothing |
| **observe** | static, plus reads of the documented `/proc` entries | `inspect ollama --mode observe` |
| **active** | Explicitly requested features that contact something | `inspect ollama --active api-probe`, with `--mode static` or `--mode observe`. Off by default |

PR-1 made the contracts below checkable for the v0.1 CLI. Since PR-3b-1 they are checked over the v2 commands.

### 2. Contracts

| # | Contract | Applies to |
|---|---|---|
| C-1 | **No child process execution.** No `execve`/`execveat` after startup, and no process creation (`fork`, `vfork`, `clone`/`clone3` without `CLONE_THREAD`). Threads are allowed | static, observe |
| C-2 | **Never load an inspected artifact as code.** No `dlopen`, and no executable mapping of an inspected file. The dynamic loader mapping SIGIL's own runtime libraries at startup is not a violation | all modes |
| C-3 | **Never `mmap` an inspected target file.** Targets are read with `read`/`pread` | all modes |
| C-4 | **No network I/O.** No socket-family syscall of any address family (`AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_NETLINK`, …) | static, observe |
| C-5 | **Read-only.** No write-capable open (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`O_APPEND`/`O_TMPFILE`) and no file-system mutation (`rename*`, `unlink*`, `rmdir`, `mkdir*`, `symlink*`, `link*`, `truncate`, `ch{mod,own}*`, `*xattr`, `utime*`, `mknod*`) except on the output files the user named. Creating the missing parent directories of those outputs is allowed | static, observe |
| C-6 | **`/proc` access stays within its documented scope.** Every path-taking access under `/proc`, and every directory listing there, must match the allowlist in `crates/sigil-cli/tests/safety/proc_allowlist.txt` for the run's scope. `ptrace` and `process_vm_*` are violations | static (runtime entries only), observe (plus observe entries) |

**Active mode.** This completes the active mode defined in §1. It changes none of C-1…C-6 for static and observe runs. An active feature is added to a static or observe run; it does not replace the mode. Every contract of the mode applies, except that C-4 allows the feature's own connection:

| # | Contract | Applies to |
|---|---|---|
| C-4 (active) | **Only the API probe's one connection.** At most one `socket(AF_INET\|AF_INET6, SOCK_STREAM)`, of the destination's family; a `connect` of that socket to the requested destination; and option, send (with no destination address), receive, name, and shutdown calls on it. Any other family, a second socket, `bind`, `listen`, `accept`, `socketpair`, `sendmsg`, a call on another socket, or another destination is a violation | runs with `--active api-probe` |

The destination is a literal IP address and port: SIGIL resolves no name, so no resolver, NSS module, or DNS query is involved. It is loopback (`127.0.0.0/8`, `::1`, IPv4-mapped loopback) unless `--allow-remote` is given. The probe is bounded by a connect timeout, one deadline for the request and the response, and a response byte limit, each recorded in the session as a budget. Each bound has a maximum (30 s, 60 s, 1 MiB), and the socket timeout is reset to the time left before every `write` and `read`, so the one deadline holds across partial writes and reads.

Two further contracts from the v2 plan are checked by the PRs that introduce the code they govern:
- C-7 (bounded resource use, PR-3a/PR-4);
- C-8 (no LLM in the decision path, PR-6).

### 3. How the contracts are checked

**SIGIL checks these safety contracts through build-time API restrictions and syscall tests over exercised paths.** Neither mechanism is a runtime sandbox.

#### 3a. Structurally prevented at build time

These stop obvious, accidental use of forbidden APIs in **product code**. They are enforced in CI by `cargo clippy` and `cargo deny`.

| Ban | Mechanism | Contract | Not covered |
|---|---|---|---|
| `std::process::Command`, `Command::new`, `CommandExt::exec` | `clippy.toml` `disallowed-types` / `disallowed-methods` | C-1 | `libc`/`nix`/`rustix` process calls, and raw syscalls |
| `std::net::{TcpStream, TcpListener, UdpSocket}`, `std::os::unix::net::{UnixStream, UnixListener, UnixDatagram}` | `clippy.toml` `disallowed-types` | C-4 | Sockets via FFI or raw syscalls, and sockets inside dependencies |
| Crates `libloading`, `dlopen`, `dlopen2`, `sharedlib` | `deny.toml` `[bans]` | C-2 | `dlopen` via FFI |
| Crates `memmap`, `memmap2` | `deny.toml` `[bans]` | C-3 | `mmap` via FFI or raw syscalls |

- Only crates whose **purpose** is a forbidden operation are banned. General-purpose crates such as `libc` are not banned. No product crate depends on them directly today; adding such a dependency to a product crate needs review against this ADR.
- **Exceptions:**
  - Test code that must spawn processes (compiling fixtures, running the CLI, the safety harness) allows the C-1/C-4 lints at file level, with a reason.
  - The one product exception (C-4): the active API probe, a scoped `#[allow]` on `exchange` in `sigil-probe`, the one function that holds the `TcpStream`. Only the CLI depends on `sigil-probe`; `sigil-engine` and `sigil-model` keep the ban, so the engine cannot perform network I/O.
  - Any new product exception needs an ADR.

#### 3b. Checked by syscall tests over exercised paths

`crates/sigil-cli/tests/safety` runs the real `sigil` binary under `strace -ff -yy -xx -qq`.
- `-ff` gives one file per process or thread.
- `-xx` prints strings in hex, so they cannot be misparsed.
- `-yy` annotates fd arguments with their paths.

The filter is the `%process`, `%network`, `%file`, and `%desc` classes plus every syscall a rule inspects. A unit test keeps the rules and the filter in sync.

**Startup vs. target operations:**
- The first `execve` of the root process is the start of SIGIL itself.
- Executable mappings of the SIGIL binary and of shared objects under `/lib*` and `/usr/lib*` are the dynamic loader's work for SIGIL.
- Rust std's read of `/proc/self/maps` is a `runtime` allowlist entry.
- Inspected targets are identified by path, from both the requested path and the kernel-resolved fd annotation.

**Exercised paths** (each must also be seen reading its inspected input, so a broken fixture cannot pass vacuously):

| Path | Outcome |
|---|---|
| `inspect ollama` (static, to stdout) | Clean; no `/proc` read beyond SIGIL's runtime |
| `inspect ollama --format md --out <new dir>/…` | Writes only the named file |
| `inspect ollama` on a store with a malformed manifest | Clean |
| `inspect ollama --mode observe --out` (observe scope) | `/proc` reads match the allowlist; under the static scope the same trace fails C-6 |
| `session render --out <new dir>/…` | Writes only the named file |
| `explain --verdict` | Clean |
| `rules` | Clean |
| `inspect ollama --active api-probe --api-addr <loopback server>` (answered) | Clean with that destination allowed; without it, the same trace breaks C-4 (the case really connects) |
| `inspect ollama --active api-probe --api-addr <loopback port with no listener>` (refused) | As above |

**Negative controls** prove the detectors work. Each re-runs the test binary under strace to perform a forbidden operation, and the test fails unless the expected contract is reported:
- exec a child (C-1);
- a real `dlopen` of a compiled shared object in the inspected root (C-2, C-3);
- `mmap` of a target with `PROT_READ` (C-3 only) and with `PROT_READ|PROT_EXEC` (C-2, C-3);
- TCP connect, UDP bind, and `AF_UNIX` connect (C-4);
- the same TCP connect with another destination allowed (C-4 active), and with exactly its own destination allowed (no violation);
- append to a target, create a file in the target root, rename a target, and an `openat2` write (C-5);
- read `/proc/self/environ`, `openat2` on `/proc/self/status`, and `process_vm_readv` (C-6);
- `io_uring_setup` (harness integrity).

**Failure reports** name, for each violation:
- the contract;
- the syscall;
- the path, fd, or flags;
- the trace `file:line`.

They also show the command, the working directory, the exit status, and the trace directory: `target/tmp/safety-traces/<case>/`, which holds the `t.<pid>` files and `command.txt`. CI uploads these traces on failure.

**Skipping:** without a usable `strace` (or without permission to trace), the tests skip with a printed reason. With `SIGIL_SAFETY_REQUIRED=1`, as set in CI, they fail instead.

#### 3c. Not enforced: limitations

- **No runtime sandbox.** Nothing stops SIGIL at run time from doing a forbidden operation on a path the tests do not exercise. **An untested path could violate a contract.** The tests are evidence about the exercised paths, not a proof about all paths.
- A `dlopen` that fails before mapping anything (e.g. on a non-ELF file) looks like an ordinary `open` + `read` in a trace. It is covered only by the build-time bans.
- `/proc` paths are matched lexically on the requested path; symlinks inside `/proc` are not resolved.
- System-library detection for C-2 is path-based (`/lib*`, `/usr/lib*`).
- io_uring would hide file and network operations from syscall tracing. Its setup is therefore flagged, but this only covers io_uring itself.
- **Runtime enforcement**, e.g. a seccomp self-filter installed before collection, is a **separate future decision** (plan H-5) and is not part of this ADR.

### 4. Changing the contracts

- Changing or removing a contract, or adding a product exception to a ban, needs a new ADR.
- Adding or widening a `/proc` allowlist entry is an intentional, reviewed change to `proc_allowlist.txt` that names the reading code and the plan section it serves. An unknown `/proc` access fails the tests.

## Consequences

- The safety promises in the README and the docs are stated as **checked**, not as guaranteed. Until PR-3b-1, "no network" held only with `--no-probe-api`. Since PR-3b-2, network I/O happens only with `--active api-probe`, and only to its one destination.
- CI has a dedicated `safety` job that cannot pass by skipping.
- New I/O code in an exercised path is caught by the tests. New code in an unexercised path is not; PR authors add the path to the harness.

## Running locally

```sh
cargo clippy --workspace --all-targets -- -D warnings      # build-time bans (touch or `cargo clean -p` the workspace crates after editing clippy.toml)
cargo deny check bans                                       # crate bans
SIGIL_SAFETY_REQUIRED=1 cargo test -p sigil-cli --test safety
```
