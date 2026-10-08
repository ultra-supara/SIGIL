# Exposure (`sigil-engine`, observe mode)

In observe mode, SIGIL reads the running system to find the runtime's listening sockets, and
classifies each one by its bind address.

- **Status:** `sigil_engine::inspect::observe_session` builds an observe-mode session: the model
  store plus exposure. The CLI uses it from PR-3b (`--mode observe`). Until then, the v0.1
  `runtime inspect ollama` is unchanged.
- **Source:** plan §4.6.8 and the migration table (§6.3). The session types are in
  [`docs/session-model.md`](session-model.md); the model store is in
  [`docs/model-store.md`](model-store.md).

## What is read

All reads are under the proc root (`/proc`), and every entry is on the C-6 allowlist
(`crates/sigil-cli/tests/safety/proc_allowlist.txt`).

| Entry | Why | How |
|---|---|---|
| `net/tcp`, `net/tcp6` | The LISTEN rows of SIGIL's own network namespace | read, bounded (16 MiB each) |
| `self/ns/net` | SIGIL's own network namespace | `readlinkat` |
| the proc root | The PIDs (PID 1 hidden means `hidepid`) | `getdents64`, bounded (32,768) |
| `<pid>/comm` | The process name: selects `ollama` candidates and fronting processes | read |
| `<pid>/fd`, `<pid>/fd/<n>` | Which sockets a process holds (`socket:[inode]`) | `getdents64` and `readlinkat`, bounded (65,536 per process) |
| `<pid>/cmdline` | `argv` of an `ollama` process (only those) | read |
| `<pid>/exe` | Confirms the runtime's executable | `readlinkat` |
| `<pid>/stat` | The start time, part of a process's identity | read |
| `<pid>/ns/net` | The process's network namespace | `readlinkat` |

Magic links (`exe`, `fd/<n>`, `ns/net`) are read with `readlinkat` and are never followed or
opened.

## The runtime

- **`ollama serve`** is a process whose `argv[0]` basename is `ollama` and whose `argv[1]` is
  `serve`.
- **Confirmation by `exe`.** When `exe` can be read, its basename must be `ollama` as well, or the
  process is not the runtime. `exe` cannot be read for another user's process, so an unprivileged
  run relies on `cmdline`, which the process sets itself. `ProcessObs.exe` records which case
  applied.
- **Not identified is not absent.** A process whose name (`comm`) or, for an `ollama`, arguments
  (`cmdline`) cannot be read may be the runtime. The same holds for a process whose directory
  cannot be opened. Each is a gap, and the listeners such a process holds are recorded with no
  role, so `exposure.binds` cannot be `Complete`. A process that exited between the listing and
  the read is skipped: its sockets are gone with it.
- **Not recorded is not dropped.** The runtime whose `stat` (its start time, part of its identity)
  cannot be read or understood cannot be recorded. That is a gap, and the listeners it holds are
  recorded with owner `Unknown`.
- **Bounded open files.** Processes are read one at a time; each one's directory is closed before
  the next is opened.

## Who holds a socket

A listening socket is attributed to a process only through that process's fd table, never by its
port (I-08).

| Listener | Recorded as |
|---|---|
| held by the runtime | a listener owned by it |
| held by a fronting process (nginx, caddy, traefik, haproxy, envoy, docker-proxy) | a listener owned by it: a hint, never a finding |
| held by a process that may be the runtime (not identified) | a listener owned by it, no role; a gap |
| held by the runtime, which cannot be recorded | owner `Unknown`; a gap |
| held by no table that was read, while some table was not read: a process not listed (the list's budget, a read error), a process hidden (`hidepid`), or an fd table not listed completely | owner `Unknown` (`PermissionDenied` when a table was denied or processes are hidden, otherwise `ReadIncomplete`) |
| held by no fd table, every process having been listed, PID 1 among them, and every table listed completely | owner `Unheld` |
| held by any other known process | not recorded |

## Classes and findings

The class comes from the bind address alone. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is read as its
IPv4 address (I-09).

| Class | Addresses | Finding (runtime-held only) |
|---|---|---|
| loopback | `127.0.0.0/8`, `::1` | — |
| wildcard | `0.0.0.0`, `::` | `exposure.bind_public` (WARN) |
| private | RFC 1918, `169.254/16`, `fc00::/7`, `fe80::/10` | `exposure.bind_lan` (WARN) |
| global | everything else | `exposure.bind_public` (WARN) |

- **Process names never lower a class (I-10).** A runtime bound to `0.0.0.0` is
  `exposure.bind_public` whatever else listens, and a public nginx listener is a recorded hint.
- **A class is about the bind address, not reachability.** Firewalls, NAT, and routing are not
  observed.

## `exposure.binds` coverage

The audit entry says whether every process that may be the runtime was seen. It is always
recorded, next to each runtime's own entry: a runtime that was found never closes the check for
those that were not, and its findings stand.

| Situation | State |
|---|---|
| PID 1 missing from a complete process list (`hidepid`), or the list denied | `Unavailable(PermissionDenied)` on the audit |
| the process list cut short (its budget, a read error): PID 1 missing from it says nothing | `Partial` on the audit |
| any other gap | `Partial` on the audit |
| otherwise | `Complete` on the audit |
| a runtime whose fd table cannot be read | `Unavailable(PermissionDenied)` on it |
| a runtime whose fd table was listed in part (`ReadIncomplete`) | `Partial` on it; findings for the listeners found stand |
| a process that may be the runtime could not be identified | `Partial` (a gap) |
| the runtime cannot be recorded (its `stat`) | `Partial` (a gap) |
| a LISTEN row that cannot be read | `Partial` (a gap); the other rows stand |
| a runtime in another network namespace | `Partial` on it: its sockets are not in SIGIL's table |
| a runtime whose network namespace cannot be read | `Partial` on it; findings for the listeners it holds in SIGIL's table stand |
| a table or list not read completely | `Partial` on it |
| otherwise | `Complete` on it |

An unprivileged SIGIL usually cannot read `ollama serve`'s fd table. The result is then `INCOMPLETE`
for `exposure.binds`, never a guess.

## From v0.1

v0.1's tests stay until PR-3b removes `sigil-core`.

| v0.1 test | v2 |
|---|---|
| `runtime_public_bind_listener_warns` (`tests/ollama.rs`) | `observe_session::a_public_bind_warns` |
| `runtime_localhost_listener_keeps_pass` | `observe_session::a_loopback_bind_passes` |
| `runtime_lan_listener_warns` | `observe_session::a_lan_bind_warns` |
| the 5 `/proc/net` parsing tests (`listeners.rs`) | `observe::proc::parse` unit tests, made byte-order independent |
| the 8 address classification tests | `exposure_analysis::bind_classes_come_from_the_address_alone`, with the IPv4-mapped cases added |
| `classifies_docker_proxy_process_as_docker_published`, `classifies_reverse_proxy_process_as_proxy` | replaced: fronting processes are hints (`a_fronting_process_never_lowers_the_runtimes_class`) |
| `unavailable_snapshot_is_unknown`, `no_matching_port_is_unknown` | replaced by coverage (`an_unreadable_owner_is_incomplete_not_attributed`); port matching is gone |
| `picks_most_exposed_when_multiple_listeners` | replaced: one finding per runtime-held listener |
| `proc_snapshot_does_not_panic` | replaced by fixture tests of the collector (`proc_observe`) |
| `exposure_as_str_*`, `exposure_serializes_*` | not applicable (v0.1's output enum) |
| `ai_bom_includes_runtime_exposure_and_binds`, `ai_bom_runtime_exposure_unknown_when_disabled` | PR-3b (AI-BOM v2) |
