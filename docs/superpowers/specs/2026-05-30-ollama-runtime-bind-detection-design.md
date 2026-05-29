# Ollama Runtime Port and Bind Detection Design

Tracks GitHub issue #5.

## Goal

Extend SIGIL's Ollama inspection from configured `--host` checks to actual
runtime exposure detection. SIGIL should detect how Ollama is really bound on
the local machine and classify whether it is reachable only from loopback,
exposed to the LAN, exposed through a wildcard/public bind, published through
Docker, or fronted by a reverse proxy.

This adds a new evidence dimension. The existing `--host` probing remains an
explicit, separate endpoint check.

## Non-Goals

- No active network scanning of remote hosts. Inspection is local-only.
- No subprocess execution. Listener inspection reads `/proc` files only; it does
  not spawn `ss`, `lsof`, `netstat`, or `docker`.
- No full reverse-proxy config analysis. `proxy` is detected only from a clear
  process-name signal; otherwise the observed bind class or `unknown` is used.
- No Windows/macOS listener backend in this change. Non-Linux degrades to
  `unknown` gracefully.
- Do not change the existing host-based `ApiExposure` classification or its
  findings.

## Background

Current state (`crates/sigil-core/src/ollama.rs`):

- `ApiExposure` (`not_probed`/`localhost`/`network`/`public_bind`/`unavailable`)
  classifies the **configured `--host` string**, not the actual bind.
- `inspect_ollama` builds an `OllamaReport`, optionally probes `/api/version`,
  and emits findings + a PASS/WARN/FAIL verdict.
- AI-BOM rendering and JSON output are in the same module.

The new feature is orthogonal: it observes the machine's listening sockets and
attributes the Ollama port's bind class.

## Safety Alignment

SIGIL's identity is read-only, local-first, deterministic, no process launch.
The design honors this by reading `/proc/net/tcp`, `/proc/net/tcp6`, and
`/proc/<pid>/fd` + `/proc/<pid>/comm` as plain files. No external command is
spawned. Missing files or insufficient permissions degrade gracefully.

## Architecture

### New module: `crates/sigil-core/src/runtime/listeners.rs`

Separates pure logic from `/proc` I/O so classification is unit-testable
without a real `/proc`. The snapshot is plain data (derives
`Clone, Debug, PartialEq, Eq`) so it can be embedded in `OllamaInspectOptions`
and injected by tests without trait objects.

```rust
pub struct Listener {
    pub addr: IpAddr,
    pub port: u16,
    pub inode: u64,
}

pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String, // best-effort
}

pub struct ListenerSnapshot {
    pub listeners: Vec<Listener>,
    pub processes: HashMap<u64, ProcessInfo>, // inode -> process, best-effort
    pub available: bool,                       // false when /proc unreadable
    pub source: String,                        // "proc" | "disabled" | "unavailable"
}

// How inspect_ollama obtains a snapshot. Plain enum -> options keep all derives.
pub enum RuntimeListeners {
    Inspect,                 // call proc_snapshot()
    Disabled,                // unavailable, source = "disabled"
    Fixed(ListenerSnapshot), // test injection
}

pub fn proc_snapshot() -> ListenerSnapshot; // reads /proc; non-Linux -> available=false
```

`proc_snapshot()`:

1. Parse `/proc/net/tcp` and `/proc/net/tcp6`. Keep rows whose state is `0A`
   (LISTEN). Decode `local_address` (little-endian hex IP + hex port) into
   `IpAddr` + `u16`, and read the socket inode column.
2. Best-effort process attribution: scan `/proc/<pid>/fd/*` symlinks for
   `socket:[<inode>]` targets to build an inode→pid map, then read
   `/proc/<pid>/comm`. Silently skip pids that cannot be read (permissions).
3. On any I/O failure for the netfiles themselves (incl. non-Linux where the
   files are absent), return `available=false`, `source="unavailable"`, empty
   data.

### Pure classifier (same module)

```rust
pub enum RuntimeExposure {
    Localhost,
    Lan,
    PublicBind,
    DockerPublished,
    Proxy,
    Unknown,
}

pub struct BindEvidence {
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
}

pub struct RuntimeExposureReport {
    pub class: RuntimeExposure,
    pub observed: Vec<BindEvidence>,
    pub source: String, // "proc" | "disabled" | "unavailable"
}

pub fn classify_runtime_exposure(
    snapshot: &ListenerSnapshot,
    ollama_port: u16,
) -> RuntimeExposureReport;
```

Classification rules, applied per listener whose `port == ollama_port`:

- process name `docker-proxy` → `DockerPublished`
- process name in {`nginx`, `caddy`, `traefik`, `haproxy`, `envoy`} → `Proxy`
- addr in `127.0.0.0/8` or `::1` → `Localhost`
- addr is wildcard `0.0.0.0` or `::` → `PublicBind`
- addr in private ranges (`10/8`, `172.16/12`, `192.168/16`, `169.254/16`,
  `fc00::/7`, `fe80::/10`) → `Lan`
- addr is a globally routable specific IP → `PublicBind`

When multiple matching listeners disagree, pick the most-exposed class with
ordering `PublicBind > DockerPublished > Proxy > Lan > Localhost`. Record every
matching listener in `observed`.

`RuntimeExposureReport.source` is copied from `snapshot.source`. When
`snapshot.available == false` → class `Unknown` (source `"disabled"` or
`"unavailable"`). When available but no listener matches `ollama_port` → class
`Unknown`, source `"proc"`.

Port resolution order for `ollama_port`: parse `--host` → `OLLAMA_HOST` env →
default `11434`. (Reuse the existing host-parsing helper in `ollama.rs`.)

### Integration into `ollama.rs`

- `OllamaInspectOptions` gains `runtime_listeners: RuntimeListeners`
  (plain enum, so the struct keeps `Clone, Debug, PartialEq, Eq`). CLI default =
  `RuntimeListeners::Inspect`.
- `OllamaReport` gains `runtime_exposure: RuntimeExposureReport`
  (serde, snake_case enum like existing `ApiExposure`).
- After host classification, call `classify_runtime_exposure` and push WARN
  findings for non-local classes. `Localhost` and `Unknown` add **no** finding,
  preserving the PASS path:
  - `ollama.runtime_lan_exposure` (WARN)
  - `ollama.runtime_public_bind` (WARN)
  - `ollama.runtime_docker_published` (WARN)
  - `ollama.runtime_proxy` (WARN)
- The existing host-based `api` field and `ollama.public_bind` /
  `ollama.network_endpoint` findings are unchanged.

### CLI (`crates/sigil-cli/src/main.rs`)

- `OllamaArgs` and `AiBomGenerateArgs` gain
  `--no-inspect-runtime` (mirrors `--no-probe-api`, default ON).
- `ollama_options` / `cmd_aibom` set `runtime_listeners` to
  `RuntimeListeners::Inspect` when enabled, else `RuntimeListeners::Disabled`.

### Output

- JSON: `OllamaReport` serializes `runtime_exposure` with `class`, `observed`,
  `source`.
- AI-BOM (`render_ai_bom`): add a `- Runtime exposure: \`<class>\`` line and, when
  present, observed bind evidence lines (`addr:port` and process when known).

## Data Flow

```
--host / OLLAMA_HOST / 11434  ─┐
                               ├─> ollama_port
ProcListenerSource.snapshot() ─┘        │
        │ (Listener + inode->process)   v
        └────────────────> classify_runtime_exposure(snapshot, ollama_port)
                                         │
                                         v
                         RuntimeExposureReport ──> findings (WARN if non-local)
                                         │                 │
                                         └──> OllamaReport ─┴─> JSON + AI-BOM + verdict
```

## Error Handling / Graceful Degradation

- Non-Linux (incl. dev macOS M3): `/proc` absent → `available=false` →
  `Unknown`, source `"unavailable"`, no finding → PASS preserved.
- Permission denied on `/proc/<pid>/fd`: process attribution skipped; bind-based
  classification still proceeds.
- Malformed `/proc/net/tcp` rows are skipped individually, not fatal.

## Testing

Acceptance requires tests for localhost, `0.0.0.0`, and non-local endpoints.

Unit tests (no real `/proc`), feeding synthetic `ListenerSnapshot`:

- `127.0.0.1:11434` → `Localhost`, no finding, verdict PASS.
- `0.0.0.0:11434` → `PublicBind`, `ollama.runtime_public_bind` WARN.
- `192.0.2.10:11434` (non-local routable) → `PublicBind`, WARN.
- `10.0.0.5:11434` → `Lan`, `ollama.runtime_lan_exposure` WARN.
- process `docker-proxy` on the port → `DockerPublished`, WARN.
- process `nginx` on the port → `Proxy`, WARN.
- empty / `available=false` snapshot → `Unknown`, no finding.
- most-exposed selection when multiple listeners disagree.

`/proc` parser unit tests: known v4 and v6 hex rows decode to the expected
`IpAddr` + port + inode; non-LISTEN rows ignored.

Integration tests via `RuntimeListeners::Fixed(snapshot)` (exercises the
classify → finding → verdict wiring inside `inspect_ollama` without a real
listener): a public-bind snapshot yields `ollama.runtime_public_bind` and verdict
WARN; a localhost snapshot yields no runtime finding and preserves PASS.

Existing test updates (behavior unchanged, only struct construction):

- `crates/sigil-core/tests/ollama.rs`: set `runtime_listeners` to
  `RuntimeListeners::Disabled` in each `OllamaInspectOptions` literal; assert
  `runtime_exposure.class == Unknown` and existing verdicts hold.
- `crates/sigil-cli/tests/ollama_cli.rs`: pass `--no-inspect-runtime` so results
  stay deterministic regardless of the test machine's real listeners.

## Documentation

`docs/ollama-inspection.md`: add a "Runtime Exposure" section describing the new
classification, the four `ollama.runtime_*` findings, the `/proc`-only,
no-subprocess approach, and graceful degradation on non-Linux.

## Acceptance Criteria Mapping

- "reports actual bind evidence when Ollama is running" → `runtime_exposure`
  populated from `/proc` with `observed` binds.
- "public or non-local exposure produces a WARN finding" → `ollama.runtime_*`
  WARN findings for Lan/PublicBind/DockerPublished/Proxy.
- "existing PASS path unchanged for localhost-only" → Localhost/Unknown add no
  finding; host-based logic untouched.
- "degrades gracefully when tools unavailable" → `available=false` → `Unknown`,
  no finding.
