# Ollama Runtime Port and Bind Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect how Ollama is actually bound on the local machine by parsing `/proc`, classify the exposure (localhost / lan / public_bind / docker_published / proxy / unknown), and surface WARN findings + JSON/AI-BOM evidence for non-local binds.

**Architecture:** A new `sigil-core::runtime::listeners` module reads `/proc/net/tcp{,6}` (LISTEN sockets) and best-effort `/proc/<pid>/fd`+`comm` for process names — no subprocess spawn. A pure `classify_runtime_exposure(snapshot, port)` maps observed binds to a `RuntimeExposure`. `inspect_ollama` resolves the Ollama port from `--host`/`OLLAMA_HOST`/`11434`, classifies, and emits findings. The listener source is a plain `RuntimeListeners` enum (`Inspect`/`Disabled`/`Fixed`) stored in options so tests inject synthetic snapshots and the options struct keeps all derives.

**Tech Stack:** Rust (edition 2021), `serde`, `std::net`, `std::fs`. Tests with `cargo test`. Spec: `docs/superpowers/specs/2026-05-30-ollama-runtime-bind-detection-design.md`.

> **Commit policy for this repo:** the user prefers not to auto-commit. Each task lists a commit step per TDD convention, but at execution time confirm with the user before running `git commit` (or batch commits at the end if they prefer).

---

## File Structure

- Create `crates/sigil-core/src/runtime/mod.rs` — module root, re-exports `listeners`.
- Create `crates/sigil-core/src/runtime/listeners.rs` — types, `/proc` parser, classifier, `proc_snapshot()`.
- Modify `crates/sigil-core/src/lib.rs` — add `pub mod runtime;`.
- Modify `crates/sigil-core/src/ollama.rs` — options field, report field, port resolution, runtime findings, AI-BOM line.
- Modify `crates/sigil-core/tests/ollama.rs` — add `runtime_listeners` to literals; add Fixed-snapshot integration tests.
- Modify `crates/sigil-cli/src/main.rs` — `--no-inspect-runtime` flag, wire `runtime_listeners`.
- Modify `crates/sigil-cli/tests/ollama_cli.rs` — pass `--no-inspect-runtime`.
- Modify `docs/ollama-inspection.md` — Runtime Exposure section.

---

## Task 1: Runtime module skeleton and core types

**Files:**
- Create: `crates/sigil-core/src/runtime/mod.rs`
- Create: `crates/sigil-core/src/runtime/listeners.rs`
- Modify: `crates/sigil-core/src/lib.rs`
- Test: inline `#[cfg(test)]` in `crates/sigil-core/src/runtime/listeners.rs`

- [ ] **Step 1: Register the module in `lib.rs`**

Modify `crates/sigil-core/src/lib.rs` to add the line (keep alphabetical-ish ordering, place after `report`):

```rust
pub mod assess;
pub mod evidence;
pub mod ir;
pub mod ollama;
pub mod report;
pub mod runtime;
pub mod safeisa;
pub mod x86;
```

- [ ] **Step 2: Create `crates/sigil-core/src/runtime/mod.rs`**

```rust
pub mod listeners;

pub use listeners::{
    classify_runtime_exposure, proc_snapshot, BindEvidence, Listener, ListenerSnapshot,
    ProcessInfo, RuntimeExposure, RuntimeExposureReport, RuntimeListeners,
};
```

- [ ] **Step 3: Create `crates/sigil-core/src/runtime/listeners.rs` with the types**

```rust
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub addr: IpAddr,
    pub port: u16,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerSnapshot {
    pub listeners: Vec<Listener>,
    pub processes: HashMap<u64, ProcessInfo>,
    pub available: bool,
    pub source: String,
}

impl ListenerSnapshot {
    pub fn unavailable(source: &str) -> Self {
        Self {
            listeners: Vec::new(),
            processes: HashMap::new(),
            available: false,
            source: source.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeListeners {
    Inspect,
    Disabled,
    Fixed(ListenerSnapshot),
}

impl RuntimeListeners {
    pub fn snapshot(&self) -> ListenerSnapshot {
        match self {
            RuntimeListeners::Inspect => proc_snapshot(),
            RuntimeListeners::Disabled => ListenerSnapshot::unavailable("disabled"),
            RuntimeListeners::Fixed(snapshot) => snapshot.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExposure {
    Localhost,
    Lan,
    PublicBind,
    DockerPublished,
    Proxy,
    Unknown,
}

impl RuntimeExposure {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Localhost => "localhost",
            Self::Lan => "lan",
            Self::PublicBind => "public_bind",
            Self::DockerPublished => "docker_published",
            Self::Proxy => "proxy",
            Self::Unknown => "unknown",
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Self::PublicBind => 5,
            Self::DockerPublished => 4,
            Self::Proxy => 3,
            Self::Lan => 2,
            Self::Localhost => 1,
            Self::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindEvidence {
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExposureReport {
    pub class: RuntimeExposure,
    pub observed: Vec<BindEvidence>,
    pub source: String,
}

// Placeholder body so the crate compiles; real implementation in Task 4.
pub fn proc_snapshot() -> ListenerSnapshot {
    ListenerSnapshot::unavailable("unavailable")
}

// Placeholder body so the crate compiles; real implementation in Task 3.
pub fn classify_runtime_exposure(
    _snapshot: &ListenerSnapshot,
    _ollama_port: u16,
) -> RuntimeExposureReport {
    RuntimeExposureReport {
        class: RuntimeExposure::Unknown,
        observed: Vec::new(),
        source: "unavailable".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_as_str_matches_snake_case() {
        assert_eq!(RuntimeExposure::Localhost.as_str(), "localhost");
        assert_eq!(RuntimeExposure::Lan.as_str(), "lan");
        assert_eq!(RuntimeExposure::PublicBind.as_str(), "public_bind");
        assert_eq!(RuntimeExposure::DockerPublished.as_str(), "docker_published");
        assert_eq!(RuntimeExposure::Proxy.as_str(), "proxy");
        assert_eq!(RuntimeExposure::Unknown.as_str(), "unknown");
    }

    #[test]
    fn exposure_serializes_snake_case() {
        let json = serde_json::to_string(&RuntimeExposure::PublicBind).unwrap();
        assert_eq!(json, "\"public_bind\"");
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --lib runtime::`
Expected: PASS (`exposure_as_str_matches_snake_case`, `exposure_serializes_snake_case`).

- [ ] **Step 5: Verify the whole workspace still builds**

Run: `cargo build`
Expected: builds with no errors (warnings about unused placeholder args are acceptable for now).

- [ ] **Step 6: Commit** (confirm with user first per commit policy)

```bash
git add crates/sigil-core/src/lib.rs crates/sigil-core/src/runtime/mod.rs crates/sigil-core/src/runtime/listeners.rs
git commit -m "feat(runtime): add listener types and RuntimeExposure scaffold"
```

---

## Task 2: `/proc/net/tcp{,6}` line parser

Parses one data line into a `Listener`, decoding the little-endian hex IP and big-endian hex port, keeping only LISTEN (`0A`) rows.

**Files:**
- Modify: `crates/sigil-core/src/runtime/listeners.rs`
- Test: inline `#[cfg(test)]` in the same file

- [ ] **Step 1: Write the failing tests**

Add these to the `mod tests` block in `crates/sigil-core/src/runtime/listeners.rs`:

```rust
#[test]
fn parses_ipv4_loopback_listen_row() {
    // 0100007F = 127.0.0.1 little-endian, 94F9 = port 38137, state 0A = LISTEN
    let line = "   1: 0100007F:94F9 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18568 1 00000000c7521507 100 0 0 10 0";
    let listener = parse_proc_net_line(line, false).unwrap();
    assert_eq!(listener.addr, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(listener.port, 0x94F9);
    assert_eq!(listener.inode, 18568);
}

#[test]
fn parses_ipv4_wildcard_listen_row() {
    // 00000000 = 0.0.0.0, 0016 = port 22
    let line = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8917 1 0000000043890958 100 0 0 10 0";
    let listener = parse_proc_net_line(line, false).unwrap();
    assert_eq!(listener.addr, "0.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(listener.port, 22);
}

#[test]
fn skips_non_listen_rows() {
    // state 01 = ESTABLISHED, must be ignored
    let line = "   2: 73014064:BE2C 1A72528C:01BB 01 00000000:00000000 02:00000F26 00000000  1000        0 4442946 2 000000000fbb84c8 45 4 26 10 -1";
    assert!(parse_proc_net_line(line, false).is_none());
}

#[test]
fn parses_ipv6_loopback_listen_row() {
    // ::1 is stored as 00000000000000000000000001000000 (per-dword byte reversal)
    let line = "   0: 00000000000000000000000001000000:D431 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0 100 0 0 10 0";
    let listener = parse_proc_net_line(line, true).unwrap();
    assert_eq!(listener.addr, "::1".parse::<IpAddr>().unwrap());
    assert_eq!(listener.port, 0xD431);
    assert_eq!(listener.inode, 99999);
}

#[test]
fn parses_ipv6_wildcard_listen_row() {
    let line = "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 8919 1 0 100 0 0 10 0";
    let listener = parse_proc_net_line(line, true).unwrap();
    assert_eq!(listener.addr, "::".parse::<IpAddr>().unwrap());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p sigil-core --lib runtime::tests::parses`
Expected: FAIL — `parse_proc_net_line` not found.

- [ ] **Step 3: Implement the parser**

Add these functions to `crates/sigil-core/src/runtime/listeners.rs` (above the `#[cfg(test)]` block):

```rust
pub fn parse_proc_net_line(line: &str, is_v6: bool) -> Option<Listener> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let local = fields.next()?;
    let _rem = fields.next()?;
    let state = fields.next()?;
    if state != "0A" {
        return None;
    }
    // After state the columns are: tx:rx, tr:when, retrnsmt, uid, timeout, inode.
    // inode is offset 5 from the current position.
    let inode_field = fields.nth(5)?;
    let inode: u64 = inode_field.parse().ok()?;

    let (addr_hex, port_hex) = local.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if is_v6 {
        parse_v6_hex(addr_hex)?
    } else {
        parse_v4_hex(addr_hex)?
    };
    Some(Listener { addr, port, inode })
}

fn parse_v4_hex(hex: &str) -> Option<IpAddr> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(raw.swap_bytes())))
}

fn parse_v6_hex(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        let chunk = hex.get(index * 8..index * 8 + 8)?;
        let word = u32::from_str_radix(chunk, 16).ok()?;
        let be = word.swap_bytes().to_be_bytes();
        bytes[index * 4..index * 4 + 4].copy_from_slice(&be);
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --lib runtime::`
Expected: PASS (all parser tests + Task 1 tests).

- [ ] **Step 5: Commit** (confirm with user first)

```bash
git add crates/sigil-core/src/runtime/listeners.rs
git commit -m "feat(runtime): parse /proc/net/tcp listen rows into Listener"
```

---

## Task 3: Exposure classifier

Maps a `ListenerSnapshot` + Ollama port to a `RuntimeExposureReport`, applying process-name and address rules and picking the most-exposed class.

**Files:**
- Modify: `crates/sigil-core/src/runtime/listeners.rs`
- Test: inline `#[cfg(test)]` in the same file

- [ ] **Step 1: Write the failing tests**

Add a test helper and tests to the `mod tests` block:

```rust
fn snapshot_with(addr: &str, port: u16, process: Option<&str>) -> ListenerSnapshot {
    let inode = 4242;
    let mut processes = HashMap::new();
    if let Some(name) = process {
        processes.insert(
            inode,
            ProcessInfo {
                pid: 1,
                comm: name.to_string(),
            },
        );
    }
    ListenerSnapshot {
        listeners: vec![Listener {
            addr: addr.parse().unwrap(),
            port,
            inode,
        }],
        processes,
        available: true,
        source: "proc".to_string(),
    }
}

#[test]
fn classifies_loopback_as_localhost() {
    let snap = snapshot_with("127.0.0.1", 11434, None);
    let report = classify_runtime_exposure(&snap, 11434);
    assert_eq!(report.class, RuntimeExposure::Localhost);
    assert_eq!(report.observed.len(), 1);
    assert_eq!(report.source, "proc");
}

#[test]
fn classifies_wildcard_as_public_bind() {
    let snap = snapshot_with("0.0.0.0", 11434, None);
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::PublicBind
    );
}

#[test]
fn classifies_routable_specific_ip_as_public_bind() {
    let snap = snapshot_with("192.0.2.10", 11434, None);
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::PublicBind
    );
}

#[test]
fn classifies_private_range_as_lan() {
    let snap = snapshot_with("10.0.0.5", 11434, None);
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::Lan
    );
}

#[test]
fn classifies_docker_proxy_process_as_docker_published() {
    let snap = snapshot_with("0.0.0.0", 11434, Some("docker-proxy"));
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::DockerPublished
    );
}

#[test]
fn classifies_reverse_proxy_process_as_proxy() {
    let snap = snapshot_with("0.0.0.0", 11434, Some("nginx"));
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::Proxy
    );
}

#[test]
fn unavailable_snapshot_is_unknown() {
    let snap = ListenerSnapshot::unavailable("disabled");
    let report = classify_runtime_exposure(&snap, 11434);
    assert_eq!(report.class, RuntimeExposure::Unknown);
    assert_eq!(report.source, "disabled");
    assert!(report.observed.is_empty());
}

#[test]
fn no_matching_port_is_unknown() {
    let snap = snapshot_with("0.0.0.0", 8080, None);
    assert_eq!(
        classify_runtime_exposure(&snap, 11434).class,
        RuntimeExposure::Unknown
    );
}

#[test]
fn picks_most_exposed_when_multiple_listeners() {
    let mut snap = snapshot_with("127.0.0.1", 11434, None);
    snap.listeners.push(Listener {
        addr: "0.0.0.0".parse().unwrap(),
        port: 11434,
        inode: 5,
    });
    let report = classify_runtime_exposure(&snap, 11434);
    assert_eq!(report.class, RuntimeExposure::PublicBind);
    assert_eq!(report.observed.len(), 2);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p sigil-core --lib runtime::tests::classifies`
Expected: FAIL — placeholder always returns `Unknown`.

- [ ] **Step 3: Replace the placeholder `classify_runtime_exposure` with the real implementation**

In `crates/sigil-core/src/runtime/listeners.rs`, replace the placeholder `classify_runtime_exposure` (from Task 1) with:

```rust
enum AddrClass {
    Loopback,
    Wildcard,
    Private,
    Global,
}

fn classify_addr(addr: &IpAddr) -> AddrClass {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                AddrClass::Loopback
            } else if v4.is_unspecified() {
                AddrClass::Wildcard
            } else if v4.is_private() || v4.is_link_local() {
                AddrClass::Private
            } else {
                AddrClass::Global
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                AddrClass::Loopback
            } else if v6.is_unspecified() {
                AddrClass::Wildcard
            } else {
                let seg0 = v6.segments()[0];
                // fc00::/7 (ULA) or fe80::/10 (link-local) -> private
                if (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                    AddrClass::Private
                } else {
                    AddrClass::Global
                }
            }
        }
    }
}

fn exposure_for(addr: &IpAddr, process: Option<&str>) -> RuntimeExposure {
    if let Some(name) = process {
        if name == "docker-proxy" {
            return RuntimeExposure::DockerPublished;
        }
        if matches!(name, "nginx" | "caddy" | "traefik" | "haproxy" | "envoy") {
            return RuntimeExposure::Proxy;
        }
    }
    match classify_addr(addr) {
        AddrClass::Loopback => RuntimeExposure::Localhost,
        AddrClass::Wildcard => RuntimeExposure::PublicBind,
        AddrClass::Private => RuntimeExposure::Lan,
        AddrClass::Global => RuntimeExposure::PublicBind,
    }
}

pub fn classify_runtime_exposure(
    snapshot: &ListenerSnapshot,
    ollama_port: u16,
) -> RuntimeExposureReport {
    if !snapshot.available {
        return RuntimeExposureReport {
            class: RuntimeExposure::Unknown,
            observed: Vec::new(),
            source: snapshot.source.clone(),
        };
    }
    let mut observed = Vec::new();
    let mut best: Option<RuntimeExposure> = None;
    for listener in &snapshot.listeners {
        if listener.port != ollama_port {
            continue;
        }
        let process = snapshot
            .processes
            .get(&listener.inode)
            .map(|info| info.comm.clone());
        let class = exposure_for(&listener.addr, process.as_deref());
        observed.push(BindEvidence {
            addr: listener.addr.to_string(),
            port: listener.port,
            process,
        });
        best = Some(match best {
            Some(current) if current.rank() >= class.rank() => current,
            _ => class,
        });
    }
    RuntimeExposureReport {
        class: best.unwrap_or(RuntimeExposure::Unknown),
        observed,
        source: snapshot.source.clone(),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --lib runtime::`
Expected: PASS (all classifier + parser + type tests).

- [ ] **Step 5: Commit** (confirm with user first)

```bash
git add crates/sigil-core/src/runtime/listeners.rs
git commit -m "feat(runtime): classify Ollama bind exposure from listener snapshot"
```

---

## Task 4: Real `proc_snapshot()` and inode→process map

Replaces the Task 1 placeholder with the real `/proc` reader. This is environment-dependent, so the test is a non-panicking smoke test only.

**Files:**
- Modify: `crates/sigil-core/src/runtime/listeners.rs`
- Test: inline `#[cfg(test)]` in the same file

- [ ] **Step 1: Write the smoke test**

Add to the `mod tests` block:

```rust
#[test]
fn proc_snapshot_does_not_panic() {
    // On Linux this reads /proc; on other OSes it returns unavailable.
    // Either way it must not panic and must return a consistent source.
    let snap = proc_snapshot();
    if snap.available {
        assert_eq!(snap.source, "proc");
    } else {
        assert_eq!(snap.source, "unavailable");
        assert!(snap.listeners.is_empty());
    }
}
```

- [ ] **Step 2: Run the smoke test (passes against the placeholder)**

Run: `cargo test -p sigil-core --lib runtime::tests::proc_snapshot_does_not_panic`
Expected: PASS (placeholder returns `unavailable`). This guards the real impl in Step 3.

- [ ] **Step 3: Replace the placeholder `proc_snapshot` with the real implementation**

In `crates/sigil-core/src/runtime/listeners.rs`, replace the placeholder `proc_snapshot` (from Task 1) with:

```rust
pub fn proc_snapshot() -> ListenerSnapshot {
    let mut listeners = Vec::new();
    let mut any_file = false;
    for (path, is_v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            any_file = true;
            for line in contents.lines().skip(1) {
                if let Some(listener) = parse_proc_net_line(line, is_v6) {
                    listeners.push(listener);
                }
            }
        }
    }
    if !any_file {
        return ListenerSnapshot::unavailable("unavailable");
    }
    ListenerSnapshot {
        processes: inode_process_map(),
        listeners,
        available: true,
        source: "proc".to_string(),
    }
}

fn inode_process_map() -> HashMap<u64, ProcessInfo> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let mut comm: Option<String> = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|digits| digits.parse::<u64>().ok())
            else {
                continue;
            };
            if comm.is_none() {
                comm = std::fs::read_to_string(entry.path().join("comm"))
                    .ok()
                    .map(|value| value.trim().to_string());
            }
            if let Some(name) = &comm {
                map.entry(inode).or_insert_with(|| ProcessInfo {
                    pid,
                    comm: name.clone(),
                });
            }
        }
    }
    map
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --lib runtime::`
Expected: PASS. On this Linux box `proc_snapshot().available` is `true` and `source == "proc"`.

- [ ] **Step 5: Commit** (confirm with user first)

```bash
git add crates/sigil-core/src/runtime/listeners.rs
git commit -m "feat(runtime): read /proc listeners and best-effort process names"
```

---

## Task 5: Integrate runtime exposure into `inspect_ollama`

Adds the options field, report field, port resolution, and WARN findings. Uses `RuntimeListeners::Fixed` to test the finding/verdict wiring without a real listener.

**Files:**
- Modify: `crates/sigil-core/src/ollama.rs`
- Modify: `crates/sigil-core/tests/ollama.rs`

- [ ] **Step 1: Write the failing integration tests**

Add to the top imports of `crates/sigil-core/tests/ollama.rs`:

```rust
use sigil_core::runtime::{
    BindEvidence, Listener, ListenerSnapshot, RuntimeExposure, RuntimeListeners,
};
use std::collections::HashMap;
```

Add a helper near the top of `crates/sigil-core/tests/ollama.rs`:

```rust
fn fixed_listener(addr: &str, port: u16) -> RuntimeListeners {
    RuntimeListeners::Fixed(ListenerSnapshot {
        listeners: vec![Listener {
            addr: addr.parse().unwrap(),
            port,
            inode: 1,
        }],
        processes: HashMap::new(),
        available: true,
        source: "proc".to_string(),
    })
}
```

Add these tests to `crates/sigil-core/tests/ollama.rs`:

```rust
#[test]
fn runtime_public_bind_listener_warns() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("0.0.0.0", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::PublicBind);
    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.runtime_public_bind"));
    assert_eq!(
        report.runtime_exposure.observed,
        vec![BindEvidence {
            addr: "0.0.0.0".to_string(),
            port: 11434,
            process: None,
        }]
    );
}

#[test]
fn runtime_localhost_listener_keeps_pass() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("127.0.0.1", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Localhost);
    assert_eq!(report.verdict, "PASS");
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.id.starts_with("ollama.runtime_")));
}

#[test]
fn runtime_lan_listener_warns() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("10.0.0.5", 11434),
    })
    .unwrap();

    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Lan);
    assert_eq!(report.verdict, "WARN");
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.id == "ollama.runtime_lan_exposure"));
}
```

- [ ] **Step 2: Update existing literals in `crates/sigil-core/tests/ollama.rs`**

Every existing `OllamaInspectOptions { ... }` literal in this file (there are 7) is missing the new field and will fail to compile. Add `runtime_listeners: RuntimeListeners::Disabled,` as the last field to each one. The existing literals are in these tests:
- `inventories_ollama_model_store_manifest_and_blobs`
- `flags_public_bind_host_as_warn_without_network_probe`
- `treats_scheme_less_loopback_host_as_local`
- `flags_non_local_network_host_as_warn_without_probe`
- `flags_manifest_blob_digest_mismatch_as_fail`
- `rejects_manifest_digest_with_path_separators_before_blob_lookup`
- `renders_ai_bom_with_model_runtime_and_files`

Also add this assertion to `inventories_ollama_model_store_manifest_and_blobs` after the existing asserts:

```rust
    assert_eq!(report.runtime_exposure.class, RuntimeExposure::Unknown);
    assert_eq!(report.runtime_exposure.source, "disabled");
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p sigil-core --test ollama`
Expected: FAIL — `OllamaInspectOptions` has no field `runtime_listeners`, `OllamaReport` has no field `runtime_exposure`.

- [ ] **Step 4: Add imports and the options field in `crates/sigil-core/src/ollama.rs`**

At the top of `crates/sigil-core/src/ollama.rs`, add to the `use` block:

```rust
use crate::runtime::{classify_runtime_exposure, RuntimeExposureReport, RuntimeListeners};
```

Add the field to `OllamaInspectOptions` (after `probe_api`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OllamaInspectOptions {
    pub model: Option<String>,
    pub models_dir: PathBuf,
    pub host: String,
    pub probe_api: bool,
    pub runtime_listeners: RuntimeListeners,
}
```

- [ ] **Step 5: Add the report field to `OllamaReport`**

Add the field to `OllamaReport` (after `api`):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OllamaReport {
    pub runtime: String,
    pub model: Option<String>,
    pub models_dir: PathBuf,
    pub host: String,
    pub api: ApiExposure,
    pub runtime_exposure: RuntimeExposureReport,
    pub runtime_status: RuntimeStatus,
    pub version: Option<String>,
    pub models: Vec<OllamaModel>,
    pub findings: Vec<RuntimeFinding>,
    pub verdict: String,
}
```

- [ ] **Step 6: Add port resolution + classification + findings in `inspect_ollama`**

In `crates/sigil-core/src/ollama.rs`, inside `inspect_ollama`, after the existing host-classification findings block (after the `if static_host_classification == ApiExposure::Network { ... }` block, before `let mut version = None;`), insert:

```rust
    let ollama_port = resolve_ollama_port(&options.host);
    let runtime_exposure =
        classify_runtime_exposure(&options.runtime_listeners.snapshot(), ollama_port);
    push_runtime_exposure_finding(&runtime_exposure, ollama_port, &mut findings);
```

Then in the final `Ok(OllamaReport { ... })` constructor, add the field (after `api`):

```rust
        api,
        runtime_exposure,
        runtime_status,
```

- [ ] **Step 7: Add the helper functions**

Add these near `classify_host` in `crates/sigil-core/src/ollama.rs`:

```rust
fn resolve_ollama_port(host: &str) -> u16 {
    if let Some((_, port)) = parse_http_host(host) {
        return port;
    }
    if let Ok(env_host) = std::env::var("OLLAMA_HOST") {
        if let Some((_, port)) = parse_http_host(&env_host) {
            return port;
        }
    }
    11434
}

fn push_runtime_exposure_finding(
    exposure: &RuntimeExposureReport,
    port: u16,
    findings: &mut Vec<RuntimeFinding>,
) {
    use crate::runtime::RuntimeExposure;

    let (id, message) = match exposure.class {
        RuntimeExposure::Lan => (
            "ollama.runtime_lan_exposure",
            "Ollama is bound to a LAN-reachable address",
        ),
        RuntimeExposure::PublicBind => (
            "ollama.runtime_public_bind",
            "Ollama is bound to a public/wildcard address",
        ),
        RuntimeExposure::DockerPublished => (
            "ollama.runtime_docker_published",
            "Ollama appears published through a Docker port mapping",
        ),
        RuntimeExposure::Proxy => (
            "ollama.runtime_proxy",
            "Ollama port appears fronted by a reverse proxy",
        ),
        RuntimeExposure::Localhost | RuntimeExposure::Unknown => return,
    };

    let observed = if exposure.observed.is_empty() {
        format!("port={port}")
    } else {
        exposure
            .observed
            .iter()
            .map(|bind| match &bind.process {
                Some(process) => format!("{}:{} ({process})", bind.addr, bind.port),
                None => format!("{}:{}", bind.addr, bind.port),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    findings.push(RuntimeFinding {
        id: id.to_string(),
        severity: "WARN".to_string(),
        message: message.to_string(),
        evidence: observed,
    });
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --test ollama`
Expected: PASS — new runtime tests pass, all existing Ollama tests still pass (Disabled → Unknown → no runtime finding → original verdicts hold).

- [ ] **Step 9: Commit** (confirm with user first)

```bash
git add crates/sigil-core/src/ollama.rs crates/sigil-core/tests/ollama.rs
git commit -m "feat(ollama): classify runtime bind exposure and emit WARN findings"
```

---

## Task 6: AI-BOM rendering of runtime exposure

Adds a runtime-exposure line and observed bind evidence to the AI-BOM markdown.

**Files:**
- Modify: `crates/sigil-core/src/ollama.rs`
- Modify: `crates/sigil-core/tests/ollama.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/sigil-core/tests/ollama.rs`:

```rust
#[test]
fn ai_bom_includes_runtime_exposure_and_binds() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: fixed_listener("0.0.0.0", 11434),
    })
    .unwrap();

    let bom = render_ai_bom(&report);
    assert!(bom.contains("- Runtime exposure: `public_bind`"));
    assert!(bom.contains("0.0.0.0:11434"));
}

#[test]
fn ai_bom_runtime_exposure_unknown_when_disabled() {
    let tmp = fake_store();
    let report = inspect_ollama(OllamaInspectOptions {
        model: Some("gemma4:e2b".to_string()),
        models_dir: tmp.path().join("models"),
        host: "http://127.0.0.1:11434".to_string(),
        probe_api: false,
        runtime_listeners: RuntimeListeners::Disabled,
    })
    .unwrap();

    let bom = render_ai_bom(&report);
    assert!(bom.contains("- Runtime exposure: `unknown`"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p sigil-core --test ollama ai_bom_includes_runtime_exposure_and_binds`
Expected: FAIL — markdown lacks the runtime-exposure line.

- [ ] **Step 3: Update `render_ai_bom` in `crates/sigil-core/src/ollama.rs`**

In `render_ai_bom`, add the runtime-exposure line into the initial `lines` vector, right after the `- API exposure:` line:

```rust
        format!("- API exposure: `{}`", report.api.as_str()),
        format!(
            "- Runtime exposure: `{}`",
            report.runtime_exposure.class.as_str()
        ),
        format!("- Runtime status: `{}`", report.runtime_status.as_str()),
```

Then, immediately after the `lines.push(format!("- Version: ...))` / version block and before `lines.push(String::new());` that precedes `## Models`, add observed bind evidence:

```rust
    for bind in &report.runtime_exposure.observed {
        match &bind.process {
            Some(process) => lines.push(format!(
                "- Runtime bind: `{}:{}` process=`{process}`",
                bind.addr, bind.port
            )),
            None => lines.push(format!("- Runtime bind: `{}:{}`", bind.addr, bind.port)),
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sigil-core --test ollama`
Expected: PASS — including the existing `renders_ai_bom_with_model_runtime_and_files` (still finds its asserted lines; the new line is additive).

- [ ] **Step 5: Commit** (confirm with user first)

```bash
git add crates/sigil-core/src/ollama.rs crates/sigil-core/tests/ollama.rs
git commit -m "feat(ollama): render runtime exposure in AI-BOM"
```

---

## Task 7: CLI flag and wiring

Adds `--no-inspect-runtime` (default ON) to both subcommands and wires `runtime_listeners`. Updates CLI tests to opt out for determinism.

**Files:**
- Modify: `crates/sigil-cli/src/main.rs`
- Modify: `crates/sigil-cli/tests/ollama_cli.rs`

- [ ] **Step 1: Update the CLI tests to pass `--no-inspect-runtime` and assert output**

In `crates/sigil-cli/tests/ollama_cli.rs`, in `runtime_inspect_ollama_writes_evidence_json`, add `"--no-inspect-runtime",` to the args array (e.g. right after `"--no-probe-api",`), and after the existing JSON asserts add:

```rust
    assert!(json.contains("\"runtime_exposure\""));
    assert!(json.contains("\"class\": \"unknown\""));
```

In `aibom_generate_ollama_writes_markdown`, add `"--no-inspect-runtime",` to the args array (right after `"--no-probe-api",`), and after the existing markdown asserts add:

```rust
    assert!(markdown.contains("- Runtime exposure: `unknown`"));
```

- [ ] **Step 2: Run the CLI tests to verify they fail**

Run: `cargo test -p sigil-cli --test ollama_cli`
Expected: FAIL — `--no-inspect-runtime` is an unknown argument.

- [ ] **Step 3: Add the flag to both arg structs in `crates/sigil-cli/src/main.rs`**

Add the import near the other `sigil_core` imports:

```rust
use sigil_core::runtime::RuntimeListeners;
```

Add this field to `OllamaArgs` (after `probe_api`):

```rust
    #[arg(long = "no-inspect-runtime", action = ArgAction::SetFalse, default_value_t = true)]
    inspect_runtime: bool,
```

Add the same field to `AiBomGenerateArgs` (after `probe_api`):

```rust
    #[arg(long = "no-inspect-runtime", action = ArgAction::SetFalse, default_value_t = true)]
    inspect_runtime: bool,
```

- [ ] **Step 4: Wire `runtime_listeners` in `ollama_options` and `cmd_aibom`**

In `crates/sigil-cli/src/main.rs`, add this helper:

```rust
fn runtime_listeners(inspect_runtime: bool) -> RuntimeListeners {
    if inspect_runtime {
        RuntimeListeners::Inspect
    } else {
        RuntimeListeners::Disabled
    }
}
```

Update `ollama_options` to set the field:

```rust
fn ollama_options(args: OllamaArgs) -> OllamaInspectOptions {
    OllamaInspectOptions {
        model: args.model,
        models_dir: args
            .models_dir
            .unwrap_or_else(OllamaInspectOptions::default_models_dir),
        host: args.host,
        probe_api: args.probe_api,
        runtime_listeners: runtime_listeners(args.inspect_runtime),
    }
}
```

Update the `OllamaInspectOptions { ... }` literal inside `cmd_aibom` to add the field:

```rust
            let options = OllamaInspectOptions {
                model: args.model,
                models_dir: args
                    .models_dir
                    .unwrap_or_else(OllamaInspectOptions::default_models_dir),
                host: args.host,
                probe_api: args.probe_api,
                runtime_listeners: runtime_listeners(args.inspect_runtime),
            };
```

- [ ] **Step 5: Run the CLI tests to verify they pass**

Run: `cargo test -p sigil-cli`
Expected: PASS.

- [ ] **Step 6: Commit** (confirm with user first)

```bash
git add crates/sigil-cli/src/main.rs crates/sigil-cli/tests/ollama_cli.rs
git commit -m "feat(cli): add --no-inspect-runtime and wire runtime bind detection"
```

---

## Task 8: Docs, full verification, and final commit

**Files:**
- Modify: `docs/ollama-inspection.md`

- [ ] **Step 1: Add a Runtime Exposure section to `docs/ollama-inspection.md`**

Insert this section after the existing `## Findings` section:

```markdown
## Runtime Exposure

Beyond the configured `--host` endpoint check, SIGIL inspects how Ollama is
actually bound on the local machine. On Linux it parses `/proc/net/tcp` and
`/proc/net/tcp6` for listening sockets and, best-effort, attributes a process
name via `/proc/<pid>/fd` and `/proc/<pid>/comm`. No external command is
spawned.

The Ollama port is resolved from `--host`, then `OLLAMA_HOST`, then the default
`11434`. The bind on that port is classified as one of:

- `localhost` — loopback only (`127.0.0.0/8`, `::1`). No finding; PASS preserved.
- `lan` — a private/link-local address (`10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, `fc00::/7`, `fe80::/10`). WARN.
- `public_bind` — a wildcard (`0.0.0.0`, `::`) or globally routable address. WARN.
- `docker_published` — the listening process is `docker-proxy`. WARN.
- `proxy` — the listening process is a known reverse proxy
  (`nginx`, `caddy`, `traefik`, `haproxy`, `envoy`). WARN.
- `unknown` — listener inspection unavailable or no listener on the port. No
  finding.

Disable runtime inspection with `--no-inspect-runtime`. On non-Linux platforms
runtime inspection degrades gracefully to `unknown`.

Runtime findings:

- `ollama.runtime_lan_exposure`
- `ollama.runtime_public_bind`
- `ollama.runtime_docker_published`
- `ollama.runtime_proxy`
```

- [ ] **Step 2: Run the full test suite**

Run: `cargo test`
Expected: PASS for all crates (`sigil-core` lib + integration tests, `sigil-cli` tests).

- [ ] **Step 3: Run formatting and lints**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings`
Expected: no diff from fmt; clippy passes with no warnings. Fix any clippy findings (e.g. needless clones) before committing.

- [ ] **Step 4: Manual smoke check (optional, Linux)**

Run: `cargo run -p sigil-cli -- runtime inspect ollama --no-probe-api --out out/runtime.json` then inspect `out/runtime.json` for a `runtime_exposure` object. If Ollama is not installed, `runtime_exposure.class` will be `unknown` (no listener on `11434`).

- [ ] **Step 5: Commit** (confirm with user first)

```bash
git add docs/ollama-inspection.md
git commit -m "docs(ollama): document runtime bind exposure detection"
```

---

## Self-Review Notes

**Spec coverage:**
- Inspect active listeners (Linux) → Task 4 `proc_snapshot`.
- Detect actual bind address/port → Tasks 2–3.
- Classify into the six classes → Task 3 `classify_runtime_exposure` + `exposure_for`.
- Exposure evidence in JSON + AI-BOM → Tasks 5 (`runtime_exposure` field) and 6 (AI-BOM).
- Keep `--host` probing as explicit endpoint check → unchanged; host classification block left intact in Task 5.
- Tests for localhost / `0.0.0.0` / non-local → Task 3 (unit) + Task 5 (integration).
- WARN for public/non-local → Task 5 `push_runtime_exposure_finding`.
- PASS path unchanged for localhost-only → Task 5 `runtime_localhost_listener_keeps_pass` + existing tests with `Disabled`.
- Graceful degradation when tools unavailable → Task 4 (`unavailable`) + Task 3 (`Unknown`).

**Type consistency:** `RuntimeListeners`, `ListenerSnapshot`, `RuntimeExposure`, `RuntimeExposureReport`, `BindEvidence` are defined in Task 1 and used unchanged in Tasks 3, 5, 6, 7. `classify_runtime_exposure(&ListenerSnapshot, u16)` signature is stable from Task 1 placeholder through Task 3 implementation. `proc_snapshot() -> ListenerSnapshot` stable from Task 1 through Task 4.

**Placeholder scan:** Task 1 intentionally ships placeholder bodies for `proc_snapshot` and `classify_runtime_exposure` so the crate compiles before their TDD tasks; both are explicitly replaced in Tasks 3 and 4. No unresolved TODOs remain after Task 8.
