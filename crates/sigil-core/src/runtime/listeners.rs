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

#[derive(Debug)]
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
    // Process name takes precedence over bind address: a known proxy or docker-proxy
    // process indicates intentional forwarding regardless of the local bind IP.
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

    #[test]
    fn classifies_ipv6_loopback_as_localhost() {
        let snap = snapshot_with("::1", 11434, None);
        assert_eq!(
            classify_runtime_exposure(&snap, 11434).class,
            RuntimeExposure::Localhost
        );
    }

    #[test]
    fn classifies_ipv6_wildcard_as_public_bind() {
        let snap = snapshot_with("::", 11434, None);
        assert_eq!(
            classify_runtime_exposure(&snap, 11434).class,
            RuntimeExposure::PublicBind
        );
    }

    #[test]
    fn classifies_ipv6_ula_as_lan() {
        let snap = snapshot_with("fd00::1", 11434, None);
        assert_eq!(
            classify_runtime_exposure(&snap, 11434).class,
            RuntimeExposure::Lan
        );
    }

    #[test]
    fn classifies_ipv6_link_local_as_lan() {
        let snap = snapshot_with("fe80::1", 11434, None);
        assert_eq!(
            classify_runtime_exposure(&snap, 11434).class,
            RuntimeExposure::Lan
        );
    }

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
}
