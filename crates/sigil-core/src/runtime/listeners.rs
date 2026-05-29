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
}
