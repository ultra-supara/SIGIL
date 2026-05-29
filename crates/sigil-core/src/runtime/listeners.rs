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
