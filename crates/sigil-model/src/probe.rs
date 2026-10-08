//! Active probes: what an explicitly requested active feature asked, and what came back (ADR-002,
//! active mode).
//!
//! The only active feature is the API probe: one `GET /api/version` to a literal address,
//! loopback unless the request allows remote targets. An [`ApiProbe`] records the outcome as
//! seen. A refused connection is an observation (nothing answers there); a timeout is not.

use core::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::id::{ProbeId, Timestamp};
use crate::text::UntrustedText;

/// An active feature the request asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ActiveFeature {
    /// `--active api-probe`: one `GET /api/version` to `address:port`.
    ApiProbe {
        /// The canonical text of an IP address.
        address: String,
        port: u16,
        /// Whether a non-loopback target was allowed (`--allow-remote`).
        allow_remote: bool,
    },
}

/// One API probe and its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiProbe {
    /// `probe:api/<address>:<port>`, with an IPv6 address in brackets.
    pub id: ProbeId,
    /// The canonical text of an IP address.
    pub address: String,
    pub port: u16,
    /// When the connection was attempted.
    pub at: Timestamp,
    pub result: ProbeResult,
}

/// How a probe ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ProbeResult {
    /// An HTTP response was read. `version` is set only for status 200 with a JSON object whose
    /// `version` is a short string.
    Answered {
        status: u16,
        version: Option<UntrustedText>,
    },
    /// The connection was refused: nothing answers at the target from this host.
    Refused,
    /// The phase did not finish within its bound.
    TimedOut { phase: ProbePhase },
    /// The response exceeded `limit` bytes (head and body).
    TooLarge { limit: u64 },
    /// The response is not HTTP/1.x as SIGIL reads it. Fixed text, never response bytes.
    Malformed { why: String },
    /// Any other I/O error, e.g. an unreachable network or a reset.
    Failed { message: UntrustedText },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbePhase {
    Connect,
    Write,
    Read,
}

/// Whether `address` is loopback: `127.0.0.0/8`, `::1`, or IPv4-mapped `::ffff:127.0.0.0/104`.
/// The one definition the CLI, the probe, and validation share.
pub fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_addresses() {
        for a in ["127.0.0.1", "127.255.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(is_loopback(a.parse().unwrap()), "{a}");
        }
        for a in [
            "0.0.0.0",
            "::",
            "10.0.0.1",
            "::ffff:10.0.0.1",
            "192.0.2.1",
            "::2",
            "128.0.0.1",
        ] {
            assert!(!is_loopback(a.parse().unwrap()), "{a}");
        }
    }
}
