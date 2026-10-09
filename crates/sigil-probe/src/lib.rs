//! `sigil-probe`: the active API probe (ADR-002 active mode; plan §4.2, §4.3).
//!
//! The only SIGIL code that opens a network connection, and only when `--active api-probe` asks
//! for it. [`probe_version`] sends one `GET /api/version` to a literal address and records how it
//! ended.
//!
//! - **Where:** a `SocketAddr`, never a name: nothing is resolved, so no resolver, NSS module, or
//!   DNS query is involved. Proxy settings are ignored. A non-loopback target is refused unless
//!   the caller allows remote targets.
//! - **How much:** a connect timeout, one deadline for writing the request and reading the
//!   response together, and a byte limit on the response (head and body).
//! - **What:** plain HTTP/1.1 only, with no TLS and no redirects (see [`http`]).

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod http;

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sigil_model::{
    is_loopback, ApiProbe, ProbeId, ProbePhase, ProbeResult, Timestamp, UntrustedText,
};

use crate::http::Parse;

/// The bounds of one probe. The CLI records each as a budget of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOptions {
    /// `api_connect_ms`.
    pub connect_timeout: Duration,
    /// `api_io_ms`: writing the request and reading the response, together.
    pub io_deadline: Duration,
    /// `api_response_bytes`: the largest response read (head and body).
    pub max_response: u64,
    /// Whether a non-loopback target may be probed (`--allow-remote`).
    pub allow_remote: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(2000),
            io_deadline: Duration::from_millis(2000),
            max_response: 65536,
            allow_remote: false,
        }
    }
}

/// Why a probe was not attempted. Nothing touches the network in these cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// The target is not loopback and remote targets are not allowed.
    RemoteNotAllowed(SocketAddr),
    /// The target is an unspecified address, has port 0, or has an IPv6 scope ID.
    InvalidTarget(SocketAddr),
    /// A timeout or the byte limit is zero.
    ZeroBound,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::RemoteNotAllowed(target) => {
                write!(
                    f,
                    "{target} is not loopback, and remote targets are not allowed"
                )
            }
            ProbeError::InvalidTarget(target) => write!(
                f,
                "{target} is not a probe target (unspecified address, port 0, or scope ID)"
            ),
            ProbeError::ZeroBound => write!(f, "a probe timeout or byte limit is zero"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Probes `target`'s `/api/version` once. `at` is recorded as the time of the attempt.
pub fn probe_version(
    target: SocketAddr,
    opts: &ProbeOptions,
    at: Timestamp,
) -> Result<ApiProbe, ProbeError> {
    let scoped = matches!(target, SocketAddr::V6(v6) if v6.scope_id() != 0);
    if target.ip().is_unspecified() || target.port() == 0 || scoped {
        return Err(ProbeError::InvalidTarget(target));
    }
    if !opts.allow_remote && !is_loopback(target.ip()) {
        return Err(ProbeError::RemoteNotAllowed(target));
    }
    if opts.connect_timeout.is_zero() || opts.io_deadline.is_zero() || opts.max_response == 0 {
        return Err(ProbeError::ZeroBound);
    }
    Ok(ApiProbe {
        id: ProbeId::api(target),
        address: target.ip().to_string(),
        port: target.port(),
        at,
        result: exchange(target, opts),
    })
}

// C-4 exception (ADR-002, active mode): the API probe's one TCP connection, to a target the
// caller checked above. Every use of the stream is in this function.
#[allow(clippy::disallowed_types)]
fn exchange(target: SocketAddr, opts: &ProbeOptions) -> ProbeResult {
    let mut stream = match std::net::TcpStream::connect_timeout(&target, opts.connect_timeout) {
        Ok(stream) => stream,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return ProbeResult::Refused,
        Err(e) => return io_failure(&e, ProbePhase::Connect),
    };
    let deadline = Instant::now() + opts.io_deadline;

    let Some(left) = time_left(deadline) else {
        return timed_out(ProbePhase::Write);
    };
    if let Err(e) = stream.set_write_timeout(Some(left)) {
        return failed(&e);
    }
    if let Err(e) = stream.write_all(&http::request(target)) {
        return io_failure(&e, ProbePhase::Write);
    }

    // At most one byte more than the limit is read, to tell "at the limit" from "over it".
    let limit = usize::try_from(opts.max_response)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Some(left) = time_left(deadline) else {
            return timed_out(ProbePhase::Read);
        };
        if let Err(e) = stream.set_read_timeout(Some(left)) {
            return failed(&e);
        }
        let want = chunk.len().min(limit - response.len());
        let n = match stream.read(&mut chunk[..want]) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return io_failure(&e, ProbePhase::Read),
        };
        response.extend_from_slice(&chunk[..n]);
        if response.len() as u64 > opts.max_response {
            return ProbeResult::TooLarge {
                limit: opts.max_response,
            };
        }
        match http::parse(&response, n == 0) {
            Parse::NeedMore if n == 0 => {
                return ProbeResult::Malformed {
                    why: "the response ended early".to_string(),
                }
            }
            Parse::NeedMore => {}
            Parse::Done { status, version } => {
                return ProbeResult::Answered {
                    status,
                    version: version.map(UntrustedText::new),
                }
            }
            Parse::Malformed(why) => {
                return ProbeResult::Malformed {
                    why: why.to_string(),
                }
            }
        }
    }
}

/// The time left before `deadline`, if any.
fn time_left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

fn timed_out(phase: ProbePhase) -> ProbeResult {
    ProbeResult::TimedOut { phase }
}

/// A timeout (a socket timeout reports `WouldBlock` on Linux) in `phase`, or another failure.
fn io_failure(e: &io::Error, phase: ProbePhase) -> ProbeResult {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => timed_out(phase),
        _ => failed(e),
    }
}

fn failed(e: &io::Error) -> ProbeResult {
    ProbeResult::Failed {
        message: UntrustedText::new(e.to_string()),
    }
}
