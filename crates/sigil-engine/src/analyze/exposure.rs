//! Exposure findings and `exposure.binds` coverage, derived from observed facts (plan §4.6.8,
//! §6.3).
//!
//! **Findings.** Only for a listener the runtime holds. The bind class comes from the address
//! alone, with IPv4-mapped IPv6 normalized first (I-09). A process name never lowers it (I-10):
//! - wildcard or global: `exposure.bind_public`;
//! - private or link-local: `exposure.bind_lan`;
//! - loopback: none.
//!
//! The class describes the bind address, not reachability, which also depends on firewalls, NAT,
//! and routing that SIGIL does not see.
//!
//! **`exposure.binds` coverage:**
//!
//! | Situation | State |
//! |---|---|
//! | no runtime process; PID 1 visible | `Complete` on `Audit` |
//! | no runtime process; PID 1 hidden (`hidepid`) | `Unavailable(PermissionDenied)` on `Audit` |
//! | a runtime whose fd table is unreadable | `Unavailable(PermissionDenied)` on it (I-08) |
//! | a runtime in another network namespace, or one that is unreadable | `Partial` on it |
//! | a table or list not read completely | `Partial` |
//! | otherwise | `Complete` on it |

use std::net::IpAddr;

use sigil_model::{
    CheckId, Coverage, CoverageState, EvidenceRef, Finding, ListenerOwner, NotObservable, NsInode,
    Observability, ProcessObs, Ref, Unavailability,
};

use super::observed_finding;
use crate::observe::proc::{ProcFacts, RUNTIME_ROLE};

/// Whether the runtime's binds are known.
pub const BINDS: &str = "exposure.binds";

/// The class of a bind address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindClass {
    Loopback,
    Wildcard,
    /// RFC 1918, link-local, IPv6 unique-local and link-local.
    Private,
    Global,
}

/// The class of `address`, with IPv4-mapped IPv6 (`::ffff:a.b.c.d`) read as its IPv4 address.
pub fn bind_class(address: IpAddr) -> BindClass {
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match address {
        IpAddr::V4(v4) if v4.is_loopback() => BindClass::Loopback,
        IpAddr::V4(v4) if v4.is_unspecified() => BindClass::Wildcard,
        IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => BindClass::Private,
        IpAddr::V4(_) => BindClass::Global,
        IpAddr::V6(v6) if v6.is_loopback() => BindClass::Loopback,
        IpAddr::V6(v6) if v6.is_unspecified() => BindClass::Wildcard,
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            // fc00::/7 (unique local) and fe80::/10 (link-local).
            if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 {
                BindClass::Private
            } else {
                BindClass::Global
            }
        }
    }
}

/// The findings and `exposure.binds` coverage of `facts`.
pub fn analyze(facts: &ProcFacts) -> (Vec<Finding>, Vec<Coverage>) {
    let mut findings = vec![];
    let mut coverage = vec![];
    let runtimes: Vec<&ProcessObs> = facts
        .processes
        .iter()
        .filter(|p| p.roles.iter().any(|r| r.as_str() == RUNTIME_ROLE))
        .collect();
    if runtimes.is_empty() {
        let state = if !facts.pid1_visible {
            CoverageState::Unavailable {
                why: Unavailability::PermissionDenied,
            }
        } else if facts.gaps.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial {
                missing: facts.gaps.clone(),
            }
        };
        cover(&mut coverage, Ref::Audit, state);
        return (findings, coverage);
    }
    for runtime in runtimes {
        let scope = Ref::Process(runtime.process.clone());
        if let Observability::NotObservable(why) = runtime.fd_table {
            let state = match why {
                NotObservable::PermissionDenied => CoverageState::Unavailable {
                    why: Unavailability::PermissionDenied,
                },
                other => CoverageState::Partial {
                    missing: vec![format!("its fd table is not observable ({other:?})")],
                },
            };
            cover(&mut coverage, scope, state);
            continue;
        }
        let mut missing = facts.gaps.clone();
        match (&runtime.net_ns, facts.own_net_ns) {
            (NsInode::Inode(theirs), Some(ours)) if *theirs == ours => {}
            (NsInode::Inode(_), Some(_)) => {
                missing.push("listeners in another network namespace".to_string());
            }
            _ => missing.push("network namespace not observable".to_string()),
        }
        for listener in &facts.listeners {
            let ListenerOwner::Process { process } = &listener.owner else {
                continue;
            };
            if *process != runtime.process {
                continue;
            }
            let Ok(address) = listener.address.parse::<IpAddr>() else {
                continue;
            };
            let (rule, condition) = match bind_class(address) {
                BindClass::Loopback => continue,
                BindClass::Wildcard | BindClass::Global => ("exposure.bind_public", "bind_public"),
                BindClass::Private => ("exposure.bind_lan", "bind_private"),
            };
            let observed = vec![
                EvidenceRef::Listener {
                    listener: listener.id.clone(),
                },
                EvidenceRef::Process {
                    process: process.clone(),
                },
            ];
            findings.extend(observed_finding(
                rule,
                Ref::Listener(listener.id.clone()),
                "",
                condition,
                observed.clone(),
                observed,
            ));
        }
        let state = if missing.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Partial { missing }
        };
        cover(&mut coverage, scope, state);
    }
    (findings, coverage)
}

fn cover(coverage: &mut Vec<Coverage>, scope: Ref, state: CoverageState) {
    if let Ok(check) = CheckId::new(BINDS) {
        coverage.push(Coverage {
            check,
            scope,
            state,
            budget: None,
        });
    }
}
