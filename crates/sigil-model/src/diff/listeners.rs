//! The runtime's listeners, by port: added, removed, or bound wider or narrower.

use std::collections::{BTreeMap, BTreeSet};

use super::compare::{checks, Found};
use super::scope::closed_everywhere;
use crate::artifact::RUNTIME_ROLE;
use crate::diff::{Change, Item, Side};
use crate::id::ListenerId;
use crate::listener::{bind_class, BindClass, Listener, ListenerOwner};
use crate::session::Session;

const BINDS: &str = "exposure.binds";

/// One port of the runtime: the widest class of its listeners, and their IDs.
struct Port {
    class: BindClass,
    listeners: Vec<ListenerId>,
}

/// Whether a process with the runtime's role holds `l`: the listeners `exposure.binds` covers.
fn held_by_the_runtime(s: &Session, l: &Listener) -> bool {
    let ListenerOwner::Process { process } = &l.owner else {
        return false;
    };
    s.processes
        .iter()
        .any(|p| p.process == *process && p.roles.iter().any(|r| r.as_str() == RUNTIME_ROLE))
}

/// The runtime's ports, `Tcp` and `Tcp6` together (a loopback-to-wildcard change often moves
/// from `127.0.0.1` to `::`). Validation refuses an address that does not parse, so a validated
/// session skips none.
fn ports(s: &Session) -> BTreeMap<u16, Port> {
    let mut out: BTreeMap<u16, Port> = BTreeMap::new();
    for l in s.listeners.iter().filter(|l| held_by_the_runtime(s, l)) {
        let Ok(address) = l.address.parse::<core::net::IpAddr>() else {
            continue;
        };
        let class = bind_class(address);
        let port = out.entry(l.port).or_insert(Port {
            class,
            listeners: vec![],
        });
        port.class = port.class.max(class);
        port.listeners.push(l.id.clone());
    }
    for port in out.values_mut() {
        port.listeners.sort();
    }
    out
}

/// `exposure.binds` is judged everywhere: its per-runtime scopes are processes, which are per
/// run. A wider bind says the baseline had nothing as wide, a narrower one the current run; an
/// added or removed port says the other side had none.
pub(super) fn compare(b: &Session, c: &Session, found: &mut Found) {
    let (was, is) = (ports(b), ports(c));
    let baseline_closed = closed_everywhere(b, BINDS);
    let current_closed = closed_everywhere(c, BINDS);
    let numbers: BTreeSet<u16> = was.keys().chain(is.keys()).copied().collect();
    for port in numbers {
        let (change, closed, side) = match (was.get(&port), is.get(&port)) {
            (Some(x), Some(y)) if y.class > x.class => (
                Change::BindWidened {
                    port,
                    baseline: x.class,
                    current: y.class,
                    baseline_listeners: x.listeners.clone(),
                    current_listeners: y.listeners.clone(),
                },
                baseline_closed,
                Side::Baseline,
            ),
            (Some(x), Some(y)) if y.class < x.class => (
                Change::BindNarrowed {
                    port,
                    baseline: x.class,
                    current: y.class,
                    baseline_listeners: x.listeners.clone(),
                    current_listeners: y.listeners.clone(),
                },
                current_closed,
                Side::Current,
            ),
            (Some(x), None) => (
                Change::ListenerRemoved {
                    port,
                    class: x.class,
                    listeners: x.listeners.clone(),
                },
                current_closed,
                Side::Current,
            ),
            (None, Some(y)) => (
                Change::ListenerAdded {
                    port,
                    class: y.class,
                    listeners: y.listeners.clone(),
                },
                baseline_closed,
                Side::Baseline,
            ),
            _ => continue,
        };
        if closed {
            found.changes.push(change);
        } else {
            found.unjudged(Item::Port { port }, checks(&[BINDS]), side);
        }
    }
}
