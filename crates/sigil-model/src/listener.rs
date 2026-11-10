//! Listening sockets observed in `/proc/net/tcp{,6}` (plan §4.6.8, observe mode).
//!
//! A [`Listener`] records what the kernel table says, and who holds the socket when that could be
//! established. Its bind class ([`bind_class`]) is derived from the address,
//! never stored. A listener is never attributed to a process by its port.

use serde::{Deserialize, Serialize};

use crate::artifact::ProcessRef;
use crate::evidence::NotObservable;
use crate::id::ListenerId;

use core::net::IpAddr;

/// The class of a bind address, ordered by how widely it listens: loopback, private or
/// link-local, global, then the wildcard (every address of the host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BindClass {
    Loopback,
    /// RFC 1918, link-local, IPv6 unique-local and link-local.
    Private,
    Global,
    Wildcard,
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

/// One listening socket in SIGIL's network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// `listener:<protocol>/<address>:<port>#<socket inode>`.
    pub id: ListenerId,
    pub protocol: Protocol,
    /// The bound address as read (IPv4-mapped IPv6 is kept as such; normalizing is analysis).
    pub address: String,
    pub port: u16,
    pub socket_inode: u64,
    pub owner: ListenerOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
}

/// Who holds a listening socket, as far as the fd tables that could be read show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ListenerOwner {
    /// A file descriptor of this process refers to the socket.
    Process { process: ProcessRef },
    /// No readable fd table refers to it, and some could not be read.
    Unknown { why: NotObservable },
    /// Every fd table was read, and none refers to it.
    Unheld,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_classes_come_from_the_address_alone() {
        for (address, class) in [
            ("127.0.0.1", BindClass::Loopback),
            ("0.0.0.0", BindClass::Wildcard),
            ("8.8.8.8", BindClass::Global),
            ("192.168.1.10", BindClass::Private),
            ("10.0.0.5", BindClass::Private),
            ("169.254.1.1", BindClass::Private),
            ("::1", BindClass::Loopback),
            ("::", BindClass::Wildcard),
            ("fd00::1", BindClass::Private),
            ("fe80::1", BindClass::Private),
            ("2001:db8::7", BindClass::Global),
            ("::ffff:127.0.0.1", BindClass::Loopback),
            ("::ffff:10.0.0.5", BindClass::Private),
            ("::ffff:8.8.8.8", BindClass::Global),
            ("::ffff:0.0.0.0", BindClass::Wildcard),
        ] {
            assert_eq!(bind_class(address.parse().unwrap()), class, "{address}");
        }
    }

    #[test]
    fn classes_are_ordered_by_how_widely_they_listen() {
        assert!(BindClass::Loopback < BindClass::Private);
        assert!(BindClass::Private < BindClass::Global);
        assert!(BindClass::Global < BindClass::Wildcard);
        assert_eq!(
            serde_json::to_string(&BindClass::Wildcard).unwrap(),
            "\"Wildcard\""
        );
    }
}
