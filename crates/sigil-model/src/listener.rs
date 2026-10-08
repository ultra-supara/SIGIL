//! Listening sockets observed in `/proc/net/tcp{,6}` (plan §4.6.8, observe mode).
//!
//! A [`Listener`] records what the kernel table says, and who holds the socket when that could be
//! established. Its bind class (loopback, wildcard, private, global) is derived from the address,
//! never stored. A listener is never attributed to a process by its port.

use serde::{Deserialize, Serialize};

use crate::artifact::ProcessRef;
use crate::evidence::NotObservable;
use crate::id::ListenerId;

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
