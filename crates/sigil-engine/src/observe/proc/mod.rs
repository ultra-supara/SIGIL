//! The process table and the TCP listener tables under a proc root (plan §4.6.8).
//!
//! [`observe`] records facts only:
//! - the runtime processes and their listeners;
//! - the listeners of fronting processes, as hints;
//! - the listeners whose owner is unknown.
//!
//! What can be read:
//! - **The tables.** `net/tcp{,6}` are SIGIL's own network namespace (`self/ns/net`).
//! - **Ownership.** A socket is attributed to a process only through that process's fd table
//!   (`fd/<n>` → `socket:[inode]`), never by its port (I-08). When a table that might hold it
//!   cannot be read, the owner is unknown.
//! - **The runtime.** `ollama serve`: `argv[0]`'s basename is `ollama` and `argv[1]` is `serve`.
//!   When `exe` can be read, its basename must also be `ollama`. `cmdline` is read only for
//!   processes whose `comm` is `ollama`.
//!
//! Every entry read is in the C-6 allowlist: `net/tcp{,6}`, the proc root's directory, and, per
//! process, `comm`, `cmdline`, `stat`, `exe`, `ns/net`, `fd`, and `fd/<n>`. Links are read with
//! `readlinkat`, never followed or opened.

pub mod parse;

use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use sigil_model::{
    Listener, ListenerId, ListenerOwner, NotObservable, NsInode, Observability, ProcessExe,
    ProcessObs, ProcessRef, ProcessRole, Protocol, Timestamp, UntrustedText,
};

/// The role of the runtime's server process.
pub const RUNTIME_ROLE: &str = "ollama serve";
/// Process names (`comm`) of fronting processes: their listeners are kept as hints, and never
/// lower a bind class (§4.6.8).
pub const FRONTING: &[&str] = &[
    "nginx",
    "caddy",
    "traefik",
    "haproxy",
    "envoy",
    "docker-proxy",
];

/// Bounds on what is read (C-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcBudgets {
    /// Processes listed.
    pub max_processes: u64,
    /// File descriptors listed per process.
    pub max_fds: u64,
    /// Bytes of each TCP table.
    pub max_table_bytes: u64,
}

impl Default for ProcBudgets {
    fn default() -> Self {
        ProcBudgets {
            max_processes: 32_768,
            max_fds: 65_536,
            max_table_bytes: 16 << 20,
        }
    }
}

/// What was observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcFacts {
    /// The runtime processes, and the fronting processes that hold a recorded listener, by PID.
    pub processes: Vec<ProcessObs>,
    /// By ID.
    pub listeners: Vec<Listener>,
    /// SIGIL's own network namespace.
    pub own_net_ns: Option<u64>,
    /// PID 1 is listed. It is not, under `hidepid`, where other users' processes are hidden.
    pub pid1_visible: bool,
    /// What could not be read completely, with why: the tables, the process list, an fd table
    /// over its budget.
    pub gaps: Vec<String>,
}

/// Reads the process and listener tables under `proc_root` (`/proc` outside tests).
pub fn observe(proc_root: &Path, at: &Timestamp, boot_id: &str, budgets: ProcBudgets) -> ProcFacts {
    let mut facts = ProcFacts::default();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let root = match rustix::fs::openat(rustix::fs::CWD, proc_root, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            facts
                .gaps
                .push(format!("the proc root cannot be opened ({e})"));
            return facts;
        }
    };
    let root = root.as_fd();
    facts.own_net_ns = rustix::fs::readlinkat(root, "self/ns/net", Vec::new())
        .ok()
        .and_then(|link| parse::link_inode(link.as_bytes(), "net"));

    let mut rows = vec![];
    for (name, protocol, v6) in [
        ("net/tcp", Protocol::Tcp, false),
        ("net/tcp6", Protocol::Tcp6, true),
    ] {
        match read_limited(root, name, budgets.max_table_bytes) {
            Ok(Read::Whole(bytes)) => {
                let text = String::from_utf8_lossy(&bytes);
                rows.extend(
                    text.lines()
                        .filter_map(|line| parse::tcp_listen_line(line, v6))
                        .map(|row| (protocol, row)),
                );
            }
            Ok(Read::OverLimit) => facts.gaps.push(format!("{name} is over its budget")),
            Err(e) => facts.gaps.push(format!("{name} cannot be read ({e})")),
        }
    }

    let pids = list_pids(root, budgets, &mut facts);
    facts.pid1_visible = pids.contains(&1);
    let seen: Vec<Seen> = pids
        .into_iter()
        .filter_map(|pid| Seen::read(root, pid, budgets, &mut facts.gaps))
        .collect();
    let any_unreadable = seen.iter().any(|p| p.sockets.is_err());
    let mut holders: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, p) in seen.iter().enumerate() {
        for inode in p.sockets.as_deref().unwrap_or_default() {
            holders.entry(*inode).or_default().push(i);
        }
    }

    // The runtime processes are recorded whether or not they listen.
    let mut recorded: BTreeMap<usize, ProcessObs> = BTreeMap::new();
    for (i, p) in seen.iter().enumerate() {
        if p.runtime() {
            if let Some(obs) = p.observation(at, boot_id, true) {
                recorded.insert(i, obs);
            }
        }
    }
    for (protocol, row) in rows {
        let held = holders
            .get(&row.inode)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let runtime = held.iter().find(|i| recorded.contains_key(i));
        let fronting = held.iter().find(|i| seen[**i].fronting());
        let owner = match (runtime.or(fronting), held.is_empty()) {
            (Some(i), _) => {
                if !recorded.contains_key(i) {
                    // A fronting process: recorded once it holds a recorded listener.
                    let Some(obs) = seen[*i].observation(at, boot_id, false) else {
                        // It exited meanwhile: nothing to attribute to.
                        continue;
                    };
                    recorded.insert(*i, obs);
                }
                let Some(obs) = recorded.get(i) else {
                    continue;
                };
                ListenerOwner::Process {
                    process: obs.process.clone(),
                }
            }
            // A known owner that is neither the runtime nor fronting: not recorded.
            (None, false) => continue,
            (None, true) if any_unreadable => ListenerOwner::Unknown {
                why: NotObservable::PermissionDenied,
            },
            (None, true) => ListenerOwner::Unheld,
        };
        if let Some(listener) = listener(protocol, row, owner) {
            facts.listeners.push(listener);
        }
    }
    facts.listeners.sort_by(|a, b| a.id.cmp(&b.id));
    facts.processes = recorded.into_values().collect();
    facts
}

fn listener(protocol: Protocol, row: parse::TcpListen, owner: ListenerOwner) -> Option<Listener> {
    let (kind, address) = match protocol {
        Protocol::Tcp => ("tcp", row.address.to_string()),
        Protocol::Tcp6 => ("tcp6", format!("[{}]", row.address)),
    };
    let id = ListenerId::new(format!(
        "listener:{kind}/{address}:{}#{}",
        row.port, row.inode
    ))
    .ok()?;
    Some(Listener {
        id,
        protocol,
        address: row.address.to_string(),
        port: row.port,
        socket_inode: row.inode,
        owner,
    })
}

/// The numeric entries of the proc root, ascending, within the budget.
fn list_pids(root: BorrowedFd<'_>, budgets: ProcBudgets, facts: &mut ProcFacts) -> Vec<u32> {
    let dir = match rustix::fs::Dir::read_from(root) {
        Ok(dir) => dir,
        Err(e) => {
            facts
                .gaps
                .push(format!("the process list cannot be read ({e})"));
            return vec![];
        }
    };
    let mut pids = vec![];
    for entry in dir {
        let Ok(entry) = entry else {
            facts
                .gaps
                .push("the process list could not be read to the end".into());
            break;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .ok()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pids.len() as u64 >= budgets.max_processes {
            facts
                .gaps
                .push(format!("more than {} processes", budgets.max_processes));
            break;
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    pids
}

/// One listed process: what every process needs read (its name and sockets).
struct Seen {
    pid: u32,
    dir: OwnedFd,
    comm: Option<Vec<u8>>,
    /// The socket inodes its fds refer to, or why its fd table could not be listed.
    sockets: Result<Vec<u64>, NotObservable>,
}

impl Seen {
    fn read(
        root: BorrowedFd<'_>,
        pid: u32,
        budgets: ProcBudgets,
        gaps: &mut Vec<String>,
    ) -> Option<Seen> {
        let dir = open_dir(root, &pid.to_string()).ok()?;
        let comm = match read_limited(dir.as_fd(), "comm", 64) {
            Ok(Read::Whole(mut bytes)) => {
                while bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                Some(bytes)
            }
            _ => None,
        };
        let sockets = match open_dir(dir.as_fd(), "fd") {
            Ok(fds) => Ok(sockets(fds.as_fd(), pid, budgets, gaps)),
            Err(Errno::NOENT) => return None,
            Err(e) => Err(not_observable(e)),
        };
        Some(Seen {
            pid,
            dir,
            comm,
            sockets,
        })
    }

    fn comm_is(&self, name: &str) -> bool {
        self.comm.as_deref() == Some(name.as_bytes())
    }

    fn fronting(&self) -> bool {
        FRONTING.iter().any(|f| self.comm_is(f))
    }

    /// `ollama serve` by its arguments, unless an `exe` that can be read is not `ollama`.
    fn runtime(&self) -> bool {
        if !self.comm_is("ollama") {
            return false;
        }
        let argv = self.argv();
        let by_argv = argv.len() >= 2 && basename(&argv[0]) == b"ollama" && argv[1] == b"serve";
        by_argv
            && match self.exe() {
                Ok((path, _)) => basename(&path) == b"ollama",
                Err(_) => true,
            }
    }

    fn argv(&self) -> Vec<Vec<u8>> {
        match read_limited(self.dir.as_fd(), "cmdline", 64 << 10) {
            Ok(Read::Whole(bytes)) => parse::cmdline(&bytes),
            _ => vec![],
        }
    }

    /// The executable's path and whether it was deleted.
    fn exe(&self) -> Result<(Vec<u8>, bool), NotObservable> {
        let link =
            rustix::fs::readlinkat(self.dir.as_fd(), "exe", Vec::new()).map_err(not_observable)?;
        let bytes = link.into_bytes();
        match bytes.strip_suffix(b" (deleted)") {
            Some(path) => Ok((path.to_vec(), true)),
            None => Ok((bytes, false)),
        }
    }

    /// The process as recorded; `None` when it exited meanwhile. `argv` only for the runtime.
    fn observation(&self, at: &Timestamp, boot_id: &str, runtime: bool) -> Option<ProcessObs> {
        let start_ticks = match read_limited(self.dir.as_fd(), "stat", 4096) {
            Ok(Read::Whole(bytes)) => parse::stat_start_ticks(&String::from_utf8_lossy(&bytes))?,
            _ => return None,
        };
        let net_ns = match rustix::fs::readlinkat(self.dir.as_fd(), "ns/net", Vec::new()) {
            Ok(link) => match parse::link_inode(link.as_bytes(), "net") {
                Some(inode) => NsInode::Inode(inode),
                None => NsInode::NotObservable(NotObservable::NoProcess),
            },
            Err(e) => NsInode::NotObservable(not_observable(e)),
        };
        let exe = match self.exe() {
            Ok((path, deleted)) => ProcessExe::Path {
                path: UntrustedText::from_bytes(path),
                deleted,
            },
            Err(why) => ProcessExe::NotObservable(why),
        };
        Some(ProcessObs {
            process: ProcessRef {
                pid: self.pid,
                start_ticks,
                boot_id: boot_id.to_string(),
            },
            at: at.clone(),
            roles: if runtime {
                ProcessRole::new(RUNTIME_ROLE).ok().into_iter().collect()
            } else {
                vec![]
            },
            exe,
            mappings: vec![],
            name: self.comm.clone().map(UntrustedText::from_bytes),
            argv: runtime.then(|| {
                self.argv()
                    .into_iter()
                    .map(UntrustedText::from_bytes)
                    .collect()
            }),
            net_ns,
            fd_table: match &self.sockets {
                Ok(_) => Observability::Observed,
                Err(why) => Observability::NotObservable(*why),
            },
        })
    }
}

/// The socket inodes an fd directory's links name, within the budget.
fn sockets(
    fds: BorrowedFd<'_>,
    pid: u32,
    budgets: ProcBudgets,
    gaps: &mut Vec<String>,
) -> Vec<u64> {
    let Ok(dir) = rustix::fs::Dir::read_from(fds) else {
        gaps.push(format!("the fd table of {pid} cannot be listed"));
        return vec![];
    };
    let mut inodes = vec![];
    let mut count: u64 = 0;
    for entry in dir.flatten() {
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        count += 1;
        if count > budgets.max_fds {
            gaps.push(format!(
                "the fd table of {pid} has more than {} entries",
                budgets.max_fds
            ));
            break;
        }
        if let Ok(link) = rustix::fs::readlinkat(fds, name, Vec::new()) {
            if let Some(inode) = parse::link_inode(link.as_bytes(), "socket") {
                inodes.push(inode);
            }
        }
    }
    inodes
}

fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}

fn not_observable(e: Errno) -> NotObservable {
    match e {
        Errno::ACCESS | Errno::PERM => NotObservable::PermissionDenied,
        _ => NotObservable::NoProcess,
    }
}

fn open_dir(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

enum Read {
    Whole(Vec<u8>),
    OverLimit,
}

/// Reads `name` in `dir` (its last component not followed), up to `limit` bytes. procfs reports
/// no size, so the limit is checked while reading.
fn read_limited(dir: BorrowedFd<'_>, name: &str, limit: u64) -> Result<Read, Errno> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut out = vec![];
    let mut buffer = [0u8; 8192];
    loop {
        let n = match rustix::io::read(&fd, &mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        };
        out.extend_from_slice(&buffer[..n]);
        if out.len() as u64 > limit {
            return Ok(Read::OverLimit);
        }
    }
    Ok(Read::Whole(out))
}
