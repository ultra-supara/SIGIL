//! The process table and the TCP listener tables under a proc root (plan §4.6.8).
//!
//! [`observe`] records facts only:
//! - the runtime processes and their listeners;
//! - the listeners of fronting processes, as hints;
//! - the listeners whose owner is unknown.
//!
//! What was not seen is never taken as absent:
//! - **The tables.** `net/tcp{,6}` are SIGIL's own network namespace (`self/ns/net`). A row that
//!   cannot be read is a gap.
//! - **Ownership.** A socket is attributed to a process only through that process's fd table
//!   (`fd/<n>` → `socket:[inode]`), never by its port (I-08). A listener no table holds is
//!   `Unheld` only when every table was listed completely; otherwise its owner is `Unknown`.
//! - **The runtime.** `ollama serve`: `argv[0]`'s basename is `ollama` and `argv[1]` is `serve`.
//!   When `exe` can be read, its basename must also be `ollama`. `cmdline` is read only for
//!   processes whose `comm` is `ollama`. A process whose name or arguments cannot be read may be
//!   the runtime: it is a gap, and the listeners it holds are kept.
//!
//! Processes are read one at a time, and each one's directory is closed before the next, so the
//! number of open files does not grow with the process table.
//!
//! Every entry read is in the C-6 allowlist: `net/tcp{,6}`, the proc root's directory, and, per
//! process, `comm`, `cmdline`, `stat`, `exe`, `ns/net`, `fd`, and `fd/<n>`. Links are read with
//! `readlinkat`, never followed or opened.

pub mod parse;

use std::collections::{BTreeMap, BTreeSet};
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
    /// The runtime processes, and the processes that hold a recorded listener, by PID.
    pub processes: Vec<ProcessObs>,
    /// By ID.
    pub listeners: Vec<Listener>,
    /// SIGIL's own network namespace.
    pub own_net_ns: Option<u64>,
    /// PID 1 is listed. It is not, under `hidepid`, where other users' processes are hidden.
    pub pid1_visible: bool,
    /// What could not be read, and might hide the runtime or its sockets: a table, the process
    /// list, a process that could not be identified.
    pub gaps: Vec<String>,
}

/// Whether a process is the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeMatch {
    Confirmed,
    Rejected,
    /// Its name or arguments could not be read, so it may be.
    Unknown(String),
}

/// One process, read and closed.
struct Scanned {
    runtime: RuntimeMatch,
    fronting: bool,
    /// The listening sockets its fds refer to.
    listening: Vec<u64>,
    /// How its fd table was read: completely, or why not.
    fd_table: Observability,
    /// The process as recorded, kept when it may be needed.
    obs: Option<ProcessObs>,
}

enum Scan {
    /// It exited between the listing and the read.
    Gone,
    /// Its directory could not be opened.
    Unreadable(NotObservable),
    Read(Box<Scanned>),
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
    let rows = read_tables(root, budgets, &mut facts.gaps);
    let listening: BTreeSet<u64> = rows.iter().map(|(_, row)| row.inode).collect();

    let pids = list_pids(root, budgets, &mut facts.gaps);
    facts.pid1_visible = pids.contains(&1);
    let mut scanned: Vec<Scanned> = vec![];
    // Why some fd table could not be listed completely, if one could not.
    let mut incomplete: Option<NotObservable> = None;
    for pid in pids {
        match scan(root, pid, &listening, at, boot_id, budgets) {
            Scan::Gone => {}
            Scan::Unreadable(why) => {
                facts.gaps.push(format!(
                    "process {pid} cannot be read ({why:?}); it may be the runtime"
                ));
                incomplete = Some(worse(incomplete, why));
            }
            Scan::Read(s) => {
                if let RuntimeMatch::Unknown(why) = &s.runtime {
                    facts
                        .gaps
                        .push(format!("process {pid} may be the runtime: {why}"));
                }
                if let Observability::NotObservable(why) = s.fd_table {
                    incomplete = Some(worse(incomplete, why));
                }
                scanned.push(*s);
            }
        }
    }

    let mut holders: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, s) in scanned.iter().enumerate() {
        for inode in &s.listening {
            holders.entry(*inode).or_default().push(i);
        }
    }
    let mut recorded: BTreeMap<usize, ProcessObs> = BTreeMap::new();
    for (i, s) in scanned.iter().enumerate() {
        if s.runtime == RuntimeMatch::Confirmed {
            if let Some(obs) = &s.obs {
                recorded.insert(i, obs.clone());
            }
        }
    }
    for (protocol, row) in rows {
        let held = holders
            .get(&row.inode)
            .map(Vec::as_slice)
            .unwrap_or_default();
        // The runtime first, then a process that may be the runtime, then a fronting one.
        let rank = |i: &usize| match (&scanned[*i].runtime, scanned[*i].fronting) {
            (RuntimeMatch::Confirmed, _) => Some(0),
            (RuntimeMatch::Unknown(_), _) => Some(1),
            (RuntimeMatch::Rejected, true) => Some(2),
            (RuntimeMatch::Rejected, false) => None,
        };
        let holder = held
            .iter()
            .filter_map(|i| rank(i).map(|r| (r, *i)))
            .min()
            .map(|(_, i)| i);
        let owner = match (holder, held.is_empty()) {
            (Some(i), _) => {
                let Some(obs) = recorded.get(&i).or(scanned[i].obs.as_ref()).cloned() else {
                    // It exited meanwhile: nothing to attribute to.
                    continue;
                };
                let process = obs.process.clone();
                recorded.insert(i, obs);
                ListenerOwner::Process { process }
            }
            // A known owner that is neither the runtime nor fronting: not recorded.
            (None, false) => continue,
            // No table holds it: unheld only if every table was listed completely.
            (None, true) => match incomplete {
                Some(why) => ListenerOwner::Unknown { why },
                None => ListenerOwner::Unheld,
            },
        };
        if let Some(listener) = listener(protocol, row, owner) {
            facts.listeners.push(listener);
        }
    }
    facts.listeners.sort_by(|a, b| a.id.cmp(&b.id));
    facts.processes = recorded.into_values().collect();
    facts
}

/// `PermissionDenied` over any other reason, so that an unknown owner names the likelier cause.
fn worse(known: Option<NotObservable>, why: NotObservable) -> NotObservable {
    match known {
        Some(NotObservable::PermissionDenied) => NotObservable::PermissionDenied,
        _ => why,
    }
}

/// The LISTEN rows of both tables. A table not read, or a row not understood, is a gap.
fn read_tables(
    root: BorrowedFd<'_>,
    budgets: ProcBudgets,
    gaps: &mut Vec<String>,
) -> Vec<(Protocol, parse::TcpListen)> {
    let mut rows = vec![];
    for (name, protocol, v6) in [
        ("net/tcp", Protocol::Tcp, false),
        ("net/tcp6", Protocol::Tcp6, true),
    ] {
        match read_limited(root, name, budgets.max_table_bytes) {
            Ok(Read::Whole(bytes)) => {
                let mut malformed = 0;
                for line in String::from_utf8_lossy(&bytes).lines() {
                    match parse::tcp_row(line, v6) {
                        parse::TcpRow::Listen(row) => rows.push((protocol, row)),
                        parse::TcpRow::NotListen => {}
                        parse::TcpRow::Malformed => malformed += 1,
                    }
                }
                if malformed > 0 {
                    gaps.push(format!("{name}: {malformed} rows could not be read"));
                }
            }
            Ok(Read::OverLimit) => gaps.push(format!("{name} is over its budget")),
            Err(e) => gaps.push(format!("{name} cannot be read ({e})")),
        }
    }
    rows
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
fn list_pids(root: BorrowedFd<'_>, budgets: ProcBudgets, gaps: &mut Vec<String>) -> Vec<u32> {
    let dir = match rustix::fs::Dir::read_from(root) {
        Ok(dir) => dir,
        Err(e) => {
            gaps.push(format!("the process list cannot be read ({e})"));
            return vec![];
        }
    };
    let mut pids = vec![];
    for entry in dir {
        let Ok(entry) = entry else {
            gaps.push("the process list could not be read to the end".into());
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
            gaps.push(format!("more than {} processes", budgets.max_processes));
            break;
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    pids
}

/// Reads one process and closes its directory.
fn scan(
    root: BorrowedFd<'_>,
    pid: u32,
    listening: &BTreeSet<u64>,
    at: &Timestamp,
    boot_id: &str,
    budgets: ProcBudgets,
) -> Scan {
    let dir = match open_dir(root, &pid.to_string()) {
        Ok(dir) => dir,
        Err(Errno::NOENT | Errno::SRCH) => return Scan::Gone,
        Err(e) => return Scan::Unreadable(not_observable(e)),
    };
    let dir = dir.as_fd();
    let comm = match read_limited(dir, "comm", 64) {
        Ok(Read::Whole(mut bytes)) => {
            while bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            Some(bytes)
        }
        Err(Errno::NOENT | Errno::SRCH) => return Scan::Gone,
        _ => None,
    };
    let (listening_held, fd_table) = match sockets(dir, listening, budgets) {
        Some(found) => found,
        None => return Scan::Gone,
    };
    let runtime = match comm.as_deref() {
        None => RuntimeMatch::Unknown("its name cannot be read".into()),
        Some(b"ollama") => runtime_match(dir),
        Some(_) => RuntimeMatch::Rejected,
    };
    let fronting = comm
        .as_deref()
        .is_some_and(|c| FRONTING.iter().any(|f| f.as_bytes() == c));
    // Kept for the runtime, and for a process that may own a recorded listener.
    let keep = runtime == RuntimeMatch::Confirmed
        || (!listening_held.is_empty()
            && (fronting || matches!(runtime, RuntimeMatch::Unknown(_))));
    let obs = if keep {
        observation(dir, pid, comm, &runtime, fd_table, at, boot_id)
    } else {
        None
    };
    Scan::Read(Box::new(Scanned {
        runtime,
        fronting,
        listening: listening_held,
        fd_table,
        obs,
    }))
}

/// `ollama serve` by its arguments, unless an `exe` that can be read is not `ollama`.
fn runtime_match(dir: BorrowedFd<'_>) -> RuntimeMatch {
    let argv = match read_limited(dir, "cmdline", 64 << 10) {
        Ok(Read::Whole(bytes)) => parse::cmdline(&bytes),
        Ok(Read::OverLimit) => {
            return RuntimeMatch::Unknown("its arguments are over 64 KiB".into())
        }
        Err(e) => return RuntimeMatch::Unknown(format!("its arguments cannot be read ({e})")),
    };
    let by_argv = argv.len() >= 2 && basename(&argv[0]) == b"ollama" && argv[1] == b"serve";
    if !by_argv {
        return RuntimeMatch::Rejected;
    }
    match exe(dir) {
        Ok((path, _)) if basename(&path) != b"ollama" => RuntimeMatch::Rejected,
        _ => RuntimeMatch::Confirmed,
    }
}

/// The executable's path and whether it was deleted.
fn exe(dir: BorrowedFd<'_>) -> Result<(Vec<u8>, bool), NotObservable> {
    let link = rustix::fs::readlinkat(dir, "exe", Vec::new()).map_err(not_observable)?;
    let bytes = link.into_bytes();
    match bytes.strip_suffix(b" (deleted)") {
        Some(path) => Ok((path.to_vec(), true)),
        None => Ok((bytes, false)),
    }
}

/// The process as recorded; `None` when it exited meanwhile. `argv` only for the runtime.
fn observation(
    dir: BorrowedFd<'_>,
    pid: u32,
    comm: Option<Vec<u8>>,
    runtime: &RuntimeMatch,
    fd_table: Observability,
    at: &Timestamp,
    boot_id: &str,
) -> Option<ProcessObs> {
    let start_ticks = match read_limited(dir, "stat", 4096) {
        Ok(Read::Whole(bytes)) => parse::stat_start_ticks(&String::from_utf8_lossy(&bytes))?,
        _ => return None,
    };
    let net_ns = match rustix::fs::readlinkat(dir, "ns/net", Vec::new()) {
        Ok(link) => match parse::link_inode(link.as_bytes(), "net") {
            Some(inode) => NsInode::Inode(inode),
            None => NsInode::NotObservable(NotObservable::ReadIncomplete),
        },
        Err(e) => NsInode::NotObservable(not_observable(e)),
    };
    let exe = match exe(dir) {
        Ok((path, deleted)) => ProcessExe::Path {
            path: UntrustedText::from_bytes(path),
            deleted,
        },
        Err(why) => ProcessExe::NotObservable(why),
    };
    let confirmed = *runtime == RuntimeMatch::Confirmed;
    let argv = match read_limited(dir, "cmdline", 64 << 10) {
        Ok(Read::Whole(bytes)) if confirmed => Some(
            parse::cmdline(&bytes)
                .into_iter()
                .map(UntrustedText::from_bytes)
                .collect(),
        ),
        _ => None,
    };
    Some(ProcessObs {
        process: ProcessRef {
            pid,
            start_ticks,
            boot_id: boot_id.to_string(),
        },
        at: at.clone(),
        roles: if confirmed {
            ProcessRole::new(RUNTIME_ROLE).ok().into_iter().collect()
        } else {
            vec![]
        },
        exe,
        mappings: vec![],
        name: comm.map(UntrustedText::from_bytes),
        argv,
        net_ns,
        fd_table,
    })
}

/// The listening sockets a process's fds refer to, and whether its fd table was listed
/// completely. `None` when it exited meanwhile.
fn sockets(
    dir: BorrowedFd<'_>,
    listening: &BTreeSet<u64>,
    budgets: ProcBudgets,
) -> Option<(Vec<u64>, Observability)> {
    let fds = match open_dir(dir, "fd") {
        Ok(fds) => fds,
        Err(Errno::NOENT | Errno::SRCH) => return None,
        Err(e) => return Some((vec![], Observability::NotObservable(not_observable(e)))),
    };
    let incomplete = Observability::NotObservable(NotObservable::ReadIncomplete);
    let Ok(entries) = rustix::fs::Dir::read_from(fds.as_fd()) else {
        return Some((vec![], incomplete));
    };
    let mut held = vec![];
    let mut count: u64 = 0;
    let mut state = Observability::Observed;
    for entry in entries {
        let Ok(entry) = entry else {
            state = incomplete;
            break;
        };
        let Ok(name) = entry.file_name().to_str() else {
            state = incomplete;
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        count += 1;
        if count > budgets.max_fds {
            state = incomplete;
            break;
        }
        match rustix::fs::readlinkat(fds.as_fd(), name, Vec::new()) {
            Ok(link) => {
                if let Some(inode) = parse::link_inode(link.as_bytes(), "socket") {
                    if listening.contains(&inode) {
                        held.push(inode);
                    }
                }
            }
            // Closed meanwhile: not a socket it holds.
            Err(Errno::NOENT) => {}
            Err(_) => state = incomplete,
        }
    }
    Some((held, state))
}

fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}

fn not_observable(e: Errno) -> NotObservable {
    match e {
        Errno::ACCESS | Errno::PERM => NotObservable::PermissionDenied,
        Errno::NOENT | Errno::SRCH => NotObservable::NoProcess,
        _ => NotObservable::ReadIncomplete,
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
